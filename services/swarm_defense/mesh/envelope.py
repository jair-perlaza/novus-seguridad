#!/usr/bin/env python3
"""
Sobre Mesh: cifrado AES-256-GCM + firma Ed25519 + anti-replay metadata.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def seal_envelope(
    *,
    payload: Dict[str, Any],
    peer_id: str,
    sender_node_id: str,
    private_key,
    channel_key: bytes,
    msg_type: str = "threat_intel",
) -> Dict[str, Any]:
    """Cifra payload con AES-GCM del canal y firma el sobre con Ed25519 del nodo emisor."""
    nonce = os.urandom(12)
    plaintext = _canonical(payload)
    aes = AESGCM(channel_key)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    meta = {
        "v": 1,
        "msg_id": f"MESH-{uuid.uuid4().hex}",
        "msg_type": msg_type,
        "sender_node_id": sender_node_id,
        "recipient_peer_id": peer_id,
        "created_at_utc": _utc(),
        "created_ts": int(time.time()),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "cipher": "AES-256-GCM",
        "sig_alg": "Ed25519",
        "payload_sha256": hashlib.sha256(plaintext).hexdigest(),
    }
    to_sign = _canonical({**meta, "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii")})
    signature = private_key.sign(to_sign)
    return {
        "meta": meta,
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def open_envelope(
    *,
    envelope: Dict[str, Any],
    channel_key: bytes,
    sender_public_key,
) -> Tuple[bool, Dict[str, Any], str]:
    """
    Verifica firma, descifra, valida integridad.
    Returns (ok, payload_or_detail, reason).
    """
    try:
        meta = dict(envelope.get("meta") or {})
        ct_b64 = envelope.get("ciphertext_b64") or ""
        sig_b64 = envelope.get("signature_b64") or ""
        if not meta or not ct_b64 or not sig_b64:
            return False, {}, "missing_fields"
        to_sign = _canonical({**meta, "ciphertext_b64": ct_b64})
        signature = base64.b64decode(sig_b64)
        sender_public_key.verify(signature, to_sign)
        nonce = base64.b64decode(meta.get("nonce_b64") or "")
        ciphertext = base64.b64decode(ct_b64)
        aes = AESGCM(channel_key)
        plaintext = aes.decrypt(nonce, ciphertext, None)
        expected = meta.get("payload_sha256")
        actual = hashlib.sha256(plaintext).hexdigest()
        if expected and expected != actual:
            return False, {}, "payload_hash_mismatch"
        payload = json.loads(plaintext.decode("utf-8"))
        if not isinstance(payload, dict):
            return False, {}, "payload_not_object"
        return True, payload, "ok"
    except Exception as exc:
        return False, {"error": str(exc)[:200]}, "crypto_or_signature_failure"
