#!/usr/bin/env python3
"""Integridad SDL — SHA-256 + Ed25519 (claves forenses existentes)."""
from __future__ import annotations
import hashlib
import json
from typing import Any, Dict, Optional, Tuple

from services.sdl.limitations import NA


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def sha256_hex(payload: str | bytes) -> str:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sign_record_core(core: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Firma el nucleo del registro.
    Returns: (sha256, signature_hex, key_id) o (sha256, NA, NA) si firma no disponible.
    """
    digest = sha256_hex(canonical_json(core))
    try:
        from services.forensic_evidence_keys import load_signing_keypair
        private_key, key_id = load_signing_keypair()
        sig = private_key.sign(digest.encode("utf-8")).hex()
        return digest, sig, key_id or "novus-ed25519-default"
    except Exception:
        return digest, NA, NA


def verify_record(core: Dict[str, Any], expected_sha: str, signature_hex: Optional[str]) -> Dict[str, Any]:
    digest = sha256_hex(canonical_json(core))
    hash_ok = digest == expected_sha
    sig_ok = False
    if signature_hex and signature_hex != NA:
        try:
            from services.forensic_evidence_keys import load_trusted_public_keys
            sig = bytes.fromhex(signature_hex)
            for _name, pub in load_trusted_public_keys():
                try:
                    pub.verify(sig, digest.encode("utf-8"))
                    sig_ok = True
                    break
                except Exception:
                    continue
        except Exception:
            sig_ok = False
    return {
        "hash_ok": hash_ok,
        "signature_ok": sig_ok if signature_hex and signature_hex != NA else NA,
        "computed_sha256": digest,
        "expected_sha256": expected_sha,
    }
