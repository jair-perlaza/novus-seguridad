#!/usr/bin/env python3
"""Honeytokens DPE — tokens senuelo firmados; nunca credenciales reales."""
from __future__ import annotations
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.deception_platform.limitations import HONEYTOKEN_TYPES, NA, NAMESPACE, USERNAME_PREFIX
from services.deception_platform.segregation import assert_decoy_username
from services.deception_platform.store import append_jsonl, read_jsonl, TOKENS_PATH, ensure_dir


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _sign(digest: str) -> tuple:
    try:
        from services.forensic_evidence_keys import load_signing_keypair
        pk, kid = load_signing_keypair()
        return pk.sign(digest.encode()).hex(), kid or "novus-ed25519-default"
    except Exception:
        return NA, NA


def _mint_value(tipo: str) -> str:
    if tipo == "api_key":
        return f"dpe_ak_{secrets.token_urlsafe(24)}"
    if tipo == "jwt":
        # Synthetic JWT-shaped decoy — not a valid signed JWT from IdP
        hdr = secrets.token_urlsafe(8)
        payload = secrets.token_urlsafe(16)
        sig = secrets.token_urlsafe(16)
        return f"{hdr}.{payload}.{sig}"
    if tipo == "oauth_token":
        return f"dpe_oauth_{secrets.token_urlsafe(28)}"
    if tipo == "cookie":
        return f"dpe_sess={secrets.token_urlsafe(20)}"
    if tipo == "secret":
        return f"dpe_sec_{secrets.token_hex(16)}"
    if tipo == "password":
        return f"DPE!{secrets.token_urlsafe(12)}"
    if tipo == "usuario":
        return f"{USERNAME_PREFIX}{secrets.token_hex(4)}"
    return f"dpe_{tipo}_{secrets.token_urlsafe(16)}"


def mint_honeytoken(tipo: str, origen: str = "dpe_operator") -> Dict[str, Any]:
    tipo = (tipo or "").lower().strip()
    if tipo not in HONEYTOKEN_TYPES:
        return {"ok": False, "error": f"tipo no soportado: {tipo}", "supported": HONEYTOKEN_TYPES}
    value = _mint_value(tipo)
    if tipo == "usuario":
        check = assert_decoy_username(value)
        if not check.get("allowed"):
            return {"ok": False, "error": "colision_con_usuario_real", "check": check}
    uid = str(uuid.uuid4())
    core = {
        "uuid": uid,
        "tipo": tipo,
        "origen": origen,
        "namespace": NAMESPACE,
        "value_fingerprint": hashlib.sha256(value.encode()).hexdigest(),
        "invented_attack": False,
        "decoy": True,
    }
    digest = hashlib.sha256(_canonical(core).encode()).hexdigest()
    sig, kid = _sign(digest)
    token = {
        "uuid": uid,
        "fecha": _utc(),
        "tipo": tipo,
        "origen": origen,
        "hash": digest,
        "value_sha256": core["value_fingerprint"],
        "firma": sig,
        "key_id": kid,
        "estado": "emitido",
        "namespace": NAMESPACE,
        "decoy": True,
        "real_credential": False,
        # Valor solo en store local — nunca se envia a Swarm
        "value_local_only": value,
        "invented": False,
    }
    ensure_dir()
    append_jsonl(TOKENS_PATH, token)
    public = {k: v for k, v in token.items() if k != "value_local_only"}
    public["value_redacted"] = True
    return {"ok": True, "token": public, "has_local_secret": True}


def list_honeytokens(limit: int = 200) -> Dict[str, Any]:
    rows = read_jsonl(TOKENS_PATH, limit)
    public = []
    for t in rows:
        p = {k: v for k, v in t.items() if k != "value_local_only"}
        p["value_redacted"] = True
        public.append(p)
    return {
        "count": len(public),
        "tokens": list(reversed(public)),
        "types": HONEYTOKEN_TYPES,
        "invented": False,
    }


def get_token(uid: str) -> Optional[Dict[str, Any]]:
    for t in read_jsonl(TOKENS_PATH, 5000):
        if t.get("uuid") == uid:
            p = {k: v for k, v in t.items() if k != "value_local_only"}
            p["value_redacted"] = True
            return p
    return None


def match_token_value(raw: str) -> Optional[Dict[str, Any]]:
    """Detecta uso de honeytoken por hash del valor (interaccion real)."""
    if not raw:
        return None
    fp = hashlib.sha256(raw.encode()).hexdigest()
    for t in read_jsonl(TOKENS_PATH, 5000):
        if t.get("value_sha256") == fp or hashlib.sha256(
            str(t.get("value_local_only") or "").encode()
        ).hexdigest() == fp:
            return t
    return None
