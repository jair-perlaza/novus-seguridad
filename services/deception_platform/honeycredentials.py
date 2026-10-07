#!/usr/bin/env python3
"""Honeycredentials DPE — cuentas senuelo; nunca coinciden con usuarios reales."""
from __future__ import annotations
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from services.deception_platform.limitations import NAMESPACE, USERNAME_PREFIX, NA
from services.deception_platform.segregation import assert_decoy_username
from services.deception_platform.store import append_jsonl, read_jsonl, CREDS_PATH, ensure_dir


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


ROLES = ("usuario", "administrador", "cuenta_servicio")


def create_honeycredential(role: str = "usuario") -> Dict[str, Any]:
    role = (role or "usuario").lower().strip()
    if role not in ROLES:
        return {"ok": False, "error": f"rol no soportado: {role}", "supported": list(ROLES)}
    uid = str(uuid.uuid4())
    username = f"{USERNAME_PREFIX}{role}.{secrets.token_hex(3)}"
    check = assert_decoy_username(username)
    if not check.get("allowed"):
        return {"ok": False, "error": "colision_con_usuario_real", "check": check}
    # Password is decoy-only; never a real account password
    password = f"DPE-DECOY-{secrets.token_urlsafe(10)}"
    entry = {
        "uuid": uid,
        "username": username,
        "role": role,
        "password_local_only": password,
        "namespace": NAMESPACE,
        "decoy": True,
        "real_account": False,
        "estado": "emitido",
        "fecha": _utc(),
        "segregation": check,
        "invented": False,
    }
    ensure_dir()
    append_jsonl(CREDS_PATH, entry)
    public = {k: v for k, v in entry.items() if k != "password_local_only"}
    public["password_redacted"] = True
    return {"ok": True, "credential": public}


def list_honeycredentials(limit: int = 200) -> Dict[str, Any]:
    rows = []
    for c in read_jsonl(CREDS_PATH, limit):
        p = {k: v for k, v in c.items() if k != "password_local_only"}
        p["password_redacted"] = True
        rows.append(p)
    return {
        "count": len(rows),
        "credentials": list(reversed(rows)),
        "roles": list(ROLES),
        "invented": False,
    }
