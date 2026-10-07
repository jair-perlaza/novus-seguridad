"""
Cifrado en reposo de artefactos sensibles (compatible con arquitectura actual).

- NO usa SQLCipher (rompería SQLAlchemy/sqlite existente sin migración mayor).
- Sella archivos de evidencia/export/config/reportes internos con CryptoVault.
- Prefijo de archivo: .novusseal.json (metadatos + ciphertext versionado).
"""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime
from typing import Any, Dict, Optional

from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEALED_ROOT = os.path.join(ROOT, "data", "sealed_store")


def _vault():
    from crypto_vault import CryptoVault

    return CryptoVault()


def seal_bytes(raw: bytes, *, label: str = "blob") -> Dict[str, Any]:
    vault = _vault()
    # Binary → base64 then AES versionado
    b64 = base64.b64encode(raw).decode("ascii")
    sealed = vault.proteger(b64)
    return {
        "format": "NOVUS-SEAL-1",
        "label": label,
        "sealed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ciphertext": sealed,
        "encoding": "base64-inside-aes-gcm",
    }


def unseal_to_bytes(envelope: Dict[str, Any]) -> bytes:
    vault = _vault()
    plain_b64 = vault.desproteger(envelope.get("ciphertext") or "")
    if plain_b64.startswith("[ERROR"):
        raise RuntimeError(plain_b64)
    return base64.b64decode(plain_b64)


def seal_file(src_path: str, dest_path: Optional[str] = None) -> Dict[str, Any]:
    if not os.path.isfile(src_path):
        return {"ok": False, "reason": "missing_source"}
    with open(src_path, "rb") as fh:
        raw = fh.read()
    env = seal_bytes(raw, label=os.path.basename(src_path))
    if not dest_path:
        os.makedirs(SEALED_ROOT, exist_ok=True)
        dest_path = os.path.join(SEALED_ROOT, os.path.basename(src_path) + ".novusseal.json")
    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    with open(dest_path, "w", encoding="utf-8") as fh:
        json.dump(env, fh, indent=2)
    try:
        from services.data_access_audit_service import log_data_access

        log_data_access(
            resource=src_path,
            operation="seal_file",
            result="success",
            detail={"dest": dest_path},
        )
    except Exception:
        pass
    return {"ok": True, "dest": dest_path, "bytes": len(raw)}


def unseal_file(seal_path: str, dest_path: str) -> Dict[str, Any]:
    with open(seal_path, encoding="utf-8") as fh:
        env = json.load(fh)
    raw = unseal_to_bytes(env)
    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    with open(dest_path, "wb") as fh:
        fh.write(raw)
    try:
        from services.data_access_audit_service import log_data_access

        log_data_access(
            resource=seal_path,
            operation="unseal_file",
            result="success",
            detail={"dest": dest_path},
        )
    except Exception:
        pass
    return {"ok": True, "dest": dest_path, "bytes": len(raw)}


def seal_sensitive_config_value(key: str, value: str) -> str:
    """Cifra un valor de configuración sensible (string)."""
    return _vault().proteger(json.dumps({"k": key, "v": value}))


def unseal_sensitive_config_value(token: str) -> Optional[str]:
    raw = _vault().desproteger(token)
    if raw.startswith("[ERROR"):
        return None
    try:
        return json.loads(raw).get("v")
    except Exception:
        return None


def at_rest_capabilities() -> Dict[str, Any]:
    """Capacidades reales — SQLCipher no forzado; equivalente documentado."""
    equiv = {}
    try:
        from services.db_at_rest_encryption import capabilities as db_caps

        equiv = db_caps()
    except Exception as exc:
        equiv = {"error": str(exc)[:120]}
    return {
        "file_seal_aes_gcm": True,
        "config_value_seal": True,
        "sqlcipher_database": False,
        "db_file_aes_gcm_equivalent": bool(equiv.get("equivalent_file_aes_gcm")),
        "db_at_rest": equiv,
        "note": (
            "SQLCipher no disponible/compatible sin migrar dialecto SQLAlchemy. "
            "Equivalente: contenedor AES-256-GCM del archivo SQLite (.novusenc) + backups cifrados."
        ),
        "sealed_store": SEALED_ROOT,
    }
