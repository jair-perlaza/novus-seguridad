"""
Cifrado en reposo de la base SQLite (equivalente empresarial a SQLCipher).

DECISIÓN TÉCNICA
----------------
SQLCipher (pysqlcipher3/sqlcipher3) NO está instalado en el entorno NOVUS.
Forzar SQLCipher rompería SQLAlchemy `sqlite:///./novus_vault_v2.db` sin migración
de dialecto y recompilación.

Equivalente implementado (real, AES-256-GCM):
- Contenedor en disco `novus_vault_v2.db.novusenc` (archivo DB completo cifrado).
- Runtime: la app sigue usando SQLite estándar (compatibilidad).
- En reposo / backup / sellado: el archivo DB se cifra con la clave activa del CryptoVault.
- Al arranque: si solo existe el contenedor cifrado y falta el .db, se restaura/descifra.

Limitación honestamente documentada:
- Mientras NOVUS está en ejecución con el .db abierto, el archivo de trabajo es SQLite
  en claro en disco (igual que cualquier app sin SQLCipher). La protección at-rest
  aplica al contenedor cifrado y a backups cifrados.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime
from typing import Any, Dict, Optional

from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_NAME = "novus_vault_v2.db"
DB_PATH = os.path.join(ROOT, DB_NAME)
ENC_PATH = os.path.join(ROOT, DB_NAME + ".novusenc")
META_PATH = os.path.join(ROOT, "data", "cryptovault", "db_at_rest_meta.json")
MAGIC = b"NOVUSDBENC1"


def _vault():
    from crypto_vault import CryptoVault

    return CryptoVault()


def capabilities() -> Dict[str, Any]:
    return {
        "sqlcipher_available": False,
        "sqlcipher_implemented": False,
        "equivalent_file_aes_gcm": True,
        "container_path": ENC_PATH,
        "runtime_db_path": DB_PATH,
        "decision": (
            "SQLCipher no disponible en el entorno. "
            "Equivalente: cifrado AES-256-GCM del archivo SQLite completo (.novusenc)."
        ),
        "runtime_limitation": (
            "El .db de trabajo permanece en claro mientras el proceso lo tiene abierto; "
            "el contenedor .novusenc y los backups cifrados protegen el reposo/frío."
        ),
    }


def seal_database_at_rest(*, actor: str = "system") -> Dict[str, Any]:
    """Cifra el archivo SQLite actual hacia .novusenc (at-rest)."""
    if not os.path.isfile(DB_PATH):
        return {"ok": False, "reason": "db_missing"}
    with open(DB_PATH, "rb") as fh:
        raw = fh.read()
    digest = hashlib.sha256(raw).hexdigest()
    vault = _vault()
    # Encrypt raw bytes via base64 inside versioned AES (same as data_at_rest)
    import base64

    b64 = base64.b64encode(raw).decode("ascii")
    sealed = vault.proteger(b64)
    if sealed.startswith("[ERROR"):
        return {"ok": False, "reason": "encrypt_failed"}
    envelope = {
        "format": MAGIC.decode("ascii"),
        "sealed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sha256_plain": digest,
        "size_plain": len(raw),
        "active_kid": vault.active_kid,
        "ciphertext": sealed,
    }
    os.makedirs(os.path.dirname(META_PATH), exist_ok=True)
    tmp = ENC_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh)
    os.replace(tmp, ENC_PATH)
    with open(META_PATH, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "last_seal": envelope["sealed_at"],
                "sha256_plain": digest,
                "active_kid": vault.active_kid,
                "actor": actor,
            },
            fh,
            indent=2,
        )
    try:
        from services.forensic_evidence_integrity_service import seal_evidence

        seal_evidence(
            source_id=f"DBATREST-{digest[:16]}",
            source_type="db_at_rest",
            motor="db_at_rest_encryption",
            evidence_type="database_seal",
            payload={
                "sha256_plain": digest,
                "size": len(raw),
                "kid": vault.active_kid,
                "path": ENC_PATH,
            },
        )
    except Exception:
        pass
    logger.info("DB at-rest sealed → %s sha256=%s", ENC_PATH, digest[:16])
    return {"ok": True, "enc_path": ENC_PATH, "sha256_plain": digest, "size": len(raw)}


def unseal_database_from_at_rest(*, dest: Optional[str] = None, actor: str = "system") -> Dict[str, Any]:
    """Descifra .novusenc hacia el .db de trabajo (o dest)."""
    dest = dest or DB_PATH
    if not os.path.isfile(ENC_PATH):
        return {"ok": False, "reason": "enc_missing"}
    with open(ENC_PATH, encoding="utf-8") as fh:
        envelope = json.load(fh)
    vault = _vault()
    import base64

    plain_b64 = vault.desproteger(envelope.get("ciphertext") or "")
    if plain_b64.startswith("[ERROR"):
        return {"ok": False, "reason": "decrypt_failed", "detail": plain_b64}
    raw = base64.b64decode(plain_b64)
    digest = hashlib.sha256(raw).hexdigest()
    expected = envelope.get("sha256_plain")
    if expected and digest != expected:
        return {"ok": False, "reason": "integrity_mismatch", "expected": expected, "actual": digest}
    tmp = dest + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(raw)
    os.replace(tmp, dest)
    return {"ok": True, "db_path": dest, "sha256_plain": digest, "size": len(raw)}


def ensure_runtime_database() -> Dict[str, Any]:
    """
    Si falta el .db pero existe contenedor cifrado, restaura.
    No elimina el .enc (sigue siendo la copia at-rest).
    """
    if os.path.isfile(DB_PATH):
        return {"ok": True, "action": "db_present"}
    if os.path.isfile(ENC_PATH):
        out = unseal_database_from_at_rest(actor="startup")
        out["action"] = "restored_from_enc"
        return out
    return {"ok": False, "action": "nothing", "reason": "no_db_no_enc"}


def verify_at_rest_container() -> Dict[str, Any]:
    if not os.path.isfile(ENC_PATH):
        return {"ok": False, "status": "missing_container"}
    try:
        with open(ENC_PATH, encoding="utf-8") as fh:
            env = json.load(fh)
        vault = _vault()
        import base64

        plain_b64 = vault.desproteger(env.get("ciphertext") or "")
        if plain_b64.startswith("[ERROR"):
            return {"ok": False, "status": "decrypt_failed"}
        raw = base64.b64decode(plain_b64)
        digest = hashlib.sha256(raw).hexdigest()
        match = digest == env.get("sha256_plain")
        return {
            "ok": match,
            "status": "verified" if match else "integrity_fail",
            "sha256": digest,
            "kid": env.get("active_kid"),
            "size": len(raw),
        }
    except Exception as exc:
        return {"ok": False, "status": "error", "error": str(exc)[:200]}
