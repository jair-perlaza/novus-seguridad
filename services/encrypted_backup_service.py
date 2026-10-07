"""
Backups cifrados obligatorios (Fase 2).

- Cada respaldo se cifra con CryptoVault (AES-GCM versionado)
- Integridad SHA-256 del plaintext + sello forense
- Restore comprobado (descifrado + verificación de hash)
- Impide almacenar copias sin cifrar en el directorio de backups
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKUP_DIR = os.path.join(ROOT, "data", "encrypted_backups")
FORBIDDEN_PLAIN_EXT = (".db", ".sqlite", ".sqlite3", ".sql", ".dump")


def _vault():
    from crypto_vault import CryptoVault

    return CryptoVault()


def _ensure_dir() -> None:
    os.makedirs(BACKUP_DIR, exist_ok=True)


def enforce_no_plaintext_backups() -> Dict[str, Any]:
    """Elimina o rechaza archivos en claro en el directorio de backups."""
    _ensure_dir()
    removed: List[str] = []
    for name in os.listdir(BACKUP_DIR):
        path = os.path.join(BACKUP_DIR, name)
        if not os.path.isfile(path):
            continue
        lower = name.lower()
        if lower.endswith(".novusbak.json"):
            continue
        if any(lower.endswith(ext) for ext in FORBIDDEN_PLAIN_EXT) or lower.endswith(".zip"):
            try:
                os.remove(path)
                removed.append(name)
            except OSError:
                pass
    return {"ok": True, "removed_plaintext": removed}


def create_encrypted_backup(
    *,
    include_db: bool = True,
    include_cryptovault_meta: bool = True,
    label: str = "manual",
    actor: str = "system",
) -> Dict[str, Any]:
    """
    Empaqueta artefactos sensibles, cifra el zip completo y guarda solo .novusbak.json.
    """
    _ensure_dir()
    enforce_no_plaintext_backups()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    work = os.path.join(BACKUP_DIR, f"_work_{stamp}")
    os.makedirs(work, exist_ok=True)
    try:
        if include_db:
            db = os.path.join(ROOT, "novus_vault_v2.db")
            if os.path.isfile(db):
                shutil.copy2(db, os.path.join(work, "novus_vault_v2.db"))
            enc = db + ".novusenc"
            if os.path.isfile(enc):
                shutil.copy2(enc, os.path.join(work, "novus_vault_v2.db.novusenc"))
        if include_cryptovault_meta:
            cv = os.path.join(ROOT, "data", "cryptovault")
            if os.path.isdir(cv):
                dest_cv = os.path.join(work, "cryptovault")
                shutil.copytree(cv, dest_cv, dirs_exist_ok=True)
        zip_path = os.path.join(work, "payload.zip")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(work):
                for f in files:
                    if f == "payload.zip":
                        continue
                    full = os.path.join(root, f)
                    arc = os.path.relpath(full, work)
                    zf.write(full, arc)
        with open(zip_path, "rb") as fh:
            raw = fh.read()
        digest = hashlib.sha256(raw).hexdigest()
        import base64

        vault = _vault()
        sealed = vault.proteger(base64.b64encode(raw).decode("ascii"))
        if sealed.startswith("[ERROR"):
            return {"ok": False, "reason": "encrypt_failed"}
        bak_name = f"backup_{stamp}_{label}.novusbak.json"
        bak_path = os.path.join(BACKUP_DIR, bak_name)
        envelope = {
            "format": "NOVUSBAK1",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "label": label,
            "actor": actor,
            "sha256_plain": digest,
            "size_plain": len(raw),
            "active_kid": vault.active_kid,
            "ciphertext": sealed,
            "encrypted": True,
            "plaintext_forbidden": True,
        }
        with open(bak_path, "w", encoding="utf-8") as fh:
            json.dump(envelope, fh)
        shutil.rmtree(work, ignore_errors=True)
        enforce_no_plaintext_backups()
        try:
            from services.sensitive_operations_audit import log_sensitive_operation

            log_sensitive_operation(
                "encrypted_backup_create",
                actor=actor,
                outcome="success",
                detail={"path": bak_name, "sha256": digest, "kid": vault.active_kid},
            )
        except Exception:
            pass
        try:
            from services.forensic_evidence_integrity_service import seal_evidence

            seal_evidence(
                source_id=f"BAK-{digest[:16]}",
                source_type="encrypted_backup",
                motor="encrypted_backup_service",
                evidence_type="backup_create",
                payload={
                    "file": bak_name,
                    "sha256_plain": digest,
                    "size": len(raw),
                    "kid": vault.active_kid,
                    "encrypted": True,
                },
                user_email=actor if "@" in str(actor) else None,
            )
        except Exception:
            pass
        logger.info("Encrypted backup created: %s", bak_name)
        return {
            "ok": True,
            "path": bak_path,
            "file": bak_name,
            "sha256_plain": digest,
            "size": len(raw),
            "kid": vault.active_kid,
        }
    except Exception as exc:
        shutil.rmtree(work, ignore_errors=True)
        logger.error("encrypted backup failed: %s", exc)
        return {"ok": False, "reason": str(exc)[:300]}


def verify_backup(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {"ok": False, "reason": "missing"}
    with open(path, encoding="utf-8") as fh:
        env = json.load(fh)
    if not env.get("encrypted") or not env.get("ciphertext"):
        return {"ok": False, "reason": "not_encrypted"}
    vault = _vault()
    import base64

    plain_b64 = vault.desproteger(env["ciphertext"])
    if plain_b64.startswith("[ERROR"):
        return {"ok": False, "reason": "decrypt_failed"}
    raw = base64.b64decode(plain_b64)
    digest = hashlib.sha256(raw).hexdigest()
    match = digest == env.get("sha256_plain")
    return {
        "ok": match,
        "sha256": digest,
        "expected": env.get("sha256_plain"),
        "size": len(raw),
        "kid": env.get("active_kid"),
        "integrity": "verified" if match else "fail",
    }


def restore_encrypted_backup(
    path: str,
    *,
    dest_dir: Optional[str] = None,
    actor: str = "system",
) -> Dict[str, Any]:
    """Restaura a un directorio aislado y verifica integridad."""
    ver = verify_backup(path)
    if not ver.get("ok"):
        return {"ok": False, "verify": ver}
    with open(path, encoding="utf-8") as fh:
        env = json.load(fh)
    vault = _vault()
    import base64

    raw = base64.b64decode(vault.desproteger(env["ciphertext"]))
    dest_dir = dest_dir or os.path.join(
        BACKUP_DIR, "_restore_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    os.makedirs(dest_dir, exist_ok=True)
    zip_path = os.path.join(dest_dir, "payload.zip")
    with open(zip_path, "wb") as fh:
        fh.write(raw)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest_dir)
    os.remove(zip_path)
    try:
        from services.forensic_evidence_integrity_service import seal_evidence

        seal_evidence(
            source_id=f"BAKRESTORE-{ver['sha256'][:16]}",
            source_type="encrypted_backup",
            motor="encrypted_backup_service",
            evidence_type="backup_restore",
            payload={"source": os.path.basename(path), "dest": dest_dir, "sha256": ver["sha256"]},
            user_email=actor if "@" in str(actor) else None,
        )
    except Exception:
        pass
    return {"ok": True, "dest": dest_dir, "sha256": ver["sha256"], "verify": ver}


def list_backups() -> List[Dict[str, Any]]:
    _ensure_dir()
    out = []
    for name in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if not name.endswith(".novusbak.json"):
            continue
        path = os.path.join(BACKUP_DIR, name)
        try:
            with open(path, encoding="utf-8") as fh:
                env = json.load(fh)
            out.append(
                {
                    "file": name,
                    "path": path,
                    "created_at": env.get("created_at"),
                    "sha256_plain": env.get("sha256_plain"),
                    "encrypted": bool(env.get("encrypted")),
                    "kid": env.get("active_kid"),
                }
            )
        except Exception:
            continue
    return out
