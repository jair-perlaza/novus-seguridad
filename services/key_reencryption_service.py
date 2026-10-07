"""
Re-cifrado automático post-rotación AES (Fase 2).

- Identifica kid en NOVUSENC:v2:{kid}:…
- Descifra con keyring histórico y vuelve a cifrar con kid activo
- Escanea vaults de tokens, sellados, casos NDCI y blobs en BD conocidos
- Registra el proceso en forense
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENC_PREFIX = "NOVUSENC:v2:"
NDCI_PREFIX = "NOVUSENC:v1:"
KID_RE = re.compile(r"^NOVUSENC:v2:([^:]+):")


def _kid_of(token: str) -> Optional[str]:
    if not token or not isinstance(token, str):
        return None
    # NDCI wraps vault token
    payload = token[len(NDCI_PREFIX) :] if token.startswith(NDCI_PREFIX) else token
    m = KID_RE.match(payload)
    return m.group(1) if m else None


def needs_reencrypt(token: str, active_kid: Optional[str]) -> bool:
    if not token or not active_kid:
        return False
    if token.startswith("[ERROR"):
        return False
    kid = _kid_of(token)
    if kid is None:
        # legado sin kid → re-cifrar a v2 activo
        return True
    return kid != active_kid


def reencrypt_token(token: str, vault) -> Tuple[str, bool]:
    """
    Returns (new_token, changed).
    Preserva prefijo NDCI:v1 si existía.
    """
    if not needs_reencrypt(token, vault.active_kid):
        return token, False
    has_ndci = token.startswith(NDCI_PREFIX)
    payload = token[len(NDCI_PREFIX) :] if has_ndci else token
    plain = vault.desproteger(payload)
    if not plain or plain.startswith("[ERROR"):
        return token, False
    new_payload = vault.proteger(plain)
    if new_payload.startswith("[ERROR"):
        return token, False
    return (NDCI_PREFIX + new_payload if has_ndci else new_payload), True


def _reencrypt_mail_tokens(vault) -> Dict[str, Any]:
    base = os.path.join(ROOT, "data", "mail_shield", "tokens")
    changed = 0
    scanned = 0
    errors = 0
    if not os.path.isdir(base):
        return {"scanned": 0, "reencrypted": 0}
    for root, _dirs, files in os.walk(base):
        for name in files:
            if name != "credentials.vault":
                continue
            path = os.path.join(root, name)
            scanned += 1
            try:
                with open(path, encoding="utf-8") as fh:
                    wrap = json.load(fh)
                sealed = wrap.get("sealed") or ""
                new_sealed, did = reencrypt_token(sealed, vault)
                if did:
                    wrap["sealed"] = new_sealed
                    wrap["reencrypted_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    wrap["active_kid"] = vault.active_kid
                    with open(path, "w", encoding="utf-8") as fh:
                        json.dump(wrap, fh)
                    changed += 1
            except Exception as exc:
                errors += 1
                logger.debug("reencrypt mail token %s: %s", path, exc)
    return {"scanned": scanned, "reencrypted": changed, "errors": errors}


def _reencrypt_sealed_store(vault) -> Dict[str, Any]:
    base = os.path.join(ROOT, "data", "sealed_store")
    changed = scanned = errors = 0
    if not os.path.isdir(base):
        return {"scanned": 0, "reencrypted": 0}
    for name in os.listdir(base):
        if not name.endswith(".novusseal.json"):
            continue
        path = os.path.join(base, name)
        scanned += 1
        try:
            with open(path, encoding="utf-8") as fh:
                env = json.load(fh)
            ct = env.get("ciphertext") or ""
            new_ct, did = reencrypt_token(ct, vault)
            if did:
                env["ciphertext"] = new_ct
                env["reencrypted_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(env, fh, indent=2)
                changed += 1
        except Exception as exc:
            errors += 1
            logger.debug("reencrypt sealed %s: %s", path, exc)
    return {"scanned": scanned, "reencrypted": changed, "errors": errors}


def _reencrypt_ndci_cases(vault) -> Dict[str, Any]:
    base = os.path.join(ROOT, "data", "ndci_cases")
    if not os.path.isdir(base):
        # alternate paths used by ndci
        for alt in ("data/casos_estudio", "data/ndci", "data/study_cases"):
            p = os.path.join(ROOT, alt)
            if os.path.isdir(p):
                base = p
                break
    changed = scanned = errors = 0
    if not os.path.isdir(base):
        return {"scanned": 0, "reencrypted": 0, "base": base}
    for root, _dirs, files in os.walk(base):
        for name in files:
            if not name.endswith(".json"):
                continue
            path = os.path.join(root, name)
            scanned += 1
            try:
                with open(path, encoding="utf-8") as fh:
                    raw = fh.read().strip()
                if not raw.startswith(NDCI_PREFIX) and not raw.startswith(ENC_PREFIX):
                    continue
                new_raw, did = reencrypt_token(raw, vault)
                if did:
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(new_raw)
                    changed += 1
            except Exception as exc:
                errors += 1
                logger.debug("reencrypt ndci %s: %s", path, exc)
    return {"scanned": scanned, "reencrypted": changed, "errors": errors, "base": base}


def _reencrypt_db_text_columns(vault) -> Dict[str, Any]:
    """Re-cifra columnas de texto que contengan NOVUSENC en SQLite (best-effort)."""
    db_path = os.path.join(ROOT, "novus_vault_v2.db")
    if not os.path.isfile(db_path):
        return {"scanned": 0, "reencrypted": 0, "note": "db_missing"}
    import sqlite3
    import shutil
    import tempfile

    changed = scanned = 0
    # Si la DB está bloqueada por el proceso vivo, trabajar sobre una copia y reportar
    # (no reescribir en caliente el archivo bloqueado — evita corrupción).
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        conn.execute("SELECT 1")
        writable = True
    except Exception:
        writable = False
        conn = None

    work_path = db_path
    tmp_copy = None
    if not writable:
        try:
            fd, tmp_copy = tempfile.mkstemp(suffix=".db", prefix="novus_reenc_")
            os.close(fd)
            shutil.copy2(db_path, tmp_copy)
            conn = sqlite3.connect(tmp_copy, timeout=30)
            work_path = tmp_copy
        except Exception as exc:
            return {"scanned": 0, "reencrypted": 0, "error": f"db_locked_copy_failed:{exc}"[:200]}

    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        for table in tables:
            try:
                cur.execute(f"PRAGMA table_info([{table}])")
                cols = [r[1] for r in cur.fetchall()]
                for col in cols:
                    try:
                        cur.execute(
                            f"SELECT rowid, [{col}] FROM [{table}] WHERE typeof([{col}])='text'"
                        )
                        rows = cur.fetchall()
                    except Exception:
                        continue
                    for rowid, val in rows:
                        if not isinstance(val, str):
                            continue
                        if not (val.startswith(NDCI_PREFIX) or val.startswith(ENC_PREFIX)):
                            continue
                        scanned += 1
                        new_val, did = reencrypt_token(val, vault)
                        if did:
                            cur.execute(
                                f"UPDATE [{table}] SET [{col}]=? WHERE rowid=?",
                                (new_val, rowid),
                            )
                            changed += 1
            except Exception as exc:
                logger.debug("reencrypt table %s: %s", table, exc)
        conn.commit()
        conn.close()
        if tmp_copy and changed and writable is False:
            # No sobrescribir DB viva bloqueada — dejar informe para operador
            return {
                "scanned": scanned,
                "reencrypted": changed,
                "note": "db_locked_live; changes applied only on temp copy (not swapped)",
                "temp_copy": tmp_copy,
            }
        if tmp_copy and os.path.isfile(tmp_copy):
            try:
                os.remove(tmp_copy)
            except OSError:
                pass
    except Exception as exc:
        try:
            conn.close()
        except Exception:
            pass
        return {"scanned": scanned, "reencrypted": changed, "error": str(exc)[:200]}
    return {"scanned": scanned, "reencrypted": changed, "work_path": work_path}


def reencrypt_all_after_rotation(
    *,
    actor: str = "system",
    previous_kid: Optional[str] = None,
    new_kid: Optional[str] = None,
) -> Dict[str, Any]:
    from crypto_vault import CryptoVault

    vault = CryptoVault()
    active = vault.active_kid
    report: Dict[str, Any] = {
        "status": "success",
        "actor": actor,
        "active_kid": active,
        "previous_kid": previous_kid,
        "new_kid": new_kid or active,
        "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "targets": {},
    }
    report["targets"]["mail_tokens"] = _reencrypt_mail_tokens(vault)
    report["targets"]["sealed_store"] = _reencrypt_sealed_store(vault)
    report["targets"]["ndci_cases"] = _reencrypt_ndci_cases(vault)
    report["targets"]["database_text"] = _reencrypt_db_text_columns(vault)
    total = sum(int(t.get("reencrypted") or 0) for t in report["targets"].values() if isinstance(t, dict))
    report["total_reencrypted"] = total
    report["finished_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        from services.sensitive_operations_audit import log_sensitive_operation

        log_sensitive_operation(
            "cryptovault_reencrypt_after_rotation",
            actor=actor,
            outcome="success",
            detail={"total_reencrypted": total, "active_kid": active, "targets": report["targets"]},
        )
    except Exception:
        pass
    try:
        from services.forensic_evidence_integrity_service import seal_evidence

        seal_evidence(
            source_id=f"REENC-{active}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            source_type="cryptovault_reencrypt",
            motor="key_reencryption_service",
            evidence_type="key_rotation_reencrypt",
            payload={
                "active_kid": active,
                "previous_kid": previous_kid,
                "total_reencrypted": total,
                "targets": report["targets"],
                "verifiable": True,
            },
            user_email=actor if "@" in str(actor) else None,
        )
    except Exception as exc:
        logger.debug("reencrypt forensic: %s", exc)

    logger.info("Re-encrypt after rotation: %s items → kid=%s", total, active)
    return report
