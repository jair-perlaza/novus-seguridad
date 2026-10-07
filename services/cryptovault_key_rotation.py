"""Rotación versionada de clave AES CryptoVault — conserva claves previas para descifrado."""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict

from utils.logger import logger

from services.sensitive_operations_audit import log_sensitive_operation

KEYRING_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "cryptovault", "keyring.json"
)
LEGACY_KEY_PATH = "master_aes.key"


def _key_age_days() -> float:
    """Edad de la clave activa (mtime del wrap o keyring)."""
    try:
        from crypto_vault import CryptoVault, KEYRING_PATH as KR

        v = CryptoVault()
        kid = v.active_kid
        if kid:
            path = v._wrapped_path(kid)
            if os.path.isfile(path):
                mtime = os.path.getmtime(path)
                return (datetime.now().timestamp() - mtime) / 86400.0
        if os.path.isfile(KR):
            mtime = os.path.getmtime(KR)
            return (datetime.now().timestamp() - mtime) / 86400.0
    except Exception:
        pass
    if os.path.isfile(LEGACY_KEY_PATH):
        mtime = os.path.getmtime(LEGACY_KEY_PATH)
        return (datetime.now().timestamp() - mtime) / 86400.0
    return 0.0


def rotate_aes_master_key(*, actor: str = "system", max_age_days: int = 0) -> Dict[str, Any]:
    """
    Rota a nueva versión AES envuelta.
    Ciphertext antiguo permanece descifrable vía keyring (no requiere re-cifrado inmediato).
    """
    from crypto_vault import CryptoVault

    vault = CryptoVault()
    previous_kid = vault.active_kid
    result = vault.rotate_aes_key(actor=actor)
    result["max_age_days_requested"] = max_age_days
    result["compatibility"] = "previous_key_versions_retained_for_decrypt"
    # Fase 2: re-cifrado automático con la nueva clave (sin pérdida; kids previos se conservan)
    try:
        from services.key_reencryption_service import reencrypt_all_after_rotation

        reenc = reencrypt_all_after_rotation(
            actor=actor,
            previous_kid=result.get("previous_kid") or previous_kid,
            new_kid=result.get("new_kid"),
        )
        result["reencrypt"] = {
            "status": reenc.get("status"),
            "total_reencrypted": reenc.get("total_reencrypted"),
            "targets": reenc.get("targets"),
        }
    except Exception as exc:
        logger.error("post-rotation reencrypt failed: %s", exc)
        result["reencrypt"] = {"status": "error", "error": str(exc)[:200]}
    log_sensitive_operation(
        "cryptovault_aes_rotate",
        actor=actor,
        outcome="success",
        detail={
            "new_kid": result.get("new_kid"),
            "previous_kid": result.get("previous_kid"),
            "keys_retained": result.get("keys_retained"),
            "reencrypt_total": (result.get("reencrypt") or {}).get("total_reencrypted"),
        },
    )
    logger.info(
        "CryptoVault AES rotated kid=%s prev=%s retained=%s reencrypt=%s",
        result.get("new_kid"),
        result.get("previous_kid"),
        len(result.get("keys_retained") or []),
        (result.get("reencrypt") or {}).get("total_reencrypted"),
    )
    return result


def maybe_rotate_on_schedule(max_age_days: int = 90) -> Dict[str, Any]:
    """Rotación automática si la clave activa supera max_age_days."""
    if max_age_days <= 0:
        return {"status": "skipped", "reason": "rotation_disabled"}
    age = _key_age_days()
    if age < max_age_days:
        return {"status": "skipped", "reason": "key_within_age", "age_days": round(age, 2)}
    out = rotate_aes_master_key(actor="schedule", max_age_days=max_age_days)
    out["age_days_before"] = round(age, 2)
    return out
