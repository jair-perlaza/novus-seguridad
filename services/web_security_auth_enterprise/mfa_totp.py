"""
T1 — MFA TOTP real (pyotp) + códigos de recuperación.
CLOUD-P0: persistencia primaria en DB (MfaTotpCredential) para multi-instancia.
Secretos cifrados (Fernet derivado de NOVUS_MFA_KEY / SECRET_KEY).
Migración one-shot desde mfa_store.json si existe fila ausente.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import logger

_lock = threading.Lock()
_STORE = Path(__file__).resolve().parents[2] / "data" / "web_security_auth_enterprise" / "mfa_store.json"
# database (default) | file — file solo para emergencia/rollback local
_BACKEND = (os.environ.get("NOVUS_MFA_BACKEND") or "database").strip().lower()


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fernet():
    from cryptography.fernet import Fernet
    import base64

    raw = (
        os.environ.get("NOVUS_MFA_KEY")
        or os.environ.get("SECRET_KEY")
        or "novus-local-mfa-dev-key-change-me"
    )
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _enc(plain: str) -> str:
    return _fernet().encrypt(plain.encode("utf-8")).decode("ascii")


def _dec(token: str) -> str:
    return _fernet().decrypt(token.encode("ascii")).decode("utf-8")


def _use_database() -> bool:
    return _BACKEND in ("database", "db", "sql", "postgres", "postgresql", "sqlite")


def _file_ensure() -> None:
    _STORE.parent.mkdir(parents=True, exist_ok=True)
    if not _STORE.exists():
        _STORE.write_text("{}", encoding="utf-8")


def _file_load() -> Dict[str, Any]:
    _file_ensure()
    try:
        return json.loads(_STORE.read_text(encoding="utf-8") or "{}")
    except Exception:
        return {}


def _file_save(data: Dict[str, Any]) -> None:
    _file_ensure()
    _STORE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _row_to_rec(row) -> Dict[str, Any]:
    if row is None:
        return {}
    hashes = []
    if row.recovery_hashes_json:
        try:
            hashes = json.loads(row.recovery_hashes_json) or []
        except Exception:
            hashes = []
    return {
        "secret_enc": row.secret_enc,
        "pending_secret_enc": row.pending_secret_enc,
        "enabled": bool(row.enabled),
        "recovery_hashes": hashes,
        "pending_at_utc": row.pending_at_utc,
        "enrolled_at_utc": row.enrolled_at_utc,
        "updated_at_utc": row.updated_at_utc,
        "disabled_at_utc": row.disabled_at_utc,
        "policy_locked": bool(row.policy_locked),
    }


def _migrate_file_email_to_db(email: str) -> Optional[Dict[str, Any]]:
    """One-shot: si hay registro en JSON y no en DB, copiar a DB."""
    data = _file_load()
    rec = data.get(email)
    if not rec:
        return None
    from database import SessionLocal, MfaTotpCredential

    db = SessionLocal()
    try:
        existing = db.query(MfaTotpCredential).filter(MfaTotpCredential.email == email).first()
        if existing:
            return _row_to_rec(existing)
        row = MfaTotpCredential(
            email=email,
            secret_enc=rec.get("secret_enc"),
            pending_secret_enc=rec.get("pending_secret_enc"),
            enabled=bool(rec.get("enabled")),
            recovery_hashes_json=json.dumps(rec.get("recovery_hashes") or [], ensure_ascii=False),
            pending_at_utc=rec.get("pending_at_utc"),
            enrolled_at_utc=rec.get("enrolled_at_utc"),
            updated_at_utc=rec.get("updated_at_utc") or _utc(),
            disabled_at_utc=rec.get("disabled_at_utc"),
            policy_locked=bool(rec.get("policy_locked")),
        )
        db.add(row)
        db.commit()
        logger.info("MFA CLOUD-P0 migrated file→db for one account (email redacted)")
        return _row_to_rec(row)
    except Exception as exc:
        db.rollback()
        logger.warning("MFA file→db migrate failed: %s", exc)
        return rec
    finally:
        db.close()


def _db_get(email: str) -> Dict[str, Any]:
    from database import SessionLocal, MfaTotpCredential

    db = SessionLocal()
    try:
        row = db.query(MfaTotpCredential).filter(MfaTotpCredential.email == email).first()
        if row:
            return _row_to_rec(row)
    except Exception as exc:
        logger.debug("MFA db get: %s", exc)
        return {}
    finally:
        db.close()
    migrated = _migrate_file_email_to_db(email)
    return migrated or {}


def _db_put(email: str, rec: Dict[str, Any]) -> None:
    from database import SessionLocal, MfaTotpCredential

    db = SessionLocal()
    try:
        row = db.query(MfaTotpCredential).filter(MfaTotpCredential.email == email).first()
        if not row:
            row = MfaTotpCredential(email=email)
            db.add(row)
        row.secret_enc = rec.get("secret_enc")
        row.pending_secret_enc = rec.get("pending_secret_enc")
        row.enabled = bool(rec.get("enabled"))
        row.recovery_hashes_json = json.dumps(rec.get("recovery_hashes") or [], ensure_ascii=False)
        row.pending_at_utc = rec.get("pending_at_utc")
        row.enrolled_at_utc = rec.get("enrolled_at_utc")
        row.updated_at_utc = rec.get("updated_at_utc") or _utc()
        row.disabled_at_utc = rec.get("disabled_at_utc")
        row.policy_locked = bool(rec.get("policy_locked"))
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("MFA db put failed: %s", exc)
        raise
    finally:
        db.close()


def _get_rec(email: str) -> Dict[str, Any]:
    if _use_database():
        try:
            return _db_get(email)
        except Exception as exc:
            logger.warning("MFA DB backend unavailable, file fallback: %s", exc)
    return (_file_load().get(email) or {})


def _put_rec(email: str, rec: Dict[str, Any]) -> None:
    if _use_database():
        try:
            _db_put(email, rec)
            return
        except Exception as exc:
            logger.warning("MFA DB put failed, file fallback: %s", exc)
    data = _file_load()
    data[email] = rec
    _file_save(data)


def is_mfa_enabled(user_email: str) -> bool:
    email = (user_email or "").strip().lower()
    with _lock:
        rec = _get_rec(email)
    return bool(rec.get("enabled") and rec.get("secret_enc"))


def mfa_status(user_email: str) -> Dict[str, Any]:
    email = (user_email or "").strip().lower()
    with _lock:
        rec = _get_rec(email)
    return {
        "enabled": bool(rec.get("enabled")),
        "has_recovery_codes": bool(rec.get("recovery_hashes")),
        "enrolled_at_utc": rec.get("enrolled_at_utc"),
        "engine": "pyotp_totp",
        "simulated": False,
        "backend": "database" if _use_database() else "file",
    }


def _make_qr_png_base64(content: str) -> Optional[str]:
    try:
        import base64
        import io

        import qrcode

        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=2)
        qr.add_data(content)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        return None


def _pending_expired(updated_at_utc: Optional[str], *, max_age_hours: int = 24) -> bool:
    if not updated_at_utc:
        return True
    try:
        ts = datetime.strptime(updated_at_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - ts
        return age.total_seconds() > max_age_hours * 3600
    except Exception:
        return True


def _enrollment_payload(
    secret: str,
    email: str,
    *,
    issuer: str,
    reused: bool,
    include_sensitive: bool = True,
) -> Dict[str, Any]:
    import pyotp

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name=issuer)
    qr_b64 = _make_qr_png_base64(uri)
    out: Dict[str, Any] = {
        "ok": True,
        "issuer": issuer,
        "account_name": email,
        "qr_png_base64": qr_b64,
        "reused_pending": reused,
        "note": "Confirmar con verify_and_enable usando un código TOTP válido",
    }
    if include_sensitive:
        out["secret"] = secret
        out["otpauth_uri"] = uri
    return out


def begin_enrollment(
    user_email: str,
    *,
    issuer: str = "NOVUS",
    regenerate: bool = False,
    include_sensitive: bool = True,
) -> Dict[str, Any]:
    import pyotp

    email = (user_email or "").strip().lower()
    if not email:
        return {"ok": False, "error": "email_required"}
    with _lock:
        rec = _get_rec(email)
        if rec.get("enabled") and rec.get("secret_enc"):
            return {"ok": False, "error": "already_enabled"}
        reused = False
        secret: Optional[str] = None
        pending_enc = rec.get("pending_secret_enc")
        pending_ts = rec.get("pending_at_utc") or rec.get("updated_at_utc")
        if pending_enc and not regenerate and not _pending_expired(pending_ts):
            try:
                secret = _dec(pending_enc)
                reused = True
            except Exception:
                secret = None
        if not secret:
            secret = pyotp.random_base32()
            rec = {
                **rec,
                "pending_secret_enc": _enc(secret),
                "enabled": False,
                "pending_at_utc": _utc(),
                "updated_at_utc": _utc(),
            }
            _put_rec(email, rec)
            reused = False
    return _enrollment_payload(secret, email, issuer=issuer, reused=reused, include_sensitive=include_sensitive)


def verify_and_enable(user_email: str, code: str, *, policy_lock: Optional[bool] = None) -> Dict[str, Any]:
    import pyotp

    email = (user_email or "").strip().lower()
    code = (code or "").strip().replace(" ", "")
    with _lock:
        rec = _get_rec(email)
        pend = rec.get("pending_secret_enc") or rec.get("secret_enc")
        if not pend:
            return {"ok": False, "error": "no_pending_enrollment"}
        secret = _dec(pend)
        totp = pyotp.TOTP(secret)
        if not totp.verify(code, valid_window=1):
            return {"ok": False, "error": "invalid_code"}
        recovery_plain = [secrets.token_hex(4) for _ in range(8)]
        recovery_hashes = [
            hashlib.sha256(c.encode("utf-8")).hexdigest() for c in recovery_plain
        ]
        new_rec: Dict[str, Any] = {
            "secret_enc": _enc(secret),
            "enabled": True,
            "recovery_hashes": recovery_hashes,
            "enrolled_at_utc": _utc(),
            "updated_at_utc": _utc(),
        }
        try:
            from services.web_security_auth_enterprise.mfa_policy import user_requires_mfa

            lock = user_requires_mfa(email) if policy_lock is None else bool(policy_lock)
            if lock:
                new_rec["policy_locked"] = True
        except Exception:
            pass
        _put_rec(email, new_rec)
    _audit_mfa(email, "mfa_enabled")
    return {"ok": True, "enabled": True, "recovery_codes": recovery_plain}


def disable_mfa(user_email: str, *, code: Optional[str] = None, recovery_code: Optional[str] = None) -> Dict[str, Any]:
    from services.web_security_auth_enterprise.mfa_policy import (
        audit_mfa_policy_event,
        mfa_disable_allowed,
    )

    email = (user_email or "").strip().lower()
    with _lock:
        rec = _get_rec(email)
        if rec.get("policy_locked"):
            audit_mfa_policy_event(
                email,
                "mfa_disable_blocked_policy",
                detail={"reason": "policy_locked"},
            )
            return {"ok": False, "error": "mfa_mandatory_for_role", "policy": "admin_mfa_mandatory"}
    if not mfa_disable_allowed(email):
        audit_mfa_policy_event(
            email,
            "mfa_disable_blocked_policy",
            detail={"reason": "mandatory_admin_role"},
        )
        return {"ok": False, "error": "mfa_mandatory_for_role", "policy": "admin_mfa_mandatory"}
    if not verify_code(email, code=code, recovery_code=recovery_code).get("ok"):
        return {"ok": False, "error": "verification_failed"}
    with _lock:
        _put_rec(email, {"enabled": False, "disabled_at_utc": _utc(), "updated_at_utc": _utc()})
    _audit_mfa(email, "mfa_disabled")
    return {"ok": True, "enabled": False}


def verify_code(
    user_email: str,
    *,
    code: Optional[str] = None,
    recovery_code: Optional[str] = None,
) -> Dict[str, Any]:
    import pyotp

    email = (user_email or "").strip().lower()
    with _lock:
        rec = _get_rec(email)
        if not rec.get("enabled") or not rec.get("secret_enc"):
            return {"ok": False, "error": "mfa_not_enabled"}
        secret = _dec(rec["secret_enc"])
        if code:
            code = str(code).strip().replace(" ", "")
            if pyotp.TOTP(secret).verify(code, valid_window=1):
                return {"ok": True, "method": "totp"}
        if recovery_code:
            rc = str(recovery_code).strip().lower()
            h = hashlib.sha256(rc.encode("utf-8")).hexdigest()
            hashes = list(rec.get("recovery_hashes") or [])
            if h in hashes:
                hashes.remove(h)
                rec["recovery_hashes"] = hashes
                rec["updated_at_utc"] = _utc()
                _put_rec(email, rec)
                return {"ok": True, "method": "recovery"}
        return {"ok": False, "error": "invalid_code"}


def engine_available() -> bool:
    try:
        import pyotp  # noqa: F401

        return True
    except Exception:
        return False


def _audit_mfa(email: str, action: str) -> None:
    try:
        from services.web_security_auth_enterprise.publish import publish_wsae, seal_wsae

        fid = f"mfa-{action}-{email[:8]}"
        ev = {"action": action, "email_prefix": email[:3] + "***"}
        publish_wsae(action=action, evidence=ev, threat_type="auth_mfa", finding_id=fid, risk_level="info", user_email=email)
        seal_wsae(finding_id=fid, action=action, evidence=ev, risk_level="info")
    except Exception:
        pass
