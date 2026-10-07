"""
T6–T7 — Gestión de sesiones + refresh tokens (rotación, revocación).
"""
from __future__ import annotations

import json
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import logger

_lock = threading.Lock()
_STORE = Path(__file__).resolve().parents[2] / "data" / "web_security_auth_enterprise" / "sessions.json"

# TTL configurables (segundos)
ACCESS_TTL_SEC = 60 * 60 * 8
REFRESH_TTL_SEC = 60 * 60 * 24 * 7


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure() -> None:
    _STORE.parent.mkdir(parents=True, exist_ok=True)
    if not _STORE.exists():
        _STORE.write_text("{}", encoding="utf-8")


def _load() -> Dict[str, Any]:
    _ensure()
    try:
        return json.loads(_STORE.read_text(encoding="utf-8") or "{}")
    except Exception:
        return {"sessions": {}, "refresh": {}}


def _save(data: Dict[str, Any]) -> None:
    _ensure()
    _STORE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def register_session(
    *,
    session_id: str,
    user_email: str,
    ip: str,
    fingerprint: Optional[str] = None,
    risk: Optional[dict] = None,
) -> Dict[str, Any]:
    with _lock:
        data = _load()
        sessions = data.setdefault("sessions", {})
        # Detectar sesiones duplicadas (mismo user, distinto sid, misma FP)
        dup = []
        for sid, s in sessions.items():
            if (
                s.get("user_email") == user_email
                and sid != session_id
                and s.get("active")
                and fingerprint
                and s.get("fingerprint") == fingerprint
            ):
                dup.append(sid)
        exp = (_now() + timedelta(seconds=ACCESS_TTL_SEC)).strftime("%Y-%m-%dT%H:%M:%SZ")
        refresh = secrets.token_urlsafe(32)
        refresh_exp = (_now() + timedelta(seconds=REFRESH_TTL_SEC)).strftime("%Y-%m-%dT%H:%M:%SZ")
        sessions[session_id] = {
            "session_id": session_id,
            "user_email": user_email,
            "ip": ip,
            "fingerprint": fingerprint,
            "risk": risk,
            "active": True,
            "created_at_utc": _utc(),
            "expires_at_utc": exp,
            "duplicate_sids": dup,
        }
        data.setdefault("refresh", {})[refresh] = {
            "session_id": session_id,
            "user_email": user_email,
            "expires_at_utc": refresh_exp,
            "rotated_from": None,
            "active": True,
        }
        _save(data)
    return {
        "session_id": session_id,
        "refresh_token": refresh,
        "expires_at_utc": exp,
        "refresh_expires_at_utc": refresh_exp,
        "duplicate_sessions": dup,
    }


def list_active_sessions(user_email: str) -> List[Dict[str, Any]]:
    email = (user_email or "").strip().lower()
    with _lock:
        data = _load()
        out = []
        for sid, s in (data.get("sessions") or {}).items():
            if (s.get("user_email") or "").lower() == email and s.get("active"):
                out.append(s)
        return out


def revoke_session(session_id: str, *, reason: str = "manual") -> Dict[str, Any]:
    with _lock:
        data = _load()
        s = (data.get("sessions") or {}).get(session_id)
        if not s:
            return {"ok": False, "error": "not_found"}
        s["active"] = False
        s["revoked_at_utc"] = _utc()
        s["revoke_reason"] = reason
        # invalidate refresh tokens for session
        for tok, r in list((data.get("refresh") or {}).items()):
            if r.get("session_id") == session_id:
                r["active"] = False
                r["revoked_at_utc"] = _utc()
        _save(data)
    try:
        from services.swarm_defense.session_revoke import revoke_user_sessions

        revoke_user_sessions(user_email=s.get("user_email"), session_id=session_id, reason=reason)
    except Exception as exc:
        logger.debug("wsae swarm revoke hook: %s", exc)
    return {"ok": True, "session_id": session_id, "reason": reason}


def revoke_all_user_sessions(user_email: str, *, reason: str = "logout_global") -> Dict[str, Any]:
    email = (user_email or "").strip().lower()
    n = 0
    with _lock:
        data = _load()
        for sid, s in (data.get("sessions") or {}).items():
            if (s.get("user_email") or "").lower() == email and s.get("active"):
                s["active"] = False
                s["revoked_at_utc"] = _utc()
                s["revoke_reason"] = reason
                n += 1
        for tok, r in list((data.get("refresh") or {}).items()):
            if (r.get("user_email") or "").lower() == email:
                r["active"] = False
        _save(data)
    try:
        from services.swarm_defense.session_revoke import revoke_user_sessions

        revoke_user_sessions(user_email=email, reason=reason)
    except Exception as exc:
        logger.debug("wsae logout global: %s", exc)
    return {"ok": True, "revoked_n": n, "reason": reason}


def rotate_refresh_token(refresh_token: str) -> Dict[str, Any]:
    """Rotación automática: invalida el refresh anterior, emite uno nuevo."""
    with _lock:
        data = _load()
        r = (data.get("refresh") or {}).get(refresh_token)
        if not r or not r.get("active"):
            return {"ok": False, "error": "invalid_refresh"}
        # expiry check
        try:
            exp = datetime.strptime(r["expires_at_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if _now() > exp:
                r["active"] = False
                _save(data)
                return {"ok": False, "error": "refresh_expired"}
        except Exception:
            pass
        r["active"] = False
        r["rotated_at_utc"] = _utc()
        new_tok = secrets.token_urlsafe(32)
        refresh_exp = (_now() + timedelta(seconds=REFRESH_TTL_SEC)).strftime("%Y-%m-%dT%H:%M:%SZ")
        data.setdefault("refresh", {})[new_tok] = {
            "session_id": r.get("session_id"),
            "user_email": r.get("user_email"),
            "expires_at_utc": refresh_exp,
            "rotated_from": refresh_token[:8] + "…",
            "active": True,
        }
        _save(data)
    return {
        "ok": True,
        "refresh_token": new_tok,
        "refresh_expires_at_utc": refresh_exp,
        "session_id": r.get("session_id"),
        "rotated": True,
    }


def is_session_active(session_id: str) -> bool:
    with _lock:
        s = (_load().get("sessions") or {}).get(session_id) or {}
    if not s.get("active"):
        return False
    try:
        exp = datetime.strptime(s["expires_at_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return _now() <= exp
    except Exception:
        return bool(s.get("active"))
