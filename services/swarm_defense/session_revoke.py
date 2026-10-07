"""Revocación de sesiones de usuario — registro verificable + chequeo en security."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

_LOCK = threading.Lock()
_PATH = os.path.join("data", "swarm_defense", "revoked_sessions.jsonl")
_revoke_cache: Optional[Tuple[float, set]] = None
_revoke_lock = threading.Lock()


def _revoke_index() -> set:
    """Índice en memoria invalidado por mtime del jsonl."""
    global _revoke_cache
    if not os.path.isfile(_PATH):
        return set()
    try:
        mtime = os.path.getmtime(_PATH)
    except OSError:
        return set()
    with _revoke_lock:
        if _revoke_cache and _revoke_cache[0] == mtime:
            return _revoke_cache[1]
        emails: set = set()
        sessions: set = set()
        try:
            with open(_PATH, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not row.get("active", True):
                        continue
                    sid = row.get("session_id")
                    email = row.get("user_email")
                    if sid:
                        sessions.add(sid)
                    if email:
                        emails.add(str(email).strip().lower())
        except OSError:
            pass
        index = (("email", e) for e in emails)
        index_set = set(index) | {("session", s) for s in sessions}
        _revoke_cache = (mtime, index_set)
        return index_set


def _ensure() -> None:
    os.makedirs(os.path.dirname(_PATH), exist_ok=True)


def revoke_user_sessions(
    *,
    user_email: Optional[str] = None,
    session_id: Optional[str] = None,
    reason: str = "",
    actor: str = "swarm",
) -> Dict[str, Any]:
    """
    Revoca sesiones por email y/o session_id NOVUS.
    El middleware en core/security.py rechaza sesiones listadas aquí.
    """
    if not user_email and not session_id:
        return {"ok": False, "status": "insufficient_evidence", "message": "Falta user_email o session_id"}
    _ensure()
    entry = {
        "revoked_at": datetime.now(timezone.utc).isoformat(),
        "user_email": (user_email or "").strip().lower() or None,
        "session_id": session_id,
        "reason": reason[:500],
        "actor": actor,
        "active": True,
    }
    with _LOCK:
        with open(_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    global _revoke_cache
    with _revoke_lock:
        _revoke_cache = None
    return {"ok": True, "status": "executed", "entry": entry, "motor": "session_revocation"}


def is_session_revoked(*, user_email: Optional[str] = None, session_id: Optional[str] = None) -> bool:
    if not os.path.isfile(_PATH):
        return False
    index = _revoke_index()
    email = (user_email or "").strip().lower()
    if session_id and ("session", session_id) in index:
        return True
    if email and ("email", email) in index:
        return True
    return False


def list_revocations(limit: int = 50) -> List[Dict[str, Any]]:
    if not os.path.isfile(_PATH):
        return []
    rows = []
    with open(_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:]
