#!/usr/bin/env python3
"""Pruebas auditoría avanzada de inicio de sesión."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RESULTS = []


def check(name: str, fn):
    try:
        ok, detail = fn()
        RESULTS.append({"name": name, "pass": bool(ok), "detail": str(detail)[:400]})
        print(f"[{'OK' if ok else 'FAIL'}] {name}")
        return bool(ok)
    except Exception as exc:
        RESULTS.append({"name": name, "pass": False, "error": str(exc)})
        print(f"[FAIL] {name}: {exc}")
        return False


def main():
    from database import Base, engine, ensure_tables_exist, SessionLocal, LoginSessionAudit, Log
    from services.login_session_audit_service import (
        parse_client_from_user_agent,
        open_login_session,
        close_login_session,
        list_login_sessions,
        get_login_session,
        run_post_login_security_check,
    )

    ensure_tables_exist()

    check("tabla login_session_audits", lambda: (
        "login_session_audits" in [t.name for t in Base.metadata.tables.values()],
        "model exists",
    ))

    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
    info = parse_client_from_user_agent(ua)
    check("parse user agent", lambda: (
        info.get("browser") == "Chrome" and info.get("os_name") != "No disponible",
        info,
    ))

    opened = open_login_session(
        user_id=1,
        user_email="novus.qa.jul2026@example.com",
        ip="127.0.0.1",
        session_id="test-session-audit-01",
        user_agent=ua,
        login_result="success",
    )
    sid = opened.get("session_audit_id")
    check("open login session", lambda: (opened.get("success") and sid, opened))

    check("post-login check evidence", lambda: (
        isinstance((get_login_session(sid) or {}).get("post_login_check"), dict),
        (get_login_session(sid) or {}).keys(),
    ))

    check("security status assigned", lambda: (
        (get_login_session(sid) or {}).get("security_status") in ("clean", "warning", "alert"),
        (get_login_session(sid) or {}).get("security_status"),
    ))

    closed = close_login_session(session_audit_id=sid)
    check("close session duration", lambda: (
        closed.get("closed") and closed.get("duration_seconds") is not None,
        closed,
    ))

    db = SessionLocal()
    try:
        has_start = db.query(Log).filter(Log.evento == "SESSION_START").count() >= 1
        has_end = db.query(Log).filter(Log.evento == "SESSION_END").count() >= 1
    finally:
        db.close()
    check("audit logs SESSION_START/END", lambda: (has_start and has_end, f"start={has_start} end={has_end}"))

    check("list sessions", lambda: (len(list_login_sessions(limit=5)) >= 1, list_login_sessions(3)))

    check("no fake data in check", lambda: (
        "fake" not in json.dumps(run_post_login_security_check("test@example.com", "127.0.0.1", "LS-test")).lower(),
        "evidence from real motors",
    ))

    out = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "login_session_audit", "test_results.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    passed = sum(1 for r in RESULTS if r["pass"])
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"results": RESULTS, "passed": passed, "total": len(RESULTS)}, fh, indent=2)

    print(f"\n=== LOGIN SESSION AUDIT: {passed}/{len(RESULTS)} ===")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
