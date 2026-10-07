#!/usr/bin/env python3
"""Diagnóstico de emergencia — tiempos login/dashboard sin modificar código."""
from __future__ import annotations

import json
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_release_candidate" / "EMERGENCY_PERF_PROBE.json"

QA_EMAIL = "novus.qa.jul2026@example.com"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rss_mb() -> float | None:
    try:
        import psutil
        return round(psutil.Process().memory_info().rss / 1024 / 1024, 1)
    except Exception:
        return None


def _host_ram_pct() -> float | None:
    try:
        import psutil
        return round(psutil.virtual_memory().percent, 1)
    except Exception:
        return None


def _timed(label: str, fn):
    t0 = time.perf_counter()
    try:
        result = fn()
        err = None
    except Exception as exc:
        result = None
        err = str(exc)[:300]
    ms = round((time.perf_counter() - t0) * 1000, 1)
    return {"label": label, "ms": ms, "result": result, "error": err}


def main() -> int:
    from migrate_database import migrate_database

    migrate_database()
    from core.app import create_app
    from database import SessionLocal, Usuario

    app = create_app("development")
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SESSION_COOKIE_SECURE=False,
        SESSION_PROTECTION="basic",
    )
    app.login_manager.session_protection = "basic"

    report = {
        "generated_at": _utc(),
        "host_ram_pct_start": _host_ram_pct(),
        "rss_mb_start": _rss_mb(),
        "steps": [],
        "apis": [],
    }

    client = app.test_client()

    def record(step):
        step["host_ram_pct"] = _host_ram_pct()
        step["rss_mb"] = _rss_mb()
        report["steps"].append(step)

    record(_timed("GET /login", lambda: client.get("/login").status_code))

    db = SessionLocal()
    try:
        row = db.query(Usuario).filter(Usuario.email == QA_EMAIL).first()
        if not row:
            raise RuntimeError(f"user_not_found:{QA_EMAIL}")
        user_id = str(row.id)
        password = getattr(row, "password_plain", None) or "NovusQA2026!"
    finally:
        db.close()

    def do_post_login():
        csrf = secrets.token_urlsafe(32)
        with client.session_transaction() as sess:
            sess["_csrf_token"] = csrf
        r = client.post(
            "/login",
            data={"email": QA_EMAIL, "password": password, "csrf_token": csrf},
            follow_redirects=False,
        )
        return {"http": r.status_code, "location": r.headers.get("Location"), "len": len(r.data or b"")}

    record(_timed("POST /login", do_post_login))

    csrf = secrets.token_urlsafe(32)
    with client.session_transaction() as sess:
        sess["_user_id"] = user_id
        sess["_fresh"] = True
        sess["_novus_login_session_id"] = f"EMERG-{user_id}"
        sess["_csrf_token"] = csrf

    record(_timed("GET /dashboard", lambda: client.get("/dashboard").status_code))
    record(_timed("GET / (index)", lambda: client.get("/").status_code))

    for path in (
        "/api/health/status",
        "/api/dashboard/live",
        "/api/security/summary",
        "/api/tenant/scope",
        "/api/notifications?kind=security",
        "/api/monitoring/network-config",
    ):
        def _get(p=path):
            r = client.get(p)
            return {"http": r.status_code, "bytes": len(r.data or b"")}

        row = _timed(path, _get)
        row["host_ram_pct"] = _host_ram_pct()
        report["apis"].append(row)

    report["host_ram_pct_end"] = _host_ram_pct()
    report["rss_mb_end"] = _rss_mb()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"out": str(OUT), "steps": report["steps"], "apis": report["apis"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
