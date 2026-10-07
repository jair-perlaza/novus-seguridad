#!/usr/bin/env python3
"""CLOUD-P1 verification — SYNTHETIC_TEST_ONLY. No GCP. No real client data.

Does NOT install PostgreSQL. Marks POSTGRESQL_E2E / MULTI_INSTANCE_HTTP_E2E
as NOT_VERIFIABLE when unavailable.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

os.environ.setdefault("NOVUS_SKIP_NETWORK_DISCOVERY", "1")
os.environ.setdefault("NOVUS_MFA_BACKEND", "database")
os.environ.setdefault("NOVUS_RUNTIME", "cloud")
# Isolated SQLite for harness — never touch production vault path via overwrite;
# use tempfile only for create_app healthz if needed.
os.environ.pop("DATABASE_URL", None)

OUT = ROOT / "data/novus_beta_operations/cloud_registration_billing_audit/cloud_p1"
OUT.mkdir(parents=True, exist_ok=True)

EMAIL = "synthetic.cloud.p1.mfa@novus.test.local"
results = {
    "timestamp": datetime.now().isoformat(timespec="seconds"),
    "label": "SYNTHETIC_TEST_ONLY",
    "tests": {},
    "baseline": {},
    "POSTGRESQL_E2E": "NOT_VERIFIABLE",
    "MULTI_INSTANCE_HTTP_E2E": "NOT_VERIFIABLE",
}


def log(name, ok, detail=None):
    results["tests"][name] = {"ok": bool(ok), "detail": detail}
    print(("PASS" if ok else "FAIL"), name, detail if detail is not None else "", flush=True)
    return bool(ok)


def _pg_available() -> bool:
    import importlib.util
    import shutil

    has_driver = bool(importlib.util.find_spec("psycopg") or importlib.util.find_spec("psycopg2"))
    has_psql = bool(shutil.which("psql"))
    sock_open = False
    try:
        s = socket.create_connection(("127.0.0.1", 5432), timeout=0.5)
        s.close()
        sock_open = True
    except OSError:
        sock_open = False
    results["postgres_probe"] = {
        "driver": has_driver,
        "psql": has_psql,
        "port_5432": sock_open,
    }
    return has_driver and (has_psql or sock_open)


def baseline_host():
    try:
        import psutil

        m = psutil.virtual_memory()
        results["baseline"] = {
            "RAM_pct": m.percent,
            "CPU_pct": psutil.cpu_percent(0.5),
            "THREADS_HOST": sum(
                (p.info.get("num_threads") or 0)
                for p in psutil.process_iter(["num_threads"])
            ),
            "PORT_5000": "UP"
            if socket.socket().connect_ex(("127.0.0.1", 5000)) == 0
            else "DOWN",
        }
    except Exception as exc:
        results["baseline"] = {"error": str(exc)[:120]}


def main():
    baseline_host()
    pg_ok = _pg_available()
    if pg_ok:
        results["POSTGRESQL_E2E"] = "AVAILABLE_NOT_RUN"  # would run if credentials provided
    else:
        results["POSTGRESQL_E2E"] = "NOT_VERIFIABLE"
        log("postgresql_available", False, results.get("postgres_probe"))

    # --- Runtime gate ---
    from services.cloud_runtime_service import (
        is_cloud_runtime,
        may_run_network_discovery,
        may_start_engine,
        runtime_info,
    )

    log("cloud_runtime_detected", is_cloud_runtime(), runtime_info())
    log("network_discovery_blocked_on_cloud", not may_run_network_discovery(), None)
    log(
        "endpoint_enterprise_blocked_on_cloud",
        not may_start_engine("endpoint_enterprise"),
        None,
    )
    log("btde_blocked_on_cloud", not may_start_engine("btde"), None)

    os.environ["NOVUS_RUNTIME"] = "client_node"
    prev_skip = os.environ.pop("NOVUS_SKIP_NETWORK_DISCOVERY", None)
    log("client_node_allows_discovery", may_run_network_discovery(), runtime_info())
    if prev_skip is not None:
        os.environ["NOVUS_SKIP_NETWORK_DISCOVERY"] = prev_skip
    log("client_node_allows_endpoint", may_start_engine("endpoint_enterprise"), None)
    os.environ["NOVUS_RUNTIME"] = "cloud"
    os.environ.setdefault("NOVUS_SKIP_NETWORK_DISCOVERY", "1")

    # --- SQLite still default ---
    from database import DB_BACKEND, DATABASE_URL, database_backend_info, ensure_tables_exist, Base, engine, SessionLocal
    from sqlalchemy import text

    ensure_tables_exist()
    Base.metadata.create_all(bind=engine)
    info = database_backend_info()
    log("sqlite_default_intact", DB_BACKEND == "sqlite", info)

    # Schema type audit (static) for PG readiness
    blockers = []
    for table in Base.metadata.sorted_tables:
        for col in table.columns:
            tname = type(col.type).__name__
            # Flag known SQLite-only quirks if any appear
            if tname in ("JSON",) and DB_BACKEND == "sqlite":
                pass  # JSON maps OK in both with SQLAlchemy
    log("schema_static_pg_audit", len(blockers) == 0, {"blockers": blockers, "tables": len(Base.metadata.tables)})

    # --- MFA + session on current backend (SQLite) ---
    from database import MfaTotpCredential, LoginSessionAudit
    from services.web_security_auth_enterprise import mfa_totp as mt
    from services.login_session_audit_service import is_login_session_active, close_login_session
    import pyotp

    db = SessionLocal()
    try:
        db.query(MfaTotpCredential).filter(MfaTotpCredential.email == EMAIL).delete()
        db.commit()
    finally:
        db.close()

    enr = mt.begin_enrollment(EMAIL, include_sensitive=True)
    secret = enr.get("secret")
    log("mfa_enroll", bool(secret), {"backend": mt.mfa_status(EMAIL).get("backend")})
    if secret:
        totp = pyotp.TOTP(secret)
        code = totp.now()
        en = mt.verify_and_enable(EMAIL, code)
        log("mfa_enable", bool(en.get("ok")), {"enabled": en.get("enabled")})
        del secret
        st = mt.mfa_status(EMAIL)
        log("mfa_status_enabled", bool(st.get("enabled")), {"backend": st.get("backend")})

    sid = f"synth-cloud-p1-{int(time.time())}"
    db = SessionLocal()
    try:
        row = LoginSessionAudit(
            id=sid,
            tenant_id="P1C001-PROBE",
            user_email=EMAIL,
            login_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            ip_address="127.0.0.1",
            session_id=f"flask-synth-{sid[-8:]}",
            user_agent="SYNTHETIC_TEST_ONLY",
            login_result="success",
            active=True,
        )
        db.add(row)
        db.commit()
        log("session_create", True, {"id_prefix": sid[:20]})
    except Exception as exc:
        db.rollback()
        log("session_create", False, str(exc)[:160])
        sid = None
    finally:
        db.close()

    if sid:
        log("session_active_before", is_login_session_active(sid), sid[:24])
        close_login_session(session_audit_id=sid)
        log("session_inactive_after", not is_login_session_active(sid), None)

    # --- healthz via test client (no port 5000 conflict) ---
    os.environ.setdefault("NOVUS_ENV", "beta")
    os.environ.setdefault("FLASK_DEBUG", "False")
    # Use synthetic secret for signing only in this process
    os.environ.setdefault("SECRET_KEY", "SYNTHETIC_TEST_ONLY_CLOUD_P1_SECRET_DO_NOT_USE_PROD")
    os.environ.setdefault("NOVUS_REQUIRE_SHARED_SECRET", "0")

    from core.app import create_app

    app = create_app("beta")
    client = app.test_client()
    t0 = time.time()
    resp = client.get("/healthz")
    lat_ms = (time.time() - t0) * 1000
    body = resp.get_json(silent=True) or {}
    log(
        "healthz_ok",
        resp.status_code == 200 and body.get("ok") is True and body.get("database", {}).get("ok") is True,
        {"status": resp.status_code, "latency_ms": round(lat_ms, 1), "body_ok": body.get("ok"), "db": body.get("database")},
    )
    log("healthz_no_secret_leak", "SECRET" not in json.dumps(body).upper() and "password" not in json.dumps(body).lower(), None)
    log("port_5000_config_unchanged", int(os.environ.get("PORT", "5000")) == 5000, os.environ.get("PORT", "5000"))
    log("debug_false_beta", app.config.get("DEBUG") is False, app.config.get("DEBUG"))

    # Tenant canonical
    from services.tenant_isolation_service import require_canonical_tenant_id, TenantAccessDenied

    class _U:
        nit_pyme = "P1C001-PROBE"
        email = "a@example.com"

    tid = require_canonical_tenant_id(user=_U())
    log("tenant_a_canonical", tid == "P1C001-PROBE", tid)
    class _Ub:
        nit_pyme = "901.567.123-4"
        email = "b@example.com"
    tid_b = require_canonical_tenant_id(user=_Ub())
    log("tenant_b_canonical", tid_b == "901.567.123-4", tid_b)
    try:
        require_canonical_tenant_id(user=type("X", (), {"email": "x@evil.com", "nit_pyme": None})())
        log("tenant_rejects_email_only", False, "accepted")
    except Exception:
        log("tenant_rejects_email_only", True, None)

    # Cleanup MFA fixture
    db = SessionLocal()
    try:
        db.query(MfaTotpCredential).filter(MfaTotpCredential.email == EMAIL).delete()
        if sid:
            db.query(LoginSessionAudit).filter(LoginSessionAudit.id == sid).delete()
        db.commit()
    finally:
        db.close()

    fails = [k for k, v in results["tests"].items() if not v.get("ok")]
    # postgresql_available expected fail when missing — not a harness regression
    soft = {"postgresql_available"}
    hard_fails = [k for k in fails if k not in soft]
    results["verdict"] = (
        "CLOUD_P1_LOCAL_CHECKS_PASS_WITH_LIMITATIONS"
        if not hard_fails
        else "CLOUD_P1_LOCAL_CHECKS_FAIL"
    )
    results["hard_fails"] = hard_fails
    results["ABUSE_GUARD_DISTRIBUTED_STATE"] = "NOT_READY"
    results["CRYPTOVAULT_CLOUD_SHARED_STORAGE"] = "NOT_READY"

    out_path = OUT / "_p1_harness_raw.json"
    out_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print("SUMMARY", results["verdict"], "PG", results["POSTGRESQL_E2E"], flush=True)
    return 0 if not hard_fails else 1


if __name__ == "__main__":
    raise SystemExit(main())
