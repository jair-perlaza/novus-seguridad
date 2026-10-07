#!/usr/bin/env python3
"""CLOUD-P0 local verification — SYNTHETIC_TEST_ONLY. No GCP deploy."""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

# Ensure local sqlite default; no postgres forced
os.environ.pop("DATABASE_URL", None)
os.environ.setdefault("NOVUS_MFA_BACKEND", "database")
os.environ.setdefault("NOVUS_SKIP_NETWORK_DISCOVERY", "1")

EMAIL = "synthetic.cloud.p0.mfa@novus.test.local"
OUT = ROOT / "data/novus_beta_operations/cloud_registration_billing_audit/cloud_p0"
results = {"timestamp": datetime.now().isoformat(timespec="seconds"), "tests": {}}


def log(name, ok, detail=None):
    results["tests"][name] = {"ok": bool(ok), "detail": detail}
    print(("PASS" if ok else "FAIL"), name, detail if detail is not None else "", flush=True)
    return bool(ok)


def main():
    from database import (
        DB_BACKEND,
        DATABASE_URL,
        database_backend_info,
        ensure_tables_exist,
        SessionLocal,
        MfaTotpCredential,
        LoginSessionAudit,
        Usuario,
        Base,
        engine,
    )
    from services.login_session_audit_service import is_login_session_active, close_login_session
    from services.flask_secret_service import resolve_flask_secret_key, flask_secret_status
    from services.tenant_isolation_service import require_canonical_tenant_id, TenantAccessDenied
    from services.web_security_auth_enterprise import mfa_totp as mt
    import pyotp

    ensure_tables_exist()
    Base.metadata.create_all(bind=engine)

    info = database_backend_info()
    log("sqlite_default_backend", DB_BACKEND == "sqlite", info)
    log("database_url_not_forced_postgres", not DATABASE_URL.startswith("postgresql"), DATABASE_URL[:32])

    # SECRET_KEY status (do not print secret)
    st = flask_secret_status()
    try:
        _k, src = resolve_flask_secret_key()
        log("secret_key_resolves", bool(_k) and src in ("env", "wrapped_file", "generated"), {"source": src})
        del _k
    except Exception as exc:
        log("secret_key_resolves", False, str(exc)[:120])

    # MFA DB roundtrip
    db = SessionLocal()
    try:
        db.query(MfaTotpCredential).filter(MfaTotpCredential.email == EMAIL).delete()
        db.commit()
    finally:
        db.close()

    enr = mt.begin_enrollment(EMAIL, include_sensitive=True)
    secret = enr.get("secret")
    log("mfa_enroll_db", bool(secret) and enr.get("ok"), {"backend": mt.mfa_status(EMAIL).get("backend")})
    if secret:
        bad = mt.verify_and_enable(EMAIL, "000000")
        log("mfa_wrong_code", not bad.get("ok"), bad.get("error"))
        code = pyotp.TOTP(secret).now()
        ok = mt.verify_and_enable(EMAIL, code)
        log("mfa_enable_db", ok.get("ok") is True, {"enabled": mt.is_mfa_enabled(EMAIL)})
        # Second "instance" = new process-side SessionLocal read
        log("mfa_visible_new_session", mt.is_mfa_enabled(EMAIL), mt.mfa_status(EMAIL))

    # Session active across logical instances (shared SQLite)
    sid = f"synth-cloud-p0-{int(time.time())}"
    db = SessionLocal()
    try:
        db.add(
            LoginSessionAudit(
                id=sid,
                user_email=EMAIL,
                login_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ip_address="127.0.0.1",
                session_id=sid,
                active=True,
                tenant_id="901777701-SYN-CLOUD-P0",
            )
        )
        db.commit()
    finally:
        db.close()
    log("session_active_before", is_login_session_active(sid), sid[:20])
    closed = close_login_session(session_audit_id=sid, user_email=EMAIL)
    log("session_close", closed.get("closed") is True, closed)
    log("session_inactive_after_shared_db", is_login_session_active(sid) is False, None)

    # Canonical tenant — no email domain when nit set
    class U:
        company_id = None
        nit_pyme = "TENANT-SYN-P0"
        email = "x@other.example.com"

    tid = require_canonical_tenant_id(U())
    log("canonical_prefers_nit", tid == "TENANT-SYN-P0", tid)

    class U2:
        company_id = None
        nit_pyme = None
        email = "x@other.example.com"

    try:
        require_canonical_tenant_id(U2())
        log("canonical_rejects_email_only", False, "should_raise")
    except TenantAccessDenied:
        log("canonical_rejects_email_only", True, None)

    # Cleanup MFA synthetic
    db = SessionLocal()
    try:
        db.query(MfaTotpCredential).filter(MfaTotpCredential.email == EMAIL).delete()
        db.query(LoginSessionAudit).filter(LoginSessionAudit.id == sid).delete()
        db.commit()
    finally:
        db.close()

    # Postgres availability
    import importlib.util
    import shutil

    pg = bool(importlib.util.find_spec("psycopg") or importlib.util.find_spec("psycopg2"))
    results["POSTGRESQL_E2E"] = "NOT_VERIFIABLE" if not (pg and shutil.which("psql")) else "DRIVER_ONLY"
    results["MULTI_INSTANCE_E2E"] = "PARTIAL_SHARED_DB_SIMULATION"
    results["flask_secret_status"] = {k: st[k] for k in st}
    results["db_info"] = info

    failed = [k for k, v in results["tests"].items() if not v["ok"]]
    results["verdict"] = "CLOUD_P0_LOCAL_CHECKS_PASS" if not failed else "CLOUD_P0_LOCAL_CHECKS_FAIL"
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "_p0_harness_raw.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("SUMMARY", results["verdict"], "fail", failed, "PG", results["POSTGRESQL_E2E"], flush=True)
    return 0 if not failed else 1


if __name__ == "__main__":
    # Fix begin_enrollment call - I had a typo with manual=
    raise SystemExit(main())
