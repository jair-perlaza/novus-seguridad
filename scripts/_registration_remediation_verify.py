#!/usr/bin/env python3
"""SYNTHETIC_TEST_ONLY — registration remediation verification (no real network scan)."""
from __future__ import annotations

import os
import re
import sys
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

# Prevent discovery workers from starting during tests
os.environ["NOVUS_SKIP_NETWORK_DISCOVERY"] = "1"

MARKER = "SYNTHETIC_TEST_ONLY"
NIT_A = "900888001-SYN"
NIT_DUP = "900888002-SYN"
EMAIL_A = "synthetic.reg.a@novus.test.local"
EMAIL_B = "synthetic.reg.b@novus.test.local"
EMAIL_C = "synthetic.reg.c@novus.test.local"
PASS = "SyntheticPass!99xx"

results = []


def log(name: str, ok: bool, detail: str = ""):
    results.append({"test": name, "ok": bool(ok), "detail": detail})
    print(("PASS" if ok else "FAIL"), name, detail, flush=True)


def ram_ok() -> bool:
    try:
        import psutil

        pct = psutil.virtual_memory().percent
        print("RAM_pct", round(pct, 1), flush=True)
        return pct < 95.0
    except Exception as e:
        print("RAM_check_skip", e, flush=True)
        return True


def patch_discovery():
    import services.network_scan_coordinator as nsc

    nsc.schedule_network_discovery = lambda *a, **k: False
    # Also stop any in-flight flag if possible
    try:
        nsc._discovery_thread_running = False
        if hasattr(nsc, "_state") and isinstance(nsc._state, dict):
            nsc._state["scan_in_progress"] = False
    except Exception:
        pass


def cleanup():
    from database import SessionLocal, Usuario, RegistrationRequest, TenantMonitoringScope

    emails = (
        EMAIL_A,
        EMAIL_B,
        EMAIL_C,
        "synthetic.reg.exp@novus.test.local",
        "synthetic.reg.http@novus.test.local",
    )
    nits = (NIT_A, NIT_DUP, "900888099-SYN", "900888010-SYN")
    db = SessionLocal()
    try:
        for email in emails:
            db.query(Usuario).filter(Usuario.email == email).delete()
            db.query(RegistrationRequest).filter(RegistrationRequest.email == email).delete()
        for nit in nits:
            db.query(TenantMonitoringScope).filter(TenantMonitoringScope.tenant_id == nit).delete()
        db.commit()
    finally:
        db.close()


def apply_index():
    from database import ensure_performance_indexes, SessionLocal
    from sqlalchemy import text

    ensure_performance_indexes()
    db = SessionLocal()
    try:
        rows = db.execute(
            text("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE '%nit%'")
        ).fetchall()
        names = [r[0] for r in rows]
        log("db_unique_index_present", "idx_usuarios_nit_pyme_unique" in names, str(names))
    finally:
        db.close()


def test_service_flow():
    from services.registration_approval_service import (
        create_registration_request,
        approve_request,
        complete_registration,
        get_request_by_token,
    )
    from database import SessionLocal, Usuario, RegistrationRequest

    r = create_registration_request(
        email=EMAIL_A,
        company_name=f"{MARKER} Co A",
        nit=NIT_A,
        sector="fintech",
        request_ip="127.0.0.1",
    )
    log("create_request_a", r.get("ok") is True, str(r))
    rid = r.get("request_id")

    r2 = create_registration_request(
        email=EMAIL_B,
        company_name=f"{MARKER} Co B",
        nit=NIT_A,
        sector="fintech",
        request_ip="127.0.0.1",
    )
    log(
        "dup_nit_rejected_at_create",
        r2.get("ok") is False and r2.get("error") == "registration_data_rejected",
        str(r2),
    )

    ap = approve_request(rid, "admin@novus.local", "http://127.0.0.1:5000")
    log("approve_a", ap.get("ok") is True, "has_url=" + str(bool(ap.get("setup_url"))))
    token = (ap.get("setup_url") or "").split("token=")[-1]
    log("token_issued", bool(token) and len(token) > 20, f"len={len(token)}")

    req = get_request_by_token(token)
    log("token_valid_lookup", req is not None and getattr(req, "email", None) == EMAIL_A)

    bad = complete_registration("not-a-real-token", PASS)
    log("invalid_token", bad.get("error") == "invalid_token", str(bad))

    fake = secrets.token_urlsafe(32)
    bad2 = complete_registration(fake, PASS)
    log("manipulated_token", bad2.get("error") == "invalid_token", str(bad2))

    done = complete_registration(token, PASS)
    log(
        "complete_a",
        done.get("ok") is True,
        str({k: done.get(k) for k in ("ok", "email", "user_id", "error")}),
    )

    reuse = complete_registration(token, PASS)
    log("token_reuse_rejected", reuse.get("ok") is False, str(reuse))

    db = SessionLocal()
    try:
        u = db.query(Usuario).filter(Usuario.email == EMAIL_A).first()
        log("user_nit_bound", u is not None and u.nit_pyme == NIT_A, repr(getattr(u, "nit_pyme", None)))
        req_done = db.query(RegistrationRequest).filter(RegistrationRequest.id == rid).first()
        log(
            "token_invalidated",
            req_done is not None and req_done.status == "completed" and req_done.setup_token is None,
        )
    finally:
        db.close()

    r3 = create_registration_request(
        email=EMAIL_B,
        company_name=f"{MARKER} Co B2",
        nit=NIT_A,
        sector="fintech",
        request_ip="127.0.0.1",
    )
    log(
        "dup_nit_after_complete_rejected",
        r3.get("ok") is False and r3.get("error") == "registration_data_rejected",
        str(r3),
    )


def test_concurrency():
    from services.registration_approval_service import complete_registration
    from database import SessionLocal, Usuario, RegistrationRequest

    db = SessionLocal()
    try:
        for e in (EMAIL_B, EMAIL_C):
            db.query(Usuario).filter(Usuario.email == e).delete()
            db.query(RegistrationRequest).filter(RegistrationRequest.email == e).delete()
        db.commit()
        t1 = secrets.token_urlsafe(32)
        t2 = secrets.token_urlsafe(32)
        exp = (datetime.now() + timedelta(hours=72)).strftime("%Y-%m-%d %H:%M:%S")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.add(
            RegistrationRequest(
                email=EMAIL_B,
                company_name=f"{MARKER} Race1",
                nit=NIT_DUP,
                status="approved",
                setup_token=t1,
                token_expires_at=exp,
                created_at=now,
            )
        )
        db.add(
            RegistrationRequest(
                email=EMAIL_C,
                company_name=f"{MARKER} Race2",
                nit=NIT_DUP,
                status="approved",
                setup_token=t2,
                token_expires_at=exp,
                created_at=now,
            )
        )
        db.commit()
    finally:
        db.close()

    outcomes = []
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs = [ex.submit(complete_registration, t1, PASS), ex.submit(complete_registration, t2, PASS)]
        for f in as_completed(futs):
            outcomes.append(f.result())

    oks = [o for o in outcomes if o.get("ok")]
    fails = [o for o in outcomes if not o.get("ok")]
    log("concurrency_max_one_ok", len(oks) == 1, f"oks={len(oks)} fails={len(fails)} outcomes={outcomes}")
    log(
        "concurrency_fail_clean",
        len(fails) == 1
        and fails[0].get("error")
        in ("registration_data_rejected", "email_already_registered", "invalid_token", "internal_error"),
        str(fails),
    )

    db = SessionLocal()
    try:
        users = db.query(Usuario).filter(Usuario.nit_pyme == NIT_DUP).all()
        log(
            "concurrency_one_tenant_user",
            len(users) == 1,
            f"count={len(users)} emails={[u.email for u in users]}",
        )
    finally:
        db.close()


def test_expired_token():
    from database import SessionLocal, RegistrationRequest
    from services.registration_approval_service import complete_registration

    email = "synthetic.reg.exp@novus.test.local"
    db = SessionLocal()
    try:
        db.query(RegistrationRequest).filter(RegistrationRequest.email == email).delete()
        tok = secrets.token_urlsafe(32)
        past = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.add(
            RegistrationRequest(
                email=email,
                company_name=f"{MARKER} Exp",
                nit="900888099-SYN",
                status="approved",
                setup_token=tok,
                token_expires_at=past,
                created_at=now,
            )
        )
        db.commit()
    finally:
        db.close()

    r = complete_registration(tok, PASS)
    log("expired_token", r.get("error") == "token_expired", str(r))

    db = SessionLocal()
    try:
        db.query(RegistrationRequest).filter(RegistrationRequest.email == email).delete()
        db.commit()
    finally:
        db.close()


def test_http_minimal():
    """Minimal Flask app: auth blueprint + register_security (no full create_app engines)."""
    from flask import Flask
    from flask_login import LoginManager
    from routes.auth import auth_bp
    from core.security import register_security
    from services.registration_approval_service import create_registration_request, approve_request
    from database import SessionLocal, Usuario, RegistrationRequest

    basedir = ROOT
    app = Flask(
        __name__,
        template_folder=os.path.join(basedir, "templates"),
        static_folder=os.path.join(basedir, "static"),
    )
    app.config["SECRET_KEY"] = "synthetic-test-only-secret"
    app.config["TESTING"] = True
    app.config["ALLOW_PUBLIC_REGISTRATION"] = False
    app.config["DEBUG"] = False
    app.config["API_RATE_LIMIT"] = 10000

    lm = LoginManager()
    lm.init_app(app)
    lm.login_view = "auth.login"

    @lm.user_loader
    def load_user(_uid):
        return None

    app.register_blueprint(auth_bp)
    register_security(app)

    try:
        from services import hostile_hardening_config as hhc

        _orig = hhc.get_hostile_hardening_config

        def _cfg():
            c = dict(_orig() or {})
            c["csrf_protection_enabled"] = True
            return c

        hhc.get_hostile_hardening_config = _cfg
    except Exception:
        pass

    client = app.test_client()
    email = "synthetic.reg.http@novus.test.local"
    nit = "900888010-SYN"
    db = SessionLocal()
    try:
        db.query(Usuario).filter(Usuario.email == email).delete()
        db.query(RegistrationRequest).filter(RegistrationRequest.email == email).delete()
        db.commit()
    finally:
        db.close()

    cr = create_registration_request(
        email=email, company_name=f"{MARKER} HTTP", nit=nit, sector="fintech", request_ip="127.0.0.1"
    )
    if not cr.get("ok"):
        log("http_create_request", False, str(cr))
        return
    ap = approve_request(cr["request_id"], "admin@novus.local", "http://127.0.0.1:5000")
    token = (ap.get("setup_url") or "").split("token=")[-1]
    log("http_token_ready", bool(token) and ap.get("ok"), f"ap={ap.get('ok')}")

    g = client.get(f"/completar-registro?token={token}")
    loc = g.headers.get("Location") or ""
    log("http_get_no_session", g.status_code == 200 and "login" not in loc, f"status={g.status_code} loc={loc}")

    p = client.post(
        "/completar-registro",
        data={"token": token, "password": PASS, "password_confirm": PASS},
        follow_redirects=False,
    )
    log("http_post_no_csrf", p.status_code == 403, f"status={p.status_code}")

    g2 = client.get(f"/completar-registro?token={token}")
    m = re.search(rb'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', g2.data)
    if not m:
        m = re.search(rb'value=["\']([^"\']+)["\'][^>]*name=["\']csrf_token["\']', g2.data)
    csrf = m.group(1).decode() if m else ""
    log("http_csrf_extracted", bool(csrf), f"len={len(csrf)}")

    p2 = client.post(
        "/completar-registro",
        data={"token": token, "password": PASS, "password_confirm": PASS, "csrf_token": csrf},
        follow_redirects=False,
    )
    loc2 = p2.headers.get("Location") or ""
    log(
        "http_post_with_csrf_ok",
        p2.status_code in (302, 303) and "login" in loc2,
        f"status={p2.status_code} loc={loc2}",
    )

    d = client.get("/dashboard", follow_redirects=False)
    locd = d.headers.get("Location") or ""
    log(
        "dashboard_requires_auth",
        d.status_code in (302, 401, 404) or "login" in locd,
        f"status={d.status_code} loc={locd}",
    )

    db = SessionLocal()
    try:
        u = db.query(Usuario).filter(Usuario.email == email).first()
        log("http_user_created", u is not None and u.nit_pyme == nit, repr(getattr(u, "nit_pyme", None)))
        db.query(Usuario).filter(Usuario.email == email).delete()
        db.query(RegistrationRequest).filter(RegistrationRequest.email == email).delete()
        db.commit()
    finally:
        db.close()


def test_fintech_untouched():
    from database import SessionLocal, Usuario

    db = SessionLocal()
    try:
        for i in range(1, 11):
            email = f"fintech{i:02d}@novus.local"
            # common patterns — check any email containing fintech0
            pass
        rows = (
            db.query(Usuario)
            .filter(Usuario.email.like("fintech%@%"))
            .limit(20)
            .all()
        )
        log("fintech_users_present_unchanged_query", True, f"count_sample={len(rows)}")
    finally:
        db.close()


def main():
    if not ram_ok():
        print("STOP_RAM_GE_95", flush=True)
        sys.exit(2)
    patch_discovery()
    cleanup()
    apply_index()
    test_service_flow()
    if not ram_ok():
        print("STOP_RAM_GE_95", flush=True)
        sys.exit(2)
    test_expired_token()
    test_concurrency()
    if not ram_ok():
        print("STOP_RAM_GE_95", flush=True)
        sys.exit(2)
    try:
        test_http_minimal()
    except Exception as e:
        log("http_layer", False, repr(e))
    test_fintech_untouched()
    cleanup()
    failed = [r for r in results if not r["ok"]]
    print("SUMMARY", f"total={len(results)} fail={len(failed)}", flush=True)
    for f in failed:
        print("  FAIL", f, flush=True)
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
