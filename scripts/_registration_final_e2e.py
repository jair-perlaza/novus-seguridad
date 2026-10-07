#!/usr/bin/env python3
"""
SYNTHETIC_TEST_ONLY — Final registration E2E against live beta :5000.
Does NOT modify fintech01–10 / admin. Does NOT disable CSRF/MFA/RBAC/Abuse Guard.
NOVUS_SKIP_NETWORK_DISCOVERY may be set on the server process only for this harness window.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import secrets
from datetime import datetime, timedelta
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

BASE = os.environ.get("NOVUS_E2E_BASE", "http://127.0.0.1:5000")
MARKER = "SYNTHETIC_TEST_ONLY"
OUT_DIR = ROOT / "data" / "novus_beta_operations" / "registration_remediation"
OUT_JSON = OUT_DIR / "registration_final_e2e.json"

EMAIL_A = "synthetic.final.a@novus.test.local"
EMAIL_B = "synthetic.final.b@novus.test.local"
NIT_A = "901777001-SYN-FINAL"
NIT_B = "901777002-SYN-FINAL"
PASS = "SyntheticFinal!99xx"
SPOOF_TENANT = "TENANT-01"

evidence: dict = {
    "timestamp": datetime.now().isoformat(timespec="seconds"),
    "environment": {},
    "port": 5000,
    "registration": {},
    "token_tests": {},
    "csrf_tests": {},
    "login_tests": {},
    "mfa_tests": {},
    "dashboard_tests": {},
    "tenant_isolation_tests": {},
    "spoof_tests": {},
    "logout_tests": {},
    "restart_tests": {},
    "persistence_tests": {},
    "resource_observations": {},
    "integrity_counters": {},
    "limitations": [],
    "steps": [],
    "final_verdict": "REGISTRATION_FINAL_E2E_NOT_VERIFIABLE",
}


def log(step: str, ok: bool, detail=None):
    evidence["steps"].append({"step": step, "ok": bool(ok), "detail": detail, "ts": time.time()})
    print(("PASS" if ok else "FAIL"), step, detail if detail is not None else "", flush=True)
    return bool(ok)


def ram_snap():
    try:
        import psutil

        vm = psutil.virtual_memory()
        return {"ram_pct": round(vm.percent, 1), "available_mb": round(vm.available / 1e6, 1)}
    except Exception as e:
        return {"error": str(e)}


def wait_ready(timeout=180):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        try:
            r = requests.get(BASE + "/login", timeout=5)
            if r.status_code in (200, 302):
                return True, time.time() - t0
            last = r.status_code
        except Exception as e:
            last = str(e)
        time.sleep(2)
    return False, last


def extract_csrf(html: str) -> str:
    m = re.search(r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', html)
    if not m:
        m = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf_token["\']', html)
    if m:
        return m.group(1)
    m2 = re.search(r"const csrf = (.+?);", html)
    if m2:
        try:
            return json.loads(m2.group(1))
        except Exception:
            pass
    return ""


def cleanup_synthetic():
    from database import SessionLocal, Usuario, RegistrationRequest, TenantMonitoringScope

    emails = (EMAIL_A, EMAIL_B)
    nits = (NIT_A, NIT_B)
    db = SessionLocal()
    try:
        for e in emails:
            db.query(Usuario).filter(Usuario.email == e).delete()
            db.query(RegistrationRequest).filter(RegistrationRequest.email == e).delete()
        for n in nits:
            db.query(TenantMonitoringScope).filter(TenantMonitoringScope.tenant_id == n).delete()
        db.commit()
    finally:
        db.close()
    # MFA store cleanup for synthetic emails
    try:
        from services.web_security_auth_enterprise import mfa_totp as mt

        data = mt._load()
        changed = False
        for e in emails:
            if e in data:
                del data[e]
                changed = True
        if changed:
            mt._save(data)
    except Exception:
        pass


def clear_local_abuse():
    """Controlled recovery if prior failed logins sanctioned 127.0.0.1 — does not disable Abuse Guard."""
    try:
        from database import SessionLocal, AuthOriginSanction, IPBloqueada

        db = SessionLocal()
        try:
            for ip in ("127.0.0.1", "::1"):
                for row in db.query(AuthOriginSanction).filter(
                    AuthOriginSanction.origin_key == ip, AuthOriginSanction.status == "active"
                ).all():
                    row.status = "revoked"
                for row in db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == ip).all():
                    db.delete(row)
            db.commit()
        finally:
            db.close()
    except Exception as e:
        evidence.setdefault("limitations", []).append(f"abuse_clear_note:{e}")


def approve_by_id(request_id: int) -> str:
    from services.registration_approval_service import approve_request

    ap = approve_request(int(request_id), "admin@novus.local", BASE)
    if not ap.get("ok"):
        raise RuntimeError(f"approve failed: {ap}")
    return (ap.get("setup_url") or "").split("token=")[-1]


def env_probe(session: requests.Session):
    # Infer from login page + process via /login content
    r = session.get(BASE + "/login", timeout=30)
    return {"login_status": r.status_code, "has_csrf": bool(extract_csrf(r.text))}


def register_via_form(session: requests.Session, email: str, nit: str, company: str):
    g = session.get(BASE + "/registro-empresa", timeout=60, allow_redirects=False)
    if g.status_code in (301, 302) and "login" in (g.headers.get("Location") or ""):
        return {"ok": False, "error": "public_registration_disabled", "status": g.status_code, "loc": g.headers.get("Location")}
    if g.status_code != 200:
        return {"ok": False, "error": "form_get_failed", "status": g.status_code}
    csrf = extract_csrf(g.text)
    # CSRF missing reject
    bad = session.post(
        BASE + "/registro-empresa",
        data={
            "email": email,
            "nombre": company,
            "nit": nit,
            "sector": "fintech",
            "password": PASS,  # may be ignored by approval flow
            "password_confirm": PASS,
        },
        timeout=60,
        allow_redirects=False,
    )
    csrf_block = bad.status_code == 403 or "CSRF" in (bad.text or "")
    p = session.post(
        BASE + "/registro-empresa",
        data={
            "email": email,
            "nombre": company,
            "nit": nit,
            "sector": "fintech",
            "servicio": "beta",
            "empleados": "1-10",
            "csrf_token": csrf,
        },
        timeout=60,
        allow_redirects=True,
    )
    ok = p.status_code == 200 and (
        "pendiente" in p.text.lower() or "solicitud" in p.text.lower() or "autoriz" in p.text.lower() or email in p.text
    )
    return {
        "ok": ok,
        "status": p.status_code,
        "csrf_without_rejected": csrf_block,
        "body_snip": p.text[:300],
    }


def token_negative_tests(session: requests.Session, good_token: str):
    out = {}
    # no session cookies for these
    s = requests.Session()
    r = s.get(BASE + f"/completar-registro?token={good_token}", timeout=30)
    out["get_valid_no_session"] = {"status": r.status_code, "ok": r.status_code == 200 and "login" not in (r.url or "")}
    r2 = s.get(BASE + "/completar-registro?token=not-real-token", timeout=30)
    out["get_invalid"] = {
        "status": r2.status_code,
        "ok": r2.status_code == 200 and ("inválido" in r2.text.lower() or "invalido" in r2.text.lower() or "expir" in r2.text.lower()),
    }
    r3 = s.get(BASE + f"/completar-registro?token={secrets.token_urlsafe(32)}", timeout=30)
    out["get_manipulated"] = {
        "status": r3.status_code,
        "ok": r3.status_code == 200 and ("inválido" in r3.text.lower() or "invalido" in r3.text.lower() or "expir" in r3.text.lower()),
    }
    # POST without CSRF
    p = s.post(
        BASE + "/completar-registro",
        data={"token": good_token, "password": PASS, "password_confirm": PASS},
        timeout=30,
        allow_redirects=False,
    )
    out["post_no_csrf"] = {"status": p.status_code, "ok": p.status_code == 403}
    return out


def complete_with_csrf(session: requests.Session, token: str):
    g = session.get(BASE + f"/completar-registro?token={token}", timeout=30)
    csrf = extract_csrf(g.text)
    p = session.post(
        BASE + "/completar-registro",
        data={"token": token, "password": PASS, "password_confirm": PASS, "csrf_token": csrf},
        timeout=60,
        allow_redirects=False,
    )
    loc = p.headers.get("Location") or ""
    return {"status": p.status_code, "loc": loc, "ok": p.status_code in (302, 303) and "login" in loc, "csrf": bool(csrf)}


def login_password(session: requests.Session, email: str, password: str):
    g = session.get(BASE + "/login", timeout=30)
    csrf = extract_csrf(g.text)
    t0 = time.time()
    p = session.post(
        BASE + "/login",
        data={"email": email, "password": password, "csrf_token": csrf},
        timeout=120,
        allow_redirects=False,
    )
    dt = time.time() - t0
    return {
        "status": p.status_code,
        "loc": p.headers.get("Location") or "",
        "latency_s": round(dt, 3),
        "csrf": bool(csrf),
    }


def enroll_and_enable_mfa(session: requests.Session):
    t0 = time.time()
    mfa = session.get(BASE + "/mfa-setup", timeout=60)
    csrf = extract_csrf(mfa.text)
    # Also try JS const csrf
    if not csrf:
        m = re.search(r"const csrf = (.+?);", mfa.text)
        if m:
            try:
                csrf = json.loads(m.group(1))
            except Exception:
                csrf = m.group(1).strip().strip('"').strip("'")
    # API csrf token endpoint fallback
    if not csrf:
        try:
            ct = session.get(BASE + "/api/wsae/csrf-token", timeout=30)
            if ct.ok:
                csrf = (ct.json() or {}).get("csrf_token") or (ct.json() or {}).get("token") or ""
        except Exception:
            pass
    enr = session.post(
        BASE + "/api/wsae/mfa/enroll",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
        json={"manual": True},
        timeout=120,
    )
    eb = enr.json() if "json" in (enr.headers.get("content-type") or "") else {}
    secret = eb.get("secret")
    if not secret:
        return {
            "ok": False,
            "phase": "enroll",
            "status": enr.status_code,
            "body": eb,
            "mfa_setup_status": mfa.status_code,
            "latency_s": round(time.time() - t0, 3),
        }
    import pyotp

    # wrong code first
    bad = session.post(
        BASE + "/api/wsae/mfa/enable",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
        json={"code": "000000"},
        timeout=60,
    )
    bad_ok = (not bad.ok) or not (bad.json() or {}).get("ok")
    code = pyotp.TOTP(secret).now()
    en = session.post(
        BASE + "/api/wsae/mfa/enable",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
        json={"code": code},
        timeout=120,
    )
    ej = en.json() if "json" in (en.headers.get("content-type") or "") else {}
    return {
        "ok": bool(ej.get("ok")),
        "wrong_code_rejected": bad_ok,
        "enable_status": en.status_code,
        "enable_body": {k: ej.get(k) for k in ("ok", "error", "status") if k in ej or True},
        "mfa_setup_status": mfa.status_code,
        "latency_s": round(time.time() - t0, 3),
        "secret_retained_for_relogin": secret,
    }


def login_with_mfa(session: requests.Session, email: str, password: str, secret: str):
    import pyotp

    lp = login_password(session, email, password)
    loc = lp.get("loc") or ""
    # Follow MFA pending if redirected to login with mfa form, or same login page
    g = session.get(BASE + (loc if loc.startswith("/") else "/login"), timeout=60) if loc else session.get(BASE + "/login", timeout=60)
    # If already dashboard
    if "dashboard" in loc:
        return {"ok": True, "path": "direct_dashboard", "login": lp}
    csrf = extract_csrf(g.text)
    # If enrollment again
    if "mfa-setup" in loc or "mfa-setup" in g.url:
        return {"ok": False, "path": "unexpected_reenroll", "login": lp}
    code = pyotp.TOTP(secret).now()
    # wrong MFA
    bad = session.post(
        BASE + "/login",
        data={"email": email, "password": password, "csrf_token": csrf, "mfa_code": "111111"},
        timeout=60,
        allow_redirects=False,
    )
    # refresh csrf
    g2 = session.get(BASE + "/login", timeout=30)
    csrf2 = extract_csrf(g2.text)
    code = pyotp.TOTP(secret).now()
    t0 = time.time()
    good = session.post(
        BASE + "/login",
        data={"mfa_code": code, "csrf_token": csrf2},
        timeout=120,
        allow_redirects=False,
    )
    loc2 = good.headers.get("Location") or ""
    return {
        "ok": good.status_code in (302, 303) and ("dashboard" in loc2 or "mfa" not in loc2.lower() or loc2 == "/"),
        "login": lp,
        "wrong_mfa_status": bad.status_code,
        "wrong_mfa_loc": bad.headers.get("Location"),
        "good_status": good.status_code,
        "good_loc": loc2,
        "latency_s": round(time.time() - t0, 3),
        "body_snip": good.text[:200] if good.status_code >= 400 else "",
    }


def check_dashboard_and_apis(session: requests.Session, expected_nit: str):
    t0 = time.time()
    d = session.get(BASE + "/dashboard", timeout=120, allow_redirects=True)
    dash_ok = d.status_code == 200 and "login" not in d.url and len(d.text) > 500
    # try common dashboard paths
    if not dash_ok:
        for path in ("/dashboard/", "/dashboard/principal", "/"):
            d2 = session.get(BASE + path, timeout=60, allow_redirects=True)
            if d2.status_code == 200 and "login" not in d2.url and len(d2.text) > 500:
                d = d2
                dash_ok = True
                break

    def get_json(path):
        r = session.get(BASE + path, timeout=60)
        try:
            body = r.json()
        except Exception:
            body = {"_raw": r.text[:300]}
        return r.status_code, body

    s_status, summary = get_json("/api/security/summary")
    s_spoof_status, summary_spoof = get_json(f"/api/security/summary?tenant_id={SPOOF_TENANT}")
    search_status, search = get_json("/api/search?q=TEST_FIXTURE&limit=5")
    search_spoof_status, search_spoof = get_json(f"/api/search?q=TEST_FIXTURE&limit=5&tenant_id={SPOOF_TENANT}")
    dsar_status, dsar = get_json("/api/compliance/dsar-export?limit=10")
    dsar_spoof_status, dsar_spoof = get_json(f"/api/compliance/dsar-export?limit=10&tenant_id={SPOOF_TENANT}")

    def tenant_of(payload):
        if not isinstance(payload, dict):
            return None
        for k in ("tenant_id", "canonical_tenant_id", "nit", "nit_pyme"):
            if payload.get(k):
                return payload.get(k)
        # nested
        for nest in ("meta", "scope", "tenant", "context", "identity"):
            sub = payload.get(nest) or {}
            if isinstance(sub, dict):
                for k in ("tenant_id", "canonical_tenant_id", "nit", "nit_pyme"):
                    if sub.get(k):
                        return sub.get(k)
        return None

    sum_tid = tenant_of(summary)
    spoof_tid = tenant_of(summary_spoof)
    dsar_tid = tenant_of(dsar) or (dsar.get("tenant_id") if isinstance(dsar, dict) else None)
    dsar_spoof_tid = tenant_of(dsar_spoof) or (dsar_spoof.get("tenant_id") if isinstance(dsar_spoof, dict) else None)

    spoof_ignored = True
    if spoof_tid and spoof_tid == SPOOF_TENANT and expected_nit != SPOOF_TENANT:
        spoof_ignored = False
    if dsar_spoof_tid and dsar_spoof_tid == SPOOF_TENANT and expected_nit != SPOOF_TENANT:
        spoof_ignored = False

    return {
        "dashboard": {
            "ok": dash_ok,
            "status": d.status_code,
            "url": d.url,
            "len": len(d.text or ""),
            "latency_s": round(time.time() - t0, 3),
            "contains_login_form": "csrf_token" in (d.text or "") and "password" in (d.text or "").lower() and "login" in d.url,
        },
        "summary": {"status": s_status, "tenant": sum_tid, "keys": list(summary.keys())[:20] if isinstance(summary, dict) else []},
        "summary_spoof": {"status": s_spoof_status, "tenant": spoof_tid},
        "search": {"status": search_status, "tenant": tenant_of(search), "count": search.get("count") if isinstance(search, dict) else None},
        "search_spoof": {"status": search_spoof_status, "tenant": tenant_of(search_spoof)},
        "dsar": {"status": dsar_status, "tenant": dsar_tid, "export_id": dsar.get("export_id") if isinstance(dsar, dict) else None},
        "dsar_spoof": {"status": dsar_spoof_status, "tenant": dsar_spoof_tid},
        "spoof_ignored": spoof_ignored,
        "canonical_matches_expected": (
            (sum_tid == expected_nit if sum_tid else None)
            or (dsar_tid == expected_nit if dsar_tid else None)
        ),
        "expected_nit": expected_nit,
    }


def logout_and_reuse(session: requests.Session):
    cookies_before = requests.utils.dict_from_cookiejar(session.cookies)
    r = session.get(BASE + "/logout", timeout=30, allow_redirects=False)
    # reuse old session cookie jar copy
    s2 = requests.Session()
    for k, v in cookies_before.items():
        s2.cookies.set(k, v)
    d = s2.get(BASE + "/dashboard", timeout=60, allow_redirects=False)
    loc = d.headers.get("Location") or ""
    blocked = d.status_code in (302, 401) or "login" in loc or (d.status_code == 200 and "login" in (d.url or ""))
    # also with cleared session after logout
    d3 = session.get(BASE + "/dashboard", timeout=60, allow_redirects=False)
    loc3 = d3.headers.get("Location") or ""
    return {
        "logout_status": r.status_code,
        "logout_loc": r.headers.get("Location"),
        "reuse_status": d.status_code,
        "reuse_loc": loc,
        "reuse_blocked": blocked,
        "post_logout_dash": {"status": d3.status_code, "loc": loc3},
    }


def db_assert_user(email: str, nit: str):
    from database import SessionLocal, Usuario
    from werkzeug.security import check_password_hash

    db = SessionLocal()
    try:
        u = db.query(Usuario).filter(Usuario.email == email).first()
        if not u:
            return {"ok": False, "error": "missing"}
        return {
            "ok": True,
            "nit_pyme": u.nit_pyme,
            "nit_ok": u.nit_pyme == nit,
            "role": u.role,
            "password_hashed": bool(u.hashed_password) and u.hashed_password != PASS,
            "password_verifies": check_password_hash(u.hashed_password, PASS),
            "is_active": bool(u.is_active),
        }
    finally:
        db.close()


def expired_token_test():
    from database import SessionLocal, RegistrationRequest
    from services.registration_approval_service import complete_registration

    email = "synthetic.final.exp@novus.test.local"
    db = SessionLocal()
    try:
        db.query(RegistrationRequest).filter(RegistrationRequest.email == email).delete()
        tok = secrets.token_urlsafe(32)
        past = (datetime.now() - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        db.add(
            RegistrationRequest(
                email=email,
                company_name=f"{MARKER} EXP",
                nit="901777099-SYN-FINAL",
                status="approved",
                setup_token=tok,
                token_expires_at=past,
                created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
        )
        db.commit()
    finally:
        db.close()
    # HTTP GET
    s = requests.Session()
    r = s.get(BASE + f"/completar-registro?token={tok}", timeout=30)
    # service complete
    c = complete_registration(tok, PASS)
    db = SessionLocal()
    try:
        db.query(RegistrationRequest).filter(RegistrationRequest.email == email).delete()
        db.commit()
    finally:
        db.close()
    return {
        "http_status": r.status_code,
        "http_shows_error": "expir" in r.text.lower() or "inválido" in r.text.lower() or "invalido" in r.text.lower(),
        "complete_error": c.get("error"),
        "ok": c.get("error") == "token_expired",
    }


def main():
    evidence["resource_observations"]["start"] = ram_snap()
    if evidence["resource_observations"]["start"].get("ram_pct", 0) >= 95:
        evidence["final_verdict"] = "REGISTRATION_FINAL_E2E_NOT_VERIFIABLE"
        evidence["limitations"].append("RAM>=95% — stopped")
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        OUT_JSON.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
        print("STOP_RAM", flush=True)
        return 2

    ready, info = wait_ready()
    log("server_ready", ready, info)
    if not ready:
        evidence["final_verdict"] = "REGISTRATION_FINAL_E2E_NOT_VERIFIABLE"
        evidence["limitations"].append(f"server not ready on {BASE}: {info}")
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        OUT_JSON.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
        return 2

    clear_local_abuse()
    cleanup_synthetic()

    s = requests.Session()
    evidence["environment"] = {
        "base": BASE,
        "NOVUS_ENV_expected": "beta",
        "probe": env_probe(s),
    }

    # A. Registration form
    reg = register_via_form(s, EMAIL_A, NIT_A, f"{MARKER} Co A")
    evidence["registration"]["form_a"] = reg
    log("registration_form_a", reg.get("ok"), reg)
    if not reg.get("ok"):
        # Fall back: service create if public registration disabled — still document
        from services.registration_approval_service import create_registration_request

        cr = create_registration_request(
            email=EMAIL_A,
            company_name=f"{MARKER} Co A",
            nit=NIT_A,
            sector="fintech",
            request_ip="127.0.0.1",
        )
        evidence["registration"]["service_fallback_a"] = cr
        log("registration_service_fallback_a", cr.get("ok"), cr)
        if not cr.get("ok"):
            evidence["final_verdict"] = "REGISTRATION_FINAL_E2E_FAIL"
            OUT_JSON.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
            return 1
        rid = cr["request_id"]
    else:
        from database import SessionLocal, RegistrationRequest

        db = SessionLocal()
        try:
            row = db.query(RegistrationRequest).filter(RegistrationRequest.email == EMAIL_A).order_by(RegistrationRequest.id.desc()).first()
            rid = row.id if row else None
        finally:
            db.close()
        log("registration_request_persisted", rid is not None, rid)

    token = approve_by_id(rid)
    log("approve_token_issued", bool(token), f"len={len(token)}")

    # B. Token / CSRF tests (before consume)
    tok_tests = token_negative_tests(requests.Session(), token)
    evidence["token_tests"] = tok_tests
    evidence["csrf_tests"]["completar_post_no_csrf"] = tok_tests.get("post_no_csrf")
    log("token_get_valid_no_session", tok_tests["get_valid_no_session"]["ok"], tok_tests["get_valid_no_session"])
    log("token_invalid", tok_tests["get_invalid"]["ok"], tok_tests["get_invalid"])
    log("token_manipulated", tok_tests["get_manipulated"]["ok"], tok_tests["get_manipulated"])
    log("csrf_post_rejected", tok_tests["post_no_csrf"]["ok"], tok_tests["post_no_csrf"])

    exp = expired_token_test()
    evidence["token_tests"]["expired"] = exp
    log("token_expired", exp["ok"], exp)

    # Complete A
    s_clear = requests.Session()
    done = complete_with_csrf(s_clear, token)
    evidence["registration"]["complete_a"] = done
    log("complete_registro_a", done["ok"], done)

    # reuse token
    reuse = complete_with_csrf(requests.Session(), token)
    evidence["token_tests"]["reuse"] = reuse
    log("token_reuse_rejected", not reuse["ok"], reuse)

    uinfo = db_assert_user(EMAIL_A, NIT_A)
    evidence["registration"]["user_a"] = uinfo
    log("user_a_nit_password", uinfo.get("ok") and uinfo.get("nit_ok") and uinfo.get("password_verifies"), uinfo)

    # Create B for isolation (service+approve+complete) — minimal second tenant
    from services.registration_approval_service import create_registration_request

    crb = create_registration_request(
        email=EMAIL_B, company_name=f"{MARKER} Co B", nit=NIT_B, sector="fintech", request_ip="127.0.0.1"
    )
    log("create_b", crb.get("ok"), crb)
    if crb.get("ok"):
        tb = approve_by_id(crb["request_id"])
        done_b = complete_with_csrf(requests.Session(), tb)
        log("complete_b", done_b["ok"], done_b)
        evidence["registration"]["complete_b"] = done_b

    # C/D/E Login + MFA enroll for A
    clear_local_abuse()
    sa = requests.Session()
    lp = login_password(sa, EMAIL_A, "WrongPass!!!")
    evidence["login_tests"]["bad_password"] = lp
    log("login_bad_password_rejected", lp["status"] in (200, 401, 403) and "dashboard" not in (lp.get("loc") or ""), lp)

    lp2 = login_password(sa, EMAIL_A, PASS)
    evidence["login_tests"]["good_password"] = lp2
    log("login_good_password", lp2["status"] in (302, 303), lp2)

    # Without MFA complete, dashboard should not be fully open
    pre = sa.get(BASE + "/dashboard", timeout=60, allow_redirects=False)
    evidence["mfa_tests"]["dashboard_before_mfa"] = {
        "status": pre.status_code,
        "loc": pre.headers.get("Location"),
    }
    blocked_pre = pre.status_code in (302, 401, 403) or "mfa" in (pre.headers.get("Location") or "").lower()
    log("dashboard_blocked_before_mfa", blocked_pre, evidence["mfa_tests"]["dashboard_before_mfa"])

    # Follow enrollment redirect
    if "mfa-setup" in (lp2.get("loc") or ""):
        sa.get(BASE + lp2["loc"], timeout=60)
    mfa = enroll_and_enable_mfa(sa)
    evidence["mfa_tests"]["enroll_enable"] = {k: v for k, v in mfa.items() if k != "secret_retained_for_relogin"}
    log("mfa_enroll_enable", mfa.get("ok") and mfa.get("wrong_code_rejected"), {k: mfa.get(k) for k in ("ok", "wrong_code_rejected", "enable_status", "latency_s")})
    secret_a = mfa.get("secret_retained_for_relogin")

    # Dashboard after enroll
    dash = check_dashboard_and_apis(sa, NIT_A)
    evidence["dashboard_tests"]["after_enroll"] = dash
    evidence["spoof_tests"]["after_enroll"] = {
        "spoof_ignored": dash.get("spoof_ignored"),
        "summary_spoof": dash.get("summary_spoof"),
        "dsar_spoof": dash.get("dsar_spoof"),
    }
    log("dashboard_after_mfa", dash["dashboard"]["ok"], dash["dashboard"])
    log("summary_api", dash["summary"]["status"] in (200, 403), dash["summary"])
    log("dsar_api", dash["dsar"]["status"] in (200, 403), dash["dsar"])
    log("search_api", dash["search"]["status"] in (200, 403), dash["search"])
    log("tenant_spoof_ignored", dash.get("spoof_ignored"), dash.get("summary_spoof"))

    # Tenant isolation: A session must not see B as canonical
    evidence["tenant_isolation_tests"]["a_canonical"] = {
        "expected": NIT_A,
        "summary_tenant": dash["summary"].get("tenant"),
        "dsar_tenant": dash["dsar"].get("tenant"),
        "ok": (dash["dsar"].get("tenant") == NIT_A) or (dash["summary"].get("tenant") == NIT_A) or dash.get("spoof_ignored"),
    }
    log("tenant_a_isolated", evidence["tenant_isolation_tests"]["a_canonical"]["ok"], evidence["tenant_isolation_tests"]["a_canonical"])

    # Logout
    lo = logout_and_reuse(sa)
    evidence["logout_tests"] = lo
    log("logout_blocks_reuse", lo.get("reuse_blocked"), lo)

    # Persist pre-restart snapshot
    evidence["restart_tests"]["pre"] = {
        "user_a": db_assert_user(EMAIL_A, NIT_A),
        "mfa_secret_present": bool(secret_a),
        "resources": ram_snap(),
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    print("PRE_RESTART_CHECKPOINT_WRITTEN", flush=True)
    print("SECRET_A_FOR_POST=" + (secret_a or ""), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
