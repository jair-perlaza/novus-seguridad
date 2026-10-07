#!/usr/bin/env python3
"""SYNTHETIC_TEST_ONLY — P0 session revocation after logout (cookie replay)."""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import pyotp
import requests
from werkzeug.security import generate_password_hash

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

BASE = os.environ.get("NOVUS_E2E_BASE", "http://127.0.0.1:5000")
EMAIL = "synthetic.session.p0@novus.test.local"
PASS = "SyntheticSessionP0!99"
NIT = "901777501-SYN-SESS"
EMAIL_B = "synthetic.session.p0b@novus.test.local"
NIT_B = "901777502-SYN-SESS"
SPOOF = "TENANT-01"
OUT_DIR = ROOT / "data/novus_beta_operations/registration_remediation"
MARKER = "SYNTHETIC_TEST_ONLY"

evidence = {
    "timestamp": datetime.now().isoformat(timespec="seconds"),
    "cause": {},
    "before": {"cookie_replay_dashboard": "HTTP 200 (registration final E2E)"},
    "correction": {},
    "after": {},
    "tests": {},
    "resources": {},
    "integrity_counters": {},
    "limitations": [],
    "final_verdict": "SESSION_REVOCATION_P0_NOT_VERIFIABLE",
}


def ram():
    import psutil

    return round(psutil.virtual_memory().percent, 1)


def log(name, ok, detail=None):
    evidence["tests"][name] = {"ok": bool(ok), "detail": detail}
    print(("PASS" if ok else "FAIL"), name, detail if detail is not None else "", flush=True)
    return bool(ok)


def csrf(html: str) -> str:
    m = re.search(r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', html)
    return m.group(1) if m else ""


def wait_ready(timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if requests.get(BASE + "/login", timeout=5).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def cleanup():
    from database import SessionLocal, Usuario, TenantMonitoringScope, RegistrationRequest

    db = SessionLocal()
    try:
        for e in (EMAIL, EMAIL_B):
            db.query(Usuario).filter(Usuario.email == e).delete()
            db.query(RegistrationRequest).filter(RegistrationRequest.email == e).delete()
        for n in (NIT, NIT_B):
            db.query(TenantMonitoringScope).filter(TenantMonitoringScope.tenant_id == n).delete()
        db.commit()
    finally:
        db.close()
    try:
        from services.web_security_auth_enterprise import mfa_totp as mt

        data = mt._load()
        ch = False
        for e in (EMAIL, EMAIL_B):
            if e in data:
                del data[e]
                ch = True
        if ch:
            mt._save(data)
    except Exception:
        pass


def ensure_users():
    from database import SessionLocal, Usuario
    from services.tenant_scope_service import provision_tenant_network_monitoring

    db = SessionLocal()
    try:
        for email, nit in ((EMAIL, NIT), (EMAIL_B, NIT_B)):
            u = db.query(Usuario).filter(Usuario.email == email).first()
            if not u:
                db.add(
                    Usuario(
                        email=email,
                        hashed_password=generate_password_hash(PASS),
                        role="company_admin",
                        nit_pyme=nit,
                        sector="fintech",
                        is_active=True,
                        is_temporal=True,
                    )
                )
            else:
                u.hashed_password = generate_password_hash(PASS)
                u.nit_pyme = nit
                u.role = "company_admin"
                u.is_active = True
        db.commit()
    finally:
        db.close()
    try:
        os.environ.setdefault("NOVUS_SKIP_NETWORK_DISCOVERY", "1")
        provision_tenant_network_monitoring(NIT, enabled=True, manual=False)
        provision_tenant_network_monitoring(NIT_B, enabled=True, manual=False)
    except Exception:
        pass


def login_enroll(session: requests.Session, email: str):
    g = session.get(BASE + "/login", timeout=30)
    p = session.post(
        BASE + "/login",
        data={"email": email, "password": PASS, "csrf_token": csrf(g.text)},
        timeout=120,
        allow_redirects=False,
    )
    loc = p.headers.get("Location") or ""
    if "mfa-setup" in loc or p.status_code == 302:
        session.get(BASE + (loc if loc.startswith("/") else "/mfa-setup"), timeout=60)
    mfa = session.get(BASE + "/mfa-setup", timeout=60)
    tok = csrf(mfa.text)
    if not tok:
        m = re.search(r"const csrf = (.+?);", mfa.text)
        if m:
            try:
                tok = json.loads(m.group(1))
            except Exception:
                tok = ""
    enr = session.post(
        BASE + "/api/wsae/mfa/enroll",
        headers={"Content-Type": "application/json", "X-CSRF-Token": tok},
        json={"manual": True},
        timeout=120,
    )
    eb = enr.json() if enr.ok else {}
    secret = eb.get("secret")
    if not secret:
        return None, {"enroll": enr.status_code, "body": eb, "login": p.status_code, "loc": loc}
    # wrong then right
    session.post(
        BASE + "/api/wsae/mfa/enable",
        headers={"Content-Type": "application/json", "X-CSRF-Token": tok},
        json={"code": "000000"},
        timeout=60,
    )
    code = pyotp.TOTP(secret).now()
    en = session.post(
        BASE + "/api/wsae/mfa/enable",
        headers={"Content-Type": "application/json", "X-CSRF-Token": tok},
        json={"code": code},
        timeout=120,
    )
    return secret, {"enable_ok": (en.json() or {}).get("ok"), "login_loc": loc}


def login_mfa(session: requests.Session, email: str, secret: str):
    g = session.get(BASE + "/login", timeout=30)
    p = session.post(
        BASE + "/login",
        data={"email": email, "password": PASS, "csrf_token": csrf(g.text)},
        timeout=120,
        allow_redirects=False,
    )
    g2 = session.get(BASE + "/login", timeout=30)
    # wrong MFA
    bad = session.post(
        BASE + "/login",
        data={"mfa_code": "111111", "csrf_token": csrf(g2.text)},
        timeout=60,
        allow_redirects=False,
    )
    g3 = session.get(BASE + "/login", timeout=30)
    good = session.post(
        BASE + "/login",
        data={"mfa_code": pyotp.TOTP(secret).now(), "csrf_token": csrf(g3.text)},
        timeout=120,
        allow_redirects=False,
    )
    return {
        "pwd_status": p.status_code,
        "pwd_loc": p.headers.get("Location"),
        "bad_mfa_blocked": "dashboard" not in (bad.headers.get("Location") or ""),
        "good_status": good.status_code,
        "good_loc": good.headers.get("Location"),
    }


def blocked(resp: requests.Response) -> bool:
    loc = resp.headers.get("Location") or ""
    if resp.status_code in (401, 403):
        return True
    if resp.status_code in (302, 303) and "login" in loc:
        return True
    if resp.status_code == 200 and ("login" in (resp.url or "") or "Inicie sesión" in (resp.text or "")):
        # redirected to login content
        if "password" in (resp.text or "").lower() and "csrf_token" in (resp.text or "") and len(resp.text) < 50000:
            return True
    return False


def copy_cookies(src: requests.Session) -> dict:
    return requests.utils.dict_from_cookiejar(src.cookies)


def session_from_cookies(cookies: dict) -> requests.Session:
    s = requests.Session()
    for k, v in cookies.items():
        s.cookies.set(k, v)
    return s


def main():
    evidence["resources"]["ram_start"] = ram()
    if evidence["resources"]["ram_start"] >= 95:
        evidence["limitations"].append("RAM>=95 at start — proceeding with light tests only after server recycle")
    if not wait_ready():
        evidence["final_verdict"] = "SESSION_REVOCATION_P0_NOT_VERIFIABLE"
        evidence["limitations"].append("server not ready")
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / "session_revocation_p0.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        return 2

    evidence["cause"] = {
        "classification": "session_replay / missing server-side invalidation on logout",
        "mechanism": "Flask signed client-side session cookie + Flask-Login user id + _novus_login_session_id",
        "logout_did": "clear current cookie + LoginSessionAudit.active=False",
        "logout_did_not": "check audit.active on request; revoke session_id in swarm list",
        "not_session_fixation": True,
        "is_replay": True,
    }
    evidence["correction"] = {
        "files": [
            "services/login_session_audit_service.py",
            "core/security.py",
            "routes/auth.py",
        ],
        "changes": [
            "close_login_session → revoke_user_sessions(session_id=...) only",
            "is_login_session_active() canonical check",
            "require_login rejects closed or revoked sid",
            "logout passes session_audit_id explicitly",
        ],
    }

    cleanup()
    ensure_users()

    # --- A enroll ---
    sa = requests.Session()
    # dashboard before auth
    d0 = sa.get(BASE + "/dashboard", timeout=30, allow_redirects=False)
    log("dashboard_unauth_denied", blocked(d0), {"status": d0.status_code, "loc": d0.headers.get("Location")})

    secret, en_meta = login_enroll(sa, EMAIL)
    log("mfa_enroll", bool(secret), en_meta)
    if not secret:
        evidence["final_verdict"] = "SESSION_REVOCATION_P0_FAIL"
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / "session_revocation_p0.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        return 1

    d1 = sa.get(BASE + "/dashboard", timeout=60, allow_redirects=True)
    log("dashboard_after_mfa", d1.status_code == 200 and "login" not in d1.url, {"status": d1.status_code, "len": len(d1.text)})

    cookies_pre = copy_cookies(sa)

    # logout
    lo = sa.get(BASE + "/logout", timeout=30, allow_redirects=False)
    log("logout", lo.status_code in (302, 303), {"loc": lo.headers.get("Location")})
    d_after = sa.get(BASE + "/dashboard", timeout=30, allow_redirects=False)
    log("same_client_after_logout_denied", blocked(d_after), {"status": d_after.status_code, "loc": d_after.headers.get("Location")})

    # replay cookie
    replay = session_from_cookies(cookies_pre)
    rd = replay.get(BASE + "/dashboard", timeout=60, allow_redirects=False)
    rs = replay.get(BASE + "/api/security/summary", timeout=60, allow_redirects=False)
    rsearch = replay.get(BASE + "/api/search?q=TEST_FIXTURE", timeout=60, allow_redirects=False)
    rdsar = replay.get(BASE + "/api/compliance/dsar-export?limit=5", timeout=60, allow_redirects=False)

    dash_replay_blocked = blocked(rd)
    # One hop max — must not land on authenticated dashboard
    try:
        rd2 = replay.get(BASE + "/dashboard", timeout=60, allow_redirects=True)
        if rd2.status_code == 200 and len(rd2.text) > 100000 and "login" not in (rd2.url or ""):
            dash_replay_blocked = False
        elif "login" in (rd2.url or "") or blocked(rd2) or (
            rd2.status_code == 200 and "password" in rd2.text.lower() and len(rd2.text) < 80000
        ):
            dash_replay_blocked = True
        rd2_meta = {"url": rd2.url, "len": len(rd2.text), "status": rd2.status_code}
    except requests.exceptions.TooManyRedirects as exc:
        # Redirect loop with stale cookie = not authenticated dashboard access
        dash_replay_blocked = True
        rd2_meta = {"error": "too_many_redirects", "note": str(exc)[:120]}

    api_blocked = all(x.status_code in (401, 403) for x in (rs, rsearch, rdsar))

    log(
        "cookie_replay_dashboard_denied",
        dash_replay_blocked,
        {"status": rd.status_code, "loc": rd.headers.get("Location"), "follow": rd2_meta},
    )
    log(
        "cookie_replay_apis_denied",
        api_blocked,
        {"summary": rs.status_code, "search": rsearch.status_code, "dsar": rdsar.status_code},
    )
    evidence["after"]["cookie_replay"] = {
        "dashboard_blocked": dash_replay_blocked,
        "apis_blocked": api_blocked,
    }

    # new login + MFA
    sb = requests.Session()
    lm = login_mfa(sb, EMAIL, secret)
    log("relogin_mfa", lm["good_status"] in (302, 303) and "dashboard" in (lm["good_loc"] or "") and lm["bad_mfa_blocked"], lm)
    d3 = sb.get(BASE + "/dashboard", timeout=60, allow_redirects=True)
    log("dashboard_after_relogin", d3.status_code == 200 and "login" not in d3.url, {"len": len(d3.text)})

    # tenant spoof
    sum_r = sb.get(BASE + "/api/security/summary", timeout=60)
    spoof_r = sb.get(BASE + f"/api/security/summary?tenant_id={SPOOF}", timeout=60)
    try:
        tid = sum_r.json().get("tenant_id")
        tid_s = spoof_r.json().get("tenant_id")
    except Exception:
        tid, tid_s = None, None
    log("tenant_canonical", tid == NIT and tid_s == NIT, {"tenant": tid, "spoof": tid_s})

    # B isolation quick
    sc = requests.Session()
    secret_b, _ = login_enroll(sc, EMAIL_B)
    if secret_b:
        sb_sum = sc.get(BASE + "/api/security/summary", timeout=60)
        try:
            tid_b = sb_sum.json().get("tenant_id")
        except Exception:
            tid_b = None
        log("tenant_b_isolated", tid_b == NIT_B and tid_b != tid, {"tenant_b": tid_b, "tenant_a": tid})
    else:
        log("tenant_b_isolated", False, "enroll_b_failed")

    # CSRF still on login
    bare = requests.Session()
    g = bare.get(BASE + "/login", timeout=30)
    bad_csrf = bare.post(
        BASE + "/login",
        data={"email": EMAIL, "password": PASS},
        timeout=30,
        allow_redirects=False,
    )
    log("csrf_login_still_enforced", bad_csrf.status_code == 403, {"status": bad_csrf.status_code})

    # Persist cookies for post-restart replay test
    evidence["_cookies_pre_logout"] = cookies_pre
    evidence["_secret"] = secret
    evidence["resources"]["ram_mid"] = ram()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    # Don't write secrets to final file yet — write checkpoint without secret in final
    (OUT_DIR / "session_revocation_p0.checkpoint.json").write_text(
        json.dumps({"cookies": cookies_pre, "secret": secret, "evidence_partial": {k: evidence[k] for k in evidence if not k.startswith("_")}}, indent=2),
        encoding="utf-8",
    )
    print("CHECKPOINT_READY", flush=True)

    all_critical = (
        evidence["tests"].get("cookie_replay_dashboard_denied", {}).get("ok")
        and evidence["tests"].get("cookie_replay_apis_denied", {}).get("ok")
        and evidence["tests"].get("relogin_mfa", {}).get("ok")
        and evidence["tests"].get("tenant_canonical", {}).get("ok")
    )
    evidence["final_verdict"] = (
        "SESSION_REVOCATION_P0_PASS" if all_critical else "SESSION_REVOCATION_P0_FAIL"
    )
    # strip secrets from main evidence file for now
    safe = {k: v for k, v in evidence.items() if not k.startswith("_")}
    (OUT_DIR / "session_revocation_p0.json").write_text(json.dumps(safe, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0 if all_critical else 1


if __name__ == "__main__":
    raise SystemExit(main())
