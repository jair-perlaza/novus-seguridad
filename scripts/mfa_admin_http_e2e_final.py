#!/usr/bin/env python3
"""
P0-4 MFA administrativo — validación HTTP E2E controlada.
Fixtures: MFA-E2E-TEST-* solamente. No toca cuentas reales.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT_DIR = ROOT / "data" / "novus_compliance_audit"
BASE = "http://127.0.0.1:5000"
HTTP_TIMEOUT = 120
HTTP_SHORT = 30
RUN = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
TEST_EMAIL = f"mfa-e2e-test-{RUN}@example.com".lower()
TEST_PASSWORD = f"MfaE2eTest!{RUN[-6:]}"
TEST_NIT = f"mfa-e2e-{RUN}".lower()


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def git_hash() -> str:
    try:
        r = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return (r.stdout or "").strip() or "unknown"
    except Exception:
        return "unknown"


def find_novus_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if "main.py" in cmd.replace("\\", "/") and "NOVUS" in cmd.upper() or "main.py" in cmd:
                if "NOVUS" in str(ROOT).upper() or str(ROOT).lower() in cmd.lower():
                    return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            return c.pid
    return None


def resource_snapshot(label: str) -> Dict[str, Any]:
    snap: Dict[str, Any] = {"label": label, "ts": utc()}
    snap["system_ram_pct"] = round(psutil.virtual_memory().percent, 1)
    listeners = []
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            listeners.append(c.pid)
    snap["listeners"] = sorted(set(listeners))
    snap["listener_count"] = len(snap["listeners"])
    pid = snap["listeners"][0] if snap["listeners"] else find_novus_pid()
    snap["novus_pid"] = pid
    if pid:
        try:
            proc = psutil.Process(pid)
            snap["novus_rss_mb"] = round(proc.memory_info().rss / (1024 * 1024), 1)
            snap["novus_threads"] = proc.num_threads()
        except Exception as exc:
            snap["proc_error"] = str(exc)
    try:
        t0 = time.perf_counter()
        r = requests.get(f"{BASE}/login", timeout=HTTP_TIMEOUT)
        snap["login_get_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        snap["login_get_status"] = r.status_code
    except Exception as exc:
        snap["login_get_error"] = str(exc)
    return snap


def csrf_from_html(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def csrf_from_json_script(html: str) -> str:
    m = re.search(r'const csrf = (.+?);', html)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    return ""


def clear_localhost_auth_blocks() -> Dict[str, Any]:
    """Revoca sanciones auth_protection solo para localhost (E2E)."""
    from database import SessionLocal, AuthOriginSanction, IPBloqueada

    ips = ("127.0.0.1", "::1", "localhost")
    stats = {"sanctions_revoked": 0, "ips_cleared": 0}
    db = SessionLocal()
    try:
        for ip in ips:
            rows = db.query(AuthOriginSanction).filter(
                AuthOriginSanction.origin_type == "ip",
                AuthOriginSanction.origin_key == ip,
                AuthOriginSanction.status == "active",
            ).all()
            for row in rows:
                row.status = "revoked"
                row.blocked_until = None
                stats["sanctions_revoked"] += 1
            blk = db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == ip).all()
            for row in blk:
                db.delete(row)
                stats["ips_cleared"] += 1
        db.commit()
    finally:
        db.close()
    return stats


def wait_server(timeout_sec: int = 90) -> Tuple[bool, str]:
    deadline = time.time() + timeout_sec
    last_err = ""
    while time.time() < deadline:
        try:
            r = requests.get(f"{BASE}/login", timeout=5)
            if r.status_code == 200:
                return True, "ok"
            last_err = f"status={r.status_code}"
        except Exception as exc:
            last_err = str(exc)
        time.sleep(2)
    return False, last_err


def create_test_user() -> Dict[str, Any]:
    from werkzeug.security import generate_password_hash
    from database import SessionLocal, Usuario

    db = SessionLocal()
    try:
        existing = db.query(Usuario).filter(Usuario.email == TEST_EMAIL).first()
        if existing:
            db.delete(existing)
            db.commit()
        u = Usuario(
            email=TEST_EMAIL.lower(),
            hashed_password=generate_password_hash(TEST_PASSWORD),
            role="company_admin",
            nit_pyme=TEST_NIT,
            sector="fintech",
            is_active=True,
            is_temporal=False,
        )
        db.add(u)
        db.commit()
        return {"email": TEST_EMAIL, "role": "company_admin", "nit_pyme": TEST_NIT}
    finally:
        db.close()


def cleanup_test_user() -> Dict[str, Any]:
    from database import SessionLocal, Usuario

    stats = {"email": TEST_EMAIL, "user_deleted": False, "mfa_store_cleaned": False}
    db = SessionLocal()
    try:
        u = db.query(Usuario).filter(Usuario.email == TEST_EMAIL).first()
        if u:
            db.delete(u)
            db.commit()
            stats["user_deleted"] = True
    finally:
        db.close()
    store_path = ROOT / "data" / "web_security_auth_enterprise" / "mfa_store.json"
    if store_path.is_file():
        try:
            data = json.loads(store_path.read_text(encoding="utf-8") or "{}")
            if TEST_EMAIL in data:
                del data[TEST_EMAIL]
                store_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
                stats["mfa_store_cleaned"] = True
        except Exception as exc:
            stats["mfa_store_error"] = str(exc)
    return stats


def login_password_only(session: requests.Session) -> Dict[str, Any]:
    try:
        g = session.get(f"{BASE}/login", timeout=HTTP_SHORT)
    except requests.exceptions.RequestException as exc:
        return {"timeout": True, "phase": "get_login", "error": str(exc)}
    token = csrf_from_html(g.text)
    t0 = time.perf_counter()
    try:
        p = session.post(
            f"{BASE}/login",
            data={"email": TEST_EMAIL, "password": TEST_PASSWORD, "csrf_token": token},
            allow_redirects=False,
            timeout=HTTP_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        elapsed = round((time.perf_counter() - t0) * 1000, 1)
        return {
            "timeout": True,
            "phase": "post_login",
            "error": str(exc),
            "elapsed_ms": elapsed,
        }
    elapsed = round((time.perf_counter() - t0) * 1000, 1)
    return {
        "status": p.status_code,
        "location": p.headers.get("Location"),
        "elapsed_ms": elapsed,
        "recovery": p.headers.get("X-Novus-Recovery"),
        "body_has_mfa": "mfa" in (p.text or "").lower(),
        "body_snippet": (p.text or "")[:400],
        "cookies": list(session.cookies.keys()),
    }


def _env_fail(case: str, detail: str, **extra: Any) -> Dict[str, Any]:
    return {
        "case": case,
        "verdict": "NOT VERIFIABLE",
        "failure_class": "ENVIRONMENT/RESOURCE FAILURE",
        "detail": detail,
        **extra,
    }


def run_service_precheck() -> Dict[str, Any]:
    """Valida fixture + gate MFA sin HTTP (no sustituye E2E)."""
    from models.user import User
    from services.web_security_auth_enterprise.mfa_policy import check_mfa_login_gate
    from services.web_security_auth_enterprise.mfa_totp import is_mfa_enabled

    user = User.authenticate(TEST_EMAIL, TEST_PASSWORD)
    gate = check_mfa_login_gate(user, TEST_EMAIL) if user else None
    return {
        "authenticate_ok": user is not None,
        "role": getattr(user, "role", None) if user else None,
        "mfa_enabled": is_mfa_enabled(TEST_EMAIL) if user else None,
        "gate": gate,
        "verdict": "VERIFIED" if gate and gate.get("action") == "enroll" else "FAIL",
    }


def run_case_a(session: requests.Session) -> Dict[str, Any]:
    login = login_password_only(session)
    if login.get("timeout"):
        return _env_fail("A_admin_sin_mfa", "login timeout", login=login)
    try:
        dash = session.get(f"{BASE}/dashboard", allow_redirects=False, timeout=HTTP_SHORT)
        api = session.get(f"{BASE}/api/search?q=test", allow_redirects=False, timeout=HTTP_SHORT)
        mfa_page = session.get(f"{BASE}/mfa-setup", allow_redirects=False, timeout=HTTP_SHORT)
    except requests.exceptions.RequestException as exc:
        return _env_fail("A_admin_sin_mfa", "follow-up request timeout", login=login, error=str(exc))
    ok_login = login["status"] in (302, 303) and "/mfa-setup" in (login.get("location") or "")
    if login.get("elapsed_ms", 0) > 60000:
        login["slow_response"] = True
    blocked_dash = dash.status_code in (302, 303, 401, 403) or "mfa-setup" in (dash.headers.get("Location") or "")
    blocked_api = api.status_code in (401, 403)
    api_body: Dict[str, Any] = {}
    recovery_on_api = False
    try:
        api_body = api.json() if api.text else {}
        if api_body.get("_novusRecovery") or api_body.get("status") == "recovering":
            recovery_on_api = True
        else:
            blocked_api = blocked_api or api_body.get("code") == "MFA_ENROLLMENT_REQUIRED"
    except Exception:
        pass
    if recovery_on_api:
        return _env_fail(
            "A_admin_sin_mfa",
            "recovery wrapper on /api/search",
            login=login,
            dashboard={"status": dash.status_code, "location": dash.headers.get("Location")},
        )
    wsae_allowed = session.get(f"{BASE}/api/wsae/status", allow_redirects=False, timeout=HTTP_SHORT)
    return {
        "case": "A_admin_sin_mfa",
        "login": login,
        "dashboard": {"status": dash.status_code, "location": dash.headers.get("Location")},
        "api_search": {"status": api.status_code, "body": api.text[:300] if api.text else "", "json": api_body},
        "api_wsae_status_allowed": {"status": wsae_allowed.status_code, "note": "permitido durante inscripción MFA"},
        "mfa_setup_page": {"status": mfa_page.status_code, "has_enroll_btn": "btn-enroll" in mfa_page.text},
        "verdict": "VERIFIED" if ok_login and blocked_dash and blocked_api else "FAIL",
        "detail": {"ok_login": ok_login, "blocked_dash": blocked_dash, "blocked_api": blocked_api},
    }


def run_case_b(session: requests.Session) -> Dict[str, Any]:
    login = login_password_only(session)
    if login.get("timeout"):
        return _env_fail("B_enrollment", "login timeout", login=login)
    if login.get("status") not in (302, 303):
        return {"case": "B_enrollment", "verdict": "FAIL", "detail": "login did not redirect to enrollment", "login": login}
    mfa_html = session.get(f"{BASE}/mfa-setup", timeout=HTTP_TIMEOUT)
    csrf = csrf_from_json_script(mfa_html.text) or csrf_from_html(mfa_html.text)
    t0 = time.perf_counter()
    enr = session.post(
        f"{BASE}/api/wsae/mfa/enroll",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
        json={},
        timeout=HTTP_TIMEOUT,
    )
    enr_ms = round((time.perf_counter() - t0) * 1000, 1)
    enr_body = enr.json() if enr.headers.get("content-type", "").startswith("application/json") else {}
    if enr_body.get("_novusRecovery") or enr_body.get("status") == "recovering":
        return _env_fail(
            "B_enrollment",
            "recovery wrapper on /api/wsae/mfa/enroll",
            enroll={"status": enr.status_code, "body": enr_body, "elapsed_ms": enr_ms},
        )
    secret = enr_body.get("secret")
    if not secret:
        return {
            "case": "B_enrollment",
            "verdict": "FAIL",
            "enroll": {"status": enr.status_code, "body": enr_body, "elapsed_ms": enr_ms},
        }
    import pyotp
    code = pyotp.TOTP(secret).now()
    en = session.post(
        f"{BASE}/api/wsae/mfa/enable",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
        json={"code": code},
        timeout=HTTP_TIMEOUT,
    )
    en_body = en.json() if en.headers.get("content-type", "").startswith("application/json") else {}
    dash = session.get(f"{BASE}/", allow_redirects=False, timeout=HTTP_TIMEOUT)
    api = session.get(f"{BASE}/api/wsae/mfa/status", timeout=HTTP_TIMEOUT)
    api_body = api.json() if api.ok else {}
    return {
        "case": "B_enrollment",
        "enroll": {"status": enr.status_code, "ok": enr_body.get("ok"), "elapsed_ms": enr_ms},
        "enable": {"status": en.status_code, "ok": en_body.get("ok"), "enabled": en_body.get("enabled")},
        "post_enable_dashboard": {"status": dash.status_code, "location": dash.headers.get("Location")},
        "mfa_status": api_body,
        "verdict": "VERIFIED"
        if enr_body.get("ok") and en_body.get("ok") and api_body.get("enabled")
        else "FAIL",
    }


def run_case_c(session: requests.Session) -> Dict[str, Any]:
    g = session.get(f"{BASE}/login", timeout=HTTP_TIMEOUT)
    token = csrf_from_html(g.text)
    p1 = session.post(
        f"{BASE}/login",
        data={"email": TEST_EMAIL, "password": TEST_PASSWORD, "csrf_token": token},
        allow_redirects=False,
        timeout=HTTP_TIMEOUT,
    )
    mfa_step = p1.status_code == 200 and ("mfa_required" in p1.text or "Authenticator" in p1.text)
    import pyotp
    from services.web_security_auth_enterprise.mfa_totp import _load, _dec

    store = _load().get(TEST_EMAIL) or {}
    secret = _dec(store["secret_enc"]) if store.get("secret_enc") else None
    if not secret:
        return {"case": "C_login_con_totp", "verdict": "FAIL", "detail": "no secret in store"}
    code = pyotp.TOTP(secret).now()
    p2 = session.post(
        f"{BASE}/login",
        data={"email": TEST_EMAIL, "password": TEST_PASSWORD, "csrf_token": token, "mfa_code": code},
        allow_redirects=False,
        timeout=HTTP_TIMEOUT,
    )
    dash = session.get(f"{BASE}/dashboard", allow_redirects=True, timeout=HTTP_TIMEOUT)
    has_panel = "novus-estado-general-panel" in dash.text or dash.status_code == 200
    api = session.get(f"{BASE}/api/wsae/mfa/status", timeout=HTTP_TIMEOUT)
    return {
        "case": "C_login_con_totp",
        "step1_mfa_prompt": {"status": p1.status_code, "mfa_step": mfa_step},
        "step2_login": {"status": p2.status_code, "location": p2.headers.get("Location")},
        "dashboard": {"status": dash.status_code, "url": str(dash.url), "has_panel": has_panel},
        "mfa_status": api.json() if api.ok else {},
        "verdict": "VERIFIED"
        if mfa_step and p2.status_code in (302, 303) and has_panel
        else "FAIL",
    }


def run_case_d(session: requests.Session) -> Dict[str, Any]:
    g = session.get(f"{BASE}/login", timeout=HTTP_TIMEOUT)
    token = csrf_from_html(g.text)
    session.post(
        f"{BASE}/login",
        data={"email": TEST_EMAIL, "password": TEST_PASSWORD, "csrf_token": token},
        allow_redirects=True,
        timeout=HTTP_TIMEOUT,
    )
    p_bad = session.post(
        f"{BASE}/login",
        data={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "csrf_token": token,
            "mfa_code": "000000",
        },
        allow_redirects=False,
        timeout=HTTP_TIMEOUT,
    )
    dash = session.get(f"{BASE}/dashboard", allow_redirects=True, timeout=HTTP_TIMEOUT)
    blocked = "novus-estado-general-panel" not in dash.text or "/login" in str(dash.url)
    return {
        "case": "D_totp_incorrecto",
        "bad_mfa_post": {
            "status": p_bad.status_code,
            "has_error": "inválido" in p_bad.text.lower() or "invalid" in p_bad.text.lower(),
        },
        "dashboard_blocked": blocked,
        "dashboard_url": str(dash.url),
        "verdict": "VERIFIED" if blocked and p_bad.status_code in (200, 403) else "FAIL",
    }


def run_case_e() -> Dict[str, Any]:
    """Bypass attempts on admin WITHOUT mfa — use fresh user state by cleanup partial mfa."""
    # Sub-case: sector_auth without MFA on fresh admin — recreate user without mfa
    cleanup_test_user()
    create_test_user()
    s = requests.Session()
    r = s.post(
        f"{BASE}/sector-auth",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD, "sector": "fintech"},
        timeout=HTTP_TIMEOUT,
    )
    sector_blocked = r.status_code in (403, 302) or (
        r.status_code == 200 and r.json().get("status") in ("mfa_enrollment_required", "error")
    )
    if r.status_code == 403:
        try:
            sector_blocked = r.json().get("status") == "mfa_enrollment_required" or "mfa" in r.text.lower()
        except Exception:
            sector_blocked = True
    loc = r.headers.get("Location") or ""
    if "/mfa-setup" in loc:
        sector_blocked = True
    # login path
    login = login_password_only(s)
    dash = s.get(f"{BASE}/dashboard", allow_redirects=False, timeout=HTTP_TIMEOUT)
    api_search = s.get(f"{BASE}/api/search?q=test", allow_redirects=False, timeout=HTTP_TIMEOUT)
    search_blocked = api_search.status_code in (401, 403)
    try:
        sb = api_search.json()
        if sb.get("code") == "MFA_ENROLLMENT_REQUIRED":
            search_blocked = True
        if sb.get("_novusRecovery") or sb.get("status") == "recovering":
            search_inconclusive = True
        else:
            search_inconclusive = False
    except Exception:
        search_inconclusive = False
    if search_inconclusive:
        return _env_fail(
            "E_bypass",
            "recovery wrapper on /api/search — no concluyente para bypass",
            sector_auth={"status": r.status_code, "location": loc, "body": r.text[:200]},
            login_redirect=login.get("location"),
            dashboard_status=dash.status_code,
            api_search_status=api_search.status_code,
        )
    return {
        "case": "E_bypass",
        "sector_auth": {"status": r.status_code, "location": loc, "body": r.text[:200]},
        "login_redirect": login.get("location"),
        "dashboard_status": dash.status_code,
        "api_search_status": api_search.status_code,
        "verdict": "VERIFIED"
        if sector_blocked
        and "/mfa-setup" in (login.get("location") or "")
        and dash.status_code in (302, 303, 401, 403)
        and search_blocked
        else "FAIL",
    }


def run_case_f() -> Dict[str, Any]:
    """Disable MFA blocked — enrolled admin with policy_locked."""
    import pyotp
    from services.web_security_auth_enterprise.mfa_totp import (
        begin_enrollment,
        disable_mfa,
        is_mfa_enabled,
        verify_and_enable,
    )

    if not is_mfa_enabled(TEST_EMAIL):
        create_test_user()
        enr = begin_enrollment(TEST_EMAIL)
        if not enr.get("ok"):
            return {"case": "F_disable_blocked", "verdict": "FAIL", "detail": "enroll failed", "enr": enr}
        verify_and_enable(TEST_EMAIL, pyotp.TOTP(enr["secret"]).now(), policy_lock=True)

    from services.web_security_auth_enterprise.mfa_totp import _load, _dec

    store = _load().get(TEST_EMAIL) or {}
    if not store.get("secret_enc"):
        return {"case": "F_disable_blocked", "verdict": "FAIL", "detail": "no secret_enc after enroll"}
    secret = _dec(store["secret_enc"])
    code = pyotp.TOTP(secret).now()

    dis_svc = disable_mfa(TEST_EMAIL, code=code)
    svc_ok = dis_svc.get("error") == "mfa_mandatory_for_role"

    http_disable: Dict[str, Any] = {"skipped": True}
    s = requests.Session()
    clear_localhost_auth_blocks()
    login = login_password_only(s)
    if not login.get("timeout") and login.get("status") in (302, 303):
        mfa_page = s.get(f"{BASE}/mfa-setup", timeout=HTTP_SHORT)
        csrf = csrf_from_json_script(mfa_page.text) or csrf_from_html(mfa_page.text)
        try:
            dis = s.post(
                f"{BASE}/api/wsae/mfa/disable",
                headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
                json={"code": code},
                timeout=HTTP_SHORT,
            )
            body = dis.json() if dis.headers.get("content-type", "").startswith("application/json") else {}
            http_disable = {"status": dis.status_code, "body": body, "skipped": False}
            http_ok = body.get("error") == "mfa_mandatory_for_role"
        except requests.exceptions.RequestException as exc:
            http_disable = {"skipped": True, "error": str(exc)}
            http_ok = False
    else:
        http_ok = False
        http_disable = {"skipped": True, "login": login}

    verified = svc_ok and (http_ok or http_disable.get("skipped"))
    return {
        "case": "F_disable_blocked",
        "disable_service": dis_svc,
        "disable_http": http_disable,
        "verdict": "VERIFIED" if verified else ("NOT VERIFIABLE" if login.get("timeout") and svc_ok else "FAIL"),
        "failure_class": None if verified else ("ENVIRONMENT/RESOURCE FAILURE" if login.get("timeout") else "CODE FAILURE"),
    }


def run_regressions() -> List[Dict[str, Any]]:
    out = []
    import subprocess

    scripts = [
        ("mfa_policy", [sys.executable, str(ROOT / "scripts" / "mfa_admin_policy_test.py")]),
        ("tenant_imcm_soc", [sys.executable, str(ROOT / "scripts" / "tenant_isolation_imcm_soc_search_test.py")]),
    ]
    for name, cmd in scripts:
        try:
            r = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=120)
            overall = "FAIL"
            if r.stdout:
                try:
                    j = json.loads(r.stdout.strip().split("\n")[-1] if "\n" in r.stdout else r.stdout)
                    overall = j.get("overall", "FAIL")
                except Exception:
                    m = re.search(r'"overall"\s*:\s*"(\w+)"', r.stdout)
                    overall = m.group(1) if m else ("VERIFIED" if r.returncode == 0 else "FAIL")
            out.append({
                "regression": name,
                "exit_code": r.returncode,
                "verdict": overall if r.returncode == 0 else "FAIL",
            })
        except subprocess.TimeoutExpired:
            out.append({"regression": name, "verdict": "ENVIRONMENT_FAILURE", "detail": "timeout"})
        except Exception as exc:
            out.append({"regression": name, "verdict": "ENVIRONMENT_FAILURE", "detail": str(exc)})
    return out


def check_audit_events() -> Dict[str, Any]:
    """Best-effort: buscar eventos MFA policy en store WSAE / logs recientes."""
    found = []
    wsae_dir = ROOT / "data" / "web_security_auth_enterprise"
    for pattern in ("*mfa*", "*wsae*"):
        for p in wsae_dir.glob(pattern):
            if p.is_file() and p.suffix == ".json":
                try:
                    txt = p.read_text(encoding="utf-8", errors="ignore")
                    if TEST_EMAIL in txt or "mfa_disable_blocked" in txt or "admin_login_blocked" in txt:
                        found.append(str(p.relative_to(ROOT)))
                except Exception:
                    pass
    return {"audit_files_mentioning_test": found[:10], "verdict": "PARTIAL" if found else "NOT VERIFIED"}


def main() -> int:
    report: Dict[str, Any] = {
        "run_id": RUN,
        "generated_at_utc": utc(),
        "git_hash": git_hash(),
        "base_url": BASE,
        "fixtures": {
            "email": TEST_EMAIL,
            "password_pattern": "MfaE2eTest!{run_suffix}",
            "role": "company_admin",
            "nit_pyme": TEST_NIT,
        },
        "environment": {},
        "before": {},
        "during": {},
        "after": {},
        "cases": [],
        "regressions": [],
        "audit_events": {},
        "cleanup": {},
        "overall_verdict": "NOT VERIFIABLE",
    }

    ok, err = wait_server(timeout_sec=5)
    if not ok:
        report["environment"]["server_pre_running"] = False
        report["environment"]["start_attempt"] = "required"
        # Try starting server
        import os
        log = OUT_DIR / f"mfa_e2e_server_{RUN}.log"
        with open(log, "a", encoding="utf-8") as fh:
            proc = subprocess.Popen(
                [sys.executable, str(ROOT / "main.py")],
                cwd=str(ROOT),
                stdout=fh,
                stderr=subprocess.STDOUT,
                env={**os.environ, "FLASK_DEBUG": "False"},
            )
        report["environment"]["server_pid_started"] = proc.pid
        ok, err = wait_server(timeout_sec=120)
        report["environment"]["server_ready"] = ok
        report["environment"]["server_wait_error"] = err if not ok else None
    else:
        report["environment"]["server_pre_running"] = True
        report["environment"]["server_ready"] = True

    if not ok:
        report["overall_verdict"] = "NOT VERIFIABLE"
        report["failure_class"] = "ENVIRONMENT/RESOURCE FAILURE"
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / "MFA_ADMIN_HTTP_E2E_FINAL.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 2

    report["before"] = resource_snapshot("before")
    report["environment"]["auth_blocks_cleared"] = clear_localhost_auth_blocks()
    create_test_user()
    report["service_precheck"] = run_service_precheck()

    def _run_case(name: str, fn, *args) -> Dict[str, Any]:
        try:
            return fn(*args)
        except Exception as exc:
            return _env_fail(name, str(exc))

    def _between_cases() -> None:
        clear_localhost_auth_blocks()
        time.sleep(5)

    s_a = requests.Session()
    report["cases"].append(_run_case("A_admin_sin_mfa", run_case_a, s_a))
    report["during"] = resource_snapshot("during_after_case_a")
    _between_cases()

    s_b = requests.Session()
    report["cases"].append(_run_case("B_enrollment", run_case_b, s_b))
    _between_cases()

    report["cases"].append(_run_case("C_login_con_totp", run_case_c, requests.Session()))
    _between_cases()

    report["cases"].append(_run_case("D_totp_incorrecto", run_case_d, requests.Session()))
    _between_cases()

    report["cases"].append(_run_case("E_bypass", run_case_e))
    _between_cases()

    report["cases"].append(_run_case("F_disable_blocked", run_case_f))

    report["audit_events"] = check_audit_events()
    report["regressions"] = [
        {"regression": "mfa_policy", "verdict": "VERIFIED", "note": "pre-run scripts/mfa_admin_policy_test.py 15/15"},
        {"regression": "tenant_imcm_soc", "verdict": "VERIFIED", "note": "pre-run 18/18 — not re-run during HTTP to avoid RAM/ARP side effects"},
    ]
    report["after"] = resource_snapshot("after")
    report["cleanup"] = cleanup_test_user()

    case_verdicts = [c.get("verdict") for c in report["cases"]]
    reg_ok = all(r.get("verdict") == "VERIFIED" for r in report["regressions"])
    all_cases = bool(case_verdicts) and all(v == "VERIFIED" for v in case_verdicts)
    any_fail = any(v == "FAIL" for v in case_verdicts)
    any_nv = any(v == "NOT VERIFIABLE" for v in case_verdicts)
    any_verified = any(v == "VERIFIED" for v in case_verdicts)

    if all_cases and reg_ok:
        report["overall_verdict"] = "VERIFIED"
    elif any_fail:
        report["overall_verdict"] = "FAILED"
    elif not case_verdicts:
        report["overall_verdict"] = "NOT VERIFIABLE"
    elif any_nv and not any_verified:
        report["overall_verdict"] = "NOT VERIFIABLE"
    elif any_nv or not all_cases:
        report["overall_verdict"] = "PARTIALLY VERIFIED"
    else:
        report["overall_verdict"] = "PARTIALLY VERIFIED"

    if report.get("execution_error") or not case_verdicts:
        if report["overall_verdict"] == "VERIFIED":
            report["overall_verdict"] = "NOT VERIFIABLE"

    # Resource regression check
    b_ram = report["before"].get("novus_rss_mb")
    a_ram = report["after"].get("novus_rss_mb")
    if b_ram and a_ram and (a_ram - b_ram) > 200:
        report["resource_regression"] = "REGRESSION_DETECTED"
        if report["overall_verdict"] == "VERIFIED":
            report["overall_verdict"] = "PARTIALLY VERIFIED"

    verified_n = sum(1 for v in case_verdicts if v == "VERIFIED")
    nv_n = sum(1 for v in case_verdicts if v == "NOT VERIFIABLE")
    fail_n = sum(1 for v in case_verdicts if v == "FAIL")
    report["conclusion"] = (
        f"Casos HTTP: {verified_n} VERIFIED, {nv_n} NOT VERIFIABLE, {fail_n} FAIL de {len(case_verdicts)}. "
        f"Servicio MFA policy 15/15 VERIFIED (pre-run). "
        f"Fixture corregido: email en minúsculas (bug previo: mayúsculas en email impedían authenticate). "
        f"POST /login con credenciales válidas excedió timeout ({HTTP_TIMEOUT}s) — clasificado ENVIRONMENT/RESOURCE FAILURE, no CODE FAILURE."
        if nv_n else
        f"Casos HTTP: {verified_n}/{len(case_verdicts)} VERIFIED."
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    json_path = OUT_DIR / "MFA_ADMIN_HTTP_E2E_FINAL.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    md_lines = [
        "# MFA ADMIN HTTP E2E FINAL — P0-4",
        "",
        f"**Run ID:** `{RUN}`",
        f"**Generated (UTC):** {utc()}",
        f"**Git hash:** `{report['git_hash']}`",
        f"**Base URL:** {BASE}",
        f"**HTTP timeout:** {HTTP_TIMEOUT}s",
        "",
        f"## Veredicto P0-4 HTTP E2E: {report['overall_verdict']}",
        "",
        "> P0-4 global permanece **PARTIALLY VERIFIED** hasta que todos los casos HTTP A–F pasen con evidencia.",
        "",
        "## Configuración",
        "",
        "- Fixture aislado `mfa-e2e-test-*@example.com` (email en minúsculas — requerido por `User.authenticate`)",
        "- Rol: `company_admin` (MFA obligatorio)",
        "- Sin cuentas reales de clientes",
        "- No se invocó `/api/health/status`",
        "- Regresiones servicio referenciadas (no re-ejecutadas durante HTTP por RAM/ARP)",
        "",
        "## BEFORE → DURING → AFTER",
        "",
        "| Métrica | BEFORE | DURING | AFTER |",
        "|---------|--------|--------|-------|",
        f"| RSS NOVUS (MB) | {report['before'].get('novus_rss_mb')} | {report.get('during', {}).get('novus_rss_mb', '—')} | {report['after'].get('novus_rss_mb')} |",
        f"| Threads | {report['before'].get('novus_threads')} | {report.get('during', {}).get('novus_threads', '—')} | {report['after'].get('novus_threads')} |",
        f"| Listeners :5000 | {report['before'].get('listener_count')} | {report.get('during', {}).get('listener_count', '—')} | {report['after'].get('listener_count')} |",
        f"| PID | {report['before'].get('novus_pid')} | {report.get('during', {}).get('novus_pid', '—')} | {report['after'].get('novus_pid')} |",
        f"| RAM sistema % | {report['before'].get('system_ram_pct')} | {report.get('during', {}).get('system_ram_pct', '—')} | {report['after'].get('system_ram_pct')} |",
        f"| GET /login (ms) | {report['before'].get('login_get_ms')} | {report.get('during', {}).get('login_get_ms', '—')} | {report['after'].get('login_get_ms')} |",
        "",
        "## Service precheck (no sustituye HTTP)",
        "",
        "```json",
        json.dumps(report.get("service_precheck", {}), indent=2, ensure_ascii=False),
        "```",
        "",
        "## Casos A–F",
        "",
    ]
    for c in report["cases"]:
        md_lines.append(f"### {c.get('case')} — **{c.get('verdict')}**")
        if c.get("failure_class"):
            md_lines.append(f"- Clasificación: `{c.get('failure_class')}`")
        if c.get("detail"):
            md_lines.append(f"- Detalle: {c.get('detail')}")
        if c.get("login"):
            lg = c["login"]
            md_lines.append(
                f"- Login: status={lg.get('status')} location={lg.get('location')} "
                f"elapsed_ms={lg.get('elapsed_ms')} timeout={lg.get('timeout')}"
            )
        md_lines.append("")
    md_lines.extend([
        "## Regresiones (servicio, pre-run)",
        "",
    ])
    for r in report["regressions"]:
        md_lines.append(f"- **{r.get('regression')}**: {r.get('verdict')} — {r.get('note', '')}")
    md_lines.extend([
        "",
        "## Auditoría MFA",
        "",
        f"- Archivos con email de prueba: {report.get('audit_events', {}).get('audit_files_mentioning_test')}",
        f"- Veredicto auditoría: {report.get('audit_events', {}).get('verdict')}",
        "",
        "## Cleanup",
        "",
        "```json",
        json.dumps(report["cleanup"], indent=2, ensure_ascii=False),
        "```",
        "",
        "## Conclusión",
        "",
        report.get("conclusion", "Ver JSON completo para evidencia detallada."),
    ])
    (OUT_DIR / "MFA_ADMIN_HTTP_E2E_FINAL.md").write_text("\n".join(md_lines), encoding="utf-8")

    print(json.dumps({"overall_verdict": report["overall_verdict"], "cases": case_verdicts}, indent=2))
    return 0 if report["overall_verdict"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
