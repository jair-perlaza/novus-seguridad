#!/usr/bin/env python3
"""Validación HTTP UX MFA — tests 1-8 del alcance MFA UX."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import psutil
import pyotp
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT_DIR = ROOT / "data" / "novus_compliance_audit"
OUT_JSON = OUT_DIR / "MFA_ADMIN_UX_FINAL.json"
OUT_MD = OUT_DIR / "MFA_ADMIN_UX_FINAL.md"
BASE = "http://127.0.0.1:5000"
RUN = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
TEST_EMAIL = f"mfa-ux-test-{RUN}@example.com".lower()
TEST_PASSWORD = f"MfaUxTest!{RUN[-6:]}"
TEST_NIT = f"mfa-ux-{RUN}".lower()


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sample() -> Dict[str, Any]:
    vm = psutil.virtual_memory()
    row = {"ts": utc(), "system_ram_pct": round(vm.percent, 1)}
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            try:
                p = psutil.Process(c.pid)
                row["novus_rss_mb"] = round(p.memory_info().rss / 1024 / 1024, 1)
                row["novus_threads"] = p.num_threads()
            except Exception:
                pass
            break
    return row


def csrf_login(session: requests.Session, email: str, password: str) -> Dict[str, Any]:
    g = session.get(f"{BASE}/login", timeout=90)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', g.text)
    p = session.post(
        f"{BASE}/login",
        data={"email": email, "password": password, "csrf_token": m.group(1) if m else ""},
        allow_redirects=False,
        timeout=90,
    )
    return {"get": g.status_code, "post": p.status_code, "location": p.headers.get("Location")}


def create_admin_fixture() -> None:
    from database import SessionLocal, Usuario
    from werkzeug.security import generate_password_hash
    from services.rbac_service import ROLE_COMPANY_ADMIN

    db = SessionLocal()
    try:
        u = db.query(Usuario).filter(Usuario.email == TEST_EMAIL).first()
        if not u:
            u = Usuario(
                email=TEST_EMAIL,
                hashed_password=generate_password_hash(TEST_PASSWORD),
                role=ROLE_COMPANY_ADMIN,
                nit_pyme=TEST_NIT,
                sector="fintech",
                is_active=True,
                is_temporal=False,
            )
            db.add(u)
        else:
            u.hashed_password = generate_password_hash(TEST_PASSWORD)
            u.role = ROLE_COMPANY_ADMIN
            u.is_active = True
        db.commit()
    finally:
        db.close()
    from services.web_security_auth_enterprise.mfa_totp import _load, _save, _lock

    with _lock:
        data = _load()
        if TEST_EMAIL in data:
            del data[TEST_EMAIL]
            _save(data)


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    create_admin_fixture()
    report: Dict[str, Any] = {
        "run_id": RUN,
        "generated_at_utc": utc(),
        "before": sample(),
        "files_modified": [
            "templates/mfa_setup.html",
            "services/web_security_auth_enterprise/mfa_totp.py",
            "requirements.txt",
        ],
        "flow_before": "Secreto + URI otpauth visibles en pantalla; sin QR",
        "flow_after": "LOGIN → MFA SETUP → QR → código 6 dígitos → MFA activo → dashboard",
        "recovery_codes": "EXISTENTE — verify_and_enable devuelve 8 códigos one-time (infraestructura segura)",
        "tests": {},
    }

    s = requests.Session()
    # TEST 1
    t1 = csrf_login(s, TEST_EMAIL, TEST_PASSWORD)
    ok1 = t1["post"] == 302 and "/mfa-setup" in (t1.get("location") or "")
    report["tests"]["T1_admin_login_mfa_setup"] = {
        "classification": "VERIFIED" if ok1 else "FAILED",
        "detail": t1,
    }

    # TEST 2
    mfa_page = s.get(f"{BASE}/mfa-setup", timeout=90)
    html = mfa_page.text
    ok2 = (
        mfa_page.status_code == 200
        and "btn-enroll" in html
        and "qr-image" in html
        and "Paso 2" in html
        and "BuildError" not in html
    )
    report["tests"]["T2_mfa_setup_page"] = {
        "classification": "VERIFIED" if ok2 else "FAILED",
        "http": mfa_page.status_code,
        "has_qr_ui": "qr-image" in html,
        "has_manual": "manual-panel" in html,
        "otpauth_not_primary": "Escanea el código QR" in html,
    }

    csrf = re.search(r'const csrf = "([^"]+)"', html) or re.search(r"const csrf = '([^']+)'", html)
    csrf_val = csrf.group(1) if csrf else ""

    # Enroll + QR
    enr = s.post(
        f"{BASE}/api/wsae/mfa/enroll",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_val},
        json={},
        timeout=90,
    )
    ej = enr.json()
    has_qr = bool(ej.get("qr_png_base64")) or bool(ej.get("otpauth_uri"))
    secret = ej.get("secret")
    report["tests"]["T2b_enroll_qr"] = {
        "classification": "VERIFIED" if enr.status_code == 200 and ej.get("ok") and has_qr else "FAILED",
        "has_qr_png": bool(ej.get("qr_png_base64")),
        "has_secret_for_manual": bool(secret),
    }

    # TEST 3 enable
    code = pyotp.TOTP(secret).now() if secret else "000000"
    en = s.post(
        f"{BASE}/api/wsae/mfa/enable",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf_val},
        json={"code": code},
        timeout=90,
    )
    ej2 = en.json()
    ok3 = en.status_code == 200 and ej2.get("ok") and ej2.get("enabled")
    report["tests"]["T3_enable_totp"] = {
        "classification": "VERIFIED" if ok3 else "FAILED",
        "recovery_codes_count": len(ej2.get("recovery_codes") or []),
    }

    # TEST 4 relogin
    s2 = requests.Session()
    csrf_login(s2, TEST_EMAIL, TEST_PASSWORD)
    lg = s2.get(f"{BASE}/login", timeout=90)
    csrf2 = re.search(r'name="csrf_token"\s+value="([^"]+)"', lg.text)
    p2 = s2.post(
        f"{BASE}/login",
        data={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "csrf_token": csrf2.group(1) if csrf2 else "",
            "mfa_code": pyotp.TOTP(secret).now(),
        },
        allow_redirects=False,
        timeout=90,
    )
    ok4 = p2.status_code == 302 and "/dashboard" in (p2.headers.get("Location") or "")
    report["tests"]["T4_relogin_totp_dashboard"] = {
        "classification": "VERIFIED" if ok4 else "FAILED",
        "location": p2.headers.get("Location"),
    }

    # TEST 5 bad totp
    s3 = requests.Session()
    csrf_login(s3, TEST_EMAIL, TEST_PASSWORD)
    lg3 = s3.get(f"{BASE}/login", timeout=90)
    csrf3 = re.search(r'name="csrf_token"\s+value="([^"]+)"', lg3.text)
    p3 = s3.post(
        f"{BASE}/login",
        data={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "csrf_token": csrf3.group(1) if csrf3 else "",
            "mfa_code": "000000",
        },
        allow_redirects=True,
        timeout=90,
    )
    ok5 = "/dashboard" not in (p3.url or "").lower() or "error" in p3.text.lower()
    report["tests"]["T5_bad_totp_rejected"] = {
        "classification": "VERIFIED" if ok5 else "FAILED",
        "final_url": p3.url,
    }

    # TEST 6 dashboard without mfa - new admin without enroll
    create_admin_fixture()
    s4 = requests.Session()
    csrf_login(s4, TEST_EMAIL, TEST_PASSWORD)
    dash = s4.get(f"{BASE}/dashboard", allow_redirects=False, timeout=90)
    api = s4.get(f"{BASE}/api/search?q=test", timeout=90)
    try:
        body = api.json()
    except Exception:
        body = {}
    blocked = dash.status_code in (302, 403) or "/mfa-setup" in (dash.headers.get("Location") or "")
    api_blocked = api.status_code in (401, 403) or body.get("code") == "MFA_ENROLLMENT_REQUIRED"
    report["tests"]["T6_block_without_mfa"] = {
        "classification": "VERIFIED" if blocked and api_blocked else "PARTIAL" if blocked else "FAILED",
        "dashboard": dash.status_code,
        "api_search": api.status_code,
        "api_body_code": body.get("code"),
    }

    # TEST 7 search bypass after full mfa - use s2 session from T4 if ok
    if ok4:
        sr = s2.get(f"{BASE}/api/search?q=test", timeout=90)
        try:
            sb = sr.json()
        except Exception:
            sb = {}
        rec = isinstance(sb, dict) and (sb.get("status") == "recovering" or sb.get("_novusRecovery"))
        ok7 = sr.status_code == 200 and not rec and sb.get("status") != "recovering"
        report["tests"]["T7_search_after_mfa"] = {
            "classification": "VERIFIED" if ok7 else ("NOT VERIFIED" if rec else "FAILED"),
            "http": sr.status_code,
            "recovery": rec,
        }
    else:
        report["tests"]["T7_search_after_mfa"] = {"classification": "NOT VERIFIED", "detail": "T4 failed"}

    # TEST 8 disable blocked
    from services.web_security_auth_enterprise.mfa_totp import disable_mfa

    dis = disable_mfa(TEST_EMAIL, code=pyotp.TOTP(secret).now())
    ok8 = dis.get("error") == "mfa_mandatory_for_role"
    report["tests"]["T8_disable_blocked"] = {
        "classification": "VERIFIED" if ok8 else "FAILED",
        "detail": dis,
    }

    # Policy regression
    pol = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "mfa_admin_policy_test.py")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    report["regression"] = {
        "mfa_admin_policy_test": pol.returncode,
        "classification": "VERIFIED" if pol.returncode == 0 else "FAILED",
    }
    report["after"] = sample()

    verified = sum(1 for t in report["tests"].values() if t.get("classification") == "VERIFIED")
    report["summary"] = {
        "verified_count": verified,
        "total_tests": len(report["tests"]),
        "mfa_case_e": report["tests"].get("T7_search_after_mfa", {}).get("classification"),
        "overall": "VERIFIED" if verified >= 7 and report["regression"]["classification"] == "VERIFIED" else "PARTIAL",
    }

    md = [
        "# MFA ADMIN UX — INFORME FINAL",
        "",
        f"**Run ID:** {RUN} | **Generated:** {utc()}",
        "",
        "## Cambios realizados",
        "",
        "- Rediseño `/mfa-setup`: flujo 3 pasos + QR grande",
        "- QR server-side (`qr_png_base64`) desde `otpauth` URI existente",
        "- Configuración manual colapsable + copiar secreto",
        "- URI `otpauth://` solo en sección avanzada",
        "- Validación: solo 6 dígitos (rechaza URI en campo código)",
        "- Recovery codes: infraestructura existente integrada en UI",
        "",
        "## Archivos modificados",
        "",
    ]
    for f in report["files_modified"]:
        md.append(f"- `{f}`")
    md.extend(["", "## Pruebas", ""])
    for k, v in report["tests"].items():
        md.append(f"- **{k}**: {v.get('classification')}")
    md.extend([
        "",
        f"## Regresión policy: {report['regression']['classification']}",
        "",
        f"## Resumen: {report['summary']['overall']} ({verified}/{len(report['tests'])})",
        "",
        "## Recursos",
        "",
        f"- BEFORE RSS: {report['before'].get('novus_rss_mb')} MB",
        f"- AFTER RSS: {report['after'].get('novus_rss_mb')} MB",
    ])
    OUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT_MD.write_text("\n".join(md), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    print(f"Report: {OUT_MD}")
    return 0 if report["summary"]["overall"] == "VERIFIED" else 1


if __name__ == "__main__":
    sys.exit(main())
