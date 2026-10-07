#!/usr/bin/env python3
"""Pruebas política MFA administrativo (capa servicio, sin HTTP destructivo)."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_compliance_audit"
RUN = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
TEST_EMAIL = f"TEST-MFA-POLICY-{RUN}@example.com"


def main():
    from services.rbac_service import ROLE_ANALYST, ROLE_COMPANY_ADMIN, ROLE_SUPER_ADMIN
    from services.web_security_auth_enterprise.mfa_policy import (
        check_mfa_login_gate,
        enrollment_route_allowed,
        mfa_disable_allowed,
        role_requires_mfa,
        user_requires_mfa,
    )
    from services.web_security_auth_enterprise.mfa_totp import (
        begin_enrollment,
        disable_mfa,
        is_mfa_enabled,
        verify_and_enable,
    )
    from models.user import User

    tests = []

    def chk(name, ok, detail=None):
        tests.append({"test": name, "verdict": "VERIFIED" if ok else "FAIL", "detail": detail})

    chk("super_admin requires MFA", role_requires_mfa(ROLE_SUPER_ADMIN))
    chk("company_admin requires MFA", role_requires_mfa(ROLE_COMPANY_ADMIN))
    chk("analyst NOT mandatory", not role_requires_mfa(ROLE_ANALYST))

    admin = User(id=999991, email=TEST_EMAIL, role=ROLE_COMPANY_ADMIN)
    analyst = User(id=999992, email="analyst-test@example.com", role=ROLE_ANALYST)

    gate_admin = check_mfa_login_gate(admin, TEST_EMAIL)
    chk("admin without MFA -> enroll", gate_admin.get("action") == "enroll")

    gate_analyst = check_mfa_login_gate(analyst, analyst.email)
    chk("analyst without MFA -> ok", gate_analyst.get("action") == "ok")

    enr = begin_enrollment(TEST_EMAIL)
    chk("enrollment begins", enr.get("ok") and enr.get("secret"))
    if enr.get("ok"):
        import pyotp
        code = pyotp.TOTP(enr["secret"]).now()
        en = verify_and_enable(TEST_EMAIL, code, policy_lock=True)
        chk("enrollment verify enables", en.get("ok") and is_mfa_enabled(TEST_EMAIL))
        gate_verify = check_mfa_login_gate(admin, TEST_EMAIL)
        chk("admin with MFA -> verify", gate_verify.get("action") == "verify")

        dis = disable_mfa(TEST_EMAIL, code=pyotp.TOTP(enr["secret"]).now())
        chk("admin disable blocked by policy", dis.get("error") == "mfa_mandatory_for_role")
        chk("admin disable allowed check", not mfa_disable_allowed(admin))

    chk("analyst disable allowed check", mfa_disable_allowed(analyst))

    chk("enrollment route mfa_setup", enrollment_route_allowed(path="/mfa-setup", endpoint="auth.mfa_setup"))
    chk("enrollment route wsae api", enrollment_route_allowed(path="/api/wsae/mfa/enroll", endpoint="wsae_api.mfa_enroll"))
    chk("dashboard blocked during enroll", not enrollment_route_allowed(path="/", endpoint="dashboard.dashboard_principal"))

    db = None
    try:
        from database import SessionLocal, Usuario
        db = SessionLocal()
        qa = db.query(Usuario).filter(Usuario.email == "novus.qa.jul2026@example.com").first()
        if qa:
            chk("QA user role requires MFA if admin", user_requires_mfa(qa.email) == role_requires_mfa(getattr(qa, "role", None)))
        else:
            tests.append({"test": "QA user present", "verdict": "NOT VERIFIED", "detail": "user not in db"})
    finally:
        if db:
            db.close()

    overall = "VERIFIED" if all(t["verdict"] == "VERIFIED" for t in tests) else "FAIL"
    report = {"run_id": RUN, "fixture_email": TEST_EMAIL, "tests": tests, "overall": overall}
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"MFA_ADMIN_POLICY_TEST_{RUN}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if overall == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
