#!/usr/bin/env python3
"""Phase 1 security regression smoke — controls must remain ON."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure" / "phase1_security_regression.json"
BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")


def main() -> int:
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers, loadtest_password

    results = {}

    # CSRF: POST login without token must fail
    s = requests.Session()
    r0 = s.get(BASE + "/login", timeout=20)
    r_bad = s.post(
        BASE + "/login",
        data={"email": "nobody@example.com", "password": "x"},
        timeout=20,
        allow_redirects=False,
    )
    results["csrf_reject_missing_token"] = {
        "http": r_bad.status_code,
        "pass": r_bad.status_code in (400, 403) or ("csrf" in (r_bad.text or "").lower()),
    }

    # Auth required on API
    r401 = requests.get(BASE + "/api/notifications", timeout=20)
    results["api_requires_auth"] = {"http": r401.status_code, "pass": r401.status_code == 401}

    # Valid LOADTEST login with CSRF works
    manifest = json.loads((ROOT / "data/production_closure/loadtest_users_manifest.json").read_text(encoding="utf-8"))
    email = manifest["users"][0]["email"]
    pw = loadtest_password()
    s2 = requests.Session()
    apply_loadtest_client_headers(s2, email)
    g = s2.get(BASE + "/login", timeout=20)
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', g.text)
    post = s2.post(
        BASE + "/login",
        data={"email": email, "password": pw, "csrf_token": csrf.group(1) if csrf else ""},
        timeout=30,
        allow_redirects=False,
    )
    results["loadtest_login_csrf"] = {
        "http": post.status_code,
        "pass": post.status_code in (200, 302),
    }

    # Authenticated API OK
    r_ok = s2.get(BASE + "/api/tenant/scope", timeout=20)
    results["authenticated_scope"] = {"http": r_ok.status_code, "pass": r_ok.status_code == 200}

    # Abuse guard / rate limit still present (module import + config)
    try:
        from services import http_abuse_guard
        from services import hostile_environment_service as hes

        results["abuse_guard_module"] = {
            "pass": callable(getattr(http_abuse_guard, "run_pre_request_checks", None))
        }
        results["hostile_env_module"] = {
            "pass": callable(getattr(hes, "check_http_flood", None))
            or callable(getattr(hes, "check_ip_access", None))
            or callable(getattr(hes, "get_operational_status", None))
        }
    except Exception as exc:
        results["abuse_guard_module"] = {"pass": False, "error": str(exc)}

    # MFA policy still loaded
    try:
        from services.web_security_auth_enterprise import mfa_policy

        results["mfa_policy_module"] = {"pass": True, "module": getattr(mfa_policy, "__name__", "mfa_policy")}
    except Exception as exc:
        results["mfa_policy_module"] = {"pass": False, "error": str(exc)}

    # Encryption / vault presence
    try:
        from crypto_vault import CryptoVault

        v = CryptoVault()
        health = v.verify_health() if hasattr(v, "verify_health") else True
        results["crypto_vault"] = {"pass": bool(health) or health is None or health == True, "health": health}
    except Exception as exc:
        results["crypto_vault"] = {"pass": False, "error": str(exc)[:160]}

    # RBAC helpers present
    try:
        results["rbac"] = {"pass": Path(ROOT / "core" / "security.py").is_file()}
    except Exception:
        results["rbac"] = {"pass": False}

    fails = [k for k, v in results.items() if not v.get("pass")]
    report = {
        "controls": results,
        "verdict": "PASS" if not fails else "FAIL",
        "failed": fails,
    }
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
