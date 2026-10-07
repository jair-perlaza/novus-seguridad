#!/usr/bin/env python3
"""Auditoría: ninguna respuesta visible al usuario debe ser página/JSON de error técnico."""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

FORBIDDEN_UI_STRINGS = [
    "No pudimos completar la operación",
    "HTTP 500",
    "HTTP 404",
    "Internal Server Error",
    "Traceback (most recent call last)",
]


def main() -> int:
    print("=== verify_no_visible_errors ===")
    fails = []

    from main import app

    client = app.test_client()

    r_login = client.get("/login")
    if r_login.status_code != 200:
        fails.append(f"login_status={r_login.status_code}")
    login_body = r_login.get_data(as_text=True)
    for bad in FORBIDDEN_UI_STRINGS:
        if bad.lower() in login_body.lower():
            fails.append(f"login_contains:{bad}")

    r_api = client.get("/api/system/platform-health")
    if r_api.status_code != 200:
        fails.append(f"api_unauth_status={r_api.status_code}")
    data = r_api.get_json(silent=True) or {}
    if data.get("status") not in ("recovering", "success", "ok"):
        if data.get("status") == "error":
            fails.append("api_still_error_status")
    if r_api.status_code != 200:
        fails.append("api_not_200")

    r_api2 = client.get("/api/ruta-api-inexistente-novus-verify")
    if r_api2.status_code != 200:
        fails.append(f"api_404_status={r_api2.status_code}")
    data2 = r_api2.get_json(silent=True) or {}
    if data2.get("status") != "recovering" and not data2.get("_novusRecovery"):
        fails.append("api_404_not_recovery")

    recovery_path = os.path.join(ROOT, "templates", "novus_recovery.html")
    with open(recovery_path, encoding="utf-8") as fh:
        rec_html = fh.read()
    if "recuperando el servicio" not in rec_html.lower():
        fails.append("recovery_template_missing_message")

    js_path = os.path.join(ROOT, "static", "js", "novus-recovery-client.js")
    if not os.path.isfile(js_path):
        fails.append("recovery_client_js")

    svc_path = os.path.join(ROOT, "services", "novus_recovery_service.py")
    if not os.path.isfile(svc_path):
        fails.append("recovery_service")

    if fails:
        print("FAIL", fails)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
