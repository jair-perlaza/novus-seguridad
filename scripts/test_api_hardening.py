"""
Pruebas de endurecimiento API NOVUS — auth, rate limit, validación, regresión funcional.
"""
from __future__ import annotations

import json
import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import requests

BASE = os.environ.get("NOVUS_TEST_BASE", "http://127.0.0.1:5000")
EMAIL = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
PASSWORD = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")

PASS = 0
FAIL = 0
RESULTS = []


def record(name: str, ok: bool, detail: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
        status = "PASS"
    else:
        FAIL += 1
        status = "FAIL"
    RESULTS.append({"test": name, "status": status, "detail": detail})
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))


def login_session():
    """Sesión autenticada vía test_client (mismo código de seguridad, sin bloqueo de red en login)."""
    from main import app
    client = app.test_client()
    with client.session_transaction() as sess:
        sess.clear()
    r = client.post(
        "/login",
        data={"email": EMAIL, "password": PASSWORD},
        follow_redirects=True,
    )
    if r.status_code not in (200, 302):
        raise RuntimeError(f"Login HTTP {r.status_code}")
    return client


def client_request(client, method: str, path: str, **kwargs):
    if method.upper() == "GET":
        return client.get(path, **kwargs)
    if method.upper() == "POST":
        return client.post(path, **kwargs)
    return client.open(path, method=method, **kwargs)


def test_unauthenticated_blocked():
    paths = [
        "/api/dashboard/live",
        "/api/system/processes",
        "/api/network/info",
        "/api/reports/",
        "/api/ai/status",
        "/api/system/automation/processes/kill",
    ]
    for path in paths:
        r = requests.get(f"{BASE}{path}", timeout=15) if path != "/api/system/automation/processes/kill" else requests.post(
            f"{BASE}{path}", json={"pid": 1}, timeout=15
        )
        record(
            f"auth_401 {path}",
            r.status_code == 401 and "autentic" in (r.text or "").lower(),
            f"status={r.status_code}",
        )


def test_sqli_query_blocked():
    r = requests.get(
        f"{BASE}/api/search/",
        params={"q": "1' OR '1'='1"},
        timeout=15,
    )
    record(
        "sqli_query_unauth",
        r.status_code in (400, 401),
        f"status={r.status_code}",
    )


def test_json_malformed(client):
    r = client.post(
        "/api/system/vulnerabilities/remediate",
        data="not-json{{{",
        headers={"Content-Type": "application/json"},
    )
    record("json_malformed", r.status_code == 400, f"status={r.status_code}")


def test_missing_required_field(client):
    r = client.post(
        "/api/system/vulnerabilities/remediate",
        json={},
    )
    record("required_field_vuln_id", r.status_code == 400, f"status={r.status_code}")


def test_invalid_ip_investigate(client):
    r = client.post("/api/network/ndr/device/not-an-ip/investigate")
    record("invalid_ip_investigate", r.status_code == 400, f"status={r.status_code}")


def test_kill_invalid_pid(client):
    r = client.post(
        "/api/system/automation/processes/kill",
        json={"pid": "abc"},
    )
    record("kill_invalid_pid", r.status_code == 400, f"status={r.status_code}")


def test_functional_reads(client):
    endpoints = [
        ("GET", "/api/dashboard/live"),
        ("GET", "/api/system/processes"),
        ("GET", "/api/network/info"),
        ("GET", "/api/ai/status"),
        ("GET", "/api/security/summary"),
        ("GET", "/api/audit/data-sources"),
        ("GET", "/api/system/defense-registry"),
    ]
    for method, path in endpoints:
        r = client_request(client, method, path)
        ok = r.status_code == 200
        try:
            body = r.get_json()
            ok = ok and (
                body.get("status") in ("success", "ok", None)
                or "reports" in body
                or "connection" in str(body)
            )
        except Exception:
            ok = ok and r.status_code == 200
        record(f"functional {method} {path}", ok, f"status={r.status_code}")


def test_reports_list(client):
    r = client.get("/api/reports/")
    record("functional GET /api/reports/", r.status_code == 200, f"status={r.status_code}")


def test_playbooks_list(client):
    r = client.get("/api/playbooks")
    record("functional GET /api/playbooks", r.status_code == 200, f"status={r.status_code}")


def test_launch_tool_whitelist(client):
    r = client.post(
        "/api/system/launch-tool",
        json={"tool": "evil_tool"},
    )
    record("launch_tool_reject", r.status_code == 400, f"status={r.status_code}")


def test_defense_registry_has_events(client):
    r = client.get("/api/system/defense-registry")
    ok = r.status_code == 200
    if ok:
        try:
            data = r.get_json()
            ok = "events" in data or "registry" in data or data.get("status") == "success"
        except Exception:
            ok = False
    record("defense_registry", ok, f"status={r.status_code}")


def wait_for_server(max_wait: int = 60):
    for _ in range(max_wait):
        try:
            r = requests.get(f"{BASE}/login", timeout=3)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def main():
    if not wait_for_server():
        print("ERROR: servidor no disponible en", BASE)
        return 1

    # Esperar estabilización post-arranque (scanners en background)
    time.sleep(8)

    test_unauthenticated_blocked()
    test_sqli_query_blocked()

    try:
        client = login_session()
    except Exception as exc:
        record("login", False, str(exc))
        _write_report()
        return 1

    record("login", True)
    test_json_malformed(client)
    test_missing_required_field(client)
    test_invalid_ip_investigate(client)
    test_kill_invalid_pid(client)
    test_functional_reads(client)
    test_reports_list(client)
    test_playbooks_list(client)
    test_launch_tool_whitelist(client)
    test_defense_registry_has_events(client)

    _write_report()
    print(f"\n=== {PASS} PASS / {FAIL} FAIL ===")
    return 0 if FAIL == 0 else 1


def _write_report():
    out = os.path.join(ROOT, "data", "api_hardening_test_results.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"pass": PASS, "fail": FAIL, "results": RESULTS}, f, indent=2)
    print(f"Results: {out}")


if __name__ == "__main__":
    raise SystemExit(main())
