#!/usr/bin/env python3
"""Ejecución única de cierre operativo NOVUS — HTTP + servicios."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_release_candidate" / "NOVUS_OPERATIONAL_CLOSURE_RUN.json"
BASE = "http://127.0.0.1:5000"

FAKE_MARKERS = (
    "simulated", "fixture", "demo threat", "fake_", "lorem ipsum",
    "mock data", "placeholder value", "synthetic alert",
)


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _login(session, timeout=180):
    from scripts.reports_regression_probe import login

    try:
        r = login(session)
        return r.status_code in (200, 302)
    except Exception:
        return False


def _walk_fake(obj, path=""):
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            hits.extend(_walk_fake(v, f"{path}.{k}" if path else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.extend(_walk_fake(v, f"{path}[{i}]"))
    elif isinstance(obj, str):
        low = obj.lower()
        for m in FAKE_MARKERS:
            if m in low:
                hits.append(f"{path}:{m}")
    return hits


def _http_modules(session):
    import requests

    modules = [
        ("/api/tenant/scope", "tenant_scope"),
        ("/api/dashboard/live", "dashboard"),
        ("/api/network/nodes?trigger_discovery=false", "network"),
        ("/api/monitoring/network-config", "network_config"),
        ("/api/security/summary", "security_summary"),
        ("/api/security/threats", "threats"),
        ("/api/security/vulnerabilities", "vulnerabilities"),
        ("/api/security/endpoints", "endpoints"),
        ("/api/reports", "reports"),
        ("/api/system/evidence-center", "evidence"),
        ("/api/system/login-sessions", "sessions"),
        ("/api/notifications?kind=security", "notifications_security"),
        ("/api/notifications?kind=system", "notifications_system"),
        ("/api/ai/status", "ai_kernel"),
        ("/api/health/status", "health"),
    ]
    rows = []
    for path, name in modules:
        row = {"name": name, "path": path}
        try:
            resp = session.get(f"{BASE}{path}", timeout=90)
            row["http"] = resp.status_code
            body = resp.json() if "json" in (resp.headers.get("content-type") or "") else {}
            row["fake_hits"] = _walk_fake(body)
            row["pass"] = resp.status_code == 200 and not row["fake_hits"]
            if name == "network_config":
                row["monitoring_enabled"] = body.get("monitoring_enabled")
                row["provenance"] = body.get("provenance")
            if name == "notifications_security":
                kinds = {n.get("notification_kind") for n in (body.get("notifications") or [])}
                row["kinds_seen"] = sorted(kinds)
                row["pass"] = row["pass"] and kinds <= {"security", None}
            if name == "ai_kernel":
                row["operational_status"] = body.get("operational_status")
        except Exception as exc:
            row["pass"] = False
            row["error"] = str(exc)[:200]
        rows.append(row)
    return rows


def _network_actions(session):
    import requests

    r = session.get(f"{BASE}/api/monitoring/network-config", timeout=60)
    if r.status_code != 200:
        return {"pass": False, "error": "network-config unreachable"}
    csrf = None
    r2 = session.get(f"{BASE}/configuracion", timeout=60)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r2.text or "")
    if m:
        csrf = m.group(1)
    if not csrf:
        return {"pass": False, "error": "csrf_missing"}
    headers = {"X-CSRF-Token": csrf, "Content-Type": "application/json"}
    actions = {}
    for action in ("stop_discovery", "resume_discovery", "discover_now"):
        try:
            resp = session.post(
                f"{BASE}/api/monitoring/network-config/action",
                json={"action": action},
                headers=headers,
                timeout=90,
            )
            actions[action] = {"http": resp.status_code, "ok": resp.json().get("status") == "success"}
        except Exception as exc:
            actions[action] = {"http": 0, "error": str(exc)[:120]}
    ok = all(v.get("http") == 200 for v in actions.values())
    return {"pass": ok, "actions": actions}


def _run_subprocess(script: str) -> dict:
    p = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    out = (p.stdout or "") + (p.stderr or "")
    verdict = "VERIFIED" if "VERIFIED" in out or p.returncode == 0 else "FAIL"
    if "13/13" in out or "overall" in out:
        try:
            for line in out.splitlines():
                if line.strip().startswith("{"):
                    j = json.loads(line)
                    if j.get("overall"):
                        verdict = j["overall"]
        except Exception:
            pass
    return {"script": script, "exit_code": p.returncode, "verdict": verdict, "tail": out[-800:]}


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    report = {"generated_at": _utc(), "base": BASE, "tests": [], "pass": True}

    # py_compile sample
    files = [
        "services/ai_kernel.py",
        "services/network_monitoring_service.py",
        "services/notification_center_service.py",
    ]
    for f in files:
        p = subprocess.run([sys.executable, "-m", "py_compile", str(ROOT / f)], capture_output=True)
        report["tests"].append({"name": f"py_compile:{f}", "pass": p.returncode == 0})

    for script in ("tenant_isolation_service_test.py",):
        row = _run_subprocess(script)
        row["name"] = script
        row["pass"] = row["verdict"] == "VERIFIED" or row["exit_code"] == 0
        report["tests"].append(row)

    import requests

    session = requests.Session()
    login_ok = _login(session, timeout=90)
    report["login"] = login_ok
    if not login_ok:
        report["pass"] = False
        report["error"] = "login_failed"
        OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps({"pass": False, "error": "login_failed"}))
        return 1

    modules = _http_modules(session)
    report["http_modules"] = modules
    for m in modules:
        report["tests"].append({"name": f"http:{m['name']}", "pass": m.get("pass", False)})

    net_actions = _network_actions(session)
    report["network_actions"] = net_actions
    report["tests"].append({"name": "network_actions", "pass": net_actions.get("pass", False)})

    report["pass"] = all(t.get("pass") for t in report["tests"])
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"pass": report["pass"], "login": login_ok, "modules": len(modules), "out": str(OUT)}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
