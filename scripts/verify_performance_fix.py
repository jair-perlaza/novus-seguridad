#!/usr/bin/env python3
"""Verificación live post-corrección rendimiento NOVUS."""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "performance_fix_verification"
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
TIMEOUT = 8


def login_session():
    import requests

    s = requests.Session()
    t0 = time.perf_counter()
    r = s.get(f"{BASE}/login", timeout=TIMEOUT)
    login_ms = round((time.perf_counter() - t0) * 1000, 1)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    csrf = csrf.group(1) if csrf else ""
    t1 = time.perf_counter()
    s.post(
        f"{BASE}/login",
        data={"email": QA[0], "password": QA[1], "csrf_token": csrf},
        allow_redirects=True,
        timeout=15,
    )
    return s, {"login_ms": round((time.perf_counter() - t1) * 1000, 1), "login_get_ms": login_ms}


def timed(s, path, method="GET", **kw):
    import requests

    t0 = time.perf_counter()
    url = BASE + path
    fn = s.post if method == "POST" else s.get
    try:
        r = fn(url, timeout=kw.pop("timeout", TIMEOUT), **kw)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        body = {}
        try:
            body = r.json()
        except Exception:
            pass
        return {"path": path, "ms": ms, "status": r.status_code, "body_keys": list(body.keys())[:12], "body": body}
    except Exception as exc:
        return {"path": path, "ms": round((time.perf_counter() - t0) * 1000, 1), "error": str(exc)[:120]}


def main():
    import subprocess

    listener = subprocess.run("netstat -ano | findstr :5000.*LISTENING", capture_output=True, text=True, shell=True)
    pid = None
    for line in (listener.stdout or "").splitlines():
        parts = line.split()
        if parts and parts[-1].isdigit():
            pid = int(parts[-1])

    session, login = login_session()
    endpoints = [
        "/dashboard",
        "/api/dashboard/live",
        "/api/security/summary",
        "/api/network/info",
        "/api/network/nodes",
        "/api/network/ndr",
    ]
    results = {"login": login, "server_pid": pid, "endpoints": [], "returns": []}
    for p in endpoints:
        results["endpoints"].append(timed(session, p))

    for mod in ["/security-operations-center", "/network", "/threat-intelligence-center"]:
        timed(session, mod)
        t0 = time.perf_counter()
        dash = timed(session, "/dashboard")
        live = timed(session, "/api/dashboard/live")
        sec = timed(session, "/api/security/summary")
        results["returns"].append(
            {
                "from": mod,
                "dashboard_html_ms": dash.get("ms"),
                "live_ms": live.get("ms"),
                "summary_ms": sec.get("ms"),
                "total_ms": round((time.perf_counter() - t0) * 1000, 1),
            }
        )

    kn = timed(session, "/api/ai/kernel/knowledge-status")
    ev = timed(
        session,
        "/api/ai/kernel/analyze-event",
        method="POST",
        json={"event": {"message": "ARP spoofing MITM phishing", "module": "network", "source": "test"}},
    )
    results["kernel"] = {"knowledge": kn, "analyze_event": ev}

    info = next((e for e in results["endpoints"] if e.get("path") == "/api/network/info"), {})
    nodes = next((e for e in results["endpoints"] if e.get("path") == "/api/network/nodes"), {})
    ib = (info.get("body") or {}) if isinstance(info.get("body"), dict) else {}
    nb = (nodes.get("body") or {}) if isinstance(nodes.get("body"), dict) else {}
    results["network_evidence"] = {
        "ssid": (nb.get("network_context") or {}).get("ssid") or ib.get("ssid"),
        "ip": ib.get("local_ip"),
        "gateway": ib.get("gateway"),
        "subnet": ib.get("network_range"),
        "adapter": ib.get("adapter"),
        "node_count": nb.get("count", len(nb.get("nodes") or [])),
        "nodes_status": nb.get("status"),
        "snapshot_meta": nb.get("snapshot_meta"),
    }

    OUT.joinpath("LIVE_VERIFICATION.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
