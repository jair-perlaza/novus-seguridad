#!/usr/bin/env python3
"""
Cierre operacional final NOVUS:
- Medición RSS 0-5 min (instancia única)
- Login → scans reales → APIs → notificaciones → IA kernel
"""
from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_release_candidate" / "FINAL_OPERATIONAL_STATE.json"
BASE = "http://127.0.0.1:5000"
EMAIL = "operaciones@novapay-fintech.co"
PASSWORD = "NovaPay#Fintech2026"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_pid() -> Optional[int]:
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            return c.pid
    return None


def proc_stats(pid: int) -> Dict[str, Any]:
    p = psutil.Process(pid)
    return {
        "rss_mb": round(p.memory_info().rss / 1024 / 1024, 1),
        "threads": p.num_threads(),
        "cpu_pct": round(p.cpu_percent(interval=0.3), 1),
    }


def login_session() -> requests.Session:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=30)
    r.raise_for_status()
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    csrf = m.group(1) if m else ""
    r = s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": csrf},
        allow_redirects=True,
        timeout=60,
    )
    r.raise_for_status()
    return s


def get_json(s: requests.Session, path: str, timeout: int = 45) -> Dict[str, Any]:
    try:
        r = s.get(f"{BASE}{path}", timeout=timeout)
        try:
            body = r.json()
        except Exception:
            body = {}
        return {"http": r.status_code, "body": body, "ms": r.elapsed.total_seconds() * 1000}
    except requests.RequestException as exc:
        return {"http": 0, "body": {}, "error": str(exc), "ms": None}


def wait_scan(s: requests.Session, path: str, field: str, max_wait: int = 120) -> Dict[str, Any]:
    """Poll API hasta que last_scan / audit.timestamp aparezca."""
    deadline = time.time() + max_wait
    last = {}
    while time.time() < deadline:
        last = get_json(s, path)
        body = last.get("body") or {}
        if body.get("last_scan") or (body.get("audit") or {}).get("timestamp"):
            return last
        if body.get("analysis_state") in ("LIVE", "EMPTY", "ERROR"):
            if body.get("last_scan") or body.get("analysis_state") == "ERROR":
                return last
        time.sleep(3)
        # Re-trigger background scan
        s.get(f"{BASE}{path}", timeout=45)
    return last


def measure_rss_series(pid: int, minutes: int = 5, session: Optional[requests.Session] = None) -> List[Dict[str, Any]]:
    series = []
    for minute in range(minutes + 1):
        st = proc_stats(pid)
        ping = {}
        if session is not None:
            ping = get_json(session, "/api/dashboard/live", timeout=30)
        series.append({"minute": minute, "utc": utc(), "dashboard_ping": ping.get("http"), **st})
        if minute < minutes:
            time.sleep(60)
    return series


def check_notifications(body: Dict[str, Any]) -> Dict[str, Any]:
    items = body if isinstance(body, list) else (body.get("notifications") or body.get("items") or [])
    bad = []
    for it in items:
        title = str(it.get("title") or it.get("message") or "").lower()
        ntype = str(it.get("type") or it.get("category") or "").lower()
        for forbidden in ("login", "scan completed", "configuration changed", "configuración"):
            if forbidden in title and "security" in ntype:
                bad.append({"item": it, "reason": f"system event as security: {forbidden}"})
    return {"count": len(items), "bad_security_misc": bad}


def main() -> int:
    pid = find_pid()
    if not pid:
        print("NOVUS not listening on :5000", file=sys.stderr)
        return 2

    out: Dict[str, Any] = {
        "generated_at": utc(),
        "pid": pid,
        "port": 5000,
        "python_processes": len([p for p in psutil.process_iter(["cmdline"]) if "main.py" in " ".join(p.info.get("cmdline") or [])]),
    }

    out["rss_initial"] = proc_stats(pid)
    out["host_ram_pct_initial"] = round(psutil.virtual_memory().percent, 1)

    s = login_session()
    t0 = time.perf_counter()
    dash = s.get(f"{BASE}/dashboard", timeout=45)
    out["login_dashboard"] = {
        "dashboard_http": dash.status_code,
        "dashboard_ms": round((time.perf_counter() - t0) * 1000, 1),
    }

    # Trigger real scans via API (background workers on live server)
    scan_timeout = 120
    for ep in (
        "/api/security/vulnerabilities",
        "/api/security/threats",
    ):
        out.setdefault("preflight", {})[ep] = get_json(s, ep, timeout=scan_timeout)
    for ep in (
        "/api/monitoring/network-config",
        "/api/network/nodes?trigger_discovery=false",
    ):
        out.setdefault("preflight", {})[ep] = get_json(s, ep, timeout=60)

    out["vuln_after_wait"] = wait_scan(s, "/api/security/vulnerabilities", "last_scan", max_wait=180)
    out["threat_after_wait"] = wait_scan(s, "/api/security/threats", "last_scan", max_wait=180)

    # Escaneo real in-process vía API autenticada
    try:
        sync_r = s.post(
            f"{BASE}/api/reports/sync",
            timeout=300,
            headers={"X-CSRFToken": s.cookies.get("csrf_token", "")},
        )
        out["reports_sync"] = {"http": sync_r.status_code, "body": sync_r.json() if sync_r.headers.get("content-type", "").startswith("application/json") else sync_r.text[:500]}
    except Exception as exc:
        out["reports_sync"] = {"error": str(exc)}

    # Re-fetch after sync
    out["vuln_post_sync"] = get_json(s, "/api/security/vulnerabilities")
    out["threat_post_sync"] = get_json(s, "/api/security/threats")
    apis: Dict[str, Any] = {}
    for path in (
        "/api/dashboard/live",
        "/api/security/summary",
        "/api/tenant/scope",
        "/api/monitoring/network-config",
        "/api/network/nodes?trigger_discovery=false",
        "/api/security/vulnerabilities",
        "/api/security/threats",
        "/api/notifications?kind=security",
        "/api/notifications?kind=system",
        "/api/ai/status",
        "/api/system/platform-health",
        "/api/evidence",
        "/api/reports",
    ):
        apis[path] = get_json(s, path)
    out["apis"] = apis

    sec_notif = apis.get("/api/notifications?kind=security", {}).get("body") or {}
    out["notifications_check"] = check_notifications(sec_notif)

    ai = apis.get("/api/ai/status", {}).get("body") or {}
    out["ai_kernel"] = {
        "status": ai.get("status") or ai.get("kernel_status"),
        "last_execution_at": ai.get("last_execution_at") or ai.get("last_run_at"),
        "state": ai.get("state"),
    }

    vb = apis.get("/api/security/vulnerabilities", {}).get("body") or {}
    tb = apis.get("/api/security/threats", {}).get("body") or {}
    out["vulnerabilities"] = {
        "analysis_state": vb.get("analysis_state"),
        "analysis_message": vb.get("analysis_message"),
        "last_scan": vb.get("last_scan"),
        "total_count": vb.get("total_count"),
        "audit": vb.get("audit"),
    }
    out["threats"] = {
        "analysis_state": tb.get("analysis_state"),
        "analysis_message": tb.get("analysis_message"),
        "last_scan": tb.get("last_scan"),
        "total_count": tb.get("total_count"),
        "source_motor": tb.get("source") or tb.get("source_engine"),
    }

    mon = apis.get("/api/monitoring/network-config", {}).get("body") or {}
    out["monitoring"] = {"monitoring_enabled": mon.get("monitoring_enabled"), "status": mon.get("status")}

    print("Starting 5-minute RSS stability series...", flush=True)
    out["rss_series"] = measure_rss_series(pid, minutes=5, session=s)
    out["rss_final"] = proc_stats(pid)
    out["host_ram_pct_final"] = round(psutil.virtual_memory().percent, 1)

    # Stability verdict
    rss_vals = [p["rss_mb"] for p in out["rss_series"]]
    growth = rss_vals[-1] - rss_vals[0] if rss_vals else 0
    out["ram_stable"] = growth < 150  # allow modest growth, not 1GB+

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
