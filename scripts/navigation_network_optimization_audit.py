#!/usr/bin/env python3
"""Diagnóstico navegación + Network Discovery — NOVUS."""
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
OUT = ROOT / "data" / "navigation_network_optimization"
OUT.mkdir(parents=True, exist_ok=True)

BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def login_session():
    import requests

    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=60)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    csrf = csrf.group(1) if csrf else ""
    s.post(
        f"{BASE}/login",
        data={"email": QA[0], "password": QA[1], "csrf_token": csrf},
        allow_redirects=True,
        timeout=120,
    )
    return s


def measure_html(session, path: str) -> dict:
    import requests

    t0 = time.perf_counter()
    r = session.get(f"{BASE}{path}", timeout=120)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    return {"path": path, "status": r.status_code, "html_ms": ms, "bytes": len(r.content or b"")}


def measure_api(session, path: str) -> dict:
    import requests

    t0 = time.perf_counter()
    try:
        r = session.get(f"{BASE}{path}", timeout=120)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        body = {}
        try:
            body = r.json()
        except Exception:
            body = {"raw_len": len(r.content or b"")}
        return {
            "path": path,
            "status": r.status_code,
            "ms": ms,
            "keys": list(body.keys())[:20] if isinstance(body, dict) else [],
            "body_snip": body if isinstance(body, dict) else {},
        }
    except Exception as exc:
        return {"path": path, "error": str(exc), "ms": round((time.perf_counter() - t0) * 1000, 1)}


def navigation_matrix(session, label: str) -> list:
    modules = [
        ("SOC", "/security-operations-center"),
        ("ASM", "/asset-intelligence"),
        ("VIEM", "/vulnerability-intelligence"),
        ("IMCM", "/incident-management"),
        ("TIE", "/threat-intelligence-center"),
        ("Network", "/network"),
    ]
    rows = []
    for name, mod_path in modules:
        measure_html(session, mod_path)
        t0 = time.perf_counter()
        dash = measure_html(session, "/dashboard")
        apis = [
            measure_api(session, p)
            for p in [
                "/api/dashboard/live",
                "/api/security/summary",
                "/api/network/nodes",
                "/api/network/info",
                "/api/dashboard/priority",
            ]
        ]
        rows.append(
            {
                "phase": label,
                "from_module": name,
                "module_path": mod_path,
                "to_dashboard_html_ms": dash["html_ms"],
                "dashboard_html_status": dash["status"],
                "apis_on_navigation": apis,
                "total_nav_ms": round((time.perf_counter() - t0) * 1000, 1),
            }
        )
    return rows


def real_network_env() -> dict:
    proof = {"observed_at_utc": _utc(), "sources": {}}

    def run(cmd):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30, shell=True)
            return {"cmd": cmd, "stdout": (p.stdout or "")[:4000], "stderr": (p.stderr or "")[:500], "code": p.returncode}
        except Exception as exc:
            return {"cmd": cmd, "error": str(exc)}

    proof["sources"]["ipconfig"] = run("ipconfig /all")
    proof["sources"]["netsh_wifi"] = run("netsh wlan show interfaces")
    proof["sources"]["route_print"] = run("route print -4")
    proof["sources"]["arp_a"] = run("arp -a")

    try:
        from utils.network_identity import get_wifi_association
        proof["novus_wifi"] = get_wifi_association()
    except Exception as exc:
        proof["novus_wifi"] = {"error": str(exc)}

    try:
        from utils.host_data import get_local_ip, get_primary_network_interface
        from utils.network_helpers import get_default_gateway, get_network_range

        primary = get_primary_network_interface() or {}
        gw = get_default_gateway()
        proof["novus_iface"] = {
            "primary": primary,
            "local_ip": get_local_ip(),
            "gateway": gw,
            "subnet": get_network_range(gw),
        }
    except Exception as exc:
        proof["novus_iface"] = {"error": str(exc)}

    return proof


def network_pipeline_status() -> dict:
    status = {"observed_at_utc": _utc()}
    try:
        from services.network_monitor_engine import get_monitor_status

        status["monitor"] = get_monitor_status()
    except Exception as exc:
        status["monitor"] = {"error": str(exc)}

    try:
        from services.network_scanner import network_scanner

        status["scanner_cache"] = network_scanner.get_cache_info()
        status["scanner_nodes_count"] = len(network_scanner.get_cached_nodes() or [])
        status["scanner_meta"] = network_scanner.get_network_meta()
        status["scanning"] = bool(getattr(network_scanner, "_scanning", False))
    except Exception as exc:
        status["scanner"] = {"error": str(exc)}

    try:
        from services.network_scan_coordinator import get_coordinator_status, get_bound_context, context_fingerprint

        ctx = get_bound_context()
        status["coordinator"] = get_coordinator_status()
        status["bound_context"] = ctx
        status["context_fingerprint"] = context_fingerprint(ctx) if ctx else None
    except Exception as exc:
        status["coordinator"] = {"error": str(exc)}

    try:
        from services.network_scan_coordinator import get_network_context

        status["live_context"] = get_network_context()
    except Exception as exc:
        status["live_context"] = {"error": str(exc)}

    return status


def cache_analysis() -> dict:
    analysis = {"observed_at_utc": _utc(), "caches": []}
    try:
        from services.network_scanner import network_scanner

        info = network_scanner.get_cache_info()
        analysis["caches"].append(
            {
                "name": "network_scanner._cache",
                "info": info,
                "node_count": len(network_scanner.get_cached_nodes() or []),
                "producer": "network_scanner.scan_arp_light / scan_network",
                "consumer": "GET /api/network/nodes",
            }
        )
    except Exception as exc:
        analysis["scanner_error"] = str(exc)

    try:
        from services.performance_cache import get_cache_stats

        analysis["performance_cache"] = get_cache_stats()
    except Exception as exc:
        analysis["performance_cache"] = {"error": str(exc)}

    baseline = ROOT / "data" / "network_baseline" / "lan_baseline.json"
    analysis["files"] = {
        "lan_baseline": {
            "exists": baseline.is_file(),
            "mtime": datetime.fromtimestamp(baseline.stat().st_mtime).isoformat() if baseline.is_file() else None,
            "size": baseline.stat().st_size if baseline.is_file() else 0,
        }
    }
    return analysis


def network_api_proof(session) -> dict:
    paths = [
        "/api/network/info",
        "/api/network/nodes",
        "/api/network/monitor/status",
        "/api/network/events?limit=10",
        "/api/network/ndr",
        "/api/network/topology",
    ]
    return {"observed_at_utc": _utc(), "endpoints": [measure_api(session, p) for p in paths]}


def frontend_analysis() -> dict:
    files = {
        "index.html": ROOT / "templates" / "index.html",
        "layout_novus.html": ROOT / "templates" / "layout_novus.html",
        "network.html": ROOT / "templates" / "network.html",
        "dashboard-investigation.js": ROOT / "static" / "js" / "dashboard-investigation.js",
    }
    patterns = [
        "fetch(",
        "Promise.all",
        "setInterval",
        "setTimeout",
        "EventSource",
        "network/refresh",
        "network/nodes",
    ]
    out = {}
    for name, path in files.items():
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        out[name] = {p: len(re.findall(re.escape(p), text)) for p in patterns}
        out[name]["lines"] = text.count("\n") + 1
    out["dashboard_mount_urls"] = [
        "/api/dashboard/priority",
        "/api/dashboard/live",
        "/api/security/summary",
        "/api/network/nodes",
        "/api/system/sector-shield/status",
        "/api/system/sector-protection",
        "/api/manual-defense/summary",
        "/api/network/events?limit=15",
        "/api/monitoring/stream",
        "/api/ai/status",
        "/api/ai/context?refresh=1",
    ]
    return out


def main():
    phase = (sys.argv[1] if len(sys.argv) > 1 else "BEFORE").upper()
    print(f"=== Navigation + Network diagnostic ({phase}) ===")

    session = login_session()
    nav = navigation_matrix(session, phase)
    nav_file = OUT / f"NAVIGATION_{phase}.json"
    nav_file.write_text(json.dumps({"observed_at_utc": _utc(), "rows": nav}, indent=2), encoding="utf-8")

    env = real_network_env()
    (OUT / "NETWORK_DISCOVERY_PROOF.json").write_text(json.dumps(env, indent=2, ensure_ascii=False), encoding="utf-8")

    pipe = network_pipeline_status()
    (OUT / "NETWORK_SNAPSHOT_STATUS.json").write_text(json.dumps(pipe, indent=2, ensure_ascii=False), encoding="utf-8")

    cache = cache_analysis()
    (OUT / "CACHE_ANALYSIS.json").write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")

    apis = network_api_proof(session)
    (OUT / "NETWORK_API_PROOF.json").write_text(json.dumps(apis, indent=2, ensure_ascii=False), encoding="utf-8")

    fe = frontend_analysis()
    (OUT / "FRONTEND_REQUEST_ANALYSIS.json").write_text(json.dumps(fe, indent=2), encoding="utf-8")

    summary = {
        "phase": phase,
        "navigation_file": str(nav_file),
        "avg_dashboard_html_ms": round(
            sum(r["to_dashboard_html_ms"] for r in nav) / max(len(nav), 1), 1
        ),
        "scanner_nodes": pipe.get("scanner_nodes_count"),
        "monitor_active": (pipe.get("monitor") or {}).get("active"),
        "network_api_nodes_status": next(
            (e.get("status") for e in apis["endpoints"] if e.get("path") == "/api/network/nodes"),
            None,
        ),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
