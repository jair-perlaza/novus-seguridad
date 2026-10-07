#!/usr/bin/env python3
"""
Auditoría forense de rendimiento NOVUS — SOLO LECTURA / MEDICIÓN.
No modifica producto, APIs, config, caches ni motores.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_performance_forensic_audit"
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def login_session():
    import requests

    s = requests.Session()
    t0 = time.perf_counter()
    r = s.get(f"{BASE}/login", timeout=60)
    login_get_ms = round((time.perf_counter() - t0) * 1000, 1)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    csrf = csrf.group(1) if csrf else ""
    t1 = time.perf_counter()
    r2 = s.post(
        f"{BASE}/login",
        data={"email": QA[0], "password": QA[1], "csrf_token": csrf},
        allow_redirects=True,
        timeout=120,
    )
    login_post_ms = round((time.perf_counter() - t1) * 1000, 1)
    return s, {"login_get_ms": login_get_ms, "login_post_ms": login_post_ms, "login_post_status": r2.status_code}


def timed_request(session, method: str, path: str, **kwargs) -> Dict[str, Any]:
    import requests

    url = f"{BASE}{path}" if path.startswith("/") else path
    t0 = time.perf_counter()
    started = _utc()
    try:
        fn = session.post if method.upper() == "POST" else session.get
        r = fn(url, timeout=kwargs.pop("timeout", 120), **kwargs)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        body_len = len(r.content or b"")
        cache_hdr = r.headers.get("X-Cache") or r.headers.get("X-Novus-Cache")
        entry = {
            "url": path,
            "method": method.upper(),
            "started_utc": started,
            "ended_utc": _utc(),
            "ms": ms,
            "status": r.status_code,
            "bytes": body_len,
            "cache_header": cache_hdr,
        }
        try:
            j = r.json()
            if isinstance(j, dict):
                entry["response_keys"] = list(j.keys())[:15]
                for k in ("source", "source_type", "cache_hit", "snapshot", "updating", "status"):
                    if k in j:
                        entry[k] = j[k]
        except Exception:
            pass
        return entry
    except Exception as exc:
        return {
            "url": path,
            "method": method.upper(),
            "started_utc": started,
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "error": str(exc),
        }


def simulate_dashboard_waterfall(session) -> Dict[str, Any]:
    """Replica orden lógico del JS actual en index.html (medición HTTP)."""
    steps: List[Dict[str, Any]] = []
    t_start = time.perf_counter()

    html = timed_request(session, "GET", "/dashboard")
    steps.append({"phase": "A_html", **html})

    # Parallel: priority (fire-and-forget in JS) + live + summary
    for p in ["/api/dashboard/priority", "/api/dashboard/live", "/api/security/summary"]:
        steps.append({"phase": "B_kpi_parallel", **timed_request(session, "GET", p)})

    # Phase 2 idle: nodes + info parallel
    for p in ["/api/network/nodes", "/api/network/info"]:
        steps.append({"phase": "C_network_idle", **timed_request(session, "GET", p)})

    # Phase 3 sector parallel
    for p in [
        "/api/system/sector-shield/status",
        "/api/system/sector-protection",
        "/api/manual-defense/summary",
    ]:
        steps.append({"phase": "D_sector_idle", **timed_request(session, "GET", p)})

    steps.append({"phase": "E_events", **timed_request(session, "GET", "/api/network/events?limit=15")})

    # Deferred kernel (may run on idle)
    for p in ["/api/ai/status", "/api/monitoring/stream"]:
        if "stream" in p:
            continue  # SSE not measured via single GET
        steps.append({"phase": "F_kernel_deferred", **timed_request(session, "GET", p)})

    api_steps = [s for s in steps if s.get("phase") != "A_html"]
    first_api_ms = api_steps[0]["ms"] if api_steps else None
    last_api_ms = api_steps[-1]["ms"] if api_steps else None
    total_ms = round((time.perf_counter() - t_start) * 1000, 1)

    return {
        "html_ms": html.get("ms"),
        "first_api_ms": first_api_ms,
        "last_api_ms": last_api_ms,
        "complete_simulated_ms": total_ms,
        "steps": steps,
        "network_refresh_in_initial_flow": False,
        "note": "/api/network/refresh solo en botón manual index.html:545",
    }


def measure_module_return(session, module: str, mod_path: str) -> Dict[str, Any]:
    timed_request(session, "GET", mod_path, timeout=120)
    t0 = time.perf_counter()
    dash_html = timed_request(session, "GET", "/dashboard", timeout=120)
    html_ms = dash_html.get("ms")
    wf = simulate_dashboard_waterfall(session)
    return {
        "module": module,
        "module_path": mod_path,
        "return_dashboard_html_ms": html_ms,
        "return_full_waterfall_ms": wf.get("complete_simulated_ms"),
        "waterfall": wf,
    }


def cache_hit_miss_test(session, path: str) -> Dict[str, Any]:
    r1 = timed_request(session, "GET", path, timeout=180)
    r2 = timed_request(session, "GET", path, timeout=180)
    speedup = None
    if r1.get("ms") and r2.get("ms") and r1["ms"] > 0:
        speedup = round(r1["ms"] / max(r2["ms"], 0.1), 2)
    verdict = "CACHE_MISS_LIKE" if r1.get("ms", 0) > 500 and r2.get("ms", 999) < r1.get("ms", 0) * 0.5 else (
        "CACHE_HIT_LIKE" if r2.get("ms", 999) < 100 else "INCONCLUSIVE"
    )
    return {"path": path, "request_1": r1, "request_2": r2, "speedup_ratio": speedup, "verdict": verdict}


def network_diagnostic(session) -> Dict[str, Any]:
    diag: Dict[str, Any] = {"observed_at_utc": _utc(), "fields": {}}

    def field(name, req_entry, body_key=None):
        diag["fields"][name] = {
            "source": req_entry.get("url"),
            "status": req_entry.get("status"),
            "latency_ms": req_entry.get("ms"),
            "error": req_entry.get("error"),
        }

    info = timed_request(session, "GET", "/api/network/info", timeout=60)
    nodes = timed_request(session, "GET", "/api/network/nodes", timeout=60)
    mon = timed_request(session, "GET", "/api/network/monitor/status", timeout=60)

    import requests

    for label, entry in [("network_info_api", info), ("network_nodes_api", nodes), ("monitor_status_api", mon)]:
        field(label, entry)

    try:
        r = session.get(f"{BASE}/api/network/info", timeout=60)
        b = r.json()
        for k in ("local_ip", "gateway", "network_range", "adapter", "node_count", "last_scan", "scan_status"):
            v = b.get(k)
            st = "VERIFIED" if v and v not in ("Sin datos disponibles", "Unknown", None) else "NOT_AVAILABLE"
            diag["fields"][k] = {"value": v, "status": st, "source": "/api/network/info", "latency_ms": info.get("ms")}
    except Exception as exc:
        diag["parse_error"] = str(exc)

    try:
        r2 = session.get(f"{BASE}/api/network/nodes", timeout=60)
        nb = r2.json()
        diag["fields"]["nodes"] = {
            "count": len(nb.get("nodes") or []),
            "api_status": nb.get("status"),
            "updating": nb.get("updating"),
            "message": nb.get("message"),
            "source": "network_scanner.get_cached_nodes",
            "latency_ms": nodes.get("ms"),
        }
    except Exception as exc:
        diag["nodes_parse_error"] = str(exc)

    try:
        from utils.network_identity import get_wifi_association
        from utils.host_data import get_local_ip, get_primary_network_interface
        from utils.network_helpers import get_default_gateway, get_network_range

        wifi = get_wifi_association()
        primary = get_primary_network_interface() or {}
        gw = get_default_gateway()
        diag["system_probe"] = {
            "ssid": {"value": wifi.get("ssid"), "status": "VERIFIED" if wifi.get("ssid") else "NOT_DETECTED", "source": "get_wifi_association"},
            "bssid": {"value": wifi.get("bssid"), "status": "VERIFIED" if wifi.get("bssid") else "NOT_AVAILABLE", "source": "get_wifi_association"},
            "local_ip": {"value": primary.get("local_ip") or get_local_ip(), "source": "get_primary_network_interface"},
            "gateway": {"value": gw, "source": "get_default_gateway"},
            "subnet": {"value": get_network_range(gw), "source": "get_network_range"},
            "adapter": {"value": primary.get("adapter"), "source": "get_primary_network_interface"},
        }
    except Exception as exc:
        diag["system_probe_error"] = str(exc)

    try:
        from services.network_scanner import network_scanner
        from services.network_monitor_engine import get_monitor_status

        diag["in_process_cache"] = {
            "note": "lectura mismo proceso script — puede diferir del servidor live",
            "cache_info": network_scanner.get_cache_info(),
            "cached_nodes": len(network_scanner.get_cached_nodes() or []),
            "monitor": get_monitor_status(),
        }
    except Exception as exc:
        diag["in_process_cache_error"] = str(exc)

    return diag


def psutil_snapshot(pid: Optional[int] = None) -> Dict[str, Any]:
    import psutil

    snap = {"timestamp_utc": _utc(), "system": {}, "processes": []}
    snap["system"]["cpu_percent"] = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    snap["system"]["ram_percent"] = mem.percent
    snap["system"]["ram_used_mb"] = round(mem.used / (1024 * 1024), 1)

    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
        try:
            if proc.info["name"] and "python" in proc.info["name"].lower():
                mi = proc.info.get("memory_info")
                mb = round(mi.rss / (1024 * 1024), 1) if mi else 0
                if mb >= 50:
                    snap["processes"].append(
                        {"pid": proc.info["pid"], "name": proc.info["name"], "mb": mb, "cpu": proc.cpu_percent()}
                    )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    snap["processes"].sort(key=lambda x: x.get("mb", 0), reverse=True)
    if pid:
        try:
            p = psutil.Process(pid)
            snap["server_pid"] = {
                "pid": pid,
                "cpu_percent": p.cpu_percent(interval=0.3),
                "ram_mb": round(p.memory_info().rss / (1024 * 1024), 1),
                "threads": p.num_threads(),
            }
        except Exception as exc:
            snap["server_pid_error"] = str(exc)
    return snap


def storage_inventory() -> Dict[str, Any]:
    paths = [
        ROOT / "data" / "defense_registry" / "events.jsonl",
        ROOT / "data" / "forensic_ledger" / "records.jsonl",
        ROOT / "data" / "threat_intelligence_enterprise" / "dashboard_snapshot.json",
        ROOT / "data" / "sope" / "dashboard_snapshot.json",
        ROOT / "data" / "imcm" / "dashboard_snapshot.json",
        ROOT / "data" / "imcm" / "timeline_snapshot.json",
    ]
    items = []
    for p in paths:
        if p.is_file():
            st = p.stat()
            t0 = time.perf_counter()
            try:
                with open(p, "rb") as fh:
                    _ = fh.read(65536)
                read_ms = round((time.perf_counter() - t0) * 1000, 3)
            except Exception as exc:
                read_ms = None
                err = str(exc)
            else:
                err = None
            items.append(
                {
                    "path": str(p.relative_to(ROOT)),
                    "bytes": st.st_size,
                    "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                    "read_first_64k_ms": read_ms,
                    "error": err,
                }
            )
        else:
            items.append({"path": str(p.relative_to(ROOT)), "exists": False})
    return {"files": items}


def grep_polling_inventory() -> List[Dict[str, Any]]:
    items = []
    patterns = [
        (r"setInterval\s*\(", "setInterval"),
        (r"EventSource\s*\(", "EventSource"),
        (r"new WebSocket\s*\(", "WebSocket"),
    ]
    for tpl in ROOT.glob("templates/**/*.html"):
        text = tpl.read_text(encoding="utf-8", errors="replace")
        for pat, kind in patterns:
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(pat, line):
                    ep = re.search(r"['\"](/api/[^'\"]+)['\"]", line)
                    items.append(
                        {
                            "file": str(tpl.relative_to(ROOT)),
                            "line": i,
                            "kind": kind,
                            "snippet": line.strip()[:120],
                            "endpoint": ep.group(1) if ep else None,
                        }
                    )
    for js in (ROOT / "static" / "js").glob("*.js"):
        text = js.read_text(encoding="utf-8", errors="replace")
        for pat, kind in patterns:
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(pat, line):
                    ep = re.search(r"['\"](/api/[^'\"]+)['\"]", line)
                    items.append(
                        {
                            "file": str(js.relative_to(ROOT)),
                            "line": i,
                            "kind": kind,
                            "snippet": line.strip()[:120],
                            "endpoint": ep.group(1) if ep else None,
                        }
                    )
    return items


def verify_optimizations() -> Dict[str, Any]:
    checks = []

    def add(name, status, evidence):
        checks.append({"optimization": name, "status": status, "evidence": evidence})

    tie_api = (ROOT / "api" / "tie.py").read_text(encoding="utf-8")
    add("TIE snapshot read", "IMPLEMENTED" if "enterprise_snapshot_service" in tie_api and "read_dashboard_api" in tie_api else "NOT", "api/tie.py")

    sope_api = (ROOT / "api" / "sope.py").read_text(encoding="utf-8")
    add("SOPE snapshot read", "IMPLEMENTED" if "read_dashboard_api" in sope_api else "NOT", "api/sope.py")

    imcm_api = (ROOT / "api" / "imcm.py").read_text(encoding="utf-8")
    add("IMCM snapshot read", "IMPLEMENTED" if "read_dashboard_api" in imcm_api else "NOT", "api/imcm.py")

    idx = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
    add(
        "Dashboard lazy KPI/secondary split",
        "IMPLEMENTED" if "fetchDashboardKPIs" in idx and "fetchDashboardSecondary" in idx else "NOT",
        "templates/index.html",
    )
    add(
        "network/refresh removed from initial dashboard load",
        "IMPLEMENTED" if "network/refresh" not in idx.split("fetchRealtimeData")[0] else "PARTIAL",
        "only button onclick line 545" if "network/refresh" in idx else "absent",
    )
    add(
        "NovusFetch dedup",
        "IMPLEMENTED" if (ROOT / "static" / "js" / "novus-progressive-fetch.js").is_file() else "NOT",
        "static/js/novus-progressive-fetch.js",
    )
    add(
        "kpisOnly poll mode",
        "IMPLEMENTED" if "kpisOnly" in idx else "NOT",
        "templates/index.html setInterval",
    )
    add(
        "NME no wipe ARP after scan",
        "IMPLEMENTED" if "_invalidate_derived_caches" in (ROOT / "services" / "network_monitor_engine.py").read_text(encoding="utf-8") else "NOT",
        "services/network_monitor_engine.py",
    )
    add(
        "Enterprise warmup boot",
        "IMPLEMENTED" if "schedule_all_enterprise_warmup" in (ROOT / "main.py").read_text(encoding="utf-8") else "NOT",
        "main.py",
    )

    snap_exists = all(
        (ROOT / "services" / "enterprise_snapshot_service.py").is_file(),
    )
    add("enterprise_snapshot_service module", "IMPLEMENTED" if snap_exists else "NOT", "services/enterprise_snapshot_service.py")

    return {"checks": checks, "verified_at_utc": _utc()}


def compare_before_after(current_nav: Dict, current_endpoints: List) -> Dict[str, Any]:
    prev_dir = ROOT / "data" / "integration_performance_audit"
    rows = []
    prev_nav = {}
    prev_perf = {}
    if (prev_dir / "NAVIGATION_LATENCY.json").is_file():
        prev_nav = json.loads((prev_dir / "NAVIGATION_LATENCY.json").read_text(encoding="utf-8"))
    if (prev_dir / "PERFORMANCE_ENDPOINT_MATRIX.json").is_file():
        prev_perf = json.loads((prev_dir / "PERFORMANCE_ENDPOINT_MATRIX.json").read_text(encoding="utf-8"))

    prev_trans = {t.get("module"): t for t in prev_nav.get("transitions", [])}
    for mod, cur in current_nav.items():
        prev = prev_trans.get(mod, {})
        rows.append(
            {
                "module": mod,
                "before_html_ms": prev.get("html_ms"),
                "current_html_ms": cur.get("html_ms"),
                "change_ms": round(cur.get("html_ms", 0) - prev.get("html_ms", 0), 1) if prev.get("html_ms") else None,
            }
        )

    prev_eps = {e.get("path"): e for e in prev_perf.get("endpoints", []) if isinstance(prev_perf.get("endpoints"), list)}
    for ep in current_endpoints:
        p = ep.get("path")
        prev_e = prev_eps.get(p, {})
        rows.append(
            {
                "endpoint": p,
                "before_ms": prev_e.get("ms_avg") or prev_e.get("ms"),
                "current_ms": ep.get("ms"),
                "before_status": prev_e.get("status"),
                "current_status": ep.get("status"),
            }
        )
    return {"comparison_rows": rows, "previous_audit": str(prev_dir)}


def find_server_pid() -> Optional[int]:
    import subprocess

    out = subprocess.run("netstat -ano | findstr :5000.*LISTENING", capture_output=True, text=True, shell=True)
    for line in (out.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[-1].isdigit():
            return int(parts[-1])
    return None


def main():
    print("=== NOVUS Performance Forensic Audit (read-only) ===")
    pid = find_server_pid()

    session, login_metrics = login_session()
    ps_before = psutil_snapshot(pid)

    modules = [
        ("login", "/login"),
        ("dashboard", "/dashboard"),
        ("soc", "/security-operations-center"),
        ("network", "/network"),
        ("endpoint", "/endpoints"),
        ("asm", "/asset-intelligence"),
        ("viem", "/vulnerability-intelligence"),
        ("imcm", "/incident-management"),
        ("tie", "/threat-intelligence-center"),
        ("sope", "/playbook-center"),
        ("ueba", "/inteligencia"),
        ("iapa", "/identity-attack-path"),
        ("dpe", "/deception-center"),
        ("health", "/health-center"),
    ]

    nav_latency = {"generated_at_utc": _utc(), "login": login_metrics, "modules": {}, "returns_to_dashboard": []}
    endpoint_latency = []

    for name, path in modules:
        if name == "login":
            continue
        entry = timed_request(session, "GET", path, timeout=120)
        nav_latency["modules"][name] = entry
        endpoint_latency.append(entry)

    dashboard_wf = simulate_dashboard_waterfall(session)
    nav_latency["dashboard_waterfall"] = dashboard_wf

    return_pairs = [
        ("soc", "/security-operations-center"),
        ("network", "/network"),
        ("tie", "/threat-intelligence-center"),
        ("imcm", "/incident-management"),
        ("sope", "/playbook-center"),
    ]
    for mod, path in return_pairs:
        nav_latency["returns_to_dashboard"].append(measure_module_return(session, mod, path))

    ps_during = psutil_snapshot(pid)

    enterprise_apis = [
        "/api/tie/dashboard",
        "/api/sope/dashboard",
        "/api/imcm/dashboard",
        "/api/imcm/timeline?limit=50",
    ]
    cache_tests = [cache_hit_miss_test(session, p) for p in enterprise_apis]
    for p in enterprise_apis:
        endpoint_latency.append(timed_request(session, "GET", p, timeout=180))

    soc_wf = {
        "html": timed_request(session, "GET", "/security-operations-center"),
        "apis": [
            timed_request(session, "GET", p)
            for p in ["/api/soc/overview", "/api/soc/health", "/api/soc/swarm"]
        ],
    }
    network_page = {
        "html": timed_request(session, "GET", "/network"),
        "apis": [
            timed_request(session, "GET", p)
            for p in ["/api/network/ndr", "/api/network/events?limit=40", "/api/network/monitor/status"]
        ],
    }
    endpoint_page = {
        "html": timed_request(session, "GET", "/endpoints"),
        "apis": [timed_request(session, "GET", "/api/endpoints/status")],
    }

    network_diag = network_diagnostic(session)
    polling = grep_polling_inventory()
    storage = storage_inventory()
    opt_verify = verify_optimizations()
    comparison = compare_before_after(
        {k: v for k, v in nav_latency["modules"].items()},
        endpoint_latency,
    )

    ps_after = psutil_snapshot(pid)

    # Blocking chain from static analysis
    blocking = [
        {"file": "templates/index.html", "function": "fetchDashboardKPIs", "request": "Promise.all /api/dashboard/live + /api/security/summary", "operation": "await blocks KPI paint", "type": "Promise.all"},
        {"file": "templates/index.html", "function": "fetchRealtimeData", "request": "await fetchDashboardKPIs before idle secondary", "operation": "sequential gate", "type": "await"},
        {"file": "templates/index.html", "function": "loadSectorPanelsDeferred", "request": "Promise.all sector APIs", "operation": "deferred but still 3 parallel", "type": "Promise.all"},
        {"file": "templates/soc_center.html", "function": "loadOverview+SSE", "request": "EventSource /api/soc/stream", "operation": "persistent connection", "type": "SSE"},
        {"file": "templates/network.html", "function": "cargarNDR", "request": "/api/network/ndr", "operation": "may trigger scan_arp_light if cache empty", "type": "conditional scan"},
        {"file": "static/js/novus-dashboard-estado-general.js", "function": "startSSE", "request": "/api/monitoring/stream", "operation": "SSE on dashboard mount", "type": "SSE"},
        {"file": "templates/partials/ai_kernel_panel.html", "function": "refreshContext", "request": "/api/ai/context?refresh=1", "operation": "deferred idle but heavy", "type": "deferred fetch"},
    ]

    all_requests = sorted(
        [s for s in dashboard_wf.get("steps", []) if s.get("ms")],
        key=lambda x: x.get("ms", 0),
        reverse=True,
    )

    payload = {
        "generated_at_utc": _utc(),
        "server_pid": pid,
        "login_ms": login_metrics,
        "nav_latency": nav_latency,
        "slowest_10": all_requests[:10],
        "blocking_chain": blocking,
    }

    OUT.joinpath("CURRENT_NAVIGATION_LATENCY.json").write_text(json.dumps(nav_latency, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT.joinpath("CURRENT_FRONTEND_WATERFALL.json").write_text(
        json.dumps({"dashboard": dashboard_wf, "soc": soc_wf, "network": network_page, "endpoint": endpoint_page}, indent=2),
        encoding="utf-8",
    )
    OUT.joinpath("CURRENT_ENDPOINT_LATENCY.json").write_text(json.dumps({"endpoints": endpoint_latency, "enterprise_cache_tests": cache_tests}, indent=2), encoding="utf-8")
    OUT.joinpath("CURRENT_CACHE_EFFECTIVENESS.json").write_text(json.dumps({"enterprise": cache_tests}, indent=2), encoding="utf-8")
    OUT.joinpath("CURRENT_NETWORK_DIAGNOSTIC.json").write_text(json.dumps(network_diag, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT.joinpath("CURRENT_BACKGROUND_WORKERS.json").write_text(
        json.dumps({"psutil": {"before": ps_before, "during": ps_during, "after": ps_after}, "note": "workers from main.py boot — see logs"}, indent=2),
        encoding="utf-8",
    )
    OUT.joinpath("CURRENT_POLLING_INVENTORY.json").write_text(json.dumps({"items": polling}, indent=2), encoding="utf-8")
    OUT.joinpath("OPTIMIZATION_VERIFICATION.json").write_text(json.dumps(opt_verify, indent=2), encoding="utf-8")
    OUT.joinpath("BEFORE_AFTER_COMPARISON.json").write_text(json.dumps(comparison, indent=2), encoding="utf-8")
    OUT.joinpath("STORAGE_READ_ANALYSIS.json").write_text(json.dumps(storage, indent=2), encoding="utf-8")
    OUT.joinpath("PERFORMANCE_FORENSIC_SUMMARY.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # Markdown report
    md = _build_report(payload, network_diag, cache_tests, opt_verify, comparison, polling, ps_after)
    OUT.joinpath("PERFORMANCE_FORENSIC_REPORT.md").write_text(md, encoding="utf-8")

    print(json.dumps({"out": str(OUT), "login": login_metrics, "dashboard_html_ms": nav_latency["modules"].get("dashboard", {}).get("ms")}, indent=2))


def _build_report(payload, network_diag, cache_tests, opt_verify, comparison, polling, ps_after) -> str:
    nav = payload["nav_latency"]
    dash_wf = nav.get("dashboard_waterfall", {})
    lines = [
        "# NOVUS — Auditoría Forensica de Rendimiento",
        f"\nGenerado: {payload['generated_at_utc']}",
        f"\nServidor PID: {payload.get('server_pid')}",
        "\n## Login",
        f"- GET /login: {payload['login_ms'].get('login_get_ms')} ms",
        f"- POST login: {payload['login_ms'].get('login_post_ms')} ms",
        "\n## Dashboard (simulación waterfall HTTP)",
        f"- HTML: {dash_wf.get('html_ms')} ms",
        f"- Primera API: {dash_wf.get('first_api_ms')} ms",
        f"- Última API: {dash_wf.get('last_api_ms')} ms",
        f"- Carga completa simulada: {dash_wf.get('complete_simulated_ms')} ms",
        f"- /api/network/refresh en flujo inicial: {dash_wf.get('network_refresh_in_initial_flow')}",
        "\n## Regreso a Dashboard",
    ]
    for r in nav.get("returns_to_dashboard", []):
        lines.append(f"- {r['module']}: HTML {r.get('return_dashboard_html_ms')} ms | waterfall {r.get('return_full_waterfall_ms')} ms")
    lines.append("\n## Enterprise cache hit/miss")
    for c in cache_tests:
        lines.append(f"- {c['path']}: req1={c['request_1'].get('ms')}ms req2={c['request_2'].get('ms')}ms → {c['verdict']}")
    lines.append("\n## Optimizaciones verificadas en código")
    for c in opt_verify.get("checks", []):
        lines.append(f"- {c['optimization']}: **{c['status']}** — {c['evidence']}")
    lines.append("\n## CPU/RAM")
    sys_ps = ps_after.get("system", {})
    lines.append(f"- CPU sistema: {sys_ps.get('cpu_percent')}%")
    lines.append(f"- RAM sistema: {sys_ps.get('ram_percent')}%")
    if ps_after.get("server_pid"):
        lines.append(f"- Servidor: {ps_after['server_pid']}")
    lines.append("\n## VEREDICTO")
    lines.append("Ver PERFORMANCE_FORENSIC_SUMMARY.json y respuesta estructurada del agente.")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
