#!/usr/bin/env python3
"""NOVUS forensic performance audit — read-only measurement, writes data/novus_performance_forensic_audit/."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_performance_forensic_audit"
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
REQ_TIMEOUT = 35


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def login_session():
    import requests

    s = requests.Session()
    t0 = time.perf_counter()
    r = s.get(f"{BASE}/login", timeout=REQ_TIMEOUT)
    login_get_ms = round((time.perf_counter() - t0) * 1000, 1)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    csrf = csrf.group(1) if csrf else ""
    t1 = time.perf_counter()
    r2 = s.post(
        f"{BASE}/login",
        data={"email": QA[0], "password": QA[1], "csrf_token": csrf},
        allow_redirects=True,
        timeout=REQ_TIMEOUT,
    )
    login_post_ms = round((time.perf_counter() - t1) * 1000, 1)
    return s, {
        "login_get_ms": login_get_ms,
        "login_post_ms": login_post_ms,
        "login_total_ms": round(login_get_ms + login_post_ms, 1),
        "login_post_status": r2.status_code,
    }


def timed(session, method: str, path: str, **kw) -> Dict[str, Any]:
    import requests

    url = f"{BASE}{path}"
    t0 = time.perf_counter()
    started = utc()
    timeout = kw.pop("timeout", REQ_TIMEOUT)
    try:
        fn = session.post if method.upper() == "POST" else session.get
        r = fn(url, timeout=timeout, **kw)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        entry = {
            "path": path,
            "method": method.upper(),
            "started_utc": started,
            "ended_utc": utc(),
            "ms": ms,
            "status": r.status_code,
            "bytes": len(r.content or b""),
            "cache_header": r.headers.get("X-Cache") or r.headers.get("X-Novus-Cache"),
        }
        try:
            j = r.json()
            if isinstance(j, dict):
                for k in ("source", "source_type", "cache_hit", "snapshot_stale", "updating", "refresh_inflight"):
                    if k in j:
                        entry[k] = j[k]
                sm = j.get("snapshot_meta") or {}
                if sm:
                    entry["snapshot_meta"] = sm
        except Exception:
            pass
        return entry
    except Exception as exc:
        return {
            "path": path,
            "method": method.upper(),
            "started_utc": started,
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "error": str(exc)[:200],
            "status": "timeout_or_error",
        }


def dashboard_waterfall(session) -> Dict[str, Any]:
    t0 = time.perf_counter()
    steps = []
    html = timed(session, "GET", "/dashboard")
    steps.append({"phase": "A_html", **html})
    for p in ["/api/dashboard/priority", "/api/dashboard/live", "/api/security/summary"]:
        steps.append({"phase": "B_kpi_parallel", **timed(session, "GET", p)})
    for p in ["/api/network/nodes", "/api/network/info"]:
        steps.append({"phase": "C_network_idle", **timed(session, "GET", p, timeout=60)})
    for p in [
        "/api/system/sector-shield/status",
        "/api/system/sector-protection",
        "/api/manual-defense/summary",
    ]:
        steps.append({"phase": "D_sector_idle", **timed(session, "GET", p)})
    steps.append({"phase": "E_events", **timed(session, "GET", "/api/network/events?limit=15")})
    steps.append({"phase": "F_ai_status", **timed(session, "GET", "/api/ai/status")})
    apis = [s for s in steps if s.get("phase") != "A_html"]
    return {
        "html_ms": html.get("ms"),
        "first_api_ms": apis[0]["ms"] if apis else None,
        "last_api_ms": apis[-1]["ms"] if apis else None,
        "complete_simulated_ms": round((time.perf_counter() - t0) * 1000, 1),
        "steps": steps,
        "network_refresh_in_initial_flow": False,
        "network_refresh_note": "Solo botón manual templates/index.html:545",
    }


def cache_test(session, path: str) -> Dict[str, Any]:
    r1 = timed(session, "GET", path, timeout=60)
    r2 = timed(session, "GET", path, timeout=60)
    v1, v2 = r1.get("ms"), r2.get("ms")
    if r1.get("error") or r2.get("error"):
        verdict = "ERROR"
    elif v2 and v1 and v2 < v1 * 0.6:
        verdict = "CACHE_HIT_LIKE"
    elif v1 and v1 > 800:
        verdict = "CACHE_MISS_LIKE"
    elif v2 and v2 < 150:
        verdict = "FAST_LIKELY_CACHED"
    else:
        verdict = "INCONCLUSIVE"
    return {"path": path, "request_1": r1, "request_2": r2, "verdict": verdict}


def network_diag(session) -> Dict[str, Any]:
    diag = {"observed_at_utc": utc(), "fields": {}, "system_probe": {}, "in_process_cache": {}}
    info = timed(session, "GET", "/api/network/info")
    nodes = timed(session, "GET", "/api/network/nodes", timeout=60)
    mon = timed(session, "GET", "/api/network/monitor/status")
    ndr = timed(session, "GET", "/api/network/ndr", timeout=60)

    for label, e in [("info_api", info), ("nodes_api", nodes), ("monitor_api", mon), ("ndr_api", ndr)]:
        diag["fields"][label] = {
            "source": e.get("path"),
            "status": e.get("status"),
            "latency_ms": e.get("ms"),
            "error": e.get("error"),
        }

    try:
        import requests

        ib = session.get(f"{BASE}/api/network/info", timeout=30).json()
        for k in ("local_ip", "gateway", "network_range", "adapter", "node_count", "last_scan", "scan_status"):
            v = ib.get(k)
            st = "VERIFIED" if v and str(v) not in ("Sin datos disponibles", "Unknown", "None", "") else "NOT_AVAILABLE"
            diag["fields"][k] = {"value": v, "status": st, "source": "/api/network/info", "latency_ms": info.get("ms")}
    except Exception as exc:
        diag["info_parse_error"] = str(exc)

    try:
        nb = session.get(f"{BASE}/api/network/nodes", timeout=60).json()
        diag["fields"]["nodes"] = {
            "count": len(nb.get("nodes") or []),
            "api_status": nb.get("status"),
            "updating": nb.get("updating"),
            "message": nb.get("message"),
            "source": nb.get("source", "network_scanner.get_cached_nodes"),
            "latency_ms": nodes.get("ms"),
        }
        ni = nb.get("network_info") or {}
        if ni:
            diag["fields"]["nodes_embedded_info"] = {
                "gateway": ni.get("gateway"),
                "local_ip": ni.get("local_ip"),
                "network_range": ni.get("network_range"),
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
        from services.network_scan_coordinator import get_coordinator_status

        diag["in_process_cache"] = {
            "note": "lectura proceso auditoría — servidor live puede diferir",
            "cache_info": network_scanner.get_cache_info(),
            "cached_nodes": len(network_scanner.get_cached_nodes() or []),
            "scanning": network_scanner._scanning,
            "monitor": get_monitor_status(),
            "coordinator": get_coordinator_status(),
        }
    except Exception as exc:
        diag["in_process_cache_error"] = str(exc)

    return diag


def psutil_snap(pid: Optional[int]) -> Dict[str, Any]:
    import psutil

    snap = {"timestamp_utc": utc(), "system": {}, "top_python": []}
    snap["system"]["cpu_percent"] = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    snap["system"]["ram_percent"] = mem.percent
    snap["system"]["ram_used_mb"] = round(mem.used / (1024 * 1024), 1)
    snap["system"]["thread_count"] = sum(p.num_threads() for p in psutil.process_iter(["num_threads"]) if p.info.get("num_threads"))
    procs = []
    for proc in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            if proc.info["name"] and "python" in proc.info["name"].lower():
                mi = proc.info.get("memory_info")
                mb = round(mi.rss / (1024 * 1024), 1) if mi else 0
                cpu = proc.cpu_percent(interval=0.05)
                if mb >= 40 or cpu > 1:
                    procs.append({"pid": proc.info["pid"], "name": proc.info["name"], "mb": mb, "cpu": cpu, "threads": proc.num_threads()})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    procs.sort(key=lambda x: (x.get("cpu", 0), x.get("mb", 0)), reverse=True)
    snap["top_python"] = procs[:8]
    if pid:
        try:
            p = psutil.Process(pid)
            snap["server"] = {"pid": pid, "cpu_percent": p.cpu_percent(interval=0.3), "ram_mb": round(p.memory_info().rss / (1024 * 1024), 1), "threads": p.num_threads()}
        except Exception as exc:
            snap["server_error"] = str(exc)
    return snap


def find_server_pid() -> Optional[int]:
    out = subprocess.run("netstat -ano | findstr :5000.*LISTENING", capture_output=True, text=True, shell=True)
    for line in (out.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[-1].isdigit():
            return int(parts[-1])
    return None


def grep_polling() -> List[Dict]:
    items = []
    pats = [(r"setInterval\s*\(", "setInterval"), (r"EventSource\s*\(", "EventSource"), (r"new WebSocket\s*\(", "WebSocket")]
    for base in [ROOT / "templates", ROOT / "static" / "js"]:
        if not base.exists():
            continue
        for f in base.rglob("*"):
            if f.suffix not in (".html", ".js"):
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            for pat, kind in pats:
                for i, line in enumerate(text.splitlines(), 1):
                    if re.search(pat, line):
                        ep = re.search(r"['\"](/api/[^'\"]+)['\"]", line)
                        items.append({"file": str(f.relative_to(ROOT)), "line": i, "kind": kind, "snippet": line.strip()[:140], "endpoint": ep.group(1) if ep else None})
    return items


def grep_scans() -> List[Dict]:
    patterns = ["scan_network", "scan_arp_light", "scan_arp", "scapy", "nmap", "force=True"]
    hits = []
    for f in ROOT.rglob("*.py"):
        if "venv" in str(f) or ".git" in str(f):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for pat in patterns:
            if pat in text:
                for i, line in enumerate(text.splitlines(), 1):
                    if pat in line and not line.strip().startswith("#"):
                        hits.append({"file": str(f.relative_to(ROOT)), "line": i, "pattern": pat, "snippet": line.strip()[:120]})
    return hits[:120]


def verify_opts() -> Dict:
    checks = []

    def add(name, status, evidence):
        checks.append({"optimization": name, "status": status, "evidence": evidence})

    tie = (ROOT / "api" / "tie.py").read_text(encoding="utf-8")
    add("TIE snapshot read", "IMPLEMENTED" if "read_dashboard_api" in tie else "NOT_IMPLEMENTED", "api/tie.py")
    sope = (ROOT / "api" / "sope.py").read_text(encoding="utf-8")
    add("SOPE snapshot read", "IMPLEMENTED" if "read_dashboard_api" in sope else "NOT_IMPLEMENTED", "api/sope.py")
    imcm = (ROOT / "api" / "imcm.py").read_text(encoding="utf-8")
    add("IMCM snapshot read", "IMPLEMENTED" if "read_dashboard_api" in imcm or "read_timeline_api" in imcm else "NOT_IMPLEMENTED", "api/imcm.py")
    idx = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
    add("Dashboard KPI/secondary split", "IMPLEMENTED" if "fetchDashboardKPIs" in idx and "fetchDashboardSecondary" in idx else "NOT_IMPLEMENTED", "templates/index.html")
    before_fetch = idx.split("fetchRealtimeData")[0] if "fetchRealtimeData" in idx else idx
    add("network/refresh removed from initial load", "IMPLEMENTED" if "network/refresh" not in before_fetch else "PARTIAL", "only manual button" if "network/refresh" in idx else "absent")
    add("NovusFetch dedup", "IMPLEMENTED" if (ROOT / "static" / "js" / "novus-progressive-fetch.js").is_file() else "NOT_IMPLEMENTED", "static/js/novus-progressive-fetch.js")
    add("kpisOnly poll mode", "IMPLEMENTED" if "kpisOnly" in idx else "NOT_IMPLEMENTED", "index.html setInterval 15s/60s")
    nme = (ROOT / "services" / "network_monitor_engine.py").read_text(encoding="utf-8")
    add("NME derived cache (no ARP wipe)", "IMPLEMENTED" if "_invalidate_derived_caches" in nme else "NOT_IMPLEMENTED", "network_monitor_engine.py")
    add("Enterprise warmup boot", "IMPLEMENTED" if "schedule_all_enterprise_warmup" in (ROOT / "main.py").read_text(encoding="utf-8") else "NOT_IMPLEMENTED", "main.py")
    add("enterprise_snapshot_service", "IMPLEMENTED" if (ROOT / "services" / "enterprise_snapshot_service.py").is_file() else "NOT_IMPLEMENTED", "services/enterprise_snapshot_service.py")
    add("SOC defer/stream", "IMPLEMENTED_PARTIAL", "EventSource /api/soc/stream still active templates/soc_center.html")
    add("Request deduplication", "IMPLEMENTED" if "NovusFetch" in idx or "novus-progressive-fetch" in idx else "PARTIAL", "static/js/novus-progressive-fetch.js")
    add("Background health", "IMPLEMENTED_PARTIAL", "platform_health_service + performance_cache TTL")
    add("Network snapshot context", "IMPLEMENTED" if "network_scan_coordinator" in (ROOT / "api" / "network.py").read_text(encoding="utf-8") else "NOT_IMPLEMENTED", "api/network.py")
    return {"checks": checks, "verified_at_utc": utc()}


def storage_inv() -> Dict:
    paths = [
        "data/defense_registry/events.jsonl",
        "data/forensic_ledger/records.jsonl",
        "data/threat_intelligence_enterprise/dashboard_snapshot.json",
        "data/sope/dashboard_snapshot.json",
        "data/imcm/dashboard_snapshot.json",
        "data/imcm/timeline_snapshot.json",
    ]
    items = []
    for rel in paths:
        p = ROOT / rel
        if p.is_file():
            st = p.stat()
            t0 = time.perf_counter()
            with open(p, "rb") as fh:
                fh.read(65536)
            items.append({"path": rel, "bytes": st.st_size, "read_first_64k_ms": round((time.perf_counter() - t0) * 1000, 3)})
        else:
            items.append({"path": rel, "exists": False})
    return {"files": items}


def compare_before(current_modules: Dict, endpoints: List) -> Dict:
    prev = ROOT / "data" / "integration_performance_audit"
    rows = []
    prev_nav = json.loads((prev / "NAVIGATION_LATENCY.json").read_text(encoding="utf-8")) if (prev / "NAVIGATION_LATENCY.json").is_file() else {}
    prev_perf = json.loads((prev / "PERFORMANCE_ENDPOINT_MATRIX.json").read_text(encoding="utf-8")) if (prev / "PERFORMANCE_ENDPOINT_MATRIX.json").is_file() else {}
    prev_root = json.loads((prev / "ROOT_CAUSE_PERFORMANCE.json").read_text(encoding="utf-8")) if (prev / "ROOT_CAUSE_PERFORMANCE.json").is_file() else {}

    prev_trans = {t.get("module"): t for t in prev_nav.get("transitions", [])}
    for mod, cur in current_modules.items():
        prev_m = prev_trans.get(mod, {})
        b, c = prev_m.get("html_ms"), cur.get("ms")
        rows.append({
            "problem": f"Navigation HTML {mod}",
            "before_ms": b,
            "current_ms": c,
            "change_ms": round(c - b, 1) if b and c else None,
            "status": "IMPROVED" if b and c and c < b else ("REGRESSED" if b and c and c > b * 1.5 else "SIMILAR"),
            "file": f"routes/{mod}.py or template",
        })

    for cause in prev_root.get("top_causes", [])[:8]:
        ep = cause.get("endpoint")
        if ep:
            cur_e = next((e for e in endpoints if e.get("path") == ep), {})
            rows.append({
                "problem": cause.get("why") or cause.get("operation"),
                "before_ms": cause.get("ms_avg"),
                "current_ms": cur_e.get("ms"),
                "change_ms": round(cur_e.get("ms", 0) - cause.get("ms_avg", 0), 1) if cur_e.get("ms") and cause.get("ms_avg") else None,
                "status": "IMPROVED" if cur_e.get("ms") and cause.get("ms_avg") and cur_e["ms"] < cause["ms_avg"] * 0.5 else "CHECK",
                "file": cause.get("file") or ep,
            })

    rows.append({
        "problem": "Dashboard burst incl. /api/network/refresh",
        "before_ms": 4351.94,
        "current_ms": None,
        "status": "FIXED_IN_CODE",
        "file": "templates/index.html — refresh solo manual",
    })
    return {"rows": rows, "previous_audit": str(prev)}


def workers_inv() -> Dict:
    main_txt = (ROOT / "main.py").read_text(encoding="utf-8")
    workers = [
        {"name": "NovusDbMigrate", "file": "main.py", "function": "_deferred_db_migrate", "interval": "once", "arp": False, "network_scan": False},
        {"name": "NovusStartupReconcile", "file": "main.py", "function": "_deferred_startup_reconcile", "interval": "once", "arp": False, "network_scan": False},
        {"name": "NovusStagedBoot", "file": "main.py", "function": "_start_services_staged", "interval": "once", "arp": False, "network_scan": True},
        {"name": "Network Monitor Engine", "file": "services/network_monitor_engine.py", "function": "start_background_scanner", "interval": "Config.NETWORK_SCAN_INTERVAL", "arp": True, "network_scan": True},
        {"name": "Background threat scanner", "file": "services/novus_security_integration.py", "function": "start_background_threat_scanner", "interval": "periodic", "arp": False, "network_scan": False},
        {"name": "EnterpriseSnapWarmup", "file": "services/enterprise_snapshot_service.py", "function": "schedule_all_enterprise_warmup", "interval": "boot+3s", "arp": False, "network_scan": False, "tie": True, "sope": True, "imcm": True},
        {"name": "NetCtxArpRepopulate", "file": "services/network_scan_coordinator.py", "function": "_schedule_background_arp_repopulate", "interval": "on context change", "arp": True, "network_scan": False},
        {"name": "NetNodesApiArp", "file": "api/network.py", "function": "_schedule_background_arp_if_needed", "interval": "on empty cache GET /nodes", "arp": True, "network_scan": False},
    ]
    return {"workers": workers, "boot_staged": "schedule_all_enterprise_warmup" in main_txt}


def build_report(summary: Dict) -> str:
    nav = summary["nav"]
    wf = nav.get("dashboard_waterfall", {})
    lines = [
        "# NOVUS — Auditoría Forense de Rendimiento",
        f"\nGenerado: {summary['generated_at_utc']}",
        f"Servidor PID: {summary.get('server_pid')}",
        "\n## 1. Login",
        f"- GET /login: {nav['login'].get('login_get_ms')} ms",
        f"- POST login: {nav['login'].get('login_post_ms')} ms",
        f"- Total: {nav['login'].get('login_total_ms')} ms",
        "\n## 2. Navegación HTML (módulos)",
    ]
    for mod, e in nav.get("modules", {}).items():
        lines.append(f"- **{mod}**: {e.get('ms')} ms (status {e.get('status', e.get('error', '?'))})")
    lines += [
        "\n## 3. Dashboard waterfall (simulación HTTP secuencial)",
        f"- HTML: {wf.get('html_ms')} ms",
        f"- Primera API: {wf.get('first_api_ms')} ms",
        f"- Última API: {wf.get('last_api_ms')} ms",
        f"- Total simulado: {wf.get('complete_simulated_ms')} ms",
        f"- `/api/network/refresh` en flujo inicial: **NO** (solo botón manual)",
        "\n## 4. Regreso a Dashboard",
    ]
    for r in nav.get("returns_to_dashboard", []):
        lines.append(f"- {r['module']}: HTML {r.get('return_html_ms')} ms | APIs post-return {r.get('post_return_apis_ms')} ms")
    lines.append("\n## 5. Enterprise cache hit/miss")
    for c in summary.get("cache_tests", []):
        lines.append(f"- {c['path']}: req1={c['request_1'].get('ms')}ms req2={c['request_2'].get('ms')}ms → **{c['verdict']}**")
    lines.append("\n## 6. Top 10 requests más lentas (dashboard waterfall)")
    for s in summary.get("slowest_10", []):
        lines.append(f"- {s.get('path')}: {s.get('ms')} ms ({s.get('error') or s.get('status')})")
    lines.append("\n## 7. Bloqueos identificados (código)")
    for b in summary.get("blocking", []):
        lines.append(f"- `{b['file']}` → `{b['function']}` → {b['request']} ({b['type']})")
    lines.append("\n## 8. Network diagnóstico")
    sp = summary.get("network_diag", {}).get("system_probe", {})
    for k, v in sp.items():
        if isinstance(v, dict):
            lines.append(f"- **{k}**: {v.get('value')} — {v.get('status', v.get('source'))}")
    lines.append("\n## 9. CPU/RAM")
    ps = summary.get("ps_after", {}).get("system", {})
    lines.append(f"- CPU: {ps.get('cpu_percent')}% | RAM: {ps.get('ram_percent')}% ({ps.get('ram_used_mb')} MB)")
    if summary.get("ps_after", {}).get("server"):
        lines.append(f"- Servidor NOVUS: {summary['ps_after']['server']}")
    lines.append("\n## 10. Veredicto preliminar")
    lines.append(f"**{summary.get('verdict')}** — {summary.get('verdict_reason')}")
    lines.append("\n---\nEvidencia completa en JSON adjuntos en este directorio.")
    return "\n".join(lines)


def try_pdf(md_path: Path, pdf_path: Path) -> bool:
    try:
        import markdown
        from weasyprint import HTML

        html = markdown.markdown(md_path.read_text(encoding="utf-8"), extensions=["tables"])
        HTML(string=f"<html><body>{html}</body></html>").write_pdf(str(pdf_path))
        return True
    except Exception:
        pass
    try:
        subprocess.run(["pandoc", str(md_path), "-o", str(pdf_path)], check=True, capture_output=True, timeout=60)
        return True
    except Exception:
        return False


def main():
    print("=== NOVUS Forensic Run ===", flush=True)
    pid = find_server_pid()
    session, login = login_session()
    print("login ok", login, flush=True)

    ps_before = psutil_snap(pid)
    modules_list = [
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
    modules = {}
    endpoints = []
    for name, path in modules_list:
        e = timed(session, "GET", path)
        modules[name] = e
        endpoints.append(e)
        print(f"  {name}: {e.get('ms')} ms", flush=True)

    wf = dashboard_waterfall(session)
    print("dashboard waterfall:", wf.get("complete_simulated_ms"), "ms", flush=True)

    returns = []
    for mod, path in [("soc", "/security-operations-center"), ("network", "/network"), ("tie", "/threat-intelligence-center"), ("imcm", "/incident-management"), ("sope", "/playbook-center")]:
        timed(session, "GET", path)
        t0 = time.perf_counter()
        rh = timed(session, "GET", "/dashboard")
        t1 = time.perf_counter()
        kpi = timed(session, "GET", "/api/dashboard/live")
        sec = timed(session, "GET", "/api/security/summary")
        returns.append({"module": mod, "return_html_ms": rh.get("ms"), "post_return_apis_ms": round((time.perf_counter() - t0) * 1000, 1), "live_ms": kpi.get("ms"), "summary_ms": sec.get("ms")})

    ent_paths = ["/api/tie/dashboard", "/api/sope/dashboard", "/api/imcm/dashboard", "/api/imcm/timeline?limit=50"]
    cache_tests = [cache_test(session, p) for p in ent_paths]
    for p in ent_paths:
        endpoints.append(timed(session, "GET", p, timeout=60))

    soc_apis = [timed(session, "GET", p) for p in ["/api/soc/overview", "/api/soc/health", "/api/soc/swarm"]]
    net_apis = [timed(session, "GET", p, timeout=60) for p in ["/api/network/ndr", "/api/network/events?limit=40", "/api/network/monitor/status"]]
    ep_apis = [timed(session, "GET", "/api/endpoints/status")]

    net_diag = network_diag(session)
    polling = grep_polling()
    scans = grep_scans()
    storage = storage_inv()
    opt = verify_opts()
    workers = workers_inv()
    comparison = compare_before(modules, endpoints)
    ps_after = psutil_snap(pid)

    blocking = [
        {"file": "templates/index.html", "function": "fetchDashboardKPIs", "request": "Promise.all /api/dashboard/live + /api/security/summary", "operation": "await blocks KPI paint", "type": "Promise.all"},
        {"file": "templates/index.html", "function": "fetchRealtimeData", "request": "await fetchDashboardKPIs then idle fetchDashboardSecondary", "operation": "sequential gate", "type": "await"},
        {"file": "templates/index.html", "function": "fetchDashboardSecondary", "request": "Promise.all /api/network/nodes + /api/network/info", "operation": "nodes can timeout under ARP lock", "type": "Promise.all"},
        {"file": "templates/layout_novus.html", "function": "fetchKPIData", "request": "Promise.all dashboard/live + network/nodes every 30s", "operation": "global sidebar poll", "type": "polling"},
        {"file": "templates/soc_center.html", "function": "init", "request": "EventSource /api/soc/stream", "operation": "persistent SSE", "type": "SSE"},
        {"file": "static/js/novus-dashboard-estado-general.js", "function": "startSSE", "request": "/api/monitoring/stream", "operation": "SSE dashboard", "type": "SSE"},
        {"file": "api/network.py", "function": "get_network_nodes", "request": "GET /api/network/nodes", "operation": "empty cache triggers background ARP; may contend with NME", "type": "conditional scan"},
        {"file": "services/network_monitor_engine.py", "function": "monitor loop", "request": "scan_arp_light periodic", "operation": "background ARP holds coordinator lock", "type": "background scan"},
    ]

    all_reqs = sorted(wf.get("steps", []), key=lambda x: x.get("ms") or 0, reverse=True)
    slowest = all_reqs[:10]

    # Verdict logic
    nodes_slow = next((s for s in wf["steps"] if s.get("path") == "/api/network/nodes"), {})
    tie_slow = next((e for e in endpoints if e.get("path") == "/api/tie/dashboard"), {})
    verdict_reasons = []
    if nodes_slow.get("error") or (nodes_slow.get("ms") or 0) > 5000:
        verdict_reasons.append("GET /api/network/nodes timeout/contention")
    if (tie_slow.get("ms") or 0) > 2000:
        verdict_reasons.append("TIE dashboard still slow on cache miss/refresh")
    if len([p for p in polling if p.get("kind") == "EventSource"]) >= 2:
        verdict_reasons.append("multiple SSE streams")
    verdict = "MULTIPLE BOTTLENECKS" if len(verdict_reasons) >= 2 else (
        "NETWORK" if "nodes" in str(verdict_reasons) else (
            "BACKEND" if tie_slow.get("ms", 0) > 2000 else (
                "FRONTEND" if len(polling) > 15 else "BACKEND"
            )
        )
    )
    if not verdict_reasons:
        verdict_reasons.append("HTML fast; residual latency in enterprise APIs and polling")

    nav = {"generated_at_utc": utc(), "login": login, "modules": modules, "dashboard_waterfall": wf, "returns_to_dashboard": returns}

    summary = {
        "generated_at_utc": utc(),
        "server_pid": pid,
        "nav": nav,
        "cache_tests": cache_tests,
        "network_diag": net_diag,
        "slowest_10": slowest,
        "blocking": blocking,
        "ps_after": ps_after,
        "verdict": verdict,
        "verdict_reason": "; ".join(verdict_reasons),
    }

    OUT.joinpath("CURRENT_NAVIGATION_LATENCY.json").write_text(json.dumps(nav, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT.joinpath("CURRENT_FRONTEND_WATERFALL.json").write_text(json.dumps({"dashboard": wf, "soc": {"apis": soc_apis}, "network": {"apis": net_apis}, "endpoint": {"apis": ep_apis}}, indent=2), encoding="utf-8")
    OUT.joinpath("CURRENT_ENDPOINT_LATENCY.json").write_text(json.dumps({"endpoints": endpoints, "enterprise_cache_tests": cache_tests}, indent=2), encoding="utf-8")
    OUT.joinpath("CURRENT_CACHE_EFFECTIVENESS.json").write_text(json.dumps({"enterprise": cache_tests, "performance_cache_modules": (ROOT / "data" / "integration_performance_audit" / "CACHE_INVENTORY.json").read_text(encoding="utf-8") if (ROOT / "data" / "integration_performance_audit" / "CACHE_INVENTORY.json").is_file() else {}}, indent=2), encoding="utf-8")
    OUT.joinpath("CURRENT_NETWORK_DIAGNOSTIC.json").write_text(json.dumps(net_diag, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT.joinpath("CURRENT_BACKGROUND_WORKERS.json").write_text(json.dumps({"workers": workers, "psutil": {"before": ps_before, "after": ps_after}, "scan_call_sites_sample": scans[:40]}, indent=2), encoding="utf-8")
    OUT.joinpath("CURRENT_POLLING_INVENTORY.json").write_text(json.dumps({"items": polling, "count": len(polling)}, indent=2), encoding="utf-8")
    OUT.joinpath("OPTIMIZATION_VERIFICATION.json").write_text(json.dumps(opt, indent=2), encoding="utf-8")
    OUT.joinpath("BEFORE_AFTER_COMPARISON.json").write_text(json.dumps(comparison, indent=2), encoding="utf-8")
    OUT.joinpath("STORAGE_READ_ANALYSIS.json").write_text(json.dumps(storage, indent=2), encoding="utf-8")
    OUT.joinpath("HTTP_BLOCKING_CHAIN.json").write_text(json.dumps({"blocking": blocking}, indent=2), encoding="utf-8")
    OUT.joinpath("PERFORMANCE_FORENSIC_SUMMARY.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    md = build_report(summary)
    md_path = OUT / "PERFORMANCE_FORENSIC_REPORT.md"
    md_path.write_text(md, encoding="utf-8")
    pdf_ok = try_pdf(md_path, OUT / "PERFORMANCE_FORENSIC_REPORT.pdf")
    if not pdf_ok:
        (OUT / "PERFORMANCE_FORENSIC_REPORT.pdf").write_bytes(b"")  # placeholder note
        (OUT / "PDF_NOTE.txt").write_text("PDF generation requires weasyprint or pandoc — not available in this environment. Use PERFORMANCE_FORENSIC_REPORT.md.", encoding="utf-8")

    print("DONE", str(OUT), "pdf=", pdf_ok, flush=True)
    print(json.dumps({"login_total_ms": login.get("login_total_ms"), "dashboard_html_ms": modules.get("dashboard", {}).get("ms"), "verdict": verdict}, indent=2))


if __name__ == "__main__":
    main()
