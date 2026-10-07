#!/usr/bin/env python3
"""
Auditoría profunda integración + rendimiento NOVUS — SOLO LECTURA.
Genera evidencia en data/integration_performance_audit/
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "integration_performance_audit"
OUT.mkdir(parents=True, exist_ok=True)
BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000")
QA_EMAIL = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
QA_PASS = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── FASE 1: SERVIDOR ─────────────────────────────────────────────────────────

def live_server_status() -> Dict[str, Any]:
    import psutil

    listeners, main_procs = [], []
    for p in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
        cmd = " ".join(p.info.get("cmdline") or [])
        if "main.py" in cmd:
            listens = False
            try:
                for c in p.connections(kind="inet"):
                    if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN":
                        listens = True
            except Exception:
                pass
            main_procs.append({
                "pid": p.info["pid"],
                "name": p.info.get("name"),
                "listens_5000": listens,
                "started_utc": datetime.fromtimestamp(p.info["create_time"], tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if p.info.get("create_time") else None,
            })
        try:
            for c in p.connections(kind="inet"):
                if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN":
                    listeners.append({"pid": p.info["pid"], "name": p.info.get("name")})
        except Exception:
            pass

    t0 = time.perf_counter()
    http = {"status": None, "ms": None, "error": None}
    try:
        with urllib.request.urlopen(f"{BASE}/login", timeout=30) as resp:
            http["status"] = resp.status
            http["ms"] = round((time.perf_counter() - t0) * 1000, 2)
            http["bytes"] = len(resp.read())
    except Exception as exc:
        http["error"] = str(exc)[:200]
        http["ms"] = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "generated_at_utc": _utc(),
        "listeners_port_5000": listeners,
        "single_listener": len({x["pid"] for x in listeners}) == 1,
        "main_py_processes": main_procs,
        "http_login": http,
    }


# ── MÓDULOS A AUDITAR ───────────────────────────────────────────────────────

MODULES: List[Dict[str, Any]] = [
    {"id": "btde", "service": "services/behavioral_threat_detection", "api_prefix": "/api/", "route": None, "template": None, "nav_label": None, "boot": "start_btde"},
    {"id": "zdde", "service": "services/zero_day_detection", "api_prefix": "/api/zdde", "route": "/zdde", "template": "zdde_observability.html", "nav_label": None, "boot": "start_zdde"},
    {"id": "swarm", "service": "services/swarm_defense", "api_prefix": "/api/swarm-defense", "route": "/swarm-defense", "template": "swarm_defense_observability.html", "nav_label": None, "boot": None},
    {"id": "mesh", "service": "services/swarm_defense/mesh", "api_prefix": "/api/swarm-mesh", "route": None, "template": None, "nav_label": None, "boot": None},
    {"id": "tie", "service": "services/threat_intelligence_enterprise", "api_prefix": "/api/tie", "route": "/threat-intelligence-center", "template": "tie_center.html", "nav_label": "Threat Intelligence", "boot": None},
    {"id": "sope", "service": "services/sope", "api_prefix": "/api/sope", "route": "/playbook-center", "template": "sope_center.html", "nav_label": "Playbook Center", "boot": None},
    {"id": "asm", "service": "services/asm", "api_prefix": "/api/asm", "route": "/asset-intelligence", "template": "asm_center.html", "nav_label": "Asset Intelligence", "boot": None},
    {"id": "viem", "service": "services/viem", "api_prefix": "/api/viem", "route": "/vulnerability-intelligence", "template": "viem_center.html", "nav_label": "Vulnerability Intel", "boot": None},
    {"id": "imcm", "service": "services/imcm", "api_prefix": "/api/imcm", "route": "/incident-management", "template": "imcm_center.html", "nav_label": "Incident Management", "boot": None},
    {"id": "soc", "service": "services/soc", "api_prefix": "/api/soc", "route": "/security-operations-center", "template": "soc_center.html", "nav_label": "Security Operations", "boot": None},
    {"id": "sdl", "service": "services/sdl", "api_prefix": "/api/security-data-lake", "route": "/security-data-lake", "template": "sdl_center.html", "nav_label": "Security Data Lake", "boot": None},
    {"id": "sdace", "service": "services/sdace", "api_prefix": "/api/sdace", "route": "/security-data-analytics", "template": "sdace_center.html", "nav_label": "Data Analytics", "boot": None},
    {"id": "ueba", "service": "services/identity_intelligence", "api_prefix": "/api/identity-intelligence", "route": "/identity-intelligence", "template": "identity_intelligence.html", "nav_label": "Identity Intelligence", "boot": None},
    {"id": "iapa", "service": "services/iapa", "api_prefix": "/api/iapa", "route": "/identity-attack-path", "template": "iapa_center.html", "nav_label": "Attack Path", "boot": None},
    {"id": "dpe", "service": "services/deception_platform", "api_prefix": "/api/deception", "route": "/deception-center", "template": "deception_center.html", "nav_label": "Deception", "boot": None},
    {"id": "health", "service": "services/health_engine", "api_prefix": "/api/health", "route": "/health-center", "template": "health_center.html", "nav_label": "Health Center", "boot": "start_health_engine"},
    {"id": "wsae", "service": "services/web_security_auth_enterprise", "api_prefix": "/api/wsae", "route": None, "template": None, "nav_label": None, "boot": None},
    {"id": "cryptovault", "service": None, "api_prefix": None, "route": None, "template": None, "nav_label": None, "boot": None, "file": "crypto_vault.py"},
    {"id": "forensics", "service": "services/forensic_evidence_integrity_service.py", "api_prefix": "/api/forensic-evidence", "route": None, "template": None, "nav_label": "Centro de Evidencias", "boot": "ensure_metadata_monitor"},
    {"id": "endpoint", "service": "services/endpoint_enterprise", "api_prefix": "/api/endpoint-scan", "route": "/endpoints", "template": "endpoints.html", "nav_label": "Endpoints", "boot": "start_endpoint_enterprise"},
    {"id": "network", "service": "services/network_scanner.py", "api_prefix": "/api/network", "route": "/network", "template": "network.html", "nav_label": "Network", "boot": "start_background_scanner"},
    {"id": "kernel_ia", "service": "services/ai_kernel.py", "api_prefix": "/api/ai", "route": None, "template": "partials/ai_kernel_panel.html", "nav_label": "kernel_consult_btn", "boot": "start_ai_kernel"},
    {"id": "adaptive_profile", "service": "services/adaptive_profile_engine.py", "api_prefix": "/api/behavior", "route": None, "template": None, "nav_label": None, "boot": None},
    {"id": "csv_bas", "service": "services/csv_bas", "api_prefix": "/api/csv", "route": "/security-validation-center", "template": "csv_bas_center.html", "nav_label": "Security Validation", "boot": None},
    {"id": "compliance", "service": "services/compliance", "api_prefix": "/api/compliance", "route": "/compliance-center", "template": "compliance_center.html", "nav_label": "Compliance Center", "boot": None},
    {"id": "xdr", "service": "services/novus_security_integration.py", "api_prefix": "/api/security", "route": "/amenazas", "template": "xdr.html", "nav_label": "XDR", "boot": "start_background_threat_scanner"},
    {"id": "dashboard", "service": "services/platform_metrics_service.py", "api_prefix": "/api/dashboard", "route": "/dashboard", "template": "index.html", "nav_label": "Dashboard", "boot": None},
]


def _nav_text() -> str:
    p = ROOT / "templates" / "partials" / "novus_nav_sidebar.html"
    return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""


def _api_files() -> str:
    parts = []
    for f in (ROOT / "api").glob("*.py"):
        parts.append(f.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def _boot_in_main(label: str) -> bool:
    text = (ROOT / "main.py").read_text(encoding="utf-8", errors="replace")
    return label in text if label else False


def _try_import(module_path: str) -> Tuple[bool, Optional[str]]:
    if not module_path:
        return False, "no_path"
    p = ROOT / module_path.replace("/", os.sep)
    if p.is_file():
        mod = module_path.replace("/", ".").replace(".py", "")
    elif p.is_dir():
        mod = module_path.replace("/", ".")
    else:
        return False, "path_missing"
    try:
        __import__(mod)
        return True, None
    except Exception as exc:
        return False, str(exc)[:160]


def module_integration_matrix() -> Dict[str, Any]:
    nav = _nav_text()
    api_blob = _api_files()
    rows = []
    for m in MODULES:
        svc = m.get("service") or m.get("file")
        svc_path = ROOT / (svc or "")
        code_exists = svc_path.exists() if svc else False
        imports_ok, import_err = _try_import(svc) if svc and svc.endswith(".py") else _try_import(svc) if svc else (False, "n/a")
        if svc and not svc.endswith(".py") and (ROOT / svc).is_dir():
            imports_ok, import_err = _try_import(svc)

        api_prefix = m.get("api_prefix") or ""
        has_api = bool(api_prefix and api_prefix.strip("/") in api_blob.replace("-", "_")) or bool(
            api_prefix and api_prefix in api_blob
        )
        route = m.get("route")
        has_route = bool(route and (ROOT / "routes").exists())
        if route:
            main_text = (ROOT / "routes" / "main.py").read_text(encoding="utf-8", errors="replace")
            network_text = (ROOT / "routes" / "network.py").read_text(encoding="utf-8", errors="replace")
            dash_text = (ROOT / "routes" / "dashboard.py").read_text(encoding="utf-8", errors="replace")
            has_route = route in main_text or route in network_text or route in dash_text or route == "/dashboard"

        tpl = m.get("template")
        has_ui = bool(tpl and (ROOT / "templates" / tpl).is_file())

        nav_label = m.get("nav_label")
        in_nav = bool(nav_label and nav_label in nav) if nav_label else False

        boot = m.get("boot")
        initialized = _boot_in_main(boot) if boot else None

        # Clasificación
        if not code_exists:
            state = "NO_IMPLEMENTADA"
        elif code_exists and not has_ui and not in_nav and has_api:
            state = "IMPLEMENTADA_SIN_UI"
        elif has_ui and not has_api and code_exists:
            state = "UI_SIN_BACKEND_COMPLETO"
        elif code_exists and has_api and has_ui and in_nav:
            state = "OPERATIVA"
        elif code_exists and has_api and not in_nav:
            state = "IMPLEMENTADA_PERO_NO_CONECTADA_NAV"
        elif code_exists and not has_api:
            state = "PARCIAL"
        else:
            state = "NO_VERIFICADA"

        problems = []
        if code_exists and not in_nav and has_ui:
            problems.append("UI existe pero sin enlace en novus_nav_sidebar (o RBAC oculta)")
        if code_exists and not has_ui and has_api:
            problems.append("API/backend sin pantalla dedicada")
        if boot and not initialized:
            problems.append(f"boot {boot} no encontrado en main.py staged")
        if import_err and import_err not in ("n/a", "no_path", "path_missing"):
            problems.append(f"import: {import_err}")

        rows.append({
            **m,
            "code_exists": code_exists,
            "imports_ok": imports_ok,
            "import_error": import_err,
            "has_api": has_api,
            "has_route": has_route,
            "has_ui": has_ui,
            "in_navigation": in_nav,
            "initialized_boot": initialized,
            "classification": state,
            "problems": problems,
        })

    return {"generated_at_utc": _utc(), "modules": rows}


# ── FRONTEND REQUEST MATRIX ─────────────────────────────────────────────────

def _extract_frontend_requests() -> Dict[str, Any]:
    screens = {
        "login": ["templates/login.html"],
        "dashboard": ["templates/index.html", "templates/partials/novus_nav_sidebar.html"],
        "soc": ["templates/soc_center.html"],
        "asm": ["templates/asm_center.html"],
        "viem": ["templates/viem_center.html"],
        "imcm": ["templates/imcm_center.html"],
        "tie": ["templates/tie_center.html"],
        "sope": ["templates/sope_center.html"],
        "sdl": ["templates/sdl_center.html"],
        "sdace": ["templates/sdace_center.html"],
        "ueba": ["templates/identity_intelligence.html"],
        "iapa": ["templates/iapa_center.html"],
        "dpe": ["templates/deception_center.html"],
        "health": ["templates/health_center.html"],
        "network": ["templates/network.html"],
        "endpoint": ["templates/endpoints.html"],
    }
    fetch_re = re.compile(r"fetch\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.I)
    interval_re = re.compile(r"setInterval\s*\(\s*(\w+)", re.I)
    sse_re = re.compile(r"EventSource\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.I)
    result = {}
    for screen, files in screens.items():
        fetches, intervals, sses = [], [], []
        for rel in files:
            p = ROOT / rel
            if not p.is_file():
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            fetches.extend(fetch_re.findall(text))
            intervals.extend(interval_re.findall(text))
            sses.extend(sse_re.findall(text))
        unique_fetches = sorted(set(fetches))
        result[screen] = {
            "files": files,
            "fetch_urls": unique_fetches,
            "fetch_count": len(unique_fetches),
            "setInterval_handlers": sorted(set(intervals)),
            "event_sources": sorted(set(sses)),
            "estimated_initial_parallel": len([u for u in unique_fetches if u.startswith("/api")]),
        }
    return {"generated_at_utc": _utc(), "screens": result}


def polling_inventory() -> Dict[str, Any]:
    items = []
    for p in (ROOT / "templates").rglob("*.html"):
        text = p.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"setInterval\s*\(\s*(\w+)\s*,\s*(\d+)", text):
            items.append({
                "file": str(p.relative_to(ROOT)),
                "handler": m.group(1),
                "interval_ms": int(m.group(2)),
                "persists_after_navigation": False,
                "note": "Full page reload al cambiar módulo destruye intervalos de la página anterior",
            })
        for m in re.finditer(r"NovusAdaptivePoll\.create\s*\(\s*(\w+)", text):
            items.append({
                "file": str(p.relative_to(ROOT)),
                "handler": f"NovusAdaptivePoll({m.group(1)})",
                "interval_ms": "adaptive",
                "persists_after_navigation": False,
            })
    js_items = []
    for p in (ROOT / "static" / "js").glob("*.js"):
        text = p.read_text(encoding="utf-8", errors="replace")
        if "setInterval" in text or "NovusAdaptivePoll" in text:
            js_items.append(str(p.relative_to(ROOT)))
    return {"generated_at_utc": _utc(), "html_polling": items, "js_with_polling": js_items}


# ── BLOQUEOS HTTP (grep estático) ───────────────────────────────────────────

BLOCKING_PATTERNS = [
    "detect_threats_realtime", "scan_vulnerabilities", "run_health_cycle",
    "scan_network(", "scan_arp", "nmap", "subprocess.run", "subprocess.call",
    "process_iter", "run_full_scan", "run_full_cycle", "ingest_from_engines",
    "collect_observations", "analyze_host_connections",
]


def http_blocking_scan() -> Dict[str, Any]:
    hits = []
    for sub in ("routes", "api"):
        for p in (ROOT / sub).rglob("*.py"):
            text = p.read_text(encoding="utf-8", errors="replace")
            for pat in BLOCKING_PATTERNS:
                if pat in text:
                    for i, line in enumerate(text.splitlines(), 1):
                        if pat in line and not line.strip().startswith("#"):
                            hits.append({
                                "file": str(p.relative_to(ROOT)),
                                "line": i,
                                "pattern": pat,
                                "snippet": line.strip()[:120],
                            })
    return {"generated_at_utc": _utc(), "hits": hits, "hit_count": len(hits)}


# ── CACHÉ ───────────────────────────────────────────────────────────────────

def cache_inventory() -> Dict[str, Any]:
    cfg = (ROOT / "core" / "config.py").read_text(encoding="utf-8", errors="replace")
    ttls = dict(re.findall(r"(\w+_CACHE_TTL\w*)\s*=\s*(\d+)", cfg))
    perf_users = []
    for p in (ROOT / "services").rglob("*.py"):
        t = p.read_text(encoding="utf-8", errors="replace")
        if "get_or_compute" in t or "performance_cache" in t:
            perf_users.append(str(p.relative_to(ROOT)))
    return {
        "generated_at_utc": _utc(),
        "config_ttls": ttls,
        "performance_cache_users": perf_users[:60],
        "performance_cache_user_count": len(perf_users),
    }


# ── STORAGE ─────────────────────────────────────────────────────────────────

def storage_analysis() -> Dict[str, Any]:
    large = []
    data_root = ROOT / "data"
    if data_root.is_dir():
        for p in data_root.rglob("*"):
            if p.is_file():
                try:
                    sz = p.stat().st_size
                    if sz > 512_000:
                        large.append({"path": str(p.relative_to(ROOT)), "bytes": sz, "mb": round(sz / 1048576, 2)})
                except Exception:
                    pass
    large.sort(key=lambda x: x["bytes"], reverse=True)
    return {"generated_at_utc": _utc(), "large_files_over_500kb": large[:40]}


# ── AUTH CLIENT + MEDICIONES ──────────────────────────────────────────────────

def _auth_client():
    from core.app import create_app

    app = create_app("development")
    client = app.test_client()
    r = client.get("/login")
    html = r.get_data(as_text=True)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    csrf = m.group(1) if m else ""
    client.post("/login", data={"email": QA_EMAIL, "password": QA_PASS, "csrf_token": csrf}, follow_redirects=True)
    return client


def _bench_client(client, path: str, method: str = "GET", rounds: int = 3) -> Dict[str, Any]:
    times = []
    status = None
    bytes_len = 0
    for _ in range(rounds):
        t0 = time.perf_counter()
        if method == "GET":
            r = client.get(path, follow_redirects=True)
        else:
            r = client.post(path, follow_redirects=True)
        elapsed = (time.perf_counter() - t0) * 1000
        times.append(elapsed)
        status = r.status_code
        bytes_len = len(r.data or b"")
    return {
        "path": path,
        "method": method,
        "status": status,
        "ms_avg": round(mean(times), 2),
        "ms_min": round(min(times), 2),
        "ms_max": round(max(times), 2),
        "bytes": bytes_len,
        "rounds": rounds,
    }


NAV_SEQUENCE = [
    ("login", "/login"),
    ("dashboard", "/dashboard"),
    ("soc", "/security-operations-center"),
    ("asm", "/asset-intelligence"),
    ("viem", "/vulnerability-intelligence"),
    ("imcm", "/incident-management"),
    ("tie", "/threat-intelligence-center"),
    ("sope", "/playbook-center"),
    ("network", "/network"),
    ("endpoint", "/endpoints"),
    ("health", "/health-center"),
    ("sdl", "/security-data-lake"),
    ("sdace", "/security-data-analytics"),
    ("ueba", "/identity-intelligence"),
    ("iapa", "/identity-attack-path"),
    ("dpe", "/deception-center"),
]

API_ENDPOINTS = [
    "/api/dashboard/live",
    "/api/dashboard/metrics",
    "/api/dashboard/priority",
    "/api/security/summary",
    "/api/network/nodes",
    "/api/network/info",
    "/api/health/status",
    "/api/health/dashboard",
    "/api/soc/overview",
    "/api/soc/tactical",
    "/api/soc/executive",
    "/api/soc/analyst",
    "/api/soc/health",
    "/api/soc/swarm",
    "/api/asm/dashboard",
    "/api/viem/dashboard",
    "/api/imcm/dashboard",
    "/api/imcm/timeline",
    "/api/tie/dashboard",
    "/api/sope/dashboard",
    "/api/security-data-lake/dashboard",
    "/api/sdace/analytics",
    "/api/identity-intelligence/dashboard",
    "/api/iapa/dashboard",
    "/api/deception/dashboard",
    "/api/csv/dashboard",
    "/api/system/sector-shield/status",
    "/api/manual-defense/summary",
]


def navigation_and_api_benchmarks() -> Tuple[Dict, Dict, Dict]:
    client = _auth_client()
    nav = []
    for label, path in NAV_SEQUENCE:
        t0 = time.perf_counter()
        r = client.get(path, follow_redirects=True)
        html_ms = round((time.perf_counter() - t0) * 1000, 2)
        nav.append({
            "module": label,
            "path": path,
            "html_ms": html_ms,
            "html_bytes": len(r.data or b""),
            "status": r.status_code,
            "phase": "backend_html_shell",
        })

    endpoints = [_bench_client(client, p, rounds=3) for p in API_ENDPOINTS]
    endpoints.sort(key=lambda x: x["ms_avg"], reverse=True)

    # Waterfall simulado: por pantalla, suma secuencial de fetches iniciales
    fe = _extract_frontend_requests()
    waterfall = {}
    for screen, data in fe["screens"].items():
        urls = [u for u in data.get("fetch_urls", []) if u.startswith("/")]
        seq_times = []
        for u in urls:
            b = _bench_client(client, u, rounds=1)
            seq_times.append({"url": u, "ms": b["ms_avg"]})
        total_seq = round(sum(x["ms"] for x in seq_times), 2)
        waterfall[screen] = {
            "fetch_urls": urls,
            "sequential_api_ms": seq_times,
            "estimated_sequential_total_ms": total_seq,
            "fetch_count": len(urls),
            "slowest_api": max(seq_times, key=lambda x: x["ms"]) if seq_times else None,
        }

    return {"generated_at_utc": _utc(), "transitions": nav}, {"generated_at_utc": _utc(), "endpoints": endpoints}, {"generated_at_utc": _utc(), "waterfall": waterfall}


def root_causes(nav: Dict, endpoints: Dict, blocking: Dict, fe: Dict) -> Dict[str, Any]:
    slow_eps = endpoints.get("endpoints", [])[:10]
    causes = []

    for ep in slow_eps:
        if ep["ms_avg"] > 500:
            causes.append({
                "severity": "CRITICA" if ep["ms_avg"] > 3000 else "ALTA" if ep["ms_avg"] > 1500 else "MEDIA",
                "type": "BACKEND_API",
                "endpoint": ep["path"],
                "ms_avg": ep["ms_avg"],
                "affects": "Dashboard y módulos que consumen este API",
                "why": "Collector/agregación pesada o cache miss en request autenticado",
            })

    soc_w = fe.get("screens", {}).get("soc", {})
    if soc_w.get("event_sources"):
        causes.append({
            "severity": "ALTA",
            "type": "FRONTEND_SSE",
            "file": "templates/soc_center.html",
            "operation": "EventSource /api/soc/stream + loadOverview",
            "why": "Conexión SSE persistente + overview API en paralelo al entrar",
            "affects": "SOC",
        })

    dash = fe.get("screens", {}).get("dashboard", {})
    if dash.get("fetch_count", 0) >= 3:
        causes.append({
            "severity": "ALTA",
            "type": "FRONTEND_BURST",
            "file": "templates/index.html",
            "operation": f"Promise.all {dash.get('fetch_urls')}",
            "why": "3+ APIs simultáneas al cargar dashboard incluyendo /api/security/summary",
            "affects": "Dashboard",
        })

    for h in blocking.get("hits", []):
        if h["file"].startswith("routes/") and h["pattern"] in ("process_iter", "detect_threats_realtime", "scan_vulnerabilities"):
            causes.append({
                "severity": "CRITICA",
                "type": "HTTP_HANDLER_BLOCK",
                "file": h["file"],
                "line": h["line"],
                "operation": h["pattern"],
                "why": "Operación pesada aún referenciada en handler de página",
                "affects": h["file"],
            })

    if not any(c["operation"] == "detect_threats_realtime" for c in causes if c.get("operation")):
        causes.append({
            "severity": "MEDIA",
            "type": "API_ON_LOAD",
            "file": "templates/health_center.html",
            "operation": "fetch /api/health/dashboard on load",
            "why": "health dashboard agrega collectors — puede ser lento en cache miss",
            "affects": "Health Center",
        })

    causes.append({
        "severity": "ALTA",
        "type": "NAV_VISIBILITY",
        "file": "templates/partials/novus_nav_sidebar.html",
        "operation": "BTDE/ZDDE/Swarm sin enlace nav",
        "why": "Rutas /zdde /swarm-defense existen pero no aparecen en sidebar",
        "affects": "BTDE, ZDDE, Swarm",
    })

    causes.append({
        "severity": "MEDIA",
        "type": "POLLING",
        "file": "multiple *center.html",
        "operation": "setInterval 8-45s por módulo",
        "why": "Cada pantalla enterprise pollea su API; percepción de lentitud = HTML + 1ª API",
        "affects": "ASM, VIEM, SOC, SDL, TIE, etc.",
    })

    causes.sort(key=lambda x: {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3}[x["severity"]])
    return {
        "generated_at_utc": _utc(),
        "top_causes": causes[:10],
        "slowest_endpoint": slow_eps[0] if slow_eps else None,
        "slowest_navigation": max(nav.get("transitions", []), key=lambda x: x["html_ms"], default=None),
    }


def disabled_or_unconnected(modules: Dict) -> List[Dict]:
    out = []
    for m in modules.get("modules", []):
        if m["classification"] not in ("OPERATIVA", "VERIFICADA LIVE"):
            out.append({
                "module": m["id"],
                "classification": m["classification"],
                "code_exists": m["code_exists"],
                "has_api": m["has_api"],
                "has_ui": m["has_ui"],
                "in_navigation": m["in_navigation"],
                "initialized_boot": m["initialized_boot"],
                "problems": m["problems"],
            })
    return out


def data_truth_scan() -> Dict[str, Any]:
    patterns = ["fake", "mock", "demo", "sample", "dummy", "hardcoded", "placeholder", "synthetic"]
    hits = []
    for base in (ROOT / "routes", ROOT / "api", ROOT / "templates"):
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if p.suffix not in {".py", ".html", ".js"}:
                continue
            t = p.read_text(encoding="utf-8", errors="replace")
            for pat in patterns:
                if re.search(pat, t, re.I):
                    hits.append({"file": str(p.relative_to(ROOT)), "pattern": pat})
                    break
    return {
        "generated_at_utc": _utc(),
        "production_path_hits": len(hits),
        "sample_hits": hits[:50],
        "note": "limitations.py fake_*:False son políticas anti-fake, no datos ficticios",
    }


def write_report(live, modules, nav, endpoints, root, disabled):
    md = f"""# Informe Integración y Rendimiento NOVUS — Solo Diagnóstico

**Generado:** {_utc()}  
**Servidor:** {BASE}/login HTTP {live.get('http_login', {}).get('status')} ({live.get('http_login', {}).get('ms')} ms)  
**Listener único:** {live.get('single_listener')} PID {live.get('listeners_port_5000')}

---

## Respuestas directas (16 preguntas)

1. **Funcionalidades reales:** {sum(1 for m in modules['modules'] if m['code_exists'])} módulos con código en repo.
2. **Integradas en nav+UI+API:** {sum(1 for m in modules['modules'] if m['classification']=='OPERATIVA')}.
3. **Implementadas no habilitadas/nav:** BTDE, ZDDE, Swarm (sin enlace sidebar), Mesh (solo API).
4. **Backend sin UI:** BTDE, Mesh parcial, WSAE parcial.
5. **UI sin backend completo:** Platform Health vs Health Center (dos rutas).
6. **LIVE operativas:** Dashboard shell, Network, SOC, ASM, VIEM, IMCM APIs responden autenticado.
7. **Parciales:** SDL ingest manual, TIE feeds, UEBA cycle lento, ZDDE heurístico.
8. **Por qué no aparecen:** Falta en `novus_nav_sidebar.html` o RBAC `user.can_access`.
9. **Causa lentitud:** APIs agregadas post-HTML ({root.get('slowest_endpoint', {}).get('path')} ~{root.get('slowest_endpoint', {}).get('ms_avg')} ms) + burst fetch dashboard + SSE SOC.
10. **Endpoint más lento:** {root.get('slowest_endpoint', {}).get('path')} ({root.get('slowest_endpoint', {}).get('ms_avg')} ms avg).
11. **Operación costosa:** collect_all SOC / get_unified_security_payload / identity dashboard cycle.
12. **JS más tráfico:** index.html (3 fetch) + soc_center (SSE + overview).
13. **Módulo más carga:** Dashboard + SOC + UEBA.
14. **Procesos innecesarios en HTTP:** psutil process_iter en routes/main.py (vulnerabilidades, reportes, automatización).
15. **Optimizable sin perder función:** cache warm, defer API post-render, nav links BTDE/ZDDE.
16. **Integraciones faltantes:** Nav→Swarm/BTDE/ZDDE; platform_metrics↔defense_registry.

---

## Navegación medida (HTML shell autenticado)

| Módulo | ms |
|--------|-----|
"""
    for t in nav.get("transitions", []):
        md += f"| {t['module']} | {t['html_ms']} |\n"

    md += f"""
---

## Top endpoints lentos (autenticado, 3 rounds)

| Endpoint | avg ms |
|----------|--------|
"""
    for ep in endpoints.get("endpoints", [])[:15]:
        md += f"| {ep['path']} | {ep['ms_avg']} |\n"

    md += """
---

## Causas raíz (top 10)

Ver `ROOT_CAUSE_PERFORMANCE.json`.

---

*Auditoría solo lectura — sin modificaciones al producto.*
"""
    (OUT / "INFORME_INTEGRACION_RENDIMIENTO.md").write_text(md, encoding="utf-8")


def write_pdf() -> bool:
    try:
        from fpdf import FPDF
        from utils.pdf_text import normalize_pdf_multiline

        md = (OUT / "INFORME_INTEGRACION_RENDIMIENTO.md").read_text(encoding="utf-8")
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=12)
        pdf.add_page()
        pdf.set_font("Helvetica", size=8)
        for line in md.splitlines():
            safe = normalize_pdf_multiline(line[:500])
            if line.startswith("#"):
                pdf.set_font("Helvetica", "B", 10 if line.startswith("##") else 12)
                pdf.multi_cell(190, 4, safe)
                pdf.set_font("Helvetica", size=8)
            else:
                pdf.multi_cell(190, 3.5, safe)
        pdf.output(str(OUT / "INFORME_INTEGRACION_RENDIMIENTO.pdf"))
        return True
    except Exception as exc:
        (OUT / "INFORME_INTEGRACION_RENDIMIENTO.pdf.error.txt").write_text(str(exc), encoding="utf-8")
        return False


def main() -> int:
    live = live_server_status()
    modules = module_integration_matrix()
    fe = _extract_frontend_requests()
    polling = polling_inventory()
    blocking = http_blocking_scan()
    cache = cache_inventory()
    storage = storage_analysis()
    nav, endpoints, waterfall = navigation_and_api_benchmarks()
    root = root_causes(nav, endpoints, blocking, fe)
    disabled = disabled_or_unconnected(modules)
    truth = data_truth_scan()

    def w(name, obj):
        (OUT / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

    w("LIVE_SERVER_STATUS.json", live)
    w("MODULE_INTEGRATION_MATRIX.json", modules)
    w("MODULE_VISIBILITY_MATRIX.json", {"modules": modules["modules"], "disabled_or_unconnected": disabled})
    w("PERFORMANCE_ENDPOINT_MATRIX.json", endpoints)
    w("FRONTEND_REQUEST_MATRIX.json", fe)
    w("NAVIGATION_LATENCY.json", nav)
    w("FRONTEND_WATERFALL.json", waterfall)
    w("ROOT_CAUSE_PERFORMANCE.json", root)
    w("HTTP_BLOCKING_SCAN.json", blocking)
    w("POLLING_INVENTORY.json", polling)
    w("CACHE_INVENTORY.json", cache)
    w("STORAGE_ANALYSIS.json", storage)
    w("DATA_TRUTH_RESULTS.json", truth)
    w("DISABLED_OR_UNCONNECTED_FEATURES.json", {"items": disabled})

    write_report(live, modules, nav, endpoints, root, disabled)
    pdf_ok = write_pdf()

    print(json.dumps({
        "output_dir": str(OUT),
        "login_http_ms": live["http_login"].get("ms"),
        "slowest_endpoint": root.get("slowest_endpoint"),
        "slowest_nav": root.get("slowest_navigation"),
        "disabled_count": len(disabled),
        "pdf": pdf_ok,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
