#!/usr/bin/env python3
"""
Fase 2.1 — Perfil de latencia HTTP (una API por invocación recomendada).
Requiere NOVUS corriendo con NOVUS_HTTP_PROFILE=1 para desglose middleware.

Uso:
  python scripts/phase2_http_profiler.py /api/network/info
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_process_audit"
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
PY = r"C:\Users\hp\AppData\Local\Python\pythoncore-3.14-64\python.exe"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def timed_call(label: str, fn: Callable, *a, **kw) -> Dict[str, Any]:
    t0 = time.perf_counter()
    try:
        result = fn(*a, **kw)
        err = None
    except Exception as exc:
        result = None
        err = str(exc)[:200]
    return {
        "component": label,
        "ms": round((time.perf_counter() - t0) * 1000, 2),
        "error": err,
        "has_result": result is not None,
    }


def find_novus_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = p.info.get("cmdline") or []
            if len(cmd) >= 2 and str(cmd[-1]).endswith("main.py"):
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def system_snapshot(pid: Optional[int]) -> Dict[str, Any]:
    vm = psutil.virtual_memory()
    row: Dict[str, Any] = {
        "ram_system_pct": round(vm.percent, 1),
        "cpu_system_pct": round(psutil.cpu_percent(interval=0.15), 1),
    }
    if pid:
        try:
            proc = psutil.Process(pid)
            row["novus_ram_mb"] = round(proc.memory_info().rss / (1024**2), 1)
            row["novus_cpu_pct"] = round(proc.cpu_percent(interval=0.15), 1)
            row["novus_threads"] = proc.num_threads()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return row


def list_active_threads(pid: Optional[int]) -> List[str]:
    if not pid:
        return []
    try:
        proc = psutil.Process(pid)
        # Windows: num_threads only; thread names via internal list unavailable
        return [f"threads={proc.num_threads()}"]
    except Exception:
        return []


def login_session() -> requests.Session:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=20)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    s.post(
        f"{BASE}/login",
        data={"email": QA[0], "password": QA[1], "csrf_token": csrf.group(1) if csrf else ""},
        timeout=30,
    )
    return s


def measure_direct(path: str) -> Dict[str, Any]:
    """Prueba A — función interna sin Flask."""
    samples: List[float] = []
    component_rows: List[Dict[str, Any]] = []

    if path.startswith("/api/network/info"):
        from services.network_snapshot_service import read_context_snapshot

        def run():
            ctx = read_context_snapshot()
            if ctx and ctx.get("body"):
                return dict(ctx["body"])
            from api.network import _build_network_info_payload

            return _build_network_info_payload()

        for _ in range(5):
            samples.append(timed_call("network_info_fn", run)["ms"])
        component_rows = [
            timed_call("read_context_snapshot", read_context_snapshot),
        ]
        snap = read_context_snapshot()
        if not (snap and snap.get("body")):
            from utils.host_data import get_primary_network_interface

            component_rows.append(timed_call("get_primary_network_interface", get_primary_network_interface))

    elif path.startswith("/api/network/nodes"):
        from services.network_snapshot_service import read_nodes_api

        fn = lambda: read_nodes_api(trigger_discovery=False, include_context=False)
        for _ in range(5):
            samples.append(timed_call("read_nodes_api", fn)["ms"])
        component_rows = [timed_call("read_nodes_api", fn)]

    elif path.startswith("/api/security/summary"):
        from services.security_snapshot_service import load_snapshot, read_security_summary_api

        for _ in range(5):
            samples.append(timed_call("read_security_summary_api", read_security_summary_api, "QA-NOVUS-2026", trigger_refresh=False)["ms"])
        component_rows = [
            timed_call("load_snapshot", load_snapshot),
            timed_call("read_security_summary_api", read_security_summary_api, "QA-NOVUS-2026", trigger_refresh=False),
        ]

    elif path.startswith("/api/dashboard/live"):
        from services.dashboard_live_service import get_dashboard_live_payload

        for _ in range(5):
            samples.append(timed_call("get_dashboard_live_payload", get_dashboard_live_payload, tenant_id="QA-NOVUS-2026")["ms"])
        component_rows = [
            timed_call("get_dashboard_live_payload", get_dashboard_live_payload, tenant_id="QA-NOVUS-2026"),
        ]
        from services.system_monitor import system_monitor
        from services.performance_cache import peek_cached

        component_rows.extend([
            timed_call("system_monitor.get_system_status", system_monitor.get_system_status),
            timed_call("peek_cached(platform_counters)", lambda: peek_cached("platform_counters:QA-NOVUS-2026")),
        ])

    return {
        "samples_ms": samples,
        "min": min(samples) if samples else None,
        "max": max(samples) if samples else None,
        "avg": round(sum(samples) / len(samples), 2) if samples else None,
        "components": component_rows,
    }


def measure_middleware_stack() -> List[Dict[str, Any]]:
    """Componentes típicos del before_request (sin request context)."""
    rows: List[Dict[str, Any]] = []
    from models.user import User

    rows.append(timed_call("User.get_by_id", User.get_by_id, 1))
    user = User.get_by_id(1)
    from services.tenant_scope_service import get_tenant_context, get_tenant_scope_record

    rows.append(timed_call("get_tenant_scope_record", get_tenant_scope_record, "QA-NOVUS-2026"))
    rows.append(timed_call("get_tenant_context", get_tenant_context, user))
    from services.swarm_defense.session_revoke import is_session_revoked

    rows.append(timed_call("is_session_revoked", is_session_revoked, user_email=QA[0], session_id="x"))
    from services.hostile_hardening_config import get_hostile_hardening_config

    rows.append(timed_call("get_hostile_hardening_config", get_hostile_hardening_config))
    from services.hostile_environment_service import check_ip_access, check_user_api_rate_limit, build_csp_header

    rows.append(timed_call("check_ip_access", check_ip_access, "127.0.0.1"))
    from services.http_abuse_guard import run_pre_request_checks

    rows.append(timed_call("run_pre_request_checks", run_pre_request_checks, "127.0.0.1", "Mozilla/5.0", "GET", None))
    rows.append(timed_call("check_user_api_rate_limit", check_user_api_rate_limit, QA[0]))
    from database import db_security

    rows.append(timed_call("db_security.check_rate_limit", db_security.check_rate_limit, "127.0.0.1", max_requests=120, window_seconds=60))
    rows.append(timed_call("build_csp_header", build_csp_header))
    return rows


def measure_real_http(path: str, sess: requests.Session, repeats: int = 5) -> Dict[str, Any]:
    times: List[float] = []
    profiles: List[Dict[str, Any]] = []
    status = None
    for i in range(repeats):
        t0 = time.perf_counter()
        r = sess.get(BASE + path, timeout=60)
        elapsed = round((time.perf_counter() - t0) * 1000, 2)
        times.append(elapsed)
        status = r.status_code
        prof_raw = r.headers.get("X-Novus-Profile")
        if prof_raw:
            try:
                profiles.append(json.loads(prof_raw))
            except json.JSONDecodeError:
                profiles.append({"raw": prof_raw[:500]})
        time.sleep(1.0 if i == 0 else 0.4)
    return {
        "samples_ms": times,
        "min": min(times),
        "max": max(times),
        "avg": round(sum(times) / len(times), 2),
        "http_status": status,
        "server_profile_marks": profiles[-1] if profiles else None,
        "all_server_profiles": profiles,
    }


def endpoint_path_arg(path: str) -> str:
    if path.rstrip("/") == "/api/network/nodes":
        return "/api/network/nodes?trigger_discovery=false&include_context=false"
    return path


def profile_endpoint(path: str) -> Dict[str, Any]:
    path = endpoint_path_arg(path.split("?")[0])
    pid = find_novus_pid()
    print(f"\n=== {path} @ {utc()} pid={pid} ===")

    report: Dict[str, Any] = {
        "endpoint": path,
        "generated_at_utc": utc(),
        "system_before": system_snapshot(pid),
        "background": list_active_threads(pid),
    }

    time.sleep(3)  # idle before measure
    report["test_a_direct_function"] = measure_direct(path.split("?")[0])
    report["middleware_components"] = measure_middleware_stack()

    sess = login_session()
    time.sleep(2)
    report["test_c_real_http"] = measure_real_http(path, sess)
    report["test_d_authenticated_browser"] = report["test_c_real_http"]

    report["system_after"] = system_snapshot(pid)
    report["gap_analysis"] = _gap(report)
    return report


def _gap(r: Dict[str, Any]) -> Dict[str, Any]:
    direct = (r.get("test_a_direct_function") or {}).get("avg")
    http = (r.get("test_c_real_http") or {}).get("avg")
    mw = sum(x["ms"] for x in r.get("middleware_components") or [])
    prof = (r.get("test_c_real_http") or {}).get("server_profile_marks") or {}
    marks = prof.get("marks") or []
    server_total = prof.get("total_ms")
    return {
        "direct_function_avg_ms": direct,
        "real_http_avg_ms": http,
        "http_minus_direct_ms": round((http or 0) - (direct or 0), 2) if http and direct else None,
        "middleware_components_sum_ms": round(mw, 2),
        "server_profile_total_ms": server_total,
        "server_profile_marks": marks,
    }


def load_existing() -> Dict[str, Any]:
    p = OUT / "PHASE_2_HTTP_ROOT_CAUSE_REPORT.json"
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"generated_at_utc": utc(), "phase": "2.1", "endpoints": []}


def write_reports(data: Dict[str, Any]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "PHASE_2_HTTP_ROOT_CAUSE_REPORT.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    lines = ["# NOVUS — Fase 2.1 HTTP Root Cause Report", "", f"Generado: {data.get('generated_at_utc')}", ""]
    for ep in data.get("endpoints", []):
        gap = ep.get("gap_analysis") or {}
        lines.extend([
            f"## {ep.get('endpoint')}",
            "",
            f"| Métrica | ms |",
            f"|---------|-----|",
            f"| Función directa (A) | {gap.get('direct_function_avg_ms')} |",
            f"| HTTP real (C/D) | {gap.get('real_http_avg_ms')} |",
            f"| HTTP − directo | {gap.get('http_minus_direct_ms')} |",
            f"| Suma middleware (off-request) | {gap.get('middleware_components_sum_ms')} |",
            f"| Server profile total | {gap.get('server_profile_total_ms')} |",
            "",
            "### Server profile marks",
            "",
        ])
        for m in gap.get("server_profile_marks") or []:
            lines.append(f"- {m.get('phase')}: {m.get('ms')} ms")
        lines.extend(["", "### Middleware (off-request)", ""])
        for row in ep.get("middleware_components") or []:
            lines.append(f"- {row['component']}: {row['ms']} ms")
        lines.extend(["", "### Handler direct components", ""])
        for row in (ep.get("test_a_direct_function") or {}).get("components") or []:
            lines.append(f"- {row['component']}: {row['ms']} ms")
        sb, sa = ep.get("system_before") or {}, ep.get("system_after") or {}
        lines.extend([
            "",
            f"RAM NOVUS: {sb.get('novus_ram_mb')} → {sa.get('novus_ram_mb')} MB",
            f"RAM sistema: {sb.get('ram_system_pct')}% → {sa.get('ram_system_pct')}%",
            f"Threads: {sb.get('novus_threads')} → {sa.get('novus_threads')}",
            "",
        ])
    (OUT / "PHASE_2_HTTP_ROOT_CAUSE_REPORT.md").write_text("\n".join(lines), encoding="utf-8")


def restart_with_profile() -> Optional[int]:
    for pid in _listeners():
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], capture_output=True)
    time.sleep(2)
    env = __import__("os").environ.copy()
    env["FLASK_DEBUG"] = "False"
    env["NOVUS_HTTP_PROFILE"] = "1"
    subprocess.Popen([PY, "main.py"], cwd=str(ROOT), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(90):
        if _listeners():
            time.sleep(5)
            return find_novus_pid()
        time.sleep(1)
    return None


def _listeners() -> List[int]:
    pids = []
    out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    for line in out.splitlines():
        if ":5000" in line and "LISTENING" in line:
            pids.append(int(line.split()[-1]))
    return pids


def main() -> int:
    endpoints = sys.argv[1:] or ["/api/network/info"]
    if "--restart" in endpoints:
        endpoints.remove("--restart")
        pid = restart_with_profile()
        if not pid:
            print("FALLO: no arrancó NOVUS con NOVUS_HTTP_PROFILE=1")
            return 1
        print(f"NOVUS reiniciado pid={pid} con NOVUS_HTTP_PROFILE=1")
        time.sleep(15)

    data = load_existing()
    for ep in endpoints:
        rep = profile_endpoint(ep)
        # merge by endpoint
        data["endpoints"] = [x for x in data.get("endpoints", []) if x.get("endpoint") != rep["endpoint"]]
        data["endpoints"].append(rep)
        data["generated_at_utc"] = utc()
        write_reports(data)
        print(json.dumps(rep["gap_analysis"], indent=2))
        time.sleep(8)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
