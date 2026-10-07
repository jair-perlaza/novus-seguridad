#!/usr/bin/env python3
"""Medición LIVE de UX: login, dashboard, navegación entre módulos."""
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

OUT = ROOT / "data" / "performance_ux_optimization"
OUT.mkdir(parents=True, exist_ok=True)
BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000")
PHASE = os.environ.get("NOVUS_UX_PHASE", "BEFORE").upper()
QA_EMAIL = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
QA_PASS = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")


MODULE_ROUTES: List[Tuple[str, str]] = [
    ("Dashboard", "/dashboard"),
    ("Threats", "/amenazas"),
    ("Vulnerabilities", "/vulnerabilidades"),
    ("Network", "/network"),
    ("Automation", "/automatizacion"),
    ("Reports", "/reportes"),
    ("Endpoints", "/endpoints"),
    ("SOC", "/security-operations-center"),
    ("ASM", "/asset-intelligence"),
    ("VIEM", "/vulnerability-intelligence"),
    ("IMCM", "/incident-management"),
    ("Threat Intelligence", "/threat-intelligence-center"),
    ("Health Center", "/health-center"),
    ("Data Lake", "/security-data-lake"),
    ("SDACE", "/security-data-analytics"),
    ("UEBA", "/inteligencia"),
    ("IAPA", "/identity-attack-path"),
    ("Deception", "/deception-center"),
]


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resource_snapshot() -> Dict[str, Any]:
    import psutil

    proc = psutil.Process()
    mem = psutil.virtual_memory()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "ram_percent": mem.percent,
        "ram_used_mb": round(mem.used / (1024 * 1024), 1),
        "process_rss_mb": round(proc.memory_info().rss / (1024 * 1024), 1),
        "process_threads": proc.num_threads(),
    }


def _timed_request(session, method: str, url: str, **kwargs) -> Dict[str, Any]:
    import requests

    t0 = time.perf_counter()
    ttfb_ms: Optional[float] = None
    resp = None
    err = None
    try:
        if method == "GET":
            resp = session.get(url, stream=True, timeout=120, **kwargs)
        else:
            resp = session.post(url, timeout=120, **kwargs)
        if resp is not None and hasattr(resp, "raw"):
            resp.raw.read(1)
            ttfb_ms = round((time.perf_counter() - t0) * 1000, 2)
            content = resp.content
        elif resp is not None:
            content = resp.content
        else:
            content = b""
        total_ms = round((time.perf_counter() - t0) * 1000, 2)
        if ttfb_ms is None:
            ttfb_ms = total_ms
        return {
            "url": url,
            "method": method,
            "status": resp.status_code if resp is not None else None,
            "ttfb_ms": ttfb_ms,
            "total_ms": total_ms,
            "bytes": len(content),
            "final_url": getattr(resp, "url", url),
            "error": None,
        }
    except Exception as exc:
        return {
            "url": url,
            "method": method,
            "status": None,
            "ttfb_ms": None,
            "total_ms": round((time.perf_counter() - t0) * 1000, 2),
            "bytes": 0,
            "error": str(exc)[:300],
        }


def _login_flow_session(session) -> Dict[str, Any]:
    snap_before = _resource_snapshot()
    t_get = time.perf_counter()
    r_login = session.get(f"{BASE}/login", timeout=60)
    login_get_ms = round((time.perf_counter() - t_get) * 1000, 2)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r_login.text or "")
    csrf = m.group(1) if m else None

    post_start = time.perf_counter()
    post = session.post(
        f"{BASE}/login",
        data={"email": QA_EMAIL, "password": QA_PASS, "csrf_token": csrf or ""},
        allow_redirects=True,
        timeout=120,
        headers={"Referer": f"{BASE}/login"},
    )
    login_total_ms = round((time.perf_counter() - post_start) * 1000, 2)

    dash = _timed_request(session, "GET", f"{BASE}/dashboard", allow_redirects=True)
    authenticated = "/login" not in (dash.get("final_url") or "").lower()
    snap_after = _resource_snapshot()
    return {
        "login_get": {
            "url": f"{BASE}/login",
            "method": "GET",
            "status": r_login.status_code,
            "ttfb_ms": login_get_ms,
            "total_ms": login_get_ms,
            "bytes": len(r_login.content or b""),
            "csrf_found": bool(csrf),
        },
        "login_post_status": post.status_code,
        "login_post_ms": login_total_ms,
        "login_authenticated": authenticated,
        "dashboard_after_login": dash,
        "cpu_delta": round(snap_after["cpu_percent"] - snap_before["cpu_percent"], 2),
        "ram_delta_mb": round(snap_after["process_rss_mb"] - snap_before["process_rss_mb"], 2),
        "transport": "requests",
    }


def _login_flow_test_client() -> Tuple[Any, Dict[str, Any]]:
    """Login vía Flask test_client — app aislada (sin importar main.py)."""
    from core.app import create_app

    app = create_app("development")
    snap_before = _resource_snapshot()
    client = app.test_client()
    t0 = time.perf_counter()
    r_login = client.get("/login")
    login_get_ms = round((time.perf_counter() - t0) * 1000, 2)
    html = r_login.get_data(as_text=True)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    csrf = m.group(1) if m else None

    post_start = time.perf_counter()
    post = client.post(
        "/login",
        data={"email": QA_EMAIL, "password": QA_PASS, "csrf_token": csrf or ""},
        follow_redirects=True,
    )
    login_total_ms = round((time.perf_counter() - post_start) * 1000, 2)

    t_dash = time.perf_counter()
    dash_resp = client.get("/dashboard", follow_redirects=True)
    dash_ms = round((time.perf_counter() - t_dash) * 1000, 2)
    authenticated = b"Cyber Command" in dash_resp.data or b"LOADING" in dash_resp.data
    snap_after = _resource_snapshot()
    login_result = {
        "login_get": {
            "url": "/login",
            "method": "GET",
            "status": r_login.status_code,
            "ttfb_ms": login_get_ms,
            "total_ms": login_get_ms,
            "bytes": len(r_login.data or b""),
            "csrf_found": bool(csrf),
        },
        "login_post_status": post.status_code,
        "login_post_ms": login_total_ms,
        "login_authenticated": authenticated,
        "dashboard_after_login": {
            "url": "/dashboard",
            "status": dash_resp.status_code,
            "total_ms": dash_ms,
            "bytes": len(dash_resp.data or b""),
            "authenticated": authenticated,
        },
        "cpu_delta": round(snap_after["cpu_percent"] - snap_before["cpu_percent"], 2),
        "ram_delta_mb": round(snap_after["process_rss_mb"] - snap_before["process_rss_mb"], 2),
        "transport": "flask_test_client",
    }
    return client, login_result


def _module_navigation_test_client(client) -> List[Dict[str, Any]]:
    results = []
    for name, path in MODULE_ROUTES:
        snap = _resource_snapshot()
        t0 = time.perf_counter()
        resp = client.get(path, follow_redirects=True)
        total_ms = round((time.perf_counter() - t0) * 1000, 2)
        results.append({
            "module": name,
            "path": path,
            "status": resp.status_code,
            "total_ms": total_ms,
            "ttfb_ms": total_ms,
            "bytes": len(resp.data or b""),
            "authenticated": "login" not in (getattr(getattr(resp, "request", None), "path", "") or "").lower(),
            "cpu_percent": snap["cpu_percent"],
            "ram_percent": snap["ram_percent"],
            "transport": "flask_test_client",
        })
    return results


def _login_flow(session) -> Dict[str, Any]:
    try:
        client, result = _login_flow_test_client()
        result["_test_client"] = client
        return result
    except Exception as exc:
        out = _login_flow_session(session)
        out["test_client_error"] = str(exc)[:200]
        return out


def _module_navigation(session) -> List[Dict[str, Any]]:
    results = []
    for name, path in MODULE_ROUTES:
        snap = _resource_snapshot()
        m = _timed_request(session, "GET", f"{BASE}{path}", allow_redirects=True)
        m["module"] = name
        m["path"] = path
        m["cpu_percent"] = snap["cpu_percent"]
        m["ram_percent"] = snap["ram_percent"]
        results.append(m)
    return results


def _regression_probes() -> Dict[str, Any]:
    scripts = [
        ("BTDE", "scripts/prove_btde.py"),
        ("Swarm", "scripts/prove_swarm_defense.py"),
        ("ASM", "scripts/prove_asm.py"),
        ("VIEM", "scripts/prove_viem.py"),
        ("IMCM", "scripts/prove_imcm.py"),
        ("SOC", "scripts/prove_soc.py"),
        ("Health", "scripts/prove_health_engine.py"),
        ("UEBA", "scripts/prove_ueba.py"),
    ]
    import subprocess

    out: Dict[str, Any] = {"generated_at_utc": _utc(), "results": []}
    for label, rel in scripts:
        path = ROOT / rel
        if not path.is_file():
            out["results"].append({"module": label, "status": "SKIP", "reason": "script missing"})
            continue
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                [sys.executable, str(path)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=900,
            )
            out["results"].append({
                "module": label,
                "status": "PASS" if proc.returncode == 0 else "FAIL",
                "exit_code": proc.returncode,
                "duration_sec": round(time.perf_counter() - t0, 2),
                "stderr_tail": (proc.stderr or "")[-400:],
            })
        except subprocess.TimeoutExpired:
            out["results"].append({
                "module": label,
                "status": "TIMEOUT",
                "duration_sec": round(time.perf_counter() - t0, 2),
            })
        except Exception as exc:
            out["results"].append({"module": label, "status": "ERROR", "error": str(exc)[:200]})
    return out


def main() -> int:
    import requests

    session = requests.Session()
    session.headers["User-Agent"] = "NOVUS-UX-Audit/1.0"

    report: Dict[str, Any] = {
        "phase": PHASE,
        "generated_at_utc": _utc(),
        "base_url": BASE,
        "process_diagnosis": {},
        "login": {},
        "module_navigation": [],
        "critical_paths": [],
    }

    try:
        import psutil

        listeners = []
        for p in psutil.process_iter(["pid", "cmdline"]):
            cmd = " ".join(p.info.get("cmdline") or [])
            if "main.py" not in cmd:
                continue
            try:
                for c in p.connections(kind="inet"):
                    if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN":
                        listeners.append(p.info["pid"])
            except Exception:
                pass
        report["process_diagnosis"] = {
            "listeners_port_5000": listeners,
            "single_instance": len(listeners) == 1,
        }
    except Exception as exc:
        report["process_diagnosis"] = {"error": str(exc)[:200]}

    report["login"] = _login_flow(session)
    client = report["login"].pop("_test_client", None)
    if client is not None:
        report["module_navigation"] = _module_navigation_test_client(client)
    else:
        report["module_navigation"] = _module_navigation(session)

    crit = ["/login", "/dashboard", "/network", "/amenazas", "/vulnerabilidades",
            "/security-operations-center", "/health-center"]
    for path in crit:
        report["critical_paths"].append(_timed_request(session, "GET", f"{BASE}{path}", allow_redirects=True))

    out_name = f"UX_PERFORMANCE_{PHASE}.json"
    out_path = OUT / out_name
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    login_path = OUT / "LOGIN_PERFORMANCE.json"
    login_path.write_text(json.dumps(report["login"], indent=2, ensure_ascii=False), encoding="utf-8")

    mod_path = OUT / "MODULE_NAVIGATION_PERFORMANCE.json"
    mod_path.write_text(json.dumps(report["module_navigation"], indent=2, ensure_ascii=False), encoding="utf-8")

    proof_path = OUT / "LIVE_NAVIGATION_PROOF.json"
    proof_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    if PHASE == "AFTER":
        reg = _regression_probes()
        (OUT / "REGRESSION_TESTS.json").write_text(json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")
    elif os.environ.get("NOVUS_UX_RUN_REGRESSION") == "1":
        reg = _regression_probes()
        (OUT / "REGRESSION_TESTS.json").write_text(json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps({
        "phase": PHASE,
        "output": str(out_path),
        "login_get_ms": report["login"]["login_get"].get("total_ms"),
        "login_to_dashboard_ms": (report["login"].get("dashboard_after_login") or {}).get("login_post_to_dashboard_ms"),
        "dashboard_ms": (report["login"].get("dashboard_after_login") or {}).get("total_ms"),
        "slowest_modules": sorted(
            [m for m in report["module_navigation"] if m.get("total_ms")],
            key=lambda x: x["total_ms"],
            reverse=True,
        )[:5],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
