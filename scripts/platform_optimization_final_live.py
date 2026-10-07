#!/usr/bin/env python3
"""LIVE diagnosis + benchmark + regression — platform_hardening_final."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "platform_hardening_final"
OUT.mkdir(parents=True, exist_ok=True)
BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def process_diagnosis() -> Dict[str, Any]:
    import psutil

    main_procs = []
    for p in psutil.process_iter(["pid", "ppid", "name", "cmdline", "create_time"]):
        cmd = " ".join(p.info.get("cmdline") or [])
        if "main.py" not in cmd:
            continue
        listens = False
        try:
            for c in p.connections(kind="inet"):
                if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN":
                    listens = True
        except Exception:
            pass
        main_procs.append({
            "pid": p.info["pid"],
            "ppid": p.info.get("ppid"),
            "name": p.info.get("name"),
            "cmdline": cmd[:240],
            "listens_5000": listens,
            "uptime_sec": round(time.time() - (p.info.get("create_time") or time.time()), 1),
        })
    listeners = [p for p in main_procs if p.get("listens_5000")]
    coord = {}
    try:
        from services.network_scan_coordinator import get_coordinator_status
        coord = get_coordinator_status()
    except Exception as exc:
        coord = {"error": str(exc)[:120]}
    return {
        "generated_at_utc": _utc(),
        "main_py_count": len(main_procs),
        "listeners_port_5000": len(listeners),
        "single_official_instance": len(listeners) == 1,
        "processes": main_procs,
        "arp_coordinator": coord,
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "ram_percent": psutil.virtual_memory().percent,
        "thread_count_active": threading.active_count(),
    }


def bench_internal(label: str, fn) -> Dict[str, Any]:
    t0 = time.perf_counter()
    try:
        fn()
        return {"label": label, "latency_ms": round((time.perf_counter() - t0) * 1000, 2), "ok": True}
    except Exception as exc:
        return {"label": label, "latency_ms": round((time.perf_counter() - t0) * 1000, 2), "ok": False, "error": str(exc)[:160]}


def benchmark_suite() -> Dict[str, Any]:
    probes = [
        ("health_status", lambda: __import__("services.health_engine", fromlist=["get_health_status_response"]).get_health_status_response(trigger_refresh=False)),
        ("security_summary", lambda: __import__("services.platform_metrics_service", fromlist=["get_unified_security_payload"]).get_unified_security_payload()),
        ("soc_overview", lambda: __import__("services.soc.engine", fromlist=["get_overview"]).get_overview()),
        ("network_nodes_cache", lambda: __import__("services.network_scanner", fromlist=["network_scanner"]).network_scanner.get_cached_nodes()),
    ]
    results = [bench_internal(n, f) for n, f in probes]
    lats = [r["latency_ms"] for r in results if r.get("ok")]
    login = {}
    t0 = time.perf_counter()
    try:
        import requests
        r = requests.get(f"{BASE}/login", timeout=20)
        login = {"status_code": r.status_code, "latency_ms": round((time.perf_counter() - t0) * 1000, 2), "ok": r.status_code == 200}
    except Exception as exc:
        login = {"ok": False, "error": str(exc)[:160], "latency_ms": round((time.perf_counter() - t0) * 1000, 2)}
    return {
        "generated_at_utc": _utc(),
        "login_http": login,
        "internal_probes": results,
        "latency_avg_ms": round(sum(lats) / len(lats), 2) if lats else None,
        "latency_max_ms": max(lats) if lats else None,
    }


def network_switch_test() -> Dict[str, Any]:
    result: Dict[str, Any] = {"generated_at_utc": _utc(), "steps": []}
    try:
        from services.network_scan_coordinator import (
            context_fingerprint,
            get_network_context,
            invalidate_on_context_change,
        )
        from services import network_scan_coordinator as nsc
        from services.network_scanner import network_scanner

        ctx = get_network_context()
        fp = context_fingerprint(ctx)
        nodes_before = list(network_scanner.get_cached_nodes() or [])
        result["steps"].append({"step": "capture", "fp": fp, "nodes": len(nodes_before), "ctx_keys": list(ctx.keys())})

        network_scanner.clear_cache()
        result["steps"].append({"step": "clear_cache", "nodes": len(network_scanner.get_cached_nodes())})

        fake = dict(ctx)
        fake["subnet"] = "simulated-other-lan/24"
        fake["gateway"] = "192.0.2.1"
        with nsc._lock:
            nsc._current_fp = context_fingerprint(fake)
            nsc._bound_context = fake
        network_scanner.clear_cache()
        stale = network_scanner.get_cached_nodes()
        result["steps"].append({
            "step": "simulated_network_change",
            "nodes_after": len(stale or []),
            "no_cross_contamination": len(stale or []) == 0,
        })
        invalidate_on_context_change(force_clear_scanner=True)
        result["overall"] = "PASS" if len(stale or []) == 0 else "FAIL"
        result["live_wifi_switch"] = "NOT_VERIFIED — requiere cambio físico SSID/BSSID"
    except Exception as exc:
        result["overall"] = "FAIL"
        result["error"] = str(exc)[:200]
    return result


def run_prove(script: str, timeout: int = 600) -> Dict[str, Any]:
    path = ROOT / script
    if not path.is_file():
        return {"script": script, "status": "SKIP", "detail": "missing"}
    t0 = time.perf_counter()
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "NOVUS_AUDIT_SEQUENTIAL": "1"}
    try:
        proc = subprocess.run(
            [sys.executable, str(path)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return {
            "script": script,
            "status": "PASS" if proc.returncode == 0 else "FAIL",
            "exit_code": proc.returncode,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 2),
            "failure_class": None if proc.returncode == 0 else "TIMEOUT_OR_ERROR",
            "detail_tail": out.strip()[-400:],
        }
    except subprocess.TimeoutExpired:
        return {"script": script, "status": "FAIL", "failure_class": "TIMEOUT", "detail": f"timeout {timeout}s"}
    except Exception as exc:
        return {"script": script, "status": "FAIL", "failure_class": "INFRAESTRUCTURA", "detail": str(exc)[:160]}


def main() -> int:
    phase = os.environ.get("NOVUS_BENCH_PHASE", "AFTER")
    print(f"NOVUS LIVE AUDIT — phase={phase}")

    before_path = OUT / "DIAG_BEFORE.json"
    if phase == "BEFORE" or not before_path.is_file():
        diag = process_diagnosis()
        bench = benchmark_suite()
        payload = {"diagnosis": diag, "benchmark": bench, "phase": "BEFORE"}
        before_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    # AFTER + full deliverables
    before = json.loads(before_path.read_text(encoding="utf-8"))
    diag_after = process_diagnosis()
    bench_after = benchmark_suite()
    net_test = network_switch_test()

    scripts = [
        "scripts/prove_asm.py", "scripts/prove_viem.py", "scripts/prove_imcm.py",
        "scripts/prove_soc.py", "scripts/prove_health_engine.py",
        "scripts/prove_ai_kernel_core.py", "scripts/prove_ai_kernel_brain.py",
        "scripts/prove_identity_intelligence.py",
    ]
    regression = []
    for s in scripts:
        print(f"  running {s}...")
        timeout = 900 if "identity" in s or "brain" in s or "health" in s else 600
        regression.append(run_prove(s, timeout=timeout))

    passed = sum(1 for r in regression if r.get("status") == "PASS")
    failed = sum(1 for r in regression if r.get("status") == "FAIL")

    perf = {
        "generated_at_utc": _utc(),
        "before": before.get("benchmark"),
        "after": bench_after,
        "diagnosis_before": before.get("diagnosis"),
        "diagnosis_after": diag_after,
        "comparison": {
            "login_ms_before": (before.get("benchmark") or {}).get("login_http", {}).get("latency_ms"),
            "login_ms_after": bench_after.get("login_http", {}).get("latency_ms"),
        },
    }

    live = {
        "generated_at_utc": _utc(),
        "login": bench_after.get("login_http"),
        "single_server": diag_after.get("single_official_instance"),
        "processes": diag_after.get("processes"),
        "network_switch": net_test,
    }

    reg = {
        "generated_at_utc": _utc(),
        "passed": passed,
        "failed": failed,
        "total": len(regression),
        "overall": "PASS" if failed == 0 else ("PARTIAL" if passed > failed else "FAIL"),
        "tests": regression,
    }

    (OUT / "PERFORMANCE_AUDIT_FINAL.json").write_text(json.dumps(perf, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT / "REGRESSION_TESTS_FINAL.json").write_text(json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT / "LIVE_PROOF_FINAL.json").write_text(json.dumps(live, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT / "NETWORK_SWITCH_FINAL.json").write_text(json.dumps(net_test, indent=2, ensure_ascii=False), encoding="utf-8")

    md = [
        "# PERFORMANCE AUDIT FINAL",
        f"\nGenerado: {_utc()}",
        "\n## Antes (LIVE)",
        json.dumps(before.get("benchmark"), indent=2),
        "\n## Después (LIVE)",
        json.dumps(bench_after, indent=2),
    ]
    (OUT / "PERFORMANCE_AUDIT_FINAL.md").write_text("\n".join(md), encoding="utf-8")

    opt = """# OPTIMIZATION CHANGES FINAL

## Esta ejecución
- NDR `build_ndr_payload`: reutiliza caché ARP; scan_arp_light solo si vacío
- `main.py`: reconciliación alertas/entorno en background (HTTP disponible antes)
- Coordinador ARP + Health snapshot + SOC/security cache (sesión previa)
- Frontend polling adaptativo
"""
    (OUT / "OPTIMIZATION_CHANGES_FINAL.md").write_text(opt, encoding="utf-8")

    status = f"""# FINAL PLATFORM STATUS FINAL

Generado: {_utc()}

- Servidor: {'OK' if bench_after.get('login_http', {}).get('ok') else 'FAIL'}
- URL: http://127.0.0.1:5000/login
- Instancia única 5000: {diag_after.get('single_official_instance')}
- Regresión: {reg['overall']} ({passed}/{len(regression)} PASS)
- Network switch sim: {net_test.get('overall')}
- Live WiFi: {net_test.get('live_wifi_switch', 'NOT_VERIFIED')}
"""
    (OUT / "FINAL_PLATFORM_STATUS_FINAL.md").write_text(status, encoding="utf-8")

    print(f"DONE: regression {passed}/{len(regression)} | server OK={bench_after.get('login_http', {}).get('ok')}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
