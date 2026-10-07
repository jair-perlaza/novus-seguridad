"""Benchmark de rendimiento NOVUS — medición reproducible Fase 1/2."""
import json
import os
import statistics
import sys
import time

import psutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_benchmark(label: str = "current") -> dict:
    from main import app

    proc = psutil.Process(os.getpid())
    mem_start = proc.memory_info().rss / (1024 * 1024)

    client = app.test_client()
    client.get("/login")
    client.post(
        "/login",
        data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!"},
        follow_redirects=False,
    )

    def bench(path: str, n: int = 3) -> dict:
        times = []
        status = None
        for _ in range(n):
            t0 = time.perf_counter()
            r = client.get(path)
            times.append((time.perf_counter() - t0) * 1000)
            status = r.status_code
        return {
            "path": path,
            "status": status,
            "ms_min": round(min(times)),
            "ms_avg": round(statistics.mean(times)),
            "ms_max": round(max(times)),
        }

    paths = [
        "/dashboard",
        "/api/dashboard/live",
        "/api/security/summary",
        "/api/system/sector-shield/status",
        "/api/system/sector-protection",
        "/api/threat-intel/dashboard",
        "/api/network/nodes",
        "/api/network/ndr",
        "/api/network/topology",
        "/vulnerabilidades",
        "/network",
        "/topology",
        "/inteligencia",
    ]

    t0 = time.perf_counter()
    login_r = client.post(
        "/login",
        data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!"},
        follow_redirects=False,
    )
    login_ms = round((time.perf_counter() - t0) * 1000)

    # Kernel IA response time
    kernel_ms = None
    try:
        t0 = time.perf_counter()
        kr = client.post(
            "/api/ai/chat",
            json={"message": "estado de amenazas runtime"},
            content_type="application/json",
        )
        kernel_ms = round((time.perf_counter() - t0) * 1000)
        kernel_status = kr.status_code
    except Exception:
        kernel_status = None

    # Report generation (si hay reportes)
    report_ms = None
    try:
        t0 = time.perf_counter()
        rr = client.get("/api/reports/list")
        report_ms = round((time.perf_counter() - t0) * 1000)
        report_status = rr.status_code
    except Exception:
        report_status = None

    # Motores internos (telemetría)
    motor_ms = {}
    try:
        from services.network_ndr_service import build_ndr_payload
        from services.topology_service import build_topology_payload
        from services.novus_security_integration import novus_security

        t0 = time.perf_counter()
        build_ndr_payload(force_refresh=False)
        motor_ms["ndr_payload"] = round((time.perf_counter() - t0) * 1000, 1)

        t0 = time.perf_counter()
        build_topology_payload(force_refresh=False)
        motor_ms["topology_payload"] = round((time.perf_counter() - t0) * 1000, 1)

        t0 = time.perf_counter()
        novus_security.get_cached_security_summary()
        motor_ms["security_summary_cached"] = round((time.perf_counter() - t0) * 1000, 1)
    except Exception as exc:
        motor_ms["error"] = str(exc)[:200]

    mem_end = proc.memory_info().rss / (1024 * 1024)

    report = {
        "label": label,
        "cpu_pct": round(psutil.cpu_percent(1), 1),
        "ram_pct": round(psutil.virtual_memory().percent, 1),
        "ram_process_mb": round(mem_end, 1),
        "ram_process_delta_mb": round(mem_end - mem_start, 1),
        "login_ms": login_ms,
        "login_status": login_r.status_code,
        "kernel_ia_ms": kernel_ms,
        "kernel_ia_status": kernel_status,
        "reports_list_ms": report_ms,
        "reports_list_status": report_status,
        "motor_internal_ms": motor_ms,
        "endpoints": [bench(p) for p in paths],
    }
    return report


if __name__ == "__main__":
    label = sys.argv[1] if len(sys.argv) > 1 else "after"
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(__file__), f"performance_{label}.json"
    )
    data = run_benchmark(label)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    print(json.dumps(data, ensure_ascii=False, indent=2))
