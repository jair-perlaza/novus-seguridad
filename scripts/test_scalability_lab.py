#!/usr/bin/env python3
"""
Pruebas de escalabilidad NOVUS — dispositivos simulados crecientes.
Documenta CPU, RAM, latencia y límite operativo observado.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "scalability")
OUT_JSON = os.path.join(OUT_DIR, "scalability_report.json")

DEVICE_COUNTS = [25, 50, 100, 150]


def _make_nodes(count: int) -> list:
    return [
        {
            "ip": f"10.99.{i // 256}.{i % 256}",
            "mac": f"02:00:00:{(i >> 16) & 0xff:02x}:{(i >> 8) & 0xff:02x}:{i & 0xff:02x}",
            "vendor": "SimDevice" if i % 3 else "",
            "is_unknown": i % 4 == 0,
            "open_ports": [{"port": 80}] if i % 10 == 0 else [],
        }
        for i in range(1, count + 1)
    ]


def main() -> int:
    import psutil
    from services.network_ndr_service import analyze_behavior, build_ndr_payload

    print("=== SCALABILITY LAB ===\n")
    proc = psutil.Process()
    mem_start = proc.memory_info().rss / (1024 * 1024)
    cpu_start = psutil.cpu_percent(interval=0.3)

    runs = []
    limit_observed = None
    stable = True

    for count in DEVICE_COUNTS:
        nodes = _make_nodes(count)
        t0 = time.perf_counter()
        try:
            alerts = analyze_behavior(nodes, {"local_ip": "10.99.0.1", "gateway": "10.99.0.254"})
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
            mem_now = proc.memory_info().rss / (1024 * 1024)
            cpu_now = psutil.cpu_percent(interval=0.2)
            run_ok = elapsed_ms < 30000
            if not run_ok:
                stable = False
                if limit_observed is None:
                    limit_observed = count
            runs.append({
                "device_count": count,
                "pass": run_ok,
                "analyze_behavior_ms": elapsed_ms,
                "alerts_generated": len(alerts),
                "ram_mb": round(mem_now, 2),
                "cpu_percent": cpu_now,
                "hostile_density_alert": any("HOSTILE-DENSITY" in a.get("id", "") for a in alerts),
            })
            print(f"  [{count} devices] {elapsed_ms}ms, alerts={len(alerts)}, RAM={mem_now:.0f}MB")
        except Exception as exc:
            stable = False
            if limit_observed is None:
                limit_observed = count
            runs.append({"device_count": count, "pass": False, "error": str(exc)})

    t_ndr = time.perf_counter()
    try:
        build_ndr_payload(force_refresh=False)
        ndr_build_ms = round((time.perf_counter() - t_ndr) * 1000, 1)
    except Exception as exc:
        ndr_build_ms = -1

    scale_100_plus = any(r.get("pass") and r.get("device_count", 0) >= 100 for r in runs)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "device_counts_tested": DEVICE_COUNTS,
        "runs": runs,
        "summary": {
            "scale_100_plus_validated": scale_100_plus,
            "stable_through_150": stable,
            "operational_limit_devices": limit_observed or 150,
            "ndr_build_ms": ndr_build_ms,
            "ram_mb_start": round(mem_start, 2),
            "ram_mb_end": round(proc.memory_info().rss / (1024 * 1024), 2),
            "cpu_percent_start": cpu_start,
        },
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    print(f"\n=== SCALE 100+: {'PASS' if scale_100_plus else 'FAIL'} ===")
    print(f"Informe: {OUT_JSON}")
    return 0 if scale_100_plus else 1


if __name__ == "__main__":
    raise SystemExit(main())
