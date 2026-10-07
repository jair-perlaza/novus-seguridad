#!/usr/bin/env python3
"""
Pruebas de rendimiento del Kernel IA — mide tiempos por nivel de análisis.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime

sys.path.insert(0, ".")

from services.kernel_agent import kernel_agent
from services.kernel_coordinator import kernel_coordinator
from services.kernel_planner import build_plan

SESSION = "perf-test-session"

CASES = [
    ("N1", "Hola", 2.0),
    ("N1", "Estado del sistema", 2.0),
    ("N1", "CPU y RAM", 2.0),
    ("N1", "Conexiones activas", 2.0),
    ("N1", "Estado de la red", 2.0),
    ("N2", "Escanear la red", 15.0),
    ("N2", "Buscar vulnerabilidades", 15.0),
    ("N2", "Analizar procesos", 15.0),
    ("N3", "Escanea completamente mi portátil", 45.0),
    ("N3", "Realizar Deep Scan", 45.0),
]


def wait_operation(op_id: str, timeout: float = 120.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = kernel_coordinator.get_status(op_id)
        if st and st.get("status") in ("completed", "error"):
            return kernel_coordinator.get_result(op_id) or {"reply": st.get("live_message", "error")}
        time.sleep(0.5)
    return {"reply": "TIMEOUT", "error": True}


def run_case(level: str, message: str, budget: float) -> dict:
    plan = build_plan(message)
    t0 = time.time()
    result = kernel_agent.process(SESSION, message, user_id=1, user_email="perf@test.local")
    elapsed = time.time() - t0

    if result.get("working") and result.get("operation_id"):
        op_result = wait_operation(result["operation_id"], timeout=max(budget * 3, 60))
        elapsed = time.time() - t0
        result = {**result, **(op_result or {})}

    perf_level = result.get("performance_level") or plan.performance_level
    ok = elapsed <= budget
    return {
        "level": level,
        "message": message,
        "perf_level": perf_level,
        "elapsed_sec": round(elapsed, 2),
        "budget_sec": budget,
        "pass": ok,
        "cache_hits": result.get("cache_hits", 0),
        "has_reply": bool(result.get("reply")),
    }


def main():
    print("=" * 70)
    print("NOVUS Kernel IA — Pruebas de rendimiento")
    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 70)

    results = []
    for level, message, budget in CASES:
        print(f"\n[{level}] {message!r} (objetivo ≤{budget}s)...", flush=True)
        try:
            row = run_case(level, message, budget)
            results.append(row)
            status = "PASS" if row["pass"] else "SLOW"
            print(
                f"  → {status} | {row['elapsed_sec']}s | N{row['perf_level']} | "
                f"caché={row['cache_hits']} | reply={'sí' if row['has_reply'] else 'no'}"
            )
        except Exception as exc:
            print(f"  → ERROR: {exc}")
            results.append({"level": level, "message": message, "pass": False, "error": str(exc)})

    print("\n" + "=" * 70)
    print("RESUMEN POR NIVEL")
    print("=" * 70)
    for lvl in ("N1", "N2", "N3"):
        rows = [r for r in results if r.get("level") == lvl and "elapsed_sec" in r]
        if not rows:
            continue
        times = [r["elapsed_sec"] for r in rows]
        passed = sum(1 for r in rows if r.get("pass"))
        print(
            f"{lvl}: {passed}/{len(rows)} dentro de objetivo | "
            f"min={min(times):.2f}s avg={sum(times)/len(times):.2f}s max={max(times):.2f}s"
        )

    total_pass = sum(1 for r in results if r.get("pass"))
    print(f"\nTotal: {total_pass}/{len(results)} PASS")
    return 0 if total_pass >= len(results) * 0.6 else 1


if __name__ == "__main__":
    raise SystemExit(main())
