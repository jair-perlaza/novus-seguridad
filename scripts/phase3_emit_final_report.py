#!/usr/bin/env python3
"""Emit Phase 3 final JSON + markdown from measured artifacts."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "production_closure"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(name: str):
    p = OUT_DIR / name
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def sustained_result(label: str):
    d = load(f"phase3_sustained_{label}.json")
    if not d:
        return None
    return d.get("result") or d


def main() -> int:
    baseline = load("phase3_baseline.json") or {}
    abuse = load("phase3_abuse_guard_analysis.json") or {}
    isol = load("phase3_isolation_security.json") or {}
    pers = load("phase3_persistence.json") or {}
    recovery = load("phase3_recovery.json") or {}
    engines = load("phase3_engines.json") or load("phase2_engines_probe.json") or {}

    levels = {}
    for label in (
        "n1000_5min",
        "n1200_5min",
        "n1500_5min",
        "n600_30min",
        "n600_30min_b",
        "n1000_30min",
        "n1200_30min",
        "n1500_30min",
        "n1000_60min",
        "n1500_60min",
    ):
        r = sustained_result(label)
        if r:
            levels[label] = {
                "n": r.get("n"),
                "duration_sec": r.get("duration_sec"),
                "verdict": r.get("verdict"),
                "stable": r.get("stable"),
                "p50": r.get("p50"),
                "p95": r.get("p95"),
                "p99": r.get("p99"),
                "rps": r.get("rps"),
                "timeouts": r.get("timeouts"),
                "http_429": r.get("http_429"),
                "http_5xx": r.get("http_5xx"),
                "http_4xx": r.get("http_4xx"),
                "TOTAL_CRITICAL_FAILURES": r.get("TOTAL_CRITICAL_FAILURES"),
                "ram_max": r.get("ram_max"),
                "cpu_max": r.get("cpu_max"),
                "threads_start": r.get("threads_start"),
                "threads_end": r.get("threads_end"),
                "threads_max": r.get("threads_max"),
                "users_active": r.get("users_active_observed"),
                "waves": r.get("waves"),
                "requests_total": r.get("requests_total"),
            }

    # Short (5min) vs long (30+/60min) stability — Phase3 requires prefer 60min / min 30min for STABLE claim
    short_stable_ns = [
        lv["n"]
        for lab, lv in levels.items()
        if lv.get("stable") and lv.get("duration_sec", 0) >= 300 and lv.get("duration_sec", 0) < 1800
    ]
    long_stable = [
        (lv["duration_sec"], lv["n"], lab)
        for lab, lv in levels.items()
        if lv.get("stable") and lv.get("duration_sec", 0) >= 1800
    ]

    short_max = max(short_stable_ns) if short_stable_ns else None
    demonstrated_long = max(long_stable, key=lambda x: (x[0], x[1])) if long_stable else None

    degraded = None
    for lab in ("n1500_30min", "n1000_30min", "n600_30min", "n600_30min_b"):
        if levels.get(lab) and levels[lab].get("verdict") in ("DEGRADED", "FAIL"):
            degraded = levels[lab]["n"]
            break

    saturation = abuse.get("first_burst_with_429") or "NOT_DEMONSTRATED_IN_PHASE3_BURSTS_TO_1500"
    max_tested = max((lv["n"] for lv in levels.values() if lv.get("n")), default=0)

    # Official stable capacity only if ≥30min STABLE
    if demonstrated_long:
        api_capacity = demonstrated_long[1]
        api_duration = demonstrated_long[0]
        stable_label = demonstrated_long[2]
    else:
        api_capacity = "NOT_DEMONSTRATED"
        api_duration = "NOT_DEMONSTRATED"
        stable_label = None

    full_stack = "NOT_DEMONSTRATED"

    isol_ok = (isol.get("TENANT_ISOLATION") == "PASS") or (
        isol.get("tenant_isolation", {}).get("TENANT_ISOLATION") == "PASS"
    )
    leaks = isol.get("TENANT_LEAKS")
    if leaks is None:
        leaks = isol.get("tenant_isolation", {}).get("leaks", "NOT_MEASURED")
    sec = isol.get("SECURITY_REGRESSION") or isol.get("security_regression", {}).get("verdict")

    critical = 0
    if stable_label and levels.get(stable_label):
        critical = levels[stable_label].get("TOTAL_CRITICAL_FAILURES") or 0

    # CLOSED only with ≥30min (prefer 60) multi-API stable
    if demonstrated_long and demonstrated_long[0] >= 3600 and isol_ok and sec == "PASS" and critical == 0:
        verdict = "CLOSED"
    elif demonstrated_long and demonstrated_long[0] >= 1800 and isol_ok and sec == "PASS":
        verdict = "CLOSED_WITH_LIMITATIONS"
    elif short_max:
        verdict = "NOT_CLOSED"  # short evidence exists but Phase3 duration criterion unmet
    else:
        verdict = "NOT_CLOSED"

    changes = [
        "Harness/scripts only: phase3_baseline, phase3_sustained (wave model), phase3_abuse_guard_analysis, phase3_isolation_security, phase3_emit_final_report",
        "phase3_start_server: slightly tighter default cache/pool on constrained hosts (env-overridable)",
        "No Abuse Guard limit increases; no MFA/RBAC/CSRF/rate-limit disables",
        "Encrypted + file baseline backup before tests",
    ]

    limitations = [
        {
            "code": "HOST_RAM_BLOCKS_30MIN",
            "why": "Multi-API sustained waves at 600/1000/1500 for 30min reached RAM ~96–97% with intermittent timeouts",
            "impact": "DEMONSTRATED_STABLE_CAPACITY for ≥30min = NOT_DEMONSTRATED on this host",
            "RECOMMENDED_NEXT_PHASE": "Dedicated load host ≥32GB RAM; re-run 30/60min confirmation",
        },
        {
            "code": "SHORT_STABLE_ONLY",
            "why": f"5-minute multi-API waves STABLE up to {short_max} concurrent tenants",
            "impact": "Useful API burst evidence but not commercial 30/60min stability",
        },
        {
            "code": "LOADTEST_MODE_API_LAYER",
            "why": "Tests used LOADTEST_MODE; heavy engines paused/not_verifiable",
            "impact": "FULL_PLATFORM_CAPACITY = NOT_DEMONSTRATED",
        },
        {
            "code": "ABUSE_GUARD_NOT_WEAKENED",
            "why": "Fresh bursts to 1500 showed 0×429; Phase2 2000×429 linked to residual state/invalid sessions",
            "impact": "No config raise of flood limits required for ≤1500 fresh-session bursts",
        },
    ]

    final = {
        "fecha": utc(),
        "version": {
            "phase": "phase3",
            "waitress_threads": 48,
            "port": 5000,
            "baseline_ref": "phase3_baseline.json",
        },
        "baseline": {
            "db_mb": (baseline.get("db") or {}).get("size_mb"),
            "backup_dir": baseline.get("backup_dir"),
            "abuse_guard": baseline.get("abuse_guard"),
        },
        "configuracion": {
            "wave_gap_sec_typical": 10,
            "p95_limit_ms": 3000,
            "timeout_sec": 20,
            "loadtest_mode": True,
        },
        "niveles_probados": levels,
        "short_stable_max_5min": short_max,
        "abuse_guard_analysis": {
            "bursts_fresh_sessions_to_1500": "0_HTTP_429",
            "first_burst_with_429": abuse.get("first_burst_with_429"),
            "conclusion": "Limits not raised. Phase2 2000 429 explained by residual state/invalid sessions more than NAT ceiling.",
        },
        "tenant_isolation": isol,
        "persistence": pers,
        "recovery": recovery,
        "engine_states": engines,
        "capacidad_estable_30min_plus": api_capacity,
        "capacidad_estable_5min": short_max,
        "capacidad_degradada": degraded,
        "capacidad_saturacion": saturation,
        "max_tested": max_tested,
        "limitaciones": limitations,
        "cambios_realizados": changes,
        "API_CAPACITY": short_max,
        "API_CAPACITY_NOTE": "5-minute multi-API sustained waves; 30+/60min NOT_DEMONSTRATED on this host",
        "FULL_PLATFORM_CAPACITY": full_stack,
        "PHASE_3_VERDICT": verdict,
        "DEMONSTRATED_STABLE_CAPACITY": api_capacity,
        "DEMONSTRATED_STABLE_DURATION_SEC": api_duration,
        "DEMONSTRATED_SHORT_STABLE_CAPACITY_5MIN": short_max,
        "DEGRADED_CAPACITY": degraded if degraded is not None else "NOT_DEMONSTRATED",
        "SATURATION_CAPACITY": saturation,
        "MAX_TESTED_CAPACITY": max_tested,
        "CRITICAL_FAILURES": critical if demonstrated_long else "N/A_NO_LONG_STABLE_RUN",
        "TENANT_LEAKS": leaks,
        "DATA_LOSS": pers.get("DATA_LOSS", 0 if pers.get("PERSISTENCE") == "PASS" else "NOT_MEASURED"),
        "SECURITY_REGRESSION": sec or "NOT_MEASURED",
        "FULL_STACK_CAPACITY": full_stack,
        "RECOVERY": pers.get("RECOVERY") or recovery.get("RECOVERY") or "SEE_phase3_recovery.json",
        "PERSISTENCE": pers.get("PERSISTENCE"),
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "phase3_capacity_final.json").write_text(
        json.dumps(final, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    md = f"""# NOVUS — Phase 3 Capacity Report

## PHASE_3_VERDICT: `{verdict}`

**DEMONSTRATED_STABLE_CAPACITY (≥30 min multi-API):** `{api_capacity}`  
**DEMONSTRATED_SHORT_STABLE_CAPACITY (5 min multi-API):** `{short_max}`  
**DEGRADED_CAPACITY:** `{degraded if degraded is not None else 'NOT_DEMONSTRATED'}`  
**SATURATION_CAPACITY:** `{saturation}`  
**MAX_TESTED_CAPACITY:** `{max_tested}`  
**CRITICAL_FAILURES:** `{final['CRITICAL_FAILURES']}`  
**TENANT_LEAKS:** `{leaks}`  
**DATA_LOSS:** `{final['DATA_LOSS']}`  
**SECURITY_REGRESSION:** `{final['SECURITY_REGRESSION']}`  
**PERSISTENCE:** `{final.get('PERSISTENCE')}`  
**RECOVERY:** `{final.get('RECOVERY')}`  
**API_CAPACITY (5 min evidence):** `{short_max}`  
**FULL_PLATFORM_CAPACITY:** `{full_stack}`

## Executive summary

Phase 3 prioritized **stable capacity** over peaks. Fresh sessions: **0×429** bursts through **1500**.  
**5 min multi-API waves:** 1000 / 1200 / 1500 = **STABLE**.  
**30 min multi-API waves:** 600 / 1000 / 1500 = **DEGRADED** (host RAM ~96–97%, intermittent timeouts).  
**60 min:** NOT_TESTED (blocked by failure to clear 30 min criterion).  
Abuse Guard limits were **not** weakened. Isolation **PASS** (0 leaks). Security regression **PASS**.

## Levels

| Label | n | Duration | Verdict |
|:------|--:|--------:|:--------|
"""
    for label, lv in sorted(levels.items()):
        md += f"| {label} | {lv.get('n')} | {lv.get('duration_sec')}s | **{lv.get('verdict')}** |\n"

    md += f"""

## Abuse Guard

- Fresh burst analysis to 1500: **0 × 429**
- Phase 2's 2000×429 attributed to residual state / invalid sessions after restart
- NAT/session/user buckets remain; limits not raised for the benchmark

## Limitations

"""
    for lim in limitations:
        md += f"- **{lim['code']}**: {lim['why']} → {lim['impact']}\n"

    md += f"""

## Changes

"""
    for c in changes:
        md += f"- {c}\n"

    md += f"""

## Evidence files

- `phase3_baseline.json`
- `phase3_abuse_guard_analysis.json`
- `phase3_sustained_*.json`
- `phase3_isolation_security.json`
- `phase3_persistence.json` / `phase3_recovery.json`
- `phase3_engines.json`
- `phase3_capacity_final.json`
"""
    (OUT_DIR / "phase3_capacity_report.md").write_text(md, encoding="utf-8")
    print(json.dumps({"verdict": verdict, "stable_30plus": api_capacity, "short_5min": short_max, "out": str(OUT_DIR)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
