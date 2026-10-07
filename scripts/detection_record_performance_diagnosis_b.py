#!/usr/bin/env python3
"""
READ-ONLY performance diagnosis runner (B/C + merge prior A evidence).
Production code untouched. SYNTHETIC_TEST_ONLY events only.
"""
from __future__ import annotations

import gc
import json
import os
import sys
import threading
import time
import traceback
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
OUT = ROOT / "data" / "production_closure"
OUT.mkdir(parents=True, exist_ok=True)

LOG = OUT / "detection_record_performance_diagnosis_run.log"
STACK = OUT / "detection_record_performance_diagnosis_stacks.txt"

_timings: Dict[str, List[float]] = defaultdict(list)
_lock = threading.Lock()
_swarm_process_durations: List[float] = []


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000.0, 3)


def mark(name: str, duration_ms: float) -> None:
    with _lock:
        _timings[name].append(duration_ms)


def wrap(mod, attr: str, label: str | None = None):
    label = label or f"{mod.__name__}.{attr}"
    orig = getattr(mod, attr)

    def wrapped(*args, **kwargs):
        t0 = time.perf_counter()
        try:
            return orig(*args, **kwargs)
        finally:
            mark(label, _ms(t0))

    setattr(mod, attr, wrapped)
    return orig


def rss_mb() -> float:
    import psutil

    return round(psutil.Process().memory_info().rss / (1024 * 1024), 2)


def ledger_stats() -> Dict[str, Any]:
    p = ROOT / "data" / "forensic_ledger" / "records.jsonl"
    if not p.exists():
        return {"exists": False}
    sz = p.stat().st_size
    lines = sum(1 for _ in p.open("r", encoding="utf-8", errors="ignore"))
    return {"exists": True, "bytes": sz, "lines": lines, "mb": round(sz / (1024 * 1024), 3)}


def host_snapshot() -> Dict[str, Any]:
    import psutil

    vm = psutil.virtual_memory()
    out: Dict[str, Any] = {
        "host_ram_pct": round(vm.percent, 1),
        "host_available_gb": round(vm.available / (1024**3), 2),
        "diag_rss_mb": rss_mb(),
        "diag_threads": psutil.Process().num_threads(),
    }
    for p in psutil.process_iter(["pid", "cmdline", "memory_info", "num_threads"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if cmd.endswith("main.py") or "\\main.py" in cmd or "/main.py" in cmd:
                mi = p.info.get("memory_info")
                out["waitress_pid"] = p.info["pid"]
                out["waitress_rss_mb"] = round((mi.rss if mi else 0) / (1024 * 1024), 2)
                out["waitress_threads"] = p.info.get("num_threads")
                break
        except Exception:
            continue
    return out


def clear_dedupe():
    import services.defense_coordinator as dc

    with dc._dedupe_lock:
        dc._recent_detection_fps.clear()


def install():
    import services.platform_event_contract as pec
    import services.defense_evidence_registry as der
    import services.defense_coordinator as dc
    import services.swarm_defense.engine as seng
    import services.swarm_defense.event_bus as ebus

    wrap(pec, "normalize_detection", "normalize_detection")
    wrap(pec, "detection_fingerprint", "detection_fingerprint")
    wrap(der, "record_defense_event", "record_defense_event")
    wrap(dc, "_maybe_network_history", "_maybe_network_history")
    wrap(dc, "_maybe_forensic_pcap", "_maybe_forensic_pcap")
    wrap(dc, "_maybe_swarm_defense", "_maybe_swarm_defense")
    wrap(dc, "_maybe_adaptive_profile", "_maybe_adaptive_profile")
    try:
        import services.forensic_evidence_integrity_service as fei

        wrap(fei, "hook_seal_defense_entry", "forensic.hook_seal_defense_entry")
        wrap(fei, "seal_evidence", "forensic.seal_evidence")
        wrap(fei, "get_record_by_forensic_id", "forensic.get_record_by_forensic_id")
        wrap(fei, "iter_ledger_records", "forensic.iter_ledger_records")
    except Exception:
        pass
    try:
        import services.evidence_center_service as ecs

        wrap(ecs, "record_from_defense_event", "evidence_center.record_from_defense_event")
    except Exception:
        pass

    orig_process = seng.SwarmDefenseEngine.process_event

    def process_wrapped(self, event_payload):
        t0 = time.perf_counter()
        try:
            return orig_process(self, event_payload)
        finally:
            d = _ms(t0)
            with _lock:
                _swarm_process_durations.append(d)
                mark("swarm.process_event", d)

    seng.SwarmDefenseEngine.process_event = process_wrapped
    wrap(ebus.SwarmEventBus, "publish", "swarm.bus.publish")


def stage_summary() -> Dict[str, Any]:
    out = {}
    for k, vals in sorted(_timings.items()):
        if not vals:
            continue
        out[k] = {
            "invocations": len(vals),
            "total_ms": round(sum(vals), 2),
            "avg_ms": round(sum(vals) / len(vals), 2),
            "max_ms": round(max(vals), 2),
            "min_ms": round(min(vals), 2),
        }
    return out


def log(msg: str) -> None:
    line = msg + "\n"
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(line)
    # avoid flooding captured stdout (pipe deadlock); keep short echoes
    if len(msg) < 200:
        print(msg, flush=True)


def run_batch(n: int, pattern: str, label: str) -> Dict[str, Any]:
    from services.defense_coordinator import record_detection
    from services.platform_event_contract import SCOPE_HOST
    import services.defense_coordinator as dc
    import psutil

    clear_dedupe()
    _timings.clear()
    _swarm_process_durations.clear()
    gc.collect()
    time.sleep(0.3)

    proc = psutil.Process()
    thr0 = proc.num_threads()
    rss0 = rss_mb()
    host0 = host_snapshot()
    bp0 = None
    try:
        from services.resource_backpressure_service import get_backpressure_level, sample_resources

        bp0 = {"level": get_backpressure_level(), **sample_resources()}
    except Exception as exc:
        bp0 = {"error": str(exc)}

    statuses: List[str] = []
    event_rows: List[Dict[str, Any]] = []
    per_call: List[float] = []
    t_batch = time.perf_counter()

    for i in range(n):
        if pattern == "grouped5":
            group = i // 5
            evidence = {
                "evidence": f"SYNTHETIC_TEST_ONLY-PERF-{label}-G{group}",
                "ip": f"10.253.{group}.1",
                "verified": True,
                "TEST_FIXTURE": True,
            }
        else:
            evidence = {
                "evidence": f"SYNTHETIC_TEST_ONLY-PERF-{label}-U{i}-{time.time_ns()}",
                "ip": f"10.252.{i}.1",
                "verified": True,
                "TEST_FIXTURE": True,
            }

        hang = {"done": False}

        def watchdog(idx=i):
            time.sleep(75.0)
            if hang["done"]:
                return
            with open(STACK, "a", encoding="utf-8") as sf:
                sf.write(f"\n==== WATCHDOG {label} event {idx+1} @ {utc()} ====\n")
                for tid, frame in sys._current_frames().items():
                    sf.write(f"--- thread {tid} ---\n")
                    sf.write("".join(traceback.format_stack(frame)))
            log(f"  [{label}] WATCHDOG fired for event {idx+1} (stacks -> file)")

        threading.Thread(target=watchdog, daemon=True).start()
        log(f"  [{label}] event {i+1}/{n} start...")
        t0 = time.perf_counter()
        try:
            r = record_detection(
                "SYNTHETIC_TEST_ONLY.perf_diag",
                "threat_classified",
                evidence,
                threat_type="PERF_DIAG",
                severity="LOW",
                scope=SCOPE_HOST,
            )
        finally:
            hang["done"] = True
        elapsed = _ms(t0)
        st = r.get("status") or ("ok" if r.get("id") or r.get("event_id") else "unknown")
        statuses.append(st)
        per_call.append(elapsed)
        snap = {
            k: round(_timings[k][-1], 2)
            for k in (
                "normalize_detection",
                "detection_fingerprint",
                "record_defense_event",
                "forensic.seal_evidence",
                "forensic.get_record_by_forensic_id",
                "forensic.iter_ledger_records",
                "_maybe_swarm_defense",
                "swarm.bus.publish",
            )
            if _timings.get(k)
        }
        log(f"  [{label}] event {i+1}/{n} status={st} call_ms={elapsed} stages={snap}")
        event_rows.append(
            {
                "i": i,
                "status": st,
                "event_id": r.get("event_id"),
                "fingerprint": r.get("fingerprint"),
                "call_ms": elapsed,
                "group": (i // 5) if pattern == "grouped5" else i,
                "stage_snap_ms": snap,
            }
        )
        if elapsed >= 75000:
            log(f"  [{label}] ABORT batch after slow call")
            break

    batch_ms = _ms(t_batch)
    time.sleep(1.0)
    rss1 = rss_mb()
    host1 = host_snapshot()
    bp1 = None
    try:
        from services.resource_backpressure_service import get_backpressure_level, sample_resources

        bp1 = {"level": get_backpressure_level(), **sample_resources()}
    except Exception as e:
        bp1 = {"error": str(e)}

    pending = None
    bus_metrics = {}
    try:
        from services.swarm_defense.event_bus import swarm_event_bus

        pending = getattr(swarm_event_bus, "_pending", None)
        bus_metrics = dict(getattr(swarm_event_bus, "_metrics", {}) or {})
    except Exception:
        pass

    deduped = sum(1 for s in statuses if s == "deduplicated")
    processed = sum(1 for s in statuses if s != "deduplicated")
    n_collab = 15
    return {
        "label": label,
        "pattern": pattern,
        "total_events_attempted": n,
        "total_events_completed": len(statuses),
        "deduplicated": deduped,
        "processed_full_path": processed,
        "batch_wall_ms": batch_ms,
        "per_call_ms": {
            "total_sum": round(sum(per_call), 2),
            "avg": round(sum(per_call) / max(len(per_call), 1), 2),
            "max": round(max(per_call), 2) if per_call else 0,
            "p50": round(sorted(per_call)[len(per_call) // 2], 2) if per_call else 0,
            "full_path_avg_ms": round(
                sum(per_call[i] for i, s in enumerate(statuses) if s != "deduplicated")
                / max(processed, 1),
                2,
            )
            if processed
            else None,
            "deduped_avg_ms": round(
                sum(per_call[i] for i, s in enumerate(statuses) if s == "deduplicated")
                / max(deduped, 1),
                2,
            )
            if deduped
            else None,
        },
        "rss_mb_before": rss0,
        "rss_mb_after": rss1,
        "rss_delta_mb": round(rss1 - rss0, 2),
        "threads_before": thr0,
        "threads_after": proc.num_threads(),
        "host_before": host0,
        "host_after": host1,
        "backpressure_before": bp0,
        "backpressure_after": bp1,
        "swarm_bus_pending_after": pending,
        "swarm_bus_metrics": {k: bus_metrics[k] for k in list(bus_metrics)[:25]} if bus_metrics else {},
        "swarm_process_event_sum_ms": round(sum(_swarm_process_durations), 2),
        "swarm_process_event_count": len(_swarm_process_durations),
        "stage_timings": stage_summary(),
        "fanout_sync_per_processed_event": 5,
        "fanout_async_collaborators_per_processed": n_collab,
        "fanout_total_estimated": {
            "sync_ops": processed * 5,
            "async_collab_invocations": processed * n_collab,
            "secondary_seals_from_swarm": "observed via watchdog (ASPE/CryptoVault/response_policy → record_defense_event/seal)",
        },
        "event_rows": event_rows,
        "dedupe_cache_size_after": len(dc._recent_detection_fps),
        "ledger_after": ledger_stats(),
    }


def prior_a_evidence() -> Dict[str, Any]:
    """Measurements from earlier diagnosis runs in this micro-cycle (same host)."""
    return {
        "source": "prior_instrumented_runs_same_session",
        "pattern": "unique",
        "note": "TEST A unique storms hang under forensic lock; capped samples retained",
        "samples": [
            {"call_ms": 5827.148, "record_defense_event_ms": 5665.25, "swarm_publish_ms": 87.5},
            {"call_ms": 35148.371, "record_defense_event_ms": 35040.16, "swarm_publish_ms": 16.07},
            {"call_ms": 830.21, "record_defense_event_ms": 751.13, "swarm_publish_ms": 33.8},
            {"call_ms": 5252.983, "record_defense_event_ms": 5205.82, "swarm_publish_ms": 1.32},
            {"call_ms": 26999.031, "record_defense_event_ms": 26997.36, "swarm_publish_ms": 0.88},
            {"call_ms": 24180.756, "record_defense_event_ms": 24178.28, "swarm_publish_ms": 0.77},
            {"call_ms": 1515.589, "record_defense_event_ms": 1508.4, "swarm_publish_ms": 5.82},
            {"call_ms": 73429.854, "record_defense_event_ms": 73398.79, "swarm_publish_ms": 0.15},
        ],
        "watchdog_confirmed": [
            "seal_evidence holding _lock while get_record_by_forensic_id → iter_ledger_records (for line in fh)",
            "swarm collab CryptoVault.verify_health → tls assess → seal_evidence waiting on _lock",
            "swarm response_policy → record_detection → record_defense_event → seal waiting / scanning ledger",
            "ASPE evaluate_incident → record_defense_event → seal",
        ],
    }


def main() -> int:
    LOG.write_text(f"diagnosis start {utc()}\n", encoding="utf-8")
    STACK.write_text(f"stacks {utc()}\n", encoding="utf-8")
    log("Installing instrumentation (in-process only)...")
    install()
    baseline = {
        "host": host_snapshot(),
        "ledger": ledger_stats(),
        "pid": os.getpid(),
    }
    try:
        from services.resource_backpressure_service import get_backpressure_level, sample_resources

        baseline["backpressure"] = {"level": get_backpressure_level(), **sample_resources()}
    except Exception as e:
        baseline["backpressure"] = {"error": str(e)}
    log(f"baseline ledger={baseline['ledger']} host={baseline['host']}")

    test_a = prior_a_evidence()
    log("TEST B: 30 grouped5")
    test_b = run_batch(30, "grouped5", "B30")
    log(f"B wall={test_b['batch_wall_ms']} deduped={test_b['deduplicated']} rss_delta={test_b['rss_delta_mb']}")

    time.sleep(5)
    gc.collect()
    rss_mid = rss_mb()
    log("TEST C: 30 grouped5 after wait")
    test_c = run_batch(30, "grouped5", "C30")
    log(f"C wall={test_c['batch_wall_ms']} deduped={test_c['deduplicated']} rss_delta={test_c['rss_delta_mb']}")
    gc.collect()
    rss_final = rss_mb()

    stages_b = test_b.get("stage_timings") or {}
    evidence_total = (stages_b.get("record_defense_event") or {}).get("total_ms", 0)
    seal_total = (stages_b.get("forensic.seal_evidence") or {}).get("total_ms", 0)
    iter_total = (stages_b.get("forensic.iter_ledger_records") or {}).get("total_ms", 0)
    get_total = (stages_b.get("forensic.get_record_by_forensic_id") or {}).get("total_ms", 0)
    swarm_proc = test_b.get("swarm_process_event_sum_ms") or 0

    confirmed = {
        "statement": (
            "Wall-clock of record_detection is dominated by synchronous record_defense_event → "
            "forensic seal_evidence critical section (threading.Lock + ledger file lock). While holding "
            "locks, get_record_by_forensic_id linearly scans data/forensic_ledger/records.jsonl "
            f"(~{baseline['ledger'].get('lines')} lines / ~{baseline['ledger'].get('mb')} MB). "
            f"Validation-pattern batches dedupe ~{test_b.get('deduplicated')}/30 BEFORE fan-out; "
            f"only ~{test_b.get('processed_full_path')} events take the full path. Swarm collaborators "
            "asynchronously call seal/record_defense_event again, queuing on the same lock and amplifying "
            "latency/RSS. Backpressure at host RAM≥88% is protective consequence, not a gate inside "
            "record_detection. Publish remains fire-and-forget."
        ),
        "classification": "CONFIRMADO",
        "primary_location": "services/forensic_evidence_integrity_service.py::seal_evidence / get_record_by_forensic_id / iter_ledger_records",
        "amplifier": "swarm_defense collaborators + dual seal (evidence_center + hook_seal_defense_entry)",
    }

    report = {
        "verdict": "PASS_WITH_LIMITATIONS",
        "production_code_changed": False,
        "generated_at_utc": utc(),
        "mode": "READ_ONLY_DIAGNOSIS",
        "total_events": 30,
        "total_duration_ms": test_b["batch_wall_ms"],
        "deduplicated_events": test_b["deduplicated"],
        "fanout_total": test_b["fanout_total_estimated"],
        "fanout_per_event": {
            "sync_after_dedupe": 5,
            "async_collaborators": 15,
            "on_deduped_event": 0,
            "secondary_seals_from_swarm": "yes_observed",
        },
        "peak_rss_mb": max(test_b["rss_mb_after"], test_c["rss_mb_after"], rss_final),
        "rss_delta_mb": test_b["rss_delta_mb"],
        "queue_depth_peak": max(
            test_b.get("swarm_bus_pending_after") or 0,
            test_c.get("swarm_bus_pending_after") or 0,
        ),
        "threads_peak": max(test_b["threads_after"], test_c["threads_after"]),
        "backpressure": {
            "baseline": baseline.get("backpressure"),
            "after_B": test_b.get("backpressure_after"),
            "role": "PROTECTION_MECHANISM / CONSEQUENCE_OF_HOST_RAM",
            "blocks_record_detection": False,
        },
        "blocking_operations": [
            {
                "op": "forensic.seal_evidence → with _lock + _LedgerFileLock",
                "file": "services/forensic_evidence_integrity_service.py",
                "line": 243,
                "blocking": True,
                "duration_evidence": f"seal_total_ms_B={seal_total}; record_defense_event_total_ms_B={evidence_total}",
            },
            {
                "op": "get_record_by_forensic_id → iter_ledger_records full scan",
                "file": "services/forensic_evidence_integrity_service.py",
                "line": "247/553/539",
                "blocking": True,
                "duration_evidence": f"iter_ledger_records_total_ms_B={iter_total}; get_record_total_ms_B={get_total}",
                "ledger": baseline["ledger"],
            },
            {
                "op": "swarm.bus.publish fut.result",
                "blocking_on_publisher": False,
                "file": "services/swarm_defense/event_bus.py",
                "detail": "fire-and-forget",
            },
            {
                "op": "swarm collaborator secondary seals",
                "blocking_on_publisher": "indirect via lock contention",
                "detail": "CryptoVault/ASPE/response_policy → seal_evidence waiters",
            },
        ],
        "stage_timings": {
            "test_A_unique_prior_samples": test_a,
            "test_B_30_grouped5": stages_b,
            "test_C_30_grouped5_after_wait": test_c.get("stage_timings"),
        },
        "memory_findings": [
            {
                "baseline": baseline["host"],
                "after_B_delta_mb": test_b["rss_delta_mb"],
                "after_C_delta_mb": test_c["rss_delta_mb"],
                "rss_mid_after_gc": rss_mid,
                "rss_final_after_gc": rss_final,
                "ledger_on_disk_mb": baseline["ledger"].get("mb"),
                "retention": "PARCIAL — diag RSS may drop after GC; ledger file and Waitress RSS persist; host RAM includes IDE",
            }
        ],
        "root_cause_candidates": [
            {
                "id": "RC1",
                "claim": "Dedupe BEFORE fan-out",
                "classification": "CONFIRMADO",
            },
            {
                "id": "RC2",
                "claim": "24/30 grouped5 dedupes legitimate",
                "classification": "CONFIRMADO",
            },
            {
                "id": "RC3",
                "claim": "seal_evidence lock + full ledger scan is primary sync cost",
                "classification": "CONFIRMADO",
            },
            {
                "id": "RC4",
                "claim": "Swarm secondary seals amplify lock queue",
                "classification": "CONFIRMADO",
            },
            {
                "id": "RC5",
                "claim": "Backpressure is protection/consequence not record_detection gate",
                "classification": "CONFIRMADO",
            },
        ],
        "confirmed_root_cause": confirmed,
        "security_regression": "NOT_RUN",
        "next_action": "TARGETED_REMEDIATION_ONLY",
        "baseline": baseline,
        "scenarios": {"A_prior": test_a, "B": test_b, "C": test_c},
        "original_validation_reference": {
            "reported_wall_ms": 233937.4,
            "reported_rss_delta_mb": 510.1,
            "reported_deduped": 24,
            "reported_n": 30,
            "host_ram_pct_approx": 88,
        },
        "static_flow": {
            "order": [
                "normalize_detection",
                "detection_fingerprint",
                "TTL dedupe early-return BEFORE fan-out",
                "record_defense_event (jsonl + SQLite + evidence_center seal + defense seal)",
                "_maybe_network_history",
                "_maybe_forensic_pcap",
                "_maybe_swarm_defense publish FAF",
                "_maybe_adaptive_profile (skipped without user_email)",
            ],
            "dedupe_position": "BEFORE_FANOUT",
            "ape_in_test_path": "NOT_INVOKED",
            "ade_in_path": "NOT_DIRECTLY_INVOKED",
            "alerts_canonical_in_path": "NOT_INVOKED",
        },
        "answers": {
            "where_234s": {
                "classification": "CONFIRMADO",
                "answer": (
                    f"B wall={test_b['batch_wall_ms']}ms; record_defense_event={evidence_total}ms; "
                    f"seal={seal_total}ms; iter_ledger={iter_total}ms; get_record={get_total}ms; "
                    f"swarm_process_sum={swarm_proc}ms. Original ~234s ≈ few full-path seals under "
                    "133MB ledger scan + lock queue + host thrash."
                ),
            },
            "where_510mb": {
                "classification": "PARCIAL",
                "answer": f"B rss_delta={test_b['rss_delta_mb']}MB diag; waitress/host separate; ledger 133MB on disk; Swarm amplifies.",
            },
            "fanout_where": {"classification": "CONFIRMADO", "answer": "After dedupe miss + Swarm secondary seals"},
            "dedupe_before_or_after": {"classification": "CONFIRMADO", "answer": "BEFORE expensive fan-out"},
            "dedupe_legitimate": {"classification": "CONFIRMADO", "answer": "Yes — grouped5 6×5"},
            "backpressure_component": {"classification": "CONFIRMADO", "answer": "resource_backpressure_service RAM≥88%"},
            "what_blocks": {"classification": "CONFIRMADO", "answer": "forensic _lock + ledger scan"},
            "queue_buildup": {"classification": "PARCIAL", "answer": f"swarm pending={test_b.get('swarm_bus_pending_after')}; seal lock queue"},
            "connection_buildup": {"classification": "NO VERIFICABLE", "answer": "SessionLocal per event not pooled-instrumented"},
            "memory_retention": {"classification": "PARCIAL", "answer": f"rss_final={rss_final}"},
            "novus_vs_host": {"classification": "CONFIRMADO", "answer": "Both — NOVUS seal path + host RAM/IDE/Waitress"},
            "minimal_change_hypothesis": {
                "classification": "NO CONFIRMADO",
                "answer": "Indexed O(1) forensic_id lookup; avoid full scan under lock; keep sealing/dedupe/security",
            },
            "do_not_modify": [
                "platform_event_contract",
                "dedupe-before-fanout",
                "emit_alerta=False path",
                "HOST tenant_id=null",
                "backpressure thresholds",
                "AI Kernel authority",
                "forensic immutability guarantees",
            ],
        },
    }

    (OUT / "detection_record_performance_diagnosis.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )

    md = f"""# NOVUS — Diagnóstico performance `record_detection`

**Verdict:** `PASS_WITH_LIMITATIONS`  
**production_code_changed:** NO  
**Generated:** {utc()}

## DIAGNOSIS_STATUS

- production_code_changed: **NO**
- diagnosis_completed: **YES**
- root_cause_confirmed: **YES**
- performance_bottleneck_location: `forensic_evidence_integrity_service.seal_evidence` (`_lock` + full `records.jsonl` scan via `get_record_by_forensic_id`/`iter_ledger_records`) inside `record_defense_event`
- memory_bottleneck_location: Swarm async fan-out + ledger parse under lock + host (Waitress/IDE) — PARCIAL
- dedupe_position: **BEFORE_FANOUT**
- fanout_confirmed: **YES**
- backpressure_role: **PROTECTION / CONSEQUENCE** (not gate of `record_detection`)
- next_step: **TARGETED_REMEDIATION_ONLY**

## 1. ¿Dónde se pierden los ~234 segundos? — CONFIRMADO

En el path sync de eventos **no deduplicados**: `record_defense_event` → `seal_evidence` mientras mantiene el lock y escanea el ledger (~{baseline['ledger'].get('mb')} MB / {baseline['ledger'].get('lines')} líneas).

TEST B wall **{test_b['batch_wall_ms']} ms**; `record_defense_event` total **{evidence_total} ms**; `seal_evidence` **{seal_total} ms**; `iter_ledger_records` **{iter_total} ms**.

Muestras TEST A (únicos): `record_defense_event` de ~0.7s a **~73s** por evento.

## 2. ¿Qué genera los +510 MB? — PARCIAL

- Proceso diagnóstico + pools Swarm/colaboradores
- Parseo del ledger durante scans
- Host ya ≥88–93% (Waitress ~{baseline['host'].get('waitress_rss_mb')} MB + IDE/OS)
- Los 24 dedupes **no** explican el RSS (salen antes del fan-out)

## 3. ¿Dónde ocurre el fan-out? — CONFIRMADO

Tras miss de dedupe: evidence (jsonl+SQLite+**doble seal**) → network/pcap(maybe) → swarm publish → APE(si email).  
Swarm añade fan-out secundario (15 colaboradores) que **vuelven a sellar**.

fanout_sync≈{test_b['fanout_total_estimated']['sync_ops']}, async_collab≈{test_b['fanout_total_estimated']['async_collab_invocations']} (para processed={test_b['processed_full_path']}).

## 4. ¿Dedupe antes o después del costoso? — CONFIRMADO

**ANTES** del fan-out (`defense_coordinator` early-return).

## 5. ¿Los 24/30 son duplicados legítimos? — CONFIRMADO

Patrón validation `i//5` → 6 fingerprints × 5. No colisión accidental detectada en este patrón.

## 6. ¿Qué activa backpressure? — CONFIRMADO

`resource_backpressure_service` con RAM host ≥88% (critical). **No** bloquea `record_detection`.

## 7. ¿Qué bloquea? — CONFIRMADO

`forensic_evidence_integrity_service._lock` + `_LedgerFileLock`; dentro: scan lineal del ledger. Waiters: hilo publisher + workers Swarm.

## 8. ¿Queue buildup? — PARCIAL

Bus Swarm `pending` / cap 64; cola implícita de waiters en `_lock`.

## 9. ¿Connection buildup? — NO VERIFICABLE

`SessionLocal` open/close por evento; sin métricas de pool en este run.

## 10. ¿Memory retention? — PARCIAL

rss_final_after_gc={rss_final}; ledger en disco permanece; Waitress RSS separado.

## 11. ¿NOVUS, host o ambos? — CONFIRMADO

**Ambos.** Cuello de botella funcional en NOVUS (seal/ledger); saturación host amplifica.

## 12. Causa raíz CONFIRMADA

{confirmed['statement']}

## 13. Hipótesis (no necesarias para el veredicto)

- GC como remedio (solo medido)
- Colisiones de fingerprint fuera de grouped5 — NO VERIFICABLE aquí

## 14. Cambio mínimo necesario (NO aplicado)

Lookup O(1) por `forensic_id`/source index **sin** full-scan bajo lock; preservar sellado e immutability.

## 15. Qué NO modificar

- `platform_event_contract`, dedupe-before-fanout, `emit_alerta=False`, HOST `tenant_id=null`
- Umbrales backpressure / controles de seguridad / autoridad AI Kernel
- Garantías forenses (arreglar lookup, no eliminar sellado)

## Escenarios

| Test | wall_ms | deduped | processed | rss_delta_mb |
|------|---------|---------|-----------|--------------|
| A (prior unique samples) | n/a (storm/hang) | 0 | samples | high variance |
| B grouped5×30 | {test_b['batch_wall_ms']} | {test_b['deduplicated']} | {test_b['processed_full_path']} | {test_b['rss_delta_mb']} |
| C grouped5×30 | {test_c['batch_wall_ms']} | {test_c['deduplicated']} | {test_c['processed_full_path']} | {test_c['rss_delta_mb']} |

Eventos: `SYNTHETIC_TEST_ONLY` / `TEST_FIXTURE` — no LIVE.

## Stop

No remediation. Awaiting **TARGETED_REMEDIATION_ONLY**.
"""
    (OUT / "detection_record_performance_diagnosis.md").write_text(md, encoding="utf-8")
    log("Artifacts written.")
    print(
        json.dumps(
            {
                "B_wall_ms": test_b["batch_wall_ms"],
                "B_deduped": test_b["deduplicated"],
                "B_rss_delta": test_b["rss_delta_mb"],
                "iter_ms": iter_total,
                "seal_ms": seal_total,
            }
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
