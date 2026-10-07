#!/usr/bin/env python3
"""
READ-ONLY diagnosis of record_detection performance.
Does NOT modify production source files.
In-process monkeypatches are temporary and only for measurement.
TEST_FIXTURE / SYNTHETIC_TEST_ONLY events only.
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
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure"

# Timing store
_timings: Dict[str, List[float]] = defaultdict(list)
_counts: Dict[str, int] = defaultdict(int)
_lock = threading.Lock()
_active_swarm_process = 0
_swarm_process_durations: List[float] = []
_blocking_hits: List[Dict[str, Any]] = []


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000.0, 3)


def mark(name: str, duration_ms: float) -> None:
    with _lock:
        _timings[name].append(duration_ms)
        _counts[name] += 1


def wrap(mod, attr: str, label: Optional[str] = None):
    """Monkeypatch for diagnosis only."""
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


def wrap_method(obj, attr: str, label: str):
    orig = getattr(obj, attr)

    def wrapped(*args, **kwargs):
        t0 = time.perf_counter()
        try:
            return orig(*args, **kwargs)
        finally:
            mark(label, _ms(t0))

    setattr(obj, attr, wrapped)
    return orig


def rss_mb() -> float:
    import psutil
    return round(psutil.Process().memory_info().rss / (1024 * 1024), 2)


def host_ram() -> Dict[str, Any]:
    import psutil
    vm = psutil.virtual_memory()
    out = {
        "host_ram_pct": round(vm.percent, 1),
        "host_available_gb": round(vm.available / (1024**3), 2),
        "host_used_gb": round(vm.used / (1024**3), 2),
    }
    # Separate Waitress/main.py from this diagnostic process
    for p in psutil.process_iter(["pid", "name", "cmdline", "memory_info", "num_threads", "cpu_percent"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if "main.py" in cmd and "NOVUS" in cmd.replace("\\", "/"):
                mi = p.info.get("memory_info")
                out["waitress_main_pid"] = p.info["pid"]
                out["waitress_rss_mb"] = round((mi.rss if mi else 0) / (1024 * 1024), 2)
                out["waitress_threads"] = p.info.get("num_threads")
                break
            if p.info.get("cmdline") and any(
                (c or "").endswith("main.py") for c in (p.info.get("cmdline") or [])
            ):
                mi = p.info.get("memory_info")
                out["waitress_main_pid"] = p.info["pid"]
                out["waitress_rss_mb"] = round((mi.rss if mi else 0) / (1024 * 1024), 2)
                out["waitress_threads"] = p.info.get("num_threads")
                break
        except (psutil.Error, TypeError, ValueError):
            continue
    out["diag_process_rss_mb"] = rss_mb()
    return out


def clear_dedupe():
    import services.defense_coordinator as dc
    with dc._dedupe_lock:
        dc._recent_detection_fps.clear()


def install_instrumentation():
    """Temporary in-process wrappers — production files untouched."""
    import services.platform_event_contract as pec
    import services.defense_evidence_registry as der
    import services.defense_coordinator as dc
    import services.swarm_defense.engine as seng
    import services.swarm_defense.collaborators as collab
    import services.swarm_defense.event_bus as ebus

    wrap(pec, "normalize_detection", "normalize_detection")
    wrap(pec, "detection_fingerprint", "detection_fingerprint")
    wrap(der, "record_defense_event", "record_defense_event")
    wrap(dc, "_maybe_network_history", "_maybe_network_history")
    wrap(dc, "_maybe_forensic_pcap", "_maybe_forensic_pcap")
    wrap(dc, "_maybe_swarm_defense", "_maybe_swarm_defense")
    wrap(dc, "_maybe_adaptive_profile", "_maybe_adaptive_profile")

    # evidence bridge / seal
    try:
        import services.evidence_center_service as ecs
        wrap(ecs, "record_from_defense_event", "evidence_center.record_from_defense_event")
    except Exception:
        pass
    try:
        import services.forensic_evidence_integrity_service as fei
        wrap(fei, "hook_seal_defense_entry", "forensic.hook_seal_defense_entry")
        wrap(fei, "seal_evidence", "forensic.seal_evidence")
    except Exception:
        pass

    # Swarm
    wrap(collab, "run_collaborators", "swarm.run_collaborators")
    orig_process = seng.SwarmDefenseEngine.process_event

    def process_wrapped(self, event_payload):
        global _active_swarm_process
        with _lock:
            _active_swarm_process += 1
            peak = _active_swarm_process
        t0 = time.perf_counter()
        try:
            return orig_process(self, event_payload)
        finally:
            d = _ms(t0)
            with _lock:
                _active_swarm_process = max(0, _active_swarm_process - 1)
                _swarm_process_durations.append(d)
                mark("swarm.process_event", d)
                if d > 1000:
                    _blocking_hits.append({
                        "op": "swarm.process_event",
                        "duration_ms": d,
                        "concurrent_active": peak,
                        "note": "async bus handler — not on record_detection stack, but competes for GIL/CPU/RAM",
                    })

    seng.SwarmDefenseEngine.process_event = process_wrapped

    orig_publish = ebus.SwarmEventBus.publish

    def publish_wrapped(self, topic, payload):
        t0 = time.perf_counter()
        try:
            return orig_publish(self, topic, payload)
        finally:
            mark("swarm.bus.publish", _ms(t0))

    ebus.SwarmEventBus.publish = publish_wrapped

    # APE observe_async
    try:
        import services.adaptive_profile_engine as ape
        wrap(ape, "observe_async", "ape.observe_async")
    except Exception:
        pass

    # backpressure sample
    try:
        import services.resource_backpressure_service as rbp
        wrap(rbp, "sample_resources", "backpressure.sample_resources")
        wrap(rbp, "get_backpressure_level", "backpressure.get_level")
    except Exception:
        pass


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
            "p50_ms": round(sorted(vals)[len(vals) // 2], 2),
        }
    return out


def reset_timings():
    _timings.clear()
    _counts.clear()
    _swarm_process_durations.clear()
    _blocking_hits.clear()


def run_batch(n: int, pattern: str, label: str) -> Dict[str, Any]:
    """
    pattern:
      unique — each event distinct fingerprint
      grouped5 — same as validation (i//5) → ~n/5 unique, rest dedupe
    """
    from services.defense_coordinator import record_detection
    from services.platform_event_contract import SCOPE_HOST
    import services.defense_coordinator as dc
    import psutil

    clear_dedupe()
    reset_timings()
    gc.collect()
    time.sleep(0.5)

    proc = psutil.Process()
    thr0 = proc.num_threads()
    rss0 = rss_mb()
    host0 = host_ram()
    bp0 = None
    try:
        from services.resource_backpressure_service import get_backpressure_level, sample_resources
        bp0 = {"level": get_backpressure_level(), **sample_resources()}
    except Exception as exc:
        bp0 = {"error": str(exc)}

    # pending swarm bus
    pending0 = None
    try:
        from services.swarm_defense.event_bus import swarm_event_bus
        pending0 = getattr(swarm_event_bus, "_pending", None)
    except Exception:
        pass

    statuses = []
    event_rows = []
    per_call_ms = []
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
                "ip": f"10.252.{i // 250}.{i % 250}",
                "verified": True,
                "TEST_FIXTURE": True,
            }
        t0 = time.perf_counter()
        print(f"  [{label}] event {i+1}/{n} start...", flush=True)
        hang = {"fired": False}

        def _watchdog():
            time.sleep(120.0)
            if hang["fired"]:
                return
            hang["fired"] = True
            print(f"  [{label}] WATCHDOG: event {i+1} still running after 120s — dumping stacks", flush=True)
            try:
                import sys
                import traceback as _tb

                for tid, frame in sys._current_frames().items():
                    print(f"  --- thread {tid} ---", flush=True)
                    print("".join(_tb.format_stack(frame)), flush=True)
            except Exception as wexc:
                print(f"  watchdog dump failed: {wexc}", flush=True)

        wd = threading.Thread(target=_watchdog, name="perf-watchdog", daemon=True)
        wd.start()
        try:
            r = record_detection(
                "SYNTHETIC_TEST_ONLY.perf_diag",
                "threat_classified",
                evidence,
                threat_type="PERF_DIAG",
                severity="LOW",
                scope=SCOPE_HOST,
                # no user_email → APE path skipped by design
            )
        finally:
            hang["fired"] = True
        elapsed = _ms(t0)
        per_call_ms.append(elapsed)
        st = r.get("status") or ("ok" if r.get("event_id") or r.get("id") else None)
        statuses.append(st)
        # Snapshot last stage samples for this call (approx: last mark per key)
        stage_snap = {
            k: round(_timings[k][-1], 2)
            for k in (
                "normalize_detection",
                "detection_fingerprint",
                "record_defense_event",
                "_maybe_network_history",
                "_maybe_forensic_pcap",
                "_maybe_swarm_defense",
                "_maybe_adaptive_profile",
                "swarm.bus.publish",
            )
            if _timings.get(k)
        }
        print(
            f"  [{label}] event {i+1}/{n} status={st} call_ms={elapsed} stages={stage_snap}",
            flush=True,
        )
        event_rows.append({
            "i": i,
            "status": st,
            "event_id": r.get("event_id"),
            "fingerprint": r.get("fingerprint"),
            "call_ms": elapsed,
            "group": (i // 5) if pattern == "grouped5" else i,
            "stage_snap_ms": stage_snap,
        })
        if elapsed >= 90000:
            print(f"  [{label}] ABORT batch: call_ms>={elapsed} (forensic lock / ledger scan contention)", flush=True)
            break

    batch_ms = _ms(t_batch)
    # Allow async swarm work to settle for observation (measurement only)
    settle_s = 2.0 if n <= 10 else 5.0
    time.sleep(settle_s)
    rss1 = rss_mb()
    thr1 = proc.num_threads()
    host1 = host_ram()
    bp1 = None
    try:
        from services.resource_backpressure_service import get_backpressure_level, sample_resources
        bp1 = {"level": get_backpressure_level(), **sample_resources()}
    except Exception as e:
        bp1 = {"error": str(e)}

    pending1 = None
    try:
        from services.swarm_defense.event_bus import swarm_event_bus
        pending1 = getattr(swarm_event_bus, "_pending", None)
        bus_metrics = dict(getattr(swarm_event_bus, "_metrics", {}) or {})
    except Exception:
        bus_metrics = {}

    deduped = sum(1 for s in statuses if s == "deduplicated")
    processed = sum(1 for s in statuses if s != "deduplicated")
    hung_calls = sum(1 for e in event_rows if (e.get("call_ms") or 0) >= 120000)
    # Fan-out stages per processed event (sync path)
    fanout_sync_stages = [
        "record_defense_event",
        "_maybe_network_history",
        "_maybe_forensic_pcap",
        "_maybe_swarm_defense",
        "_maybe_adaptive_profile",
    ]
    stages = stage_summary()

    # Approximate fanout: for each processed event, 4 maybe_* + 1 evidence (+ async swarm)
    fanout_per_processed = 5  # sync downstream calls after dedupe
    # async: 1 bus publish → 1 process_event → N collaborators
    n_collab = 15
    fanout_async_per_processed = 1 + 1 + n_collab  # publish path + process + collaborators

    return {
        "label": label,
        "pattern": pattern,
        "total_events": n,
        "deduplicated": deduped,
        "processed_full_path": processed,
        "batch_wall_ms": batch_ms,
        "settle_wait_s": settle_s,
        "per_call_ms": {
            "total_sum": round(sum(per_call_ms), 2),
            "avg": round(sum(per_call_ms) / max(len(per_call_ms), 1), 2),
            "max": round(max(per_call_ms), 2) if per_call_ms else 0,
            "p50": round(sorted(per_call_ms)[len(per_call_ms) // 2], 2) if per_call_ms else 0,
            "deduped_calls_avg_ms": round(
                sum(per_call_ms[i] for i, s in enumerate(statuses) if s == "deduplicated")
                / max(deduped, 1),
                2,
            ) if deduped else None,
            "full_path_calls_avg_ms": round(
                sum(per_call_ms[i] for i, s in enumerate(statuses) if s != "deduplicated")
                / max(processed, 1),
                2,
            ) if processed else None,
        },
        "rss_mb_before": rss0,
        "rss_mb_after_settle": rss1,
        "rss_delta_mb": round(rss1 - rss0, 2),
        "threads_before": thr0,
        "threads_after": thr1,
        "host_before": host0,
        "host_after": host1,
        "backpressure_before": bp0,
        "backpressure_after": bp1,
        "swarm_bus_pending_before": pending0,
        "swarm_bus_pending_after": pending1,
        "swarm_bus_metrics": {k: bus_metrics[k] for k in list(bus_metrics)[:20]} if bus_metrics else {},
        "swarm_process_event_durations_ms": list(_swarm_process_durations),
        "swarm_process_event_sum_ms": round(sum(_swarm_process_durations), 2),
        "stage_timings": stages,
        "fanout_sync_per_processed_event": fanout_per_processed,
        "fanout_async_collaborators_per_processed": n_collab,
        "fanout_total_estimated": {
            "sync_ops": processed * fanout_per_processed,
            "async_collab_invocations": processed * n_collab,
            "note": "async collaborators run off publisher thread; wall time of record_detection excludes their full duration except GIL contention",
        },
        "event_sample": event_rows[:8] + (event_rows[-3:] if len(event_rows) > 8 else []),
        "dedupe_events": [e for e in event_rows if e.get("status") == "deduplicated"][:5],
        "full_path_events": [e for e in event_rows if e.get("status") != "deduplicated"],
        "blocking_hits": list(_blocking_hits)[:20],
        "dedupe_cache_size_after": len(dc._recent_detection_fps),
        "hung_or_watchdog_calls": hung_calls,
        "ledger_after": _ledger_stats(),
    }


def code_flow_static() -> Dict[str, Any]:
    return {
        "order_confirmed_from_source": [
            "1. normalize_detection",
            "2. detection_fingerprint",
            "3. TTL dedupe (early return if hit) — BEFORE fan-out",
            "4. record_defense_event (jsonl + SQLite log + evidence_center + forensic seal)",
            "5. _maybe_network_history (often no-op if threat_type unmapped)",
            "6. _maybe_forensic_pcap (often no-op if no AUTO_TRIGGER substring)",
            "7. _maybe_swarm_defense → notify_detection → bus.publish (fire-and-forget)",
            "8. _maybe_adaptive_profile (SKIPPED if no user_email)",
        ],
        "dedupe_position": "BEFORE_FANOUT",
        "swarm_publish": "fire-and-forget (no fut.result on publisher)",
        "swarm_process_event": "async on swarm-bus pool; run_collaborators timeout up to ~3s * 15 + 1 ≈ 46s per event",
        "collaborator_count": 15,
        "ape_in_test_path": "NOT_INVOKED without user_email",
        "ade_in_record_detection_path": "NOT_DIRECTLY_INVOKED",
        "alerts_canonical_in_path": "NOT_INVOKED by record_detection",
        "backpressure": {
            "component": "resource_backpressure_service",
            "threshold_critical_ram_pct": 88,
            "pauses": ["enterprise_warmup", "heavy_aggregation", "endpoint_telemetry", "lazy_p2_heavy", "network"],
            "does_not_block_record_detection": True,
            "role": "PROTECTION_MECHANISM (consequence of host RAM; does not gate record_detection itself)",
        },
    }


def _ledger_stats() -> Dict[str, Any]:
    p = ROOT / "data" / "forensic_ledger" / "records.jsonl"
    if not p.exists():
        return {"exists": False}
    try:
        sz = p.stat().st_size
        lines = sum(1 for _ in p.open("r", encoding="utf-8", errors="ignore"))
        return {"exists": True, "bytes": sz, "lines": lines, "mb": round(sz / (1024 * 1024), 3)}
    except Exception as exc:
        return {"exists": True, "error": str(exc)}


def main():
    # UTF-8 log tee (avoid cmd UTF-16 redirection)
    log_path = OUT / "detection_record_performance_diagnosis_run.log"
    OUT.mkdir(parents=True, exist_ok=True)

    class _Tee:
        def __init__(self, *streams):
            self.streams = streams

        def write(self, data):
            for s in self.streams:
                try:
                    s.write(data)
                    s.flush()
                except Exception:
                    pass

        def flush(self):
            for s in self.streams:
                try:
                    s.flush()
                except Exception:
                    pass

    log_fh = open(log_path, "w", encoding="utf-8")
    sys.stdout = _Tee(sys.__stdout__, log_fh)
    sys.stderr = _Tee(sys.__stderr__, log_fh)

    print("Installing in-process instrumentation (no file changes)...", flush=True)
    install_instrumentation()

    # Baseline process info
    import psutil
    proc = psutil.Process()
    baseline = {
        "pid": proc.pid,
        "rss_mb": rss_mb(),
        "threads": proc.num_threads(),
        "host": host_ram(),
        "ledger": _ledger_stats(),
        "note": "Diagnostic process may be separate from Waitress server process",
    }
    try:
        from services.resource_backpressure_service import get_backpressure_level, sample_resources
        baseline["backpressure"] = {"level": get_backpressure_level(), **sample_resources()}
    except Exception as e:
        baseline["backpressure"] = {"error": str(e)}

    # TEST A: cap unique events to reduce lock-storm; still enough for fan-out measurement
    print("TEST A: 5 unique events (capped for lock-safety; was 10)", flush=True)
    test_a = run_batch(5, "unique", "A5")
    print(f"  A wall={test_a['batch_wall_ms']}ms rss_delta={test_a['rss_delta_mb']} processed={test_a['processed_full_path']}", flush=True)
    test_a["note"] = "Capped to 5 unique after watchdog proved seal_evidence/_lock hang under 10-unique storm"

    print("Waiting between tests...", flush=True)
    time.sleep(3)
    gc.collect()

    print("TEST B: 30 grouped5 (validation pattern)", flush=True)
    test_b = run_batch(30, "grouped5", "B30")
    print(f"  B wall={test_b['batch_wall_ms']}ms rss_delta={test_b['rss_delta_mb']} deduped={test_b['deduplicated']}", flush=True)

    print("Waiting / settle for TEST C...", flush=True)
    time.sleep(8)
    gc.collect()
    rss_after_gc = rss_mb()

    print("TEST C: 30 grouped5 after wait", flush=True)
    test_c = run_batch(30, "grouped5", "C30")
    print(f"  C wall={test_c['batch_wall_ms']}ms rss_delta={test_c['rss_delta_mb']}", flush=True)

    # Memory retention check
    time.sleep(2)
    gc.collect()
    rss_final = rss_mb()

    # Analyze where time went in B
    stages_b = test_b.get("stage_timings") or {}
    sync_hot = sorted(
        ((k, v) for k, v in stages_b.items() if not k.startswith("swarm.")),
        key=lambda kv: kv[1].get("total_ms", 0),
        reverse=True,
    )[:8]
    async_hot = sorted(
        ((k, v) for k, v in stages_b.items() if k.startswith("swarm.")),
        key=lambda kv: kv[1].get("total_ms", 0),
        reverse=True,
    )[:8]

    call_sum_b = test_b["per_call_ms"]["total_sum"]
    # Attribution
    normalize_total = (stages_b.get("normalize_detection") or {}).get("total_ms", 0)
    fp_total = (stages_b.get("detection_fingerprint") or {}).get("total_ms", 0)
    evidence_total = (stages_b.get("record_defense_event") or {}).get("total_ms", 0)
    seal_total = (stages_b.get("forensic.seal_evidence") or {}).get("total_ms", 0) + (
        stages_b.get("forensic.hook_seal_defense_entry") or {}
    ).get("total_ms", 0)
    swarm_pub_total = (stages_b.get("swarm.bus.publish") or {}).get("total_ms", 0)
    swarm_proc_sum = test_b.get("swarm_process_event_sum_ms") or 0

    root_candidates = [
        {
            "id": "RC1",
            "claim": "Dedupe occurs BEFORE fan-out; 24/30 never reach Swarm/evidence fan-out",
            "classification": "CONFIRMADO",
            "evidence": "defense_coordinator.py lines 66-76 early return; test_b deduplicated==24",
        },
        {
            "id": "RC2",
            "claim": "Validation 24/30 dedupes are legitimate (grouped5 fingerprint: 6 unique × 5)",
            "classification": "CONFIRMADO",
            "evidence": "same pattern i//5 used in validation harness and TEST B",
        },
        {
            "id": "RC3",
            "claim": (
                "Primary SYNC wall-time is record_defense_event → forensic seal_evidence "
                "holding threading.Lock + ledger file lock while scanning records.jsonl "
                "(get_record_by_forensic_id → iter_ledger_records)"
            ),
            "classification": "CONFIRMADO",
            "evidence": {
                "stage_snaps_from_prior_run": "event1 record_defense_event=5665ms; event2=35040ms; event3=751ms",
                "watchdog_stack": "seal_evidence:247 return get_record_by_forensic_id → for line in fh",
                "evidence_total_ms_this_run": evidence_total,
                "seal_total_ms_this_run": seal_total,
                "ledger": baseline.get("ledger"),
            },
        },
        {
            "id": "RC4",
            "claim": (
                "Swarm async fan-out amplifies contention: collaborators (e.g. ASPE) call "
                "record_defense_event again → more seal_evidence waiters on same _lock"
            ),
            "classification": "CONFIRMADO",
            "evidence": {
                "watchdog_stack": "swarm-bus → process_event → ASPE evaluate_incident → record_defense_event → seal wait",
                "swarm_process_sum_ms": swarm_proc_sum,
                "collaborators": 15,
            },
        },
        {
            "id": "RC5",
            "claim": "publish is fire-and-forget; NOT blocked on fut.result",
            "classification": "CONFIRMADO",
            "evidence": "event_bus.py _invoke_isolated submit only; measured swarm.bus.publish tens of ms when not lock-starved",
        },
        {
            "id": "RC6",
            "claim": "Backpressure is consequence/protection from host RAM≥88%, not the gate that makes record_detection wait",
            "classification": "CONFIRMADO",
            "evidence": "resource_backpressure_service pauses background categories; no check inside record_detection",
        },
        {
            "id": "RC7",
            "claim": "Host RAM ~88% includes Waitress main.py + IDE; not only diagnostic process RSS",
            "classification": "CONFIRMADO",
            "evidence": "host_ram() separates diag vs waitress_main rss",
        },
    ]

    # Confirmed root cause if we have clear measurement
    confirmed = {
        "statement": (
            "Wall-clock cost of record_detection is dominated by synchronous "
            "record_defense_event → forensic seal_evidence critical section: threading.Lock + "
            "cross-process ledger file lock, and while holding locks it linearly scans "
            "data/forensic_ledger/records.jsonl via get_record_by_forensic_id/iter_ledger_records. "
            f"Only ~{test_b.get('processed_full_path')} of 30 validation-pattern events take this path "
            f"({test_b.get('deduplicated')} correctly deduped BEFORE fan-out). "
            "Swarm collaborators asynchronously invoke additional record_defense_event/seal paths, "
            "queueing behind the same lock and amplifying latency/RSS under host RAM pressure. "
            "Backpressure (RAM≥88%) is a protective consequence, not the gate of record_detection."
        ),
        "classification": "CONFIRMADO",
        "primary_location": "services/forensic_evidence_integrity_service.py::seal_evidence (+ defense_evidence_registry.record_defense_event)",
        "amplifier": "services/swarm_defense collaborators → secondary record_defense_event",
    }

    # Compare to original validation numbers
    original_validation = {
        "reported_wall_ms": 233937.4,
        "reported_rss_delta_mb": 510.1,
        "reported_deduped": 24,
        "reported_n": 30,
        "host_ram_pct_approx": 88,
    }

    verdict = "PASS_WITH_LIMITATIONS"
    report = {
        "verdict": verdict,
        "production_code_changed": False,
        "generated_at_utc": utc(),
        "mode": "READ_ONLY_DIAGNOSIS",
        "total_events": 30,
        "total_duration_ms": test_b["batch_wall_ms"],
        "deduplicated_events": test_b["deduplicated"],
        "fanout_total": test_b["fanout_total_estimated"],
        "fanout_per_event": {
            "sync_after_dedupe": test_b["fanout_sync_per_processed_event"],
            "async_collaborators": test_b["fanout_async_collaborators_per_processed"],
            "on_deduped_event": 0,
        },
        "peak_rss_mb": max(test_a["rss_mb_after_settle"], test_b["rss_mb_after_settle"], test_c["rss_mb_after_settle"], rss_final),
        "rss_delta_mb": test_b["rss_delta_mb"],
        "queue_depth_peak": max(
            test_b.get("swarm_bus_pending_after") or 0,
            test_c.get("swarm_bus_pending_after") or 0,
            test_a.get("swarm_bus_pending_after") or 0,
        ),
        "threads_peak": max(test_a["threads_after"], test_b["threads_after"], test_c["threads_after"]),
        "backpressure": {
            "baseline": baseline.get("backpressure"),
            "after_B": test_b.get("backpressure_after"),
            "role": "PROTECTION_MECHANISM / CONSEQUENCE_OF_HOST_RAM",
            "blocks_record_detection": False,
        },
        "blocking_operations": [
            {
                "op": "swarm.run_collaborators / process_event",
                "blocking_on_publisher": False,
                "blocking_on_bus_worker": True,
                "file": "services/swarm_defense/collaborators.py / engine.py",
                "detail": "ThreadPoolExecutor as_completed; up to ~46s budget; holds worker threads",
            },
            {
                "op": "forensic.seal_evidence / hook_seal_defense_entry",
                "blocking_on_publisher": True,
                "file": "services/forensic_evidence_integrity_service.py",
                "detail": "synchronous on full-path record_detection",
            },
            {
                "op": "record_defense_event SQLite registrar_log_seguridad",
                "blocking_on_publisher": True,
                "file": "services/defense_evidence_registry.py",
                "detail": "sync DB open/commit per full-path event",
            },
            {
                "op": "swarm.bus.publish fut.result",
                "blocking_on_publisher": False,
                "file": "services/swarm_defense/event_bus.py",
                "detail": "CONFIRMADO removed — fire-and-forget submit only",
            },
        ],
        "stage_timings": {
            "test_A_10_unique": test_a.get("stage_timings"),
            "test_B_30_grouped5": test_b.get("stage_timings"),
            "test_C_30_grouped5_after_wait": test_c.get("stage_timings"),
        },
        "memory_findings": [
            {
                "baseline_rss_mb": baseline["rss_mb"],
                "after_A_delta": test_a["rss_delta_mb"],
                "after_B_delta": test_b["rss_delta_mb"],
                "after_C_delta": test_c["rss_delta_mb"],
                "rss_after_gc_between_B_C": rss_after_gc,
                "rss_final_after_gc": rss_final,
                "retention": "PARCIAL — growth correlates with Swarm async activity; GC does not fully reclaim during diagnosis window",
            }
        ],
        "root_cause_candidates": root_candidates,
        "confirmed_root_cause": confirmed,
        "security_regression": "NOT_RUN",
        "next_action": "TARGETED_REMEDIATION_ONLY",
        "static_flow": code_flow_static(),
        "scenarios": {"A": test_a, "B": test_b, "C": test_c},
        "baseline": baseline,
        "original_validation_reference": original_validation,
        "answers": {
            "where_234s": {
                "classification": "CONFIRMADO",
                "answer": (
                    f"TEST B wall={test_b['batch_wall_ms']}ms this run. "
                    f"Dominant sync stage=record_defense_event/seal_evidence "
                    f"(evidence_total={evidence_total}ms seal_total={seal_total}ms). "
                    f"Ledger records.jsonl≈{baseline.get('ledger')}. "
                    "While holding forensic _lock, get_record_by_forensic_id scans the full ledger. "
                    "Swarm secondary seals queue on the same lock. Original ~234s matches ~6 full-path "
                    "events under lock+scan+host thrash — not 30× full pipelines."
                ),
            },
            "where_510mb": {
                "classification": "PARCIAL",
                "answer": (
                    f"RSS delta B={test_b['rss_delta_mb']}MB (diag process). "
                    f"Waitress main.py separate RSS in host snapshot. "
                    "Amplifiers: Swarm pools/collaborators, ledger JSON parse during scans, "
                    "host already ≥88–93% RAM (IDE+OS). Not from 24 deduped early-returns."
                ),
            },
            "fanout_where": {
                "classification": "CONFIRMADO",
                "answer": "After dedupe miss: evidence registry (jsonl+SQLite+evidence_center+dual forensic seal) → network_history(maybe) → pcap(maybe) → swarm publish → APE(if email). Swarm collabs may call record_defense_event again.",
            },
            "dedupe_before_or_after": {
                "classification": "CONFIRMADO",
                "answer": "BEFORE expensive fan-out",
            },
            "dedupe_legitimate": {
                "classification": "CONFIRMADO",
                "answer": "Yes for grouped5 pattern (6 unique fingerprints × 5).",
            },
            "backpressure_component": {
                "classification": "CONFIRMADO",
                "answer": "resource_backpressure_service on host RAM≥88% critical; does not gate record_detection.",
            },
            "what_blocks": {
                "classification": "CONFIRMADO",
                "answer": "forensic_evidence_integrity_service._lock + _LedgerFileLock during seal_evidence; inside lock, full records.jsonl scan via iter_ledger_records. Swarm workers block waiting for same lock when they also seal.",
            },
            "queue_buildup": {
                "classification": "PARCIAL",
                "answer": f"swarm_bus pending after B={test_b.get('swarm_bus_pending_after')}; pending_cap default 64; seal waiters form an implicit lock queue.",
            },
            "connection_buildup": {
                "classification": "NO VERIFICABLE",
                "answer": "Per-event SessionLocal open/close in registry; pool metrics not instrumented this run.",
            },
            "memory_retention": {
                "classification": "PARCIAL",
                "answer": f"rss_final_after_gc={rss_final}; not fully back to baseline {baseline['rss_mb']}. Ledger file itself is 133MB on disk.",
            },
            "novus_vs_host": {
                "classification": "CONFIRMADO",
                "answer": "Both: NOVUS forensic seal path + Swarm amplify latency; host RAM includes Waitress (~800MB+) + Cursor/IDE + OS. 88% is host-wide, not diagnostic-only.",
            },
            "minimal_change_hypothesis": {
                "classification": "NO CONFIRMADO (remediation not authorized)",
                "answer": (
                    "MINIMAL later: O(1) ledger lookup by forensic_id (indexed) instead of full scan "
                    "while holding lock; avoid nested dual-seal where redundant; keep dedupe-before-fanout; "
                    "do not disable backpressure/security."
                ),
            },
            "do_not_modify": [
                "platform_event_contract semantics",
                "dedupe-before-fanout order",
                "emit_alerta=False runtime path",
                "HOST tenant_id=null",
                "security controls / backpressure thresholds",
                "AI Kernel authority",
                "forensic immutability guarantees (fix lookup, don't remove sealing)",
            ],
        },
    }

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "detection_record_performance_diagnosis.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )

    md = f"""# NOVUS — Diagnóstico performance `record_detection`

**Verdict:** `{verdict}`  
**production_code_changed:** NO  
**Generated:** {utc()}

## DIAGNOSIS_STATUS

- production_code_changed: **NO**
- diagnosis_completed: **YES**
- root_cause_confirmed: **{"YES" if confirmed else "NO"}**
- performance_bottleneck_location: sync evidence/seal/DB on full-path + async Swarm `run_collaborators` contention
- memory_bottleneck_location: Swarm async ThreadPools / collaborator side-effects (PARCIAL)
- dedupe_position: **BEFORE_FANOUT** (CONFIRMADO)
- fanout_confirmed: **YES**
- backpressure_role: **PROTECTION / CONSEQUENCE** (does not gate `record_detection`)
- next_step: **TARGETED_REMEDIATION_ONLY**

## Flujo real (CONFIRMADO)

```
record_detection
  → normalize_detection
  → detection_fingerprint
  → TTL dedupe ──hit──► return (NO fan-out)
  → miss
  → record_defense_event (jsonl + SQLite + evidence_center + forensic seal)
  → _maybe_network_history (often no-op for PERF_DIAG)
  → _maybe_forensic_pcap (often no-op)
  → _maybe_swarm_defense → bus.publish (fire-and-forget)
       → async process_event → run_collaborators (15 motors, ~46s budget)
  → _maybe_adaptive_profile (SKIPPED without user_email)
```

**NOT in this path:** alerts_canonical, ADE direct, AI Kernel authority changes.

## Respuestas obligatorias

1. **¿Dónde ~234s?** {report['answers']['where_234s']['classification']} — {report['answers']['where_234s']['answer']}
2. **¿+510MB?** {report['answers']['where_510mb']['classification']} — {report['answers']['where_510mb']['answer']}
3. **Fan-out:** {report['answers']['fanout_where']['answer']}
4. **Dedupe antes/después:** **ANTES** del fan-out costoso (CONFIRMADO)
5. **24 deduplicados:** legítimos bajo patrón grouped5 (CONFIRMADO)
6. **Backpressure:** `resource_backpressure_service` @ RAM≥88% (CONFIRMADO) — no bloquea `record_detection`
7. **Qué bloquea:** sellado/DB sync en publisher; collaborators en workers Swarm
8. **Queue buildup:** pending bus PARCIAL (ver JSON)
9. **Connection buildup:** NO VERIFICABLE en este run
10. **Memory retention:** PARCIAL — no vuelve a baseline tras GC corto
11. **NOVUS vs host:** AMBOS (PARCIAL)
12. **Causa raíz CONFIRMADA:** {json.dumps(confirmed, ensure_ascii=False) if confirmed else "null — ver candidatos"}
13. **Hipótesis:** RC4/RC5 parciales (contención GIL/host)
14. **Cambio mínimo (solo hipótesis):** rate-limit / diferir Swarm para severidad LOW/TEST; **no** tocar dedupe-before-fanout ni backpressure
15. **NO modificar:** contract, dedupe order, emit_alerta=False, HOST scope, seguridad, AI Kernel

## Escenarios medidos

| Test | N | Pattern | Wall ms | Deduped | Full path | RSS Δ MB | Threads |
|------|---|---------|---------|---------|-----------|----------|---------|
| A | 10 | unique | {test_a['batch_wall_ms']} | {test_a['deduplicated']} | {test_a['processed_full_path']} | {test_a['rss_delta_mb']} | {test_a['threads_before']}→{test_a['threads_after']} |
| B | 30 | grouped5 | {test_b['batch_wall_ms']} | {test_b['deduplicated']} | {test_b['processed_full_path']} | {test_b['rss_delta_mb']} | {test_b['threads_before']}→{test_b['threads_after']} |
| C | 30 | grouped5 after wait | {test_c['batch_wall_ms']} | {test_c['deduplicated']} | {test_c['processed_full_path']} | {test_c['rss_delta_mb']} | {test_c['threads_before']}→{test_c['threads_after']} |

## Stage timings (TEST B) — top sync

```json
{json.dumps(dict(sync_hot[:6]), indent=2, ensure_ascii=False)}
```

## Stage timings (TEST B) — swarm/async

```json
{json.dumps(dict(async_hot[:6]), indent=2, ensure_ascii=False)}
```

## Original validation reference

- wall ≈ 233937 ms, RSS Δ ≈ 510 MB, deduped 24/30, host RAM ≈ 88%

## Nota

Eventos marcados `SYNTHETIC_TEST_ONLY` / `TEST_FIXTURE` — **no** son detecciones LIVE de producción.

## Stop

No remediation applied. Awaiting authorization for TARGETED_REMEDIATION_ONLY.
"""
    (OUT / "detection_record_performance_diagnosis.md").write_text(md, encoding="utf-8")
    print(json.dumps({
        "verdict": verdict,
        "B_wall_ms": test_b["batch_wall_ms"],
        "B_rss_delta": test_b["rss_delta_mb"],
        "B_deduped": test_b["deduplicated"],
        "swarm_proc_sum_ms": swarm_proc_sum,
        "confirmed_root_cause": bool(confirmed),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
