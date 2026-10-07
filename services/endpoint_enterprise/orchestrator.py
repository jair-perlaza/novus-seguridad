"""
Orquestador Endpoint Enterprise — ciclos incrementales de bajo costo.
"""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import logger

INTERVAL_SEC = int(os.environ.get("NOVUS_ENDPOINT_ENTERPRISE_INTERVAL", "60"))
HEAVY_EVERY_N = 6
YARA_PROC_SAMPLE = 8

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "active": False,
    "started_at": None,
    "last_cycle_at": None,
    "cycles": 0,
    "last_error": None,
    "last_yara_hits": 0,
    "last_heuristic_n": 0,
    "last_memory_n": 0,
    "last_published_n": 0,
    "last_duration_ms": None,
    "last_host_risk": None,
}
_thread: Optional[threading.Thread] = None
_stop: Optional[threading.Event] = None
_prev_services: Optional[set] = None
_prev_tasks: Optional[set] = None


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_endpoint_enterprise_cycle(*, force_heavy: bool = False) -> Dict[str, Any]:
    global _prev_services, _prev_tasks
    t0 = time.time()
    summary: Dict[str, Any] = {"ok": False}

    from services.endpoint_enterprise.yara_engine import (
        ensure_engine,
        get_engine_status,
        scan_file,
        scan_process_memory,
        scan_watch_dirs,
    )
    from services.endpoint_enterprise.heuristics import (
        detect_unsigned_or_unusual_service,
        detect_persistence_changes,
        scan_running_processes,
    )
    from services.endpoint_enterprise.memory_analysis import analyze_sample_processes
    from services.endpoint_enterprise.rootkit_indicators import run_rootkit_indicator_checks
    from services.endpoint_enterprise.risk_score import aggregate_host_risk, compute_process_risk
    from services.endpoint_enterprise.publish import publish_findings, publish_finding, host_profile_email

    with _lock:
        cycle_n = int(_state.get("cycles") or 0) + 1
        heavy = force_heavy or (cycle_n % HEAVY_EVERY_N == 0)

    try:
        yara_status = get_engine_status()
        ensure_engine()

        # Heuristics (light every cycle)
        heur = scan_running_processes(limit=60)
        # Memory sample
        mem = analyze_sample_processes(limit=10 if not heavy else 18)

        # YARA files (watch dirs) — every cycle but capped
        yara_hits = scan_watch_dirs(max_files=25 if heavy else 12)

        # YARA process memory — sample PIDs from heuristic findings or top CPU
        import psutil

        pids_to_scan = []
        for f in heur:
            pid = (f.get("evidence") or {}).get("pid")
            if pid and pid not in pids_to_scan:
                pids_to_scan.append(int(pid))
        if len(pids_to_scan) < YARA_PROC_SAMPLE:
            try:
                for p in sorted(
                    psutil.process_iter(["pid", "cpu_percent", "name"]),
                    key=lambda x: float((x.info or {}).get("cpu_percent") or 0),
                    reverse=True,
                )[:YARA_PROC_SAMPLE]:
                    pid = int(p.info["pid"])
                    if pid not in pids_to_scan and pid > 4:
                        pids_to_scan.append(pid)
            except Exception:
                pass
        mem_yara_meta = []
        for pid in pids_to_scan[:YARA_PROC_SAMPLE]:
            hits, meta = scan_process_memory(pid)
            yara_hits.extend(hits)
            mem_yara_meta.append(meta)

        # Services / tasks diffs (heavy)
        rootkit = None
        if heavy:
            try:
                cur_svcs = set()
                if hasattr(psutil, "win_service_iter"):
                    for s in psutil.win_service_iter():
                        try:
                            if s.status() == "running":
                                cur_svcs.add(s.name().lower())
                        except Exception:
                            continue
                if _prev_services is not None:
                    added = sorted(cur_svcs - _prev_services)
                    heur.extend(detect_unsigned_or_unusual_service(added))
                _prev_services = cur_svcs
            except Exception as exc:
                logger.debug("svc diff: %s", exc)

            # scheduled tasks light
            try:
                from services.network_endpoint_enterprise.endpoint_extended import _scheduled_tasks_windows

                cur_tasks = _scheduled_tasks_windows()
                heur.extend(detect_persistence_changes(_prev_tasks, cur_tasks))
                _prev_tasks = cur_tasks
            except Exception as exc:
                logger.debug("tasks diff: %s", exc)

            rootkit = run_rootkit_indicator_checks(publish=True)
            for f in rootkit.get("findings") or []:
                heur.append(f)
            summary["rootkit_hybrid"] = rootkit.get("hybrid")

        # Risk scores for processes with findings
        by_pid: Dict[int, Dict[str, Any]] = {}
        for f in heur:
            pid = (f.get("evidence") or {}).get("pid")
            if not pid:
                continue
            pid = int(pid)
            by_pid.setdefault(pid, {"heur": [], "yara": [], "mem": [], "name": (f.get("evidence") or {}).get("name")})
            by_pid[pid]["heur"].append(f)
        for h in yara_hits:
            if h.get("pid"):
                pid = int(h["pid"])
                by_pid.setdefault(pid, {"heur": [], "yara": [], "mem": [], "name": h.get("process")})
                by_pid[pid]["yara"].append(h)
        for m in mem:
            pid = (m.get("evidence") or {}).get("pid")
            if pid:
                pid = int(pid)
                by_pid.setdefault(pid, {"heur": [], "yara": [], "mem": [], "name": (m.get("evidence") or {}).get("process")})
                by_pid[pid]["mem"].append(m)

        scores = []
        for pid, bag in by_pid.items():
            exe_temp = False
            for f in bag["heur"]:
                if f.get("finding_type") == "execution_from_temp":
                    exe_temp = True
            scores.append(
                compute_process_risk(
                    pid=pid,
                    name=bag.get("name"),
                    heuristic_findings=bag["heur"],
                    yara_hits=bag["yara"],
                    memory_findings=bag["mem"],
                    from_temp=exe_temp,
                )
            )
        host_risk = aggregate_host_risk(scores, extra_findings=len(heur) + len(yara_hits) + len(mem))

        # Publish medium+
        published = 0
        published += publish_findings(heur, prefix="heur")
        published += publish_findings(yara_hits, prefix="yara")
        published += publish_findings(mem, prefix="mem")
        if host_risk.get("score", 0) >= 60:
            publish_finding(
                action="eep_host_risk_elevated",
                evidence={"host_risk": host_risk, "verified": True},
                threat_type="endpoint_host_risk",
                confidence="medium",
                finding_id=f"EEP-HOST-RISK-{int(time.time())}",
                risk_level=host_risk.get("level"),
                feed_ape=False,
            )
            published += 1

        # APE learnable tick (non-threat)
        try:
            from services.adaptive_profile_engine import observe_async

            observe_async(
                host_profile_email(),
                event_type="endpoint_enterprise_tick",
                ip=None,
                evidence={
                    "learnable": True,
                    "process_count": len(psutil.pids()),
                    "heuristic_n": len(heur),
                    "yara_engine": yara_status.get("backend"),
                },
                risk_level="info",
                evaluate=False,
            )
        except Exception as exc:
            logger.debug("eep ape: %s", exc)

        summary.update(
            {
                "ok": True,
                "heavy": heavy,
                "yara": yara_status,
                "heuristic_n": len(heur),
                "yara_hits": len(yara_hits),
                "memory_findings": len(mem),
                "published": published,
                "host_risk": host_risk,
                "rootkit_cross_view": {
                    "ran": rootkit is not None,
                    "findings": len((rootkit or {}).get("findings") or []),
                    "kernel_engine": False,
                    "ssdt_implemented": False,
                    "hybrid": (rootkit or {}).get("hybrid"),
                },
                "rootkit_hybrid": (rootkit or {}).get("hybrid") if rootkit else summary.get("rootkit_hybrid"),
                "memory_scan_sample": mem_yara_meta[:3],
            }
        )
    except Exception as exc:
        summary["error"] = str(exc)[:300]
        logger.warning("endpoint enterprise cycle: %s", exc)

    duration_ms = round((time.time() - t0) * 1000, 1)
    with _lock:
        _state["cycles"] = cycle_n
        _state["last_cycle_at"] = _utc()
        _state["last_duration_ms"] = duration_ms
        _state["last_yara_hits"] = summary.get("yara_hits") or 0
        _state["last_heuristic_n"] = summary.get("heuristic_n") or 0
        _state["last_memory_n"] = summary.get("memory_findings") or 0
        _state["last_published_n"] = summary.get("published") or 0
        _state["last_host_risk"] = summary.get("host_risk")
        _state["last_error"] = summary.get("error")
    summary["duration_ms"] = duration_ms
    summary["cycle"] = cycle_n
    return summary


def _loop(stop: threading.Event) -> None:
    with _lock:
        _state["active"] = True
        _state["started_at"] = _utc()
    run_endpoint_enterprise_cycle(force_heavy=True)
    while not stop.is_set():
        stop.wait(INTERVAL_SEC)
        if stop.is_set():
            break
        run_endpoint_enterprise_cycle()
    with _lock:
        _state["active"] = False


def start_endpoint_enterprise() -> Dict[str, Any]:
    global _thread, _stop
    if _thread and _thread.is_alive():
        return {"status": "already_running", **get_endpoint_enterprise_status()}
    _stop = threading.Event()
    _thread = threading.Thread(target=_loop, args=(_stop,), daemon=True, name="EndpointEnterprise")
    _thread.start()
    logger.info("Endpoint Enterprise iniciado (interval=%ss)", INTERVAL_SEC)
    return {"status": "started", "interval_sec": INTERVAL_SEC}


def stop_endpoint_enterprise() -> Dict[str, Any]:
    global _thread, _stop
    if _stop:
        _stop.set()
    if _thread:
        _thread.join(timeout=8)
    with _lock:
        _state["active"] = False
    return {"status": "stopped"}


def get_endpoint_enterprise_status() -> Dict[str, Any]:
    with _lock:
        return {
            "ok": True,
            "active": _state.get("active"),
            "started_at": _state.get("started_at"),
            "last_cycle_at": _state.get("last_cycle_at"),
            "cycles": _state.get("cycles"),
            "last_duration_ms": _state.get("last_duration_ms"),
            "last_yara_hits": _state.get("last_yara_hits"),
            "last_heuristic_n": _state.get("last_heuristic_n"),
            "last_memory_n": _state.get("last_memory_n"),
            "last_published_n": _state.get("last_published_n"),
            "last_host_risk": _state.get("last_host_risk"),
            "last_error": _state.get("last_error"),
            "interval_sec": INTERVAL_SEC,
            "version": "1.0.0-endpoint-enterprise-fase1",
            "kernel_rootkit_own_driver": False,
        }
