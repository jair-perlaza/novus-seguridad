"""
T2 — Detección de anomalías comportamentales (sin firmas AV).
"""
from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from utils.logger import logger


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _finding(
    ftype: str,
    *,
    severity: str,
    confidence: str,
    evidence: dict,
    detection_method: str,
) -> Dict[str, Any]:
    return {
        "finding_type": ftype,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "detection_method": detection_method,
        "equipment": socket.gethostname(),
        "timestamp_utc": _utc(),
        "verified": True,
        "source": "behavioral_threat_detection",
        "signature_based": False,
    }


def detect_from_heuristics() -> List[Dict[str, Any]]:
    """Reutiliza heurísticas EEP (TEMP/PS/CMD/LOLBin/storm) — comportamiento real."""
    out: List[Dict[str, Any]] = []
    try:
        from services.endpoint_enterprise.heuristics import scan_running_processes

        for f in scan_running_processes(limit=70):
            ff = dict(f)
            ff["source"] = "behavioral_threat_detection.heuristics"
            ff["signature_based"] = False
            ff["detection_method"] = ff.get("finding_type") or "heuristic"
            out.append(ff)
    except Exception as exc:
        logger.debug("btde heuristics: %s", exc)
    return out


def detect_resource_spikes(snap: Dict[str, Any], prev: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    cur = snap.get("resources") or {}
    cpu = float(cur.get("cpu_percent") or 0)
    mem = float(cur.get("mem_percent") or 0)
    if cpu >= 92:
        findings.append(
            _finding(
                "cpu_spike",
                severity="medium",
                confidence="high",
                detection_method="resource_threshold",
                evidence={"cpu_percent": cpu, "note": "CPU ≥92% medido"},
            )
        )
    if mem >= 93:
        findings.append(
            _finding(
                "memory_pressure",
                severity="medium",
                confidence="high",
                detection_method="resource_threshold",
                evidence={"mem_percent": mem},
            )
        )
    if prev:
        prev_r = prev.get("resources") or {}
        pcpu = float(prev_r.get("cpu_percent") or 0)
        if pcpu > 0 and cpu - pcpu >= 45 and cpu >= 70:
            findings.append(
                _finding(
                    "abrupt_cpu_change",
                    severity="medium",
                    confidence="medium",
                    detection_method="delta_resources",
                    evidence={"cpu_now": cpu, "cpu_prev": pcpu, "delta": round(cpu - pcpu, 1)},
                )
            )
    return findings


def detect_baseline_novelties(learn_meta: Dict[str, Any], *, warm: bool) -> List[Dict[str, Any]]:
    """Comportamientos nunca vistos — solo tras warm-up (anti-FP)."""
    findings = []
    if not warm or learn_meta.get("was_cold"):
        return findings
    new_procs = learn_meta.get("new_proc_names") or []
    # Filtrar ruido común de Windows
    noise = {"conhost.exe", "runtimebroker.exe", "dllhost.exe", "taskhostw.exe", "svchost.exe", "searchprotocolhost.exe"}
    novel = [n for n in new_procs if n and n not in noise]
    if len(novel) >= 3:
        findings.append(
            _finding(
                "never_seen_processes",
                severity="medium",
                confidence="medium",
                detection_method="baseline_process_names",
                evidence={"new_names": novel[:20], "count": len(novel)},
            )
        )
    elif novel:
        # 1-2 procesos nuevos: low — no alerta solo
        findings.append(
            _finding(
                "never_seen_processes",
                severity="low",
                confidence="low",
                detection_method="baseline_process_names",
                evidence={"new_names": novel[:10], "count": len(novel)},
            )
        )
    new_svcs = learn_meta.get("new_services") or []
    if new_svcs:
        findings.append(
            _finding(
                "new_running_service",
                severity="medium",
                confidence="high",
                detection_method="baseline_services",
                evidence={"services": new_svcs[:20]},
            )
        )
    new_remotes = learn_meta.get("new_remotes_sample") or []
    n_rem = int(learn_meta.get("new_remotes_n") or 0)
    if n_rem >= 12:
        findings.append(
            _finding(
                "unusual_connections_burst",
                severity="medium",
                confidence="medium",
                detection_method="baseline_remotes",
                evidence={"new_remote_n": n_rem, "sample": new_remotes},
            )
        )
    return findings


def detect_privilege_escalation_hints(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Indicio verificable: hijo con usuario privilegiado distinto del padre (mismo árbol reciente).
    No afirma exploit; registra inconsistencia de identidad.
    """
    findings = []
    sample = (snap.get("processes") or {}).get("sample") or []
    by_pid = {p["pid"]: p for p in sample if p.get("pid")}
    privileged_markers = ("system", "local service", "network service", "authority\\system")
    for p in sample:
        try:
            user = (p.get("user") or "").lower()
            ppid = p.get("ppid")
            if not ppid or ppid not in by_pid:
                continue
            parent = by_pid[ppid]
            puser = (parent.get("user") or "").lower()
            child_priv = any(m in user for m in privileged_markers)
            parent_priv = any(m in puser for m in privileged_markers)
            if child_priv and not parent_priv and puser and "\\" in puser:
                # usuario interactivo → SYSTEM hijo
                findings.append(
                    _finding(
                        "privilege_context_anomaly",
                        severity="high",
                        confidence="medium",
                        detection_method="parent_child_user_mismatch",
                        evidence={
                            "pid": p.get("pid"),
                            "process": p.get("name"),
                            "user": p.get("user"),
                            "ppid": ppid,
                            "parent": parent.get("name"),
                            "parent_user": parent.get("user"),
                        },
                    )
                )
                if len(findings) >= 5:
                    break
        except Exception:
            continue
    return findings


def detect_persistence_changes(snap: Dict[str, Any], prev: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    cur = snap.get("persistence") or {}
    if cur.get("deferred") or not cur.get("ok"):
        return findings
    if not prev:
        return findings
    prev_p = prev.get("persistence") or {}
    if prev_p.get("deferred") or not prev_p.get("ok"):
        return findings
    cur_names = set(cur.get("names") or [])
    prev_names = set(prev_p.get("names") or [])
    added = sorted(cur_names - prev_names)
    if added:
        findings.append(
            _finding(
                "new_persistence_runkey",
                severity="high",
                confidence="high",
                detection_method="runkey_diff",
                evidence={"new_run_values": added, "entries": [e for e in (cur.get("entries") or []) if e.get("name", "").lower() in added][:10]},
            )
        )
    return findings


def detect_connection_fanout(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    conns = snap.get("connections") or {}
    if not conns.get("ok"):
        return findings
    remote_n = int(conns.get("remote_n") or 0)
    if remote_n >= 80:
        findings.append(
            _finding(
                "high_connection_fanout",
                severity="medium",
                confidence="high",
                detection_method="connection_count",
                evidence={"remote_unique": remote_n, "total": conns.get("count")},
            )
        )
    return findings


def collect_anomaly_findings(
    snap: Dict[str, Any],
    *,
    prev: Optional[Dict[str, Any]],
    learn_meta: Dict[str, Any],
    warm: bool,
    include_heuristics: bool = True,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if include_heuristics:
        findings.extend(detect_from_heuristics())
    findings.extend(detect_resource_spikes(snap, prev))
    findings.extend(detect_baseline_novelties(learn_meta, warm=warm))
    findings.extend(detect_privilege_escalation_hints(snap))
    findings.extend(detect_persistence_changes(snap, prev))
    findings.extend(detect_connection_fanout(snap))
    return findings
