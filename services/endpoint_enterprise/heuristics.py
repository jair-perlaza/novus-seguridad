"""
T2 — Heurísticas avanzadas basadas en comportamiento real (psutil / cmdline / rutas).
Sin firmas AV comerciales.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil

from utils.logger import logger

LOL_BINS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _finding(
    ftype: str,
    *,
    severity: str,
    evidence: dict,
    confidence: str = "medium",
) -> Dict[str, Any]:
    return {
        "finding_type": ftype,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "timestamp_utc": _utc(),
        "verified": True,
        "source": "endpoint_enterprise.heuristics",
    }


def analyze_process(proc: psutil.Process) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        info = proc.as_dict(
            attrs=["pid", "name", "exe", "cmdline", "username", "create_time", "ppid", "cwd"]
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return findings

    name = (info.get("name") or "").lower()
    exe = (info.get("exe") or "") or ""
    cmd = " ".join(info.get("cmdline") or [])
    cmd_l = cmd.lower()
    exe_l = exe.lower()
    pid = info.get("pid")

    # Ejecución desde TEMP
    if any(x in exe_l for x in ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\")):
        findings.append(
            _finding(
                "execution_from_temp",
                severity="high",
                confidence="high",
                evidence={"pid": pid, "name": name, "exe": exe, "user": info.get("username")},
            )
        )

    # PowerShell anómalo
    if name in ("powershell.exe", "pwsh.exe"):
        flags = []
        if "-enc" in cmd_l or "-encodedcommand" in cmd_l:
            flags.append("encoded_command")
        if "bypass" in cmd_l and "executionpolicy" in cmd_l:
            flags.append("executionpolicy_bypass")
        if "downloadstring" in cmd_l or "invoke-webrequest" in cmd_l or "wget " in cmd_l:
            flags.append("download_cradle")
        if "frombase64string" in cmd_l:
            flags.append("base64")
        if flags:
            findings.append(
                _finding(
                    "anomalous_powershell",
                    severity="high" if "encoded_command" in flags or "download_cradle" in flags else "medium",
                    confidence="high",
                    evidence={"pid": pid, "cmdline": cmd[:800], "flags": flags, "user": info.get("username")},
                )
            )

    # CMD sospechoso
    if name == "cmd.exe" and any(x in cmd_l for x in ("powershell", "bitsadmin", "certutil", "curl ", "wget ")):
        findings.append(
            _finding(
                "anomalous_cmd",
                severity="medium",
                confidence="medium",
                evidence={"pid": pid, "cmdline": cmd[:800]},
            )
        )

    # LOLBin + red de descarga
    if name in LOL_BINS and any(x in cmd_l for x in ("http://", "https://", "ftp://")):
        findings.append(
            _finding(
                "lolbin_network_fetch",
                severity="high",
                confidence="medium",
                evidence={"pid": pid, "name": name, "cmdline": cmd[:800]},
            )
        )

    return findings


def detect_process_storm(*, window_pids: Optional[List[int]] = None, threshold: int = 25) -> List[Dict[str, Any]]:
    """Creación masiva: muchos procesos nuevos recientes del mismo padre."""
    findings = []
    try:
        by_ppid: Dict[int, List[int]] = {}
        now = datetime.now().timestamp()
        for p in psutil.process_iter(["pid", "ppid", "create_time", "name"]):
            try:
                ct = p.info.get("create_time") or 0
                if now - ct > 60:
                    continue
                ppid = int(p.info.get("ppid") or 0)
                by_ppid.setdefault(ppid, []).append(int(p.info["pid"]))
            except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
                continue
        for ppid, children in by_ppid.items():
            if len(children) >= threshold:
                findings.append(
                    _finding(
                        "mass_process_creation",
                        severity="high",
                        confidence="medium",
                        evidence={"ppid": ppid, "child_count_60s": len(children), "sample_pids": children[:15]},
                    )
                )
    except Exception as exc:
        logger.debug("process storm: %s", exc)
    return findings


def detect_persistence_changes(prev_tasks: Optional[set], cur_tasks: Optional[set]) -> List[Dict[str, Any]]:
    findings = []
    if prev_tasks is None or cur_tasks is None:
        return findings
    added = sorted(cur_tasks - prev_tasks)[:20]
    if added:
        findings.append(
            _finding(
                "suspicious_persistence_task",
                severity="medium",
                confidence="medium",
                evidence={"new_scheduled_tasks": added},
            )
        )
    return findings


def detect_unsigned_or_unusual_service(new_services: List[str]) -> List[Dict[str, Any]]:
    if not new_services:
        return []
    return [
        _finding(
            "new_service_created",
            severity="medium",
            confidence="high",
            evidence={"services": new_services[:20]},
        )
    ]


def scan_running_processes(*, limit: int = 80) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    n = 0
    for p in psutil.process_iter():
        if n >= limit:
            break
        try:
            out.extend(analyze_process(p))
            n += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    out.extend(detect_process_storm())
    try:
        from services.endpoint_enterprise.detection_rules import (
            detect_office_suspicious_children,
            detect_process_masquerading,
        )
        out.extend(detect_office_suspicious_children())
        out.extend(detect_process_masquerading())
    except Exception as exc:
        logger.debug("detection_rules scan: %s", exc)
    return out
