#!/usr/bin/env python3
"""
Office → proceso hijo sospechoso — comportamiento observable (no malware confirmado).
Adaptado de ProcessBehaviorAnalyzer; integrado en Endpoint Enterprise / BTDE.
"""
from __future__ import annotations
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List

import psutil

from utils.logger import logger
from services.endpoint_enterprise.detection_rules.evidence_builder import build_process_evidence, NA

OFFICE_BINARIES = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "msaccess.exe", "outlook.exe",
})
DANGEROUS_CHILDREN = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "bitsadmin.exe", "certutil.exe", "rundll32.exe", "regsvr32.exe",
})


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _enrich_child(child: psutil.Process) -> Dict[str, Any]:
    out: Dict[str, Any] = {"pid": child.pid, "name": child.name()}
    try:
        out["exe"] = child.exe()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        out["exe"] = NA
    try:
        cmd = child.cmdline()
        out["command_line"] = " ".join(cmd) if cmd else NA
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        out["command_line"] = NA
    try:
        out["username"] = child.username()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        out["username"] = NA
    try:
        out["ppid"] = child.ppid()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        out["ppid"] = NA
    return out


def detect_office_suspicious_children() -> List[Dict[str, Any]]:
    """
    Detecta Office iniciando intérprete/consola sospechosa.
    Una coincidencia NO confirma malware — solo comportamiento sospechoso.
    """
    findings: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name", "ppid"]):
        try:
            pinfo = proc.info
            p_name = (pinfo.get("name") or "").lower()
            if p_name not in OFFICE_BINARIES:
                continue
            parent = psutil.Process(pinfo["pid"])
            parent_user = NA
            try:
                parent_user = parent.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            for child in parent.children(recursive=True):
                try:
                    child_name = (child.name() or "").lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                if child_name not in DANGEROUS_CHILDREN:
                    continue
                cinfo = _enrich_child(child)
                why = (
                    f"Comportamiento sospechoso detectado: {p_name} inició {child_name}. "
                    f"No implica malware confirmado."
                )
                ev = build_process_evidence(
                    detection_type="office_suspicious_child",
                    detection_id=f"OFFICE-SHELL-{pinfo['pid']}-{child.pid}",
                    process_name=child_name,
                    parent_process=p_name,
                    pid=child.pid,
                    parent_pid=pinfo["pid"],
                    command_line=cinfo.get("command_line") if cinfo.get("command_line") != NA else None,
                    executable_path=cinfo.get("exe") if cinfo.get("exe") != NA else None,
                    user=cinfo.get("username") if cinfo.get("username") != NA else parent_user,
                    confidence="medium",
                    severity="medium",
                    why_suspicious=why,
                    detection_class="observed_behavior",
                    extra={"child": cinfo, "office_binary": p_name},
                )
                findings.append({
                    "finding_type": "office_suspicious_child",
                    "severity": "medium",
                    "confidence": "medium",
                    "evidence": ev,
                    "detection_method": "parent_child_process_tree",
                    "message": why,
                    "timestamp_utc": _utc(),
                    "verified": True,
                    "source": "endpoint_enterprise.detection_rules.office_child_process",
                    "equipment": socket.gethostname(),
                    "invented": False,
                })
                logger.info(
                    "Office suspicious child: %s -> %s (pid=%s) — señal comportamental",
                    p_name, child_name, child.pid,
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return findings
