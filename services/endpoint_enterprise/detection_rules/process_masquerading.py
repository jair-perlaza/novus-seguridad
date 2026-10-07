#!/usr/bin/env python3
"""
Detección heurística de suplantación de proceso (ej. svchost fuera de System32).
Comportamiento observable — no afirma inyección de memoria sin evidencia adicional.
"""
from __future__ import annotations
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List

import psutil

from utils.logger import logger
from services.endpoint_enterprise.detection_rules.evidence_builder import build_process_evidence, NA

MASQUERADE_NAMES = frozenset({"svchost.exe", "explorer.exe", "lsass.exe"})
SAFE_PATH_MARKERS = ("system32", "syswow64", "windows\\system32", "windows\\syswow64")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def detect_process_masquerading() -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name", "exe", "ppid"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            if name not in MASQUERADE_NAMES:
                continue
            exe_path = info.get("exe") or ""
            if not exe_path:
                continue
            exe_l = exe_path.lower().replace("/", "\\")
            if any(m in exe_l for m in SAFE_PATH_MARKERS):
                continue
            why = (
                f"Proceso {name} ejecutándose fuera de ruta System32/SysWOW64 esperada: {exe_path}. "
                f"Indicador de posible suplantación — no confirma inyección de memoria."
            )
            user = NA
            try:
                user = psutil.Process(info["pid"]).username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            ev = build_process_evidence(
                detection_type="process_masquerading",
                detection_id=f"MASQ-{info['pid']}-{name}",
                process_name=name,
                pid=info.get("pid"),
                parent_pid=info.get("ppid"),
                executable_path=exe_path,
                user=user if user != NA else None,
                confidence="high",
                severity="high",
                why_suspicious=why,
                detection_class="observed_behavior",
            )
            findings.append({
                "finding_type": "process_masquerading",
                "severity": "high",
                "confidence": "high",
                "evidence": ev,
                "detection_method": "executable_path_heuristic",
                "message": why,
                "timestamp_utc": _utc(),
                "verified": True,
                "source": "endpoint_enterprise.detection_rules.process_masquerading",
                "equipment": socket.gethostname(),
                "invented": False,
            })
            logger.warning("Process masquerading signal: %s path=%s", name, exe_path)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings
