#!/usr/bin/env python3
"""Evidencia normalizada para detecciones endpoint — campos NA si no verificables."""
from __future__ import annotations
import hashlib
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

NA = "NO DISPONIBLE"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    try:
        from services.endpoint_enterprise.yara_engine import _sha256_file as ysha
        return ysha(path)
    except Exception:
        return None


def build_process_evidence(
    *,
    detection_type: str,
    detection_id: str,
    process_name: Optional[str] = None,
    parent_process: Optional[str] = None,
    pid: Optional[int] = None,
    parent_pid: Optional[int] = None,
    command_line: Optional[str] = None,
    executable_path: Optional[str] = None,
    user: Optional[str] = None,
    confidence: str = "medium",
    severity: str = "medium",
    source: str = "endpoint_enterprise.detection_rules",
    why_suspicious: str = "",
    detection_class: str = "observed_behavior",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Objeto evidencia canónico. Nunca inventa campos ausentes."""
    eid = f"DET-{uuid.uuid4().hex[:12].upper()}"
    hostname = socket.gethostname()
    ip = NA
    try:
        from utils.host_data import get_local_ip, format_ip_or_unavailable
        ip = format_ip_or_unavailable(get_local_ip())
    except Exception:
        pass

    sha = _sha256_file(executable_path) if executable_path else None
    sig = NA
    if executable_path:
        try:
            from services.deep_scan_engine import DeepScanEngine
            ds = DeepScanEngine()
            sig_info = ds._get_authenticode(executable_path)
            sig = sig_info.get("digital_signature") or NA
        except Exception:
            sig = NA

    ev = {
        "event_id": eid,
        "timestamp": _utc(),
        "detection_id": detection_id,
        "detection_type": detection_type,
        "detection_class": detection_class,
        "hostname": hostname or NA,
        "ip": ip if ip and ip != "Sin datos disponibles" else NA,
        "user": user if user else NA,
        "pid": pid,
        "parent_pid": parent_pid,
        "process_name": process_name or NA,
        "parent_process": parent_process or NA,
        "command_line": (command_line[:2000] if command_line else NA),
        "executable_path": executable_path or NA,
        "sha256": sha or NA,
        "digital_signature": sig,
        "file_size": NA,
        "source": source,
        "confidence": confidence,
        "severity": severity,
        "why_suspicious": why_suspicious or NA,
        "risk_score": NA,
        "mitre_techniques": NA,
        "related_iocs": [],
        "related_incidents": [],
        "related_assets": [],
        "evidence": extra or {},
        "invented": False,
        "verified": True,
    }
    if executable_path:
        try:
            import os
            ev["file_size"] = os.path.getsize(executable_path)
        except Exception:
            pass
    return ev
