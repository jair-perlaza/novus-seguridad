"""
T7 — ETW / Event Log: telemetría de procesos/servicios/drivers cuando el SO lo permite.
Sin privilegios admin, Security log puede fallar — se documenta.
"""
from __future__ import annotations

import json
import platform
import socket
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List

from utils.logger import logger


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect_etw_like_events(*, limit: int = 40) -> Dict[str, Any]:
    """
    Usa Get-WinEvent sobre canales accesibles (System / Application / Microsoft-Windows-Kernel-Process si existe).
    No requiere provider ETW session propio en Fase 1.
    """
    result: Dict[str, Any] = {
        "ok": False,
        "events": [],
        "channels_tried": [],
        "channels_ok": [],
        "limitation": None,
        "timestamp_utc": _utc(),
        "ring0": False,
        "source": "Get-WinEvent",
    }
    if platform.system() != "Windows":
        result["error"] = "windows_only"
        return result

    channels = [
        "System",
        "Application",
        "Microsoft-Windows-Kernel-Process/Analytic",
        "Microsoft-Windows-Kernel-Process/Operational",
        "Security",
    ]
    events: List[Dict[str, Any]] = []
    for ch in channels:
        result["channels_tried"].append(ch)
        try:
            ps = (
                f"Get-WinEvent -LogName '{ch}' -MaxEvents {min(limit, 25)} -ErrorAction Stop | "
                "Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message | "
                "ConvertTo-Json -Compress"
            )
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", ps],
                timeout=20,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            raw = (out or "").strip()
            if not raw:
                continue
            data = json.loads(raw)
            rows = data if isinstance(data, list) else [data]
            result["channels_ok"].append(ch)
            for r in rows:
                msg = str(r.get("Message") or "")[:240]
                eid = r.get("Id")
                # Filter to process/driver/service-ish when possible
                interesting = any(
                    x in msg.lower()
                    for x in ("process", "driver", "service", "load", "start", "stop", "image")
                ) or eid in (6, 7045, 7036, 4688, 4689, 1, 5, 10)
                if not interesting and ch not in ("System",):
                    continue
                events.append(
                    {
                        "channel": ch,
                        "event_id": eid,
                        "provider": r.get("ProviderName"),
                        "level": r.get("LevelDisplayName"),
                        "time": str(r.get("TimeCreated")),
                        "message": msg,
                        "equipment": socket.gethostname(),
                    }
                )
                if len(events) >= limit:
                    break
        except Exception as exc:
            logger.debug("etw channel %s: %s", ch, exc)
            if ch == "Security":
                result["limitation"] = (
                    "Canal Security no accesible sin privilegios de auditoría — "
                    "usar cuenta elevada o Sysmon/EDR para 4688."
                )
        if len(events) >= limit:
            break

    result["events"] = events[:limit]
    result["events_n"] = len(events)
    result["ok"] = len(result["channels_ok"]) > 0
    if not result["ok"]:
        result["limitation"] = result.get("limitation") or "Ningún canal de eventos accesible en esta sesión"
    return result


def etw_events_as_findings(etw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """No alerta por un solo evento ETW; solo metadatos para correlación."""
    # Telemetry for correlation only — severity info so publish layer can skip alone
    out = []
    for ev in (etw.get("events") or [])[:15]:
        out.append(
            {
                "finding_type": "etw_telemetry",
                "severity": "info",
                "confidence": "high",
                "detection_method": "windows_event_log",
                "evidence": ev,
                "timestamp_utc": _utc(),
                "verified": True,
                "source": "rootkit_hybrid.etw",
                "ring0": False,
                "correlate_only": True,
            }
        )
    return out
