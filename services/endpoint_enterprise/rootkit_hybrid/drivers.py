"""
T4 — Inventario y comparación de drivers (user-mode).
No afirma drivers ocultos sin evidencia.
"""
from __future__ import annotations

import csv
import io
import platform
import socket
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from utils.logger import logger


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def inventory_drivers() -> Dict[str, Any]:
    """driverquery /v — registrados/cargados según vista user-mode."""
    result: Dict[str, Any] = {
        "ok": False,
        "drivers": [],
        "by_state": {},
        "unsigned_sample": [],
        "limitation": "Vista user-mode (driverquery); no enumera drivers ocultos al Object Manager",
        "timestamp_utc": _utc(),
    }
    if platform.system() != "Windows":
        result["error"] = "windows_only"
        return result
    try:
        out = subprocess.check_output(
            ["driverquery", "/V", "/FO", "CSV"],
            timeout=45,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        reader = csv.DictReader(io.StringIO(out))
        rows = []
        states: Dict[str, int] = {}
        unsigned = []
        for row in reader:
            # Headers vary by locale — try common keys
            name = (
                row.get("Module Name")
                or row.get("Nombre de módulo")
                or row.get("Nombre módu.")
                or row.get("Display Name")
                or (list(row.values())[0] if row else None)
            )
            state = row.get("State") or row.get("Estado") or ""
            path = (
                row.get("Path")
                or row.get("Image Path")
                or row.get("Ruta de acceso")
                or row.get("Ruta")
                or ""
            )
            # DictReader may mangle accents — fallback: last path-looking value
            if not path:
                for v in row.values():
                    vs = (v or "").strip()
                    if ".sys" in vs.lower() or ":\\" in vs:
                        path = vs
                        break
            link_date = row.get("Link Date") or row.get("Fecha de vínculo") or row.get("Fecha de vínculo") or ""
            # Signing not always in driverquery /v — note absence
            entry = {
                "name": (name or "").strip(),
                "state": (state or "").strip(),
                "path": (path or "").strip(),
                "link_date": (link_date or "").strip(),
                "raw_keys": list(row.keys())[:8],
            }
            if not entry["name"]:
                continue
            rows.append(entry)
            st = entry["state"].lower() or "unknown"
            states[st] = states.get(st, 0) + 1
        result["ok"] = True
        result["drivers"] = rows[:500]
        result["count"] = len(rows)
        result["by_state"] = states
        # Digital signature via Get-AuthenticodeSignature sample (prefer Running, then any .sys)
        signed_probe = []
        candidates = [d for d in rows if (d.get("path") or "").lower().endswith(".sys")]
        running = [d for d in candidates if "run" in (d.get("state") or "").lower() or "ejecut" in (d.get("state") or "").lower()]
        sample_src = (running or candidates)[:40]
        for d in sample_src:
            p = d.get("path")
            if not p:
                continue
            if p.startswith("\\"):
                p2 = p.replace("\\??\\", "")
                if "systemroot" in p2.lower():
                    import os

                    p2 = p2.replace("\\SystemRoot", os.environ.get("SystemRoot", "C:\\Windows"), 1)
                    p2 = p2.replace("SystemRoot", os.environ.get("SystemRoot", "C:\\Windows"), 1)
                p = p2
            try:
                ps = subprocess.check_output(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        f"if (Test-Path -LiteralPath '{p}') {{ "
                        f"(Get-AuthenticodeSignature -FilePath '{p}').Status }} else {{ 'Missing' }}",
                    ],
                    timeout=8,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                )
                status = (ps or "").strip()
                signed_probe.append({"name": d["name"], "path": p, "signature_status": status})
                if status and status.lower() not in ("valid", "missing"):
                    unsigned.append(signed_probe[-1])
            except Exception:
                continue
            if len(signed_probe) >= 12:
                break
        result["signature_probe"] = signed_probe
        result["unsigned_or_untrusted_sample"] = unsigned
    except Exception as exc:
        result["error"] = str(exc)[:240]
        logger.debug("driver inventory: %s", exc)
    return result


def compare_driver_sets(inv: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Hallazgos solo con evidencia (p.ej. firma no válida en muestra). No inventa ocultos."""
    findings = []
    for u in inv.get("unsigned_or_untrusted_sample") or []:
        findings.append(
            {
                "finding_type": "driver_signature_anomaly",
                "severity": "medium",
                "confidence": "high",
                "detection_method": "authenticode_probe",
                "evidence": u,
                "equipment": socket.gethostname(),
                "timestamp_utc": _utc(),
                "verified": True,
                "source": "rootkit_hybrid.drivers",
                "ring0": False,
                "note": "No implica driver oculto; indica estado de firma verificable",
            }
        )
    return findings
