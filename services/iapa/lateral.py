#!/usr/bin/env python3
"""Lateral movement — solo si hay evidencia en observaciones/SDL/UEBA."""
from __future__ import annotations
from typing import Any, Dict, List

from services.iapa.limitations import NA, NI
from services.iapa.readers import sdl_search, val


LATERAL_MARKERS = {
    "rdp": ("mstsc", "rdp", "3389", "remote desktop"),
    "smb": ("smb", "445", "cifs"),
    "winrm": ("winrm", "5985", "5986"),
    "powershell": ("powershell", "pwsh"),
    "wmi": ("wmic", "wmi", "wmiprvse"),
    "psexec": ("psexec", "psexesvc"),
    "credential_reuse": ("credential", "credential_theft", "mimikatz"),
    "remote_service": ("remote service", "sc.exe", "services.exe"),
}


def lateral_movement_evidence(limit: int = 400) -> Dict[str, Any]:
    evidence: Dict[str, List[Dict[str, Any]]] = {k: [] for k in LATERAL_MARKERS}
    # SDL text search
    res = sdl_search(limit=limit)
    for r in res.get("records") or []:
        blob = " ".join(str(x) for x in [
            r.get("record_type"), r.get("engine"), r.get("malware"), r.get("threat_type"),
            r.get("playbook_id"), r.get("payload_json"), r.get("ioc"),
        ]).lower()
        for kind, markers in LATERAL_MARKERS.items():
            if any(m in blob for m in markers):
                evidence[kind].append({
                    "uuid": r.get("uuid"),
                    "engine": r.get("engine"),
                    "incident_id": val(r, "incident_id"),
                    "marker_hit": True,
                    "invented": False,
                })

    # UEBA process freeze / identities for shell tools
    try:
        from services.identity_intelligence import list_identities
        for i in list_identities("proceso_persistente"):
            name = (i.get("label") or "").lower()
            for kind, markers in LATERAL_MARKERS.items():
                if any(m in name for m in markers):
                    evidence[kind].append({
                        "process": name,
                        "identity_uuid": i.get("uuid"),
                        "source": "ueba_process",
                        "invented": False,
                    })
    except Exception:
        pass

    # Ports from ASM
    try:
        from services.asm.store import load_inventory
        inv = load_inventory() or {}
        for p in inv.get("open_ports") or []:
            port = str(p.get("port") if isinstance(p, dict) else p)
            if port == "3389":
                evidence["rdp"].append({"port": 3389, "source": "asm", "invented": False})
            if port == "445":
                evidence["smb"].append({"port": 445, "source": "asm", "invented": False})
            if port in ("5985", "5986"):
                evidence["winrm"].append({"port": port, "source": "asm", "invented": False})
    except Exception:
        pass

    summary = {}
    for k, items in evidence.items():
        summary[k] = {
            "count": len(items),
            "status": "evidenced" if items else NI,
            "samples": items[:5],
        }

    return {
        "ok": True,
        "lateral": summary,
        "invented": False,
        "note": "Solo marcadores con evidencia textual/puerto/proceso. Sin inferencia de movimiento.",
    }
