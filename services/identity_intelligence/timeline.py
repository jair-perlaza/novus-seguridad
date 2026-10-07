#!/usr/bin/env python3
"""Timeline de identidad — cronología de eventos reales."""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from services.identity_intelligence.limitations import NA
from services.identity_intelligence.store import load_observations, load_identities
from services.identity_intelligence.behavior_baseline import _parse_hour


def _sort_key(o: Dict[str, Any]):
    for k in ("login_at", "timestamp_utc", "logout_at"):
        v = o.get(k)
        if v:
            return str(v)
    return ""


def build_identity_timeline(identity_uuid: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
    obs = load_observations(1000)
    if identity_uuid:
        obs = [o for o in obs if o.get("identity_uuid") == identity_uuid]
    obs = sorted(obs, key=_sort_key)
    events = []
    for o in obs[-limit:]:
        kind = o.get("kind")
        label = kind
        if kind == "authentication":
            label = f"login ip={o.get('ip')} device={o.get('device_type')}"
        elif kind == "process_sighting":
            label = f"proceso {o.get('process_name')}"
        elif kind == "incident_link":
            label = f"incidente {o.get('incident_id')}"
        elif kind == "host_inventory":
            label = f"host ip={o.get('ip')} gw={o.get('gateway')}"
        elif kind == "network_snapshot":
            label = f"conexiones={o.get('connection_count')}"
        events.append({
            "timestamp": o.get("login_at") or o.get("timestamp_utc") or NA,
            "kind": kind,
            "label": label,
            "identity_uuid": o.get("identity_uuid") or NA,
            "source": o.get("source") or NA,
            "invented": False,
        })

    # Enrich with SDL events related to identity's incidents (read-only)
    try:
        from services.sdl import search as sdl_search
        linked_incidents = [e for e in events if e.get("kind") == "incident_link" or "incidente" in str(e.get("label"))]
        # Also pull from observations again
        for o in load_observations(500):
            if identity_uuid and o.get("identity_uuid") != identity_uuid:
                continue
            if o.get("kind") == "incident_link" and o.get("incident_id"):
                res = sdl_search(incident_id=o["incident_id"], limit=20)
                for r in (res.get("records") or [])[:10]:
                    events.append({
                        "timestamp": r.get("timestamp_utc") or NA,
                        "kind": r.get("record_type") or r.get("engine"),
                        "label": f"{r.get('engine')}:{r.get('record_type')} {r.get('ioc') or r.get('playbook_id') or ''}".strip(),
                        "identity_uuid": identity_uuid or NA,
                        "source": "sdl",
                        "invented": False,
                    })
    except Exception:
        pass

    events = sorted(events, key=lambda e: str(e.get("timestamp") or ""))
    first = events[0] if events else NA
    return {
        "ok": True,
        "identity_uuid": identity_uuid or NA,
        "events": events[-limit:],
        "count": len(events[-limit:]),
        "first_indicator": first,
        "message": None if events else NA,
        "invented": False,
    }
