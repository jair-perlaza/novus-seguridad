#!/usr/bin/env python3
"""
Baseline comportamental — aprendido solo de observaciones reales.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from services.identity_intelligence.limitations import NA, MIN_BASELINE_OBS
from services.identity_intelligence.store import (
    load_baselines, save_baselines, load_observations, load_identities,
)


def _parse_hour(login_at) -> Optional[int]:
    if login_at is None:
        return None
    s = str(login_at)
    # Try HH:MM inside string
    for part in s.replace("T", " ").split(" "):
        if ":" in part:
            try:
                return int(part.split(":")[0])
            except Exception:
                continue
    return None


def rebuild_baselines() -> Dict[str, Any]:
    """Reconstruye baselines por identidad a partir de observations.jsonl + identidades."""
    obs = load_observations(limit=2000)
    identities = (load_identities().get("identities") or {})
    by_id: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    global_net_counts = []

    for o in obs:
        iid = o.get("identity_uuid")
        if iid:
            by_id[iid].append(o)
        if o.get("kind") == "network_snapshot" and o.get("connection_count") is not None:
            global_net_counts.append(int(o["connection_count"]))

    baselines: Dict[str, Any] = {}
    for iid, items in by_id.items():
        ident = identities.get(iid) or {}
        hours = Counter()
        ips = Counter()
        devices = Counter()
        processes = Counter()
        gateways = Counter()
        dns_vals = Counter()
        durations = []
        auth_count = 0

        for o in items:
            if o.get("kind") == "authentication":
                auth_count += 1
                h = _parse_hour(o.get("login_at"))
                if h is not None:
                    hours[h] += 1
                if o.get("ip"):
                    ips[str(o["ip"])] += 1
                if o.get("device_type"):
                    devices[str(o["device_type"])] += 1
                if o.get("duration_seconds") is not None:
                    try:
                        durations.append(float(o["duration_seconds"]))
                    except Exception:
                        pass
            if o.get("kind") == "host_inventory":
                if o.get("ip"):
                    ips[str(o["ip"])] += 1
                if o.get("gateway"):
                    gateways[str(o["gateway"])] += 1
                dns = o.get("dns")
                if isinstance(dns, list):
                    for d in dns:
                        dns_vals[str(d)] += 1
                elif dns:
                    dns_vals[str(dns)] += 1
            if o.get("kind") == "process_sighting" and o.get("process_name"):
                processes[str(o["process_name"]).lower()] += 1
            if o.get("kind") == "device_event" and o.get("ip"):
                ips[str(o["ip"])] += 1

        obs_n = len(items)
        sufficient = obs_n >= MIN_BASELINE_OBS
        avg_duration = (sum(durations) / len(durations)) if durations else NA
        baselines[iid] = {
            "identity_uuid": iid,
            "identity_type": ident.get("type"),
            "label": ident.get("label"),
            "observation_count": obs_n,
            "sufficient": sufficient,
            "status": "ready" if sufficient else "insufficient_baseline",
            "usual_hours": dict(hours) if hours else NA,
            "usual_ips": dict(ips.most_common(20)) if ips else NA,
            "usual_devices": dict(devices) if devices else NA,
            "usual_gateways": dict(gateways) if gateways else NA,
            "usual_dns": dict(dns_vals) if dns_vals else NA,
            "usual_processes": dict(processes.most_common(50)) if processes else NA,
            "auth_frequency": auth_count if auth_count else NA,
            "avg_session_duration_sec": avg_duration,
            "invented": False,
        }

    # Host-level traffic baseline from snapshots
    traffic_baseline = NA
    if len(global_net_counts) >= MIN_BASELINE_OBS:
        avg = sum(global_net_counts) / len(global_net_counts)
        traffic_baseline = {
            "samples": len(global_net_counts),
            "avg_connections": avg,
            "max_connections": max(global_net_counts),
            "invented": False,
        }

    payload = {
        "baselines": baselines,
        "traffic_baseline": traffic_baseline,
        "min_observations": MIN_BASELINE_OBS,
        "invented": False,
    }
    save_baselines(payload)
    return {
        "ok": True,
        "baseline_count": len(baselines),
        "sufficient_count": sum(1 for b in baselines.values() if b.get("sufficient")),
        "traffic_baseline": traffic_baseline,
        "invented": False,
    }


def get_baseline(identity_uuid: str) -> Dict[str, Any]:
    data = load_baselines()
    b = (data.get("baselines") or {}).get(identity_uuid)
    if not b:
        return {"status": NA, "sufficient": False, "invented": False}
    return b
