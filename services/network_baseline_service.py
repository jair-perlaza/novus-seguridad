"""Baseline de dispositivos LAN — comparación verificable entre escaneos."""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Set

BASELINE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "network_baseline", "lan_baseline.json"
)


def _ensure_dir() -> None:
    os.makedirs(os.path.dirname(BASELINE_PATH), exist_ok=True)


def _mac_set(nodes: List[dict]) -> Set[str]:
    out: Set[str] = set()
    for n in nodes or []:
        mac = (n.get("mac") or "").lower().strip()
        if mac and mac != "00:00:00:00:00:00":
            out.add(mac)
    return out


def load_baseline() -> Dict[str, Any]:
    if not os.path.isfile(BASELINE_PATH):
        return {}
    try:
        with open(BASELINE_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def update_baseline(nodes: List[dict], *, source: str = "ndr") -> Dict[str, Any]:
    _ensure_dir()
    macs = sorted(_mac_set(nodes))
    payload = {
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "device_count": len(macs),
        "macs": macs,
        "source": source,
    }
    with open(BASELINE_PATH, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return payload


def compare_to_baseline(nodes: List[dict]) -> Dict[str, Any]:
    base = load_baseline()
    prev = set(base.get("macs") or [])
    current = _mac_set(nodes)
    new_macs = sorted(current - prev)
    missing_macs = sorted(prev - current) if prev else []
    return {
        "baseline_at": base.get("updated_at"),
        "baseline_count": len(prev),
        "current_count": len(current),
        "new_devices": new_macs,
        "missing_from_scan": missing_macs,
        "has_baseline": bool(prev),
        "verified": True,
    }
