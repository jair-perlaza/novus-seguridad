"""Configuración del Network Monitor Engine."""
from __future__ import annotations

import json
import os
from typing import Any, Dict

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "network_monitor.json")

DEFAULTS: Dict[str, Any] = {
    # Enterprise defaults: maintain monitoring while reducing continuous CPU pressure.
    "normal_interval_min_sec": 20,
    "normal_interval_max_sec": 40,
    "intensive_interval_sec": 8,
    "intensive_stable_cycles": 5,
    "full_port_rescan_sec": 900,
    "traffic_change_threshold_connections": 15,
    "traffic_change_threshold_percent": 25,
}


def get_network_monitor_config() -> Dict[str, Any]:
    cfg = dict(DEFAULTS)
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                cfg.update({k: loaded[k] for k in DEFAULTS if k in loaded})
        except Exception:
            pass
    return cfg
