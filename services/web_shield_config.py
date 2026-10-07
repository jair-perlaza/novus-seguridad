"""Configuración NOVUS Web Shield — políticas reales persistidas en disco."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "web_shield.json")

DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "sensitivity": "balanced",
    "mode": "block",
    "block_threshold": 70,
    "warn_threshold": 45,
    "whitelist_domains": [],
    "blacklist_domains": [],
    "allowed_download_extensions": [],
    "quarantine_enabled": True,
    "monitor_downloads": True,
    "monitor_hosts_proxy_dns": True,
    "cycle_interval_sec": 8,
    "max_events_per_cycle": 20,
}

SENSITIVITY_OFFSETS = {
    "low": 15,
    "balanced": 0,
    "high": -15,
}


def load_web_shield_config() -> Dict[str, Any]:
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            merged = {**DEFAULT_CONFIG, **data}
            return merged
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_web_shield_config(updates: Dict[str, Any]) -> Dict[str, Any]:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    current = load_web_shield_config()
    for key in (
        "enabled", "sensitivity", "mode", "block_threshold", "warn_threshold",
        "whitelist_domains", "blacklist_domains", "allowed_download_extensions",
        "quarantine_enabled", "monitor_downloads", "monitor_hosts_proxy_dns",
        "cycle_interval_sec",
    ):
        if key in updates:
            current[key] = updates[key]
    with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(current, fh, indent=2, ensure_ascii=False)
    return current


def effective_block_threshold(cfg: Dict[str, Any]) -> int:
    base = int(cfg.get("block_threshold") or 70)
    sens = (cfg.get("sensitivity") or "balanced").lower()
    return max(30, min(95, base + SENSITIVITY_OFFSETS.get(sens, 0)))


def effective_warn_threshold(cfg: Dict[str, Any]) -> int:
    base = int(cfg.get("warn_threshold") or 45)
    sens = (cfg.get("sensitivity") or "balanced").lower()
    return max(20, min(90, base + SENSITIVITY_OFFSETS.get(sens, 0)))
