"""Configuración NOVUS Mail Shield."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "mail_shield.json")

DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "sensitivity": "balanced",
    "mode": "quarantine",
    "risk_block_threshold": 75,
    "risk_warn_threshold": 45,
    "whitelist_domains": [],
    "blacklist_domains": [],
    "quarantine_policy": "label_and_remove_inbox",
    "notify_admin": True,
    "auto_quarantine": True,
    "analyze_links_with_web_shield": True,
}

SENSITIVITY_OFFSETS = {"low": 10, "balanced": 0, "high": -10}


def load_mail_shield_config() -> Dict[str, Any]:
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
                return {**DEFAULT_CONFIG, **json.load(fh)}
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_mail_shield_config(updates: Dict[str, Any]) -> Dict[str, Any]:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    current = load_mail_shield_config()
    for key in DEFAULT_CONFIG:
        if key in updates:
            current[key] = updates[key]
    with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(current, fh, indent=2, ensure_ascii=False)
    return current


def effective_block_threshold(cfg: Dict[str, Any]) -> int:
    base = int(cfg.get("risk_block_threshold") or 75)
    off = SENSITIVITY_OFFSETS.get((cfg.get("sensitivity") or "balanced").lower(), 0)
    return max(25, min(98, base + off))
