"""Configuración runtime de protección de autenticación — editable desde Configuración."""
from __future__ import annotations

import json
import os
from typing import Any, Dict

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "auth_protection.json")

DEFAULTS: Dict[str, Any] = {
    "failure_window_minutes": 15,
    "risk_log_attempts_max": 3,
    "monitoring_attempt": 4,
    "block_attempt": 5,
    "first_block_minutes": 30,
    "recurrence_block_minutes": 1440,
    "admin_review_after_recurrences": 2,
}


def get_auth_protection_config() -> Dict[str, Any]:
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


def save_auth_protection_config(updates: Dict[str, Any]) -> Dict[str, Any]:
    cfg = get_auth_protection_config()
    for key in DEFAULTS:
        if key in updates and updates[key] is not None:
            try:
                cfg[key] = int(updates[key])
            except (TypeError, ValueError):
                continue
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2, ensure_ascii=False)
    return cfg
