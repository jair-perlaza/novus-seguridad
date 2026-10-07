"""Configuración runtime de endurecimiento en entornos hostiles."""
from __future__ import annotations

import json
import os
import threading
from copy import deepcopy
from typing import Any, Dict, Optional, Tuple

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "hostile_hardening.json")

DEFAULTS: Dict[str, Any] = {
    "ip_whitelist": [],
    "ip_blacklist": [],
    "user_api_rate_limit_per_minute": 180,
    "user_dashboard_read_rate_limit_per_minute": 900,
    "http_flood_dashboard_read_per_10s": 1200,
    "api_path_limits": {},
    "load_shedding": {
        "enabled": True,
        "cpu_percent_threshold": 92,
        "ram_percent_threshold": 93,
        "degraded_path_prefixes": [
            "/api/reports",
            "/api/playbooks",
            "/api/ndci",
            "/api/threat-intel",
            "/api/gmail",
        ],
    },
    "csrf_protection_enabled": True,
    "csp_enabled": True,
    "hsts_when_proxy": True,
    "credential_stuffing_emails_per_ip": 8,
    "password_spray_ips_per_email": 4,
    "http_flood_per_ip_per_10s": 80,
    "http_flood_login_page_per_ip_per_10s": 600,
    "http_flood_login_per_email_per_10s": 30,
    "http_flood_session_dashboard_per_10s": 180,
    "http_flood_session_authed_per_10s": 90,
    "http_flood_nat_dashboard_per_ip_per_10s": 5000,
    "http_flood_nat_api_per_ip_per_10s": 3000,
    "adaptive_rate_multiplier": 1.0,
    "circuit_breaker_violations": 12,
    "circuit_breaker_cooldown_sec": 45,
    "bot_detection_enabled": True,
    "bot_block_enabled": False,
    "bot_allowlist_patterns": ["Googlebot", "bingbot"],
    "slowloris_guard_enabled": True,
    "max_body_bytes": 2097152,
    # Fase 1: rotación AES automática cada 90 días (0 = deshabilitada)
    "aes_key_max_age_days": 90,
}


_config_lock = threading.Lock()
_config_cache: Optional[Tuple[float, Dict[str, Any]]] = None


def _load_config_from_disk() -> Dict[str, Any]:
    cfg = deepcopy(DEFAULTS)
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                for key in DEFAULTS:
                    if key in loaded:
                        cfg[key] = loaded[key]
        except Exception:
            pass
    return cfg


def invalidate_hostile_hardening_config_cache() -> None:
    global _config_cache
    with _config_lock:
        _config_cache = None
    try:
        from flask import g, has_request_context

        if has_request_context() and hasattr(g, "_hostile_hardening_cfg"):
            delattr(g, "_hostile_hardening_cfg")
    except Exception:
        pass


def get_hostile_hardening_config() -> Dict[str, Any]:
    """Config de endurecimiento — cache global + una copia por request HTTP."""
    global _config_cache
    try:
        from flask import g, has_request_context

        if has_request_context():
            req_cached = getattr(g, "_hostile_hardening_cfg", None)
            if req_cached is not None:
                return req_cached
    except Exception:
        pass

    try:
        mtime = os.path.getmtime(CONFIG_PATH) if os.path.isfile(CONFIG_PATH) else 0.0
    except OSError:
        mtime = 0.0
    with _config_lock:
        if _config_cache and _config_cache[0] == mtime:
            cfg = deepcopy(_config_cache[1])
        else:
            cfg = _load_config_from_disk()
            _config_cache = (mtime, deepcopy(cfg))

    try:
        from flask import g, has_request_context

        if has_request_context():
            g._hostile_hardening_cfg = cfg
    except Exception:
        pass
    return cfg


def save_hostile_hardening_config(updates: Dict[str, Any]) -> Dict[str, Any]:
    cfg = get_hostile_hardening_config()
    for key in ("ip_whitelist", "ip_blacklist", "api_path_limits", "load_shedding"):
        if key in updates and updates[key] is not None:
            cfg[key] = updates[key]
    for key in (
        "user_api_rate_limit_per_minute",
        "csrf_protection_enabled",
        "csp_enabled",
        "hsts_when_proxy",
        "credential_stuffing_emails_per_ip",
        "password_spray_ips_per_email",
        "http_flood_per_ip_per_10s",
        "adaptive_rate_multiplier",
        "circuit_breaker_violations",
        "circuit_breaker_cooldown_sec",
        "bot_detection_enabled",
        "bot_block_enabled",
        "bot_allowlist_patterns",
        "slowloris_guard_enabled",
        "max_body_bytes",
        "aes_key_max_age_days",
    ):
        if key in updates and updates[key] is not None:
            cfg[key] = updates[key]
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2, ensure_ascii=False)
    invalidate_hostile_hardening_config_cache()
    return cfg
