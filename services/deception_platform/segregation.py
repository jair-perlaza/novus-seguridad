#!/usr/bin/env python3
"""Segregacion DPE — nunca mezclar activos reales con senuelos."""
from __future__ import annotations
from typing import Any, Dict, List, Optional, Set

from services.deception_platform.limitations import NA, NAMESPACE, USERNAME_PREFIX, POLICY


def _real_usernames() -> Set[str]:
    users: Set[str] = set()
    try:
        from services.identity_intelligence.store import load_identities
        data = load_identities() or {}
        items = data.get("identities") if isinstance(data, dict) else data
        if isinstance(items, dict):
            items = list(items.values())
        for row in (items or []):
            if not isinstance(row, dict):
                continue
            for k in ("identity", "user", "username", "email", "principal", "label", "id"):
                v = row.get(k)
                if isinstance(v, str) and v.strip():
                    users.add(v.strip().lower())
    except Exception:
        pass
    try:
        from services.identity_intelligence.identity_engine import list_identities
        for row in list_identities() or []:
            if isinstance(row, dict):
                for k in ("identity", "user", "username", "email", "principal", "label", "id"):
                    v = row.get(k)
                    if isinstance(v, str) and v.strip():
                        users.add(v.strip().lower())
            elif isinstance(row, str):
                users.add(row.strip().lower())
    except Exception:
        pass
    return users


def _real_asset_ids() -> Set[str]:
    assets: Set[str] = set()
    try:
        from services.asm import get_dashboard
        dash = get_dashboard()
        for a in (dash.get("assets") or dash.get("inventory") or [])[:2000]:
            if isinstance(a, dict):
                for k in ("id", "asset_id", "hostname", "ip", "fqdn"):
                    v = a.get(k)
                    if v is not None and str(v).strip():
                        assets.add(str(v).strip().lower())
    except Exception:
        pass
    return assets


def assert_decoy_username(username: str) -> Dict[str, Any]:
    u = (username or "").strip().lower()
    real = _real_usernames()
    collision = u in real
    prefixed = u.startswith(USERNAME_PREFIX.lower())
    return {
        "username": username,
        "namespace": NAMESPACE,
        "prefixed": prefixed,
        "collides_with_real": collision,
        "allowed": prefixed and not collision and not POLICY["reuse_real_assets"],
        "real_users_checked": len(real) if real else NA,
    }


def assert_decoy_asset(asset_id: str) -> Dict[str, Any]:
    a = (asset_id or "").strip().lower()
    real = _real_asset_ids()
    collision = a in real
    namespaced = a.startswith(NAMESPACE.lower()) or a.startswith("dpe.")
    return {
        "asset_id": asset_id,
        "namespace": NAMESPACE,
        "namespaced": namespaced,
        "collides_with_real": collision,
        "allowed": namespaced and not collision,
        "real_assets_checked": len(real) if real else NA,
    }


def segregation_report() -> Dict[str, Any]:
    real_u = _real_usernames()
    real_a = _real_asset_ids()
    return {
        "namespace": NAMESPACE,
        "username_prefix": USERNAME_PREFIX,
        "real_users_sample_count": len(real_u),
        "real_assets_sample_count": len(real_a),
        "policy": {
            "reuse_real_assets": POLICY["reuse_real_assets"],
            "mix_real_decoy": POLICY["mix_real_decoy"],
        },
        "invented": False,
    }
