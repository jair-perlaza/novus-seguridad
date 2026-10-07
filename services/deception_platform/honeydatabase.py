#!/usr/bin/env python3
"""Honeydatabase DPE — solo estructura ficticia; nunca datos reales."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.deception_platform.limitations import NC, CFG, NAMESPACE, NI
from services.deception_platform.store import load_json, save_json, DBS_PATH, ensure_dir


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Purely fictional schema — no real PII / no real business data
DECOY_SCHEMA = {
    "tables": [
        {"name": "dpe_fake_customers", "columns": ["id", "alias", "region_code"]},
        {"name": "dpe_fake_orders", "columns": ["id", "sku_decoy", "qty"]},
        {"name": "dpe_fake_secrets", "columns": ["id", "label", "token_ref"]},
    ],
    "contains_real_data": False,
    "note": "Estructura ficticia exclusivamente para deception.",
}


def list_honeydatabases() -> Dict[str, Any]:
    ensure_dir()
    data = load_json(DBS_PATH, {"databases": []})
    return {
        "databases": data.get("databases") or [],
        "count": len(data.get("databases") or []),
        "default_status": NC if not (data.get("databases") or []) else CFG,
        "schema_template": DECOY_SCHEMA,
        "invented": False,
        "contains_real_data": False,
    }


def configure_honeydatabase(name: Optional[str] = None) -> Dict[str, Any]:
    ensure_dir()
    data = load_json(DBS_PATH, {"databases": []})
    uid = str(uuid.uuid4())
    entry = {
        "uuid": uid,
        "name": name or f"dpe_decoy_db_{uid[:8]}",
        "status": CFG,
        "namespace": NAMESPACE,
        "schema": DECOY_SCHEMA,
        "contains_real_data": False,
        "engine_bound": False,
        "note": f"{CFG}. Binding a motor SQL real: {NI} (no se expone BD real).",
        "fecha": _utc(),
        "invented": False,
    }
    dbs: List[Dict[str, Any]] = list(data.get("databases") or [])
    dbs.append(entry)
    data["databases"] = dbs
    save_json(DBS_PATH, data)
    return {"ok": True, "database": entry}
