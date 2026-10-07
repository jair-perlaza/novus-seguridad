#!/usr/bin/env python3
"""Motor Security Data Lake Enterprise — dashboard, stats, integridad."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.sdl.limitations import NA, AUTHORIZED_ENGINES, LIMITATIONS, POLICY
from services.sdl.store import (
    init_db, count_records, count_by_engine, count_today,
    storage_stats, recent_queries, rotate_if_needed, get_by_uuid, get_versions,
)
from services.sdl.integrity import verify_record, canonical_json
from services.sdl.ingest import ingest_from_engines, build_and_insert, versioned_update
from services.sdl.search import search, correlate
from services.sdl.export import export_json, export_csv, export_zip, export_pdf
from services.sdl.feed import get_feed_for, CONSUMERS
import json


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_dashboard() -> Dict[str, Any]:
    init_db()
    by_engine = count_by_engine()
    connected = sorted(by_engine.keys())
    missing = [e for e in AUTHORIZED_ENGINES if e not in by_engine]
    storage = storage_stats()
    return {
        "generated_at_utc": _utc(),
        "invented": False,
        "eventos_ingeridos": count_records(),
        "volumen_diario": count_today(),
        "volumen_historico": count_records(),
        "motores_conectados": connected,
        "motores_conectados_count": len(connected),
        "motores_sin_datos": missing,
        "por_motor": by_engine,
        "consultas_recientes": recent_queries(20),
        "almacenamiento": storage,
        "integridad": {
            "immutable": True,
            "hash": "SHA-256",
            "signature": "Ed25519",
            "silent_mutate": False,
        },
        "capacidad": {
            "hot_limit": 500_000,
            "uso_hot": storage.get("hot_records"),
            "db_bytes": storage.get("db_bytes"),
            "archive_bytes": storage.get("archive_bytes"),
            "note": "SQLite local indexado + archivo JSONL. No cluster distribuido.",
        },
        "limitations": LIMITATIONS,
        "policy": POLICY,
    }


def stats() -> Dict[str, Any]:
    init_db()
    return {
        "total": count_records(),
        "today": count_today(),
        "by_engine": count_by_engine(),
        "invented": False,
    }


def verify_uuid(uuid: str) -> Dict[str, Any]:
    row = get_by_uuid(uuid)
    if not row:
        return {"ok": False, "error": "not_found", "uuid": uuid}
    try:
        payload = json.loads(row.get("payload_json") or "{}")
    except Exception:
        payload = {}
    core = {
        "uuid": row.get("uuid"),
        "version": row.get("version"),
        "timestamp_utc": row.get("timestamp_utc"),
        "engine": row.get("engine"),
        "record_type": row.get("record_type"),
        "severity": row.get("severity"),
        "confidence": row.get("confidence"),
        "status": row.get("status"),
        "asset": row.get("asset"),
        "user_ref": row.get("user_ref"),
        "client_ref": row.get("client_ref"),
        "incident_id": row.get("incident_id"),
        "playbook_id": row.get("playbook_id"),
        "ioc": row.get("ioc"),
        "cve": row.get("cve"),
        "payload": payload,
        "invented": False,
    }
    check = verify_record(core, row.get("sha256") or "", row.get("ed25519_sig"))
    return {
        "ok": True,
        "uuid": uuid,
        "version": row.get("version"),
        "verification": check,
        "versions": get_versions(uuid),
        "invented": False,
    }


def run_ingest(limit_per_source: int = 50) -> Dict[str, Any]:
    return ingest_from_engines(limit_per_source=limit_per_source)
