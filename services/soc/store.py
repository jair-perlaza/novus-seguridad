#!/usr/bin/env python3
"""Persistencia ligera SOC — historial de hunts por tenant (derived cache opcional)."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "soc")
BY_TENANT_DIR = os.path.join(DATA_DIR, "by_tenant")
LEGACY_HUNT_PATH = os.path.join(DATA_DIR, "hunt_history.jsonl")
LEGACY_SNAPSHOT_PATH = os.path.join(DATA_DIR, "last_overview_snapshot.json")
_lock = threading.Lock()


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_tenant_id(tenant_id: Optional[str]) -> str:
    tid = str(tenant_id or "").strip()
    if not tid:
        raise ValueError("tenant_id_required")
    return tid


def _tenant_dir(tenant_id: str) -> str:
    from services.tenant_isolation_service import sanitize_tenant_id_for_path

    safe = sanitize_tenant_id_for_path(tenant_id)
    path = os.path.join(BY_TENANT_DIR, safe)
    os.makedirs(path, exist_ok=True)
    return path


def append_jsonl(path: str, entry: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    row = dict(entry)
    row.setdefault("timestamp_utc", _utc())
    with _lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def read_jsonl_tail(path: str, limit: int = 100) -> List[Dict[str, Any]]:
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for line in lines[-max(1, limit) :]:
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def save_hunt(entry: Dict[str, Any], *, tenant_id: str) -> None:
    tid = _require_tenant_id(tenant_id)
    row = dict(entry)
    row["tenant_id"] = tid
    append_jsonl(os.path.join(_tenant_dir(tid), "hunt_history.jsonl"), row)


def load_hunts(*, tenant_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    tid = _require_tenant_id(tenant_id)
    path = os.path.join(_tenant_dir(tid), "hunt_history.jsonl")
    rows = [r for r in read_jsonl_tail(path, limit) if r.get("tenant_id") == tid]
    try:
        from services.production_runtime_guard import legacy_soc_merge_enabled
        from services.tenant_scope_service import get_platform_tenant_id

        platform_tid = get_platform_tenant_id()
        if (
            legacy_soc_merge_enabled()
            and platform_tid
            and tid == platform_tid
            and os.path.isfile(LEGACY_HUNT_PATH)
        ):
            for r in read_jsonl_tail(LEGACY_HUNT_PATH, limit):
                if not r.get("tenant_id"):
                    r = dict(r)
                    r["tenant_id"] = tid
                if r.get("tenant_id") == tid:
                    rows.append(r)
    except Exception:
        pass
    return rows[-limit:]


def save_derived_snapshot(payload: Dict[str, Any], *, tenant_id: str) -> None:
    tid = _require_tenant_id(tenant_id)
    snap = dict(payload)
    snap["cached_at_utc"] = _utc()
    snap["cache_type"] = "derived_overview"
    snap["tenant_id"] = tid
    path = os.path.join(_tenant_dir(tid), "last_overview_snapshot.json")
    with _lock:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(snap, fh, ensure_ascii=False, default=str, indent=2)


def load_derived_snapshot(*, tenant_id: str) -> Dict[str, Any]:
    tid = _require_tenant_id(tenant_id)
    path = os.path.join(_tenant_dir(tid), "last_overview_snapshot.json")
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if data.get("tenant_id") == tid:
                return data
        except Exception:
            pass
    try:
        from services.production_runtime_guard import legacy_soc_merge_enabled
        from services.tenant_scope_service import get_platform_tenant_id

        platform_tid = get_platform_tenant_id()
        if (
            legacy_soc_merge_enabled()
            and platform_tid
            and tid == platform_tid
            and os.path.isfile(LEGACY_SNAPSHOT_PATH)
        ):
            with open(LEGACY_SNAPSHOT_PATH, "r", encoding="utf-8") as fh:
                return json.load(fh)
    except Exception:
        pass
    return {}
