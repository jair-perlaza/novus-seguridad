#!/usr/bin/env python3
"""Persistencia IMCM — aislada por tenant_id."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "imcm")
BY_TENANT_DIR = os.path.join(DATA_DIR, "by_tenant")
# Legacy global paths (solo lectura para platform tenant durante migración)
LEGACY_INCIDENTS_PATH = os.path.join(DATA_DIR, "incidents.jsonl")
LEGACY_TIMELINE_PATH = os.path.join(DATA_DIR, "timeline.jsonl")
LEGACY_COMMENTS_PATH = os.path.join(DATA_DIR, "comments.jsonl")
LEGACY_HISTORY_PATH = os.path.join(DATA_DIR, "history.jsonl")
LEGACY_COUNTER_PATH = os.path.join(DATA_DIR, "counter.txt")
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


def _path(tenant_id: str, name: str) -> str:
    return os.path.join(_tenant_dir(tenant_id), name)


def append_jsonl(path: str, entry: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    row = dict(entry)
    row.setdefault("timestamp_utc", _utc())
    with _lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def read_jsonl_tail(path: str, limit: int = 300) -> List[Dict[str, Any]]:
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


def _legacy_platform_tenant_only(tenant_id: str) -> bool:
    try:
        from services.production_runtime_guard import legacy_imcm_merge_enabled
        from services.tenant_scope_service import get_platform_tenant_id

        if not legacy_imcm_merge_enabled():
            return False
        platform_tid = get_platform_tenant_id()
        return bool(platform_tid) and tenant_id == platform_tid
    except Exception:
        return False


def _merge_legacy_incidents(tenant_id: str, rows: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    if not _legacy_platform_tenant_only(tenant_id) or not os.path.isfile(LEGACY_INCIDENTS_PATH):
        return rows
    seen = {r.get("id") for r in rows if r.get("id")}
    for inc in read_jsonl_tail(LEGACY_INCIDENTS_PATH, limit):
        iid = inc.get("id")
        if iid and iid in seen:
            continue
        legacy_tid = inc.get("tenant_id")
        if legacy_tid and legacy_tid != tenant_id:
            continue
        if not legacy_tid:
            inc = dict(inc)
            inc["tenant_id"] = tenant_id
            inc["_legacy_global"] = True
        rows.append(inc)
        seen.add(iid)
    return rows


def _next_id(tenant_id: str) -> str:
    counter_path = _path(tenant_id, "counter.txt")
    with _lock:
        n = 1
        if os.path.isfile(counter_path):
            try:
                n = int(open(counter_path, encoding="utf-8").read().strip()) + 1
            except Exception:
                n = 1
        with open(counter_path, "w", encoding="utf-8") as fh:
            fh.write(str(n))
    return f"INC-{n:06d}"


def get_next_id(*, tenant_id: str) -> str:
    return _next_id(_require_tenant_id(tenant_id))


def save_incident(inc: Dict[str, Any], *, tenant_id: str) -> None:
    tid = _require_tenant_id(tenant_id)
    row = dict(inc)
    row["tenant_id"] = tid
    append_jsonl(_path(tid, "incidents.jsonl"), row)


def add_timeline(entry: Dict[str, Any], *, tenant_id: str) -> None:
    tid = _require_tenant_id(tenant_id)
    row = dict(entry)
    row["tenant_id"] = tid
    append_jsonl(_path(tid, "timeline.jsonl"), row)


def add_comment(entry: Dict[str, Any], *, tenant_id: str) -> None:
    tid = _require_tenant_id(tenant_id)
    row = dict(entry)
    row["tenant_id"] = tid
    append_jsonl(_path(tid, "comments.jsonl"), row)


def add_history(entry: Dict[str, Any], *, tenant_id: str) -> None:
    tid = _require_tenant_id(tenant_id)
    row = dict(entry)
    row["tenant_id"] = tid
    append_jsonl(_path(tid, "history.jsonl"), row)


def load_incidents(*, tenant_id: str, limit: int = 300) -> List[Dict[str, Any]]:
    tid = _require_tenant_id(tenant_id)
    from services.v1_runtime_surface import filter_lab_runtime_rows, is_lab_tenant_id, client_runtime_active

    if client_runtime_active() and is_lab_tenant_id(tid):
        return []
    rows = read_jsonl_tail(_path(tid, "incidents.jsonl"), limit)
    rows = [r for r in rows if r.get("tenant_id") == tid]
    rows = _merge_legacy_incidents(tid, rows, limit)
    rows = [r for r in rows if r.get("tenant_id") == tid][:limit]
    return filter_lab_runtime_rows(rows)


def load_timeline(*, tenant_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    tid = _require_tenant_id(tenant_id)
    rows = read_jsonl_tail(_path(tid, "timeline.jsonl"), limit)
    rows = [r for r in rows if r.get("tenant_id") == tid]
    if _legacy_platform_tenant_only(tid) and os.path.isfile(LEGACY_TIMELINE_PATH):
        for e in read_jsonl_tail(LEGACY_TIMELINE_PATH, limit):
            if not e.get("tenant_id"):
                e = dict(e)
                e["tenant_id"] = tid
            if e.get("tenant_id") == tid:
                rows.append(e)
    return rows[-limit:]


def load_comments(*, tenant_id: str, limit: int = 300) -> List[Dict[str, Any]]:
    tid = _require_tenant_id(tenant_id)
    rows = read_jsonl_tail(_path(tid, "comments.jsonl"), limit)
    rows = [r for r in rows if r.get("tenant_id") == tid]
    if _legacy_platform_tenant_only(tid) and os.path.isfile(LEGACY_COMMENTS_PATH):
        for e in read_jsonl_tail(LEGACY_COMMENTS_PATH, limit):
            if not e.get("tenant_id"):
                e = dict(e)
                e["tenant_id"] = tid
            if e.get("tenant_id") == tid:
                rows.append(e)
    return rows[-limit:]


def load_history(*, tenant_id: str, limit: int = 300) -> List[Dict[str, Any]]:
    tid = _require_tenant_id(tenant_id)
    rows = read_jsonl_tail(_path(tid, "history.jsonl"), limit)
    rows = [r for r in rows if r.get("tenant_id") == tid]
    if _legacy_platform_tenant_only(tid) and os.path.isfile(LEGACY_HISTORY_PATH):
        for e in read_jsonl_tail(LEGACY_HISTORY_PATH, limit):
            if not e.get("tenant_id"):
                e = dict(e)
                e["tenant_id"] = tid
            if e.get("tenant_id") == tid:
                rows.append(e)
    return rows[-limit:]


def find_incident_by_keys(
    *,
    tenant_id: str,
    finding_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    source_engine: Optional[str] = None,
    limit: int = 500,
) -> Optional[Dict[str, Any]]:
    for inc in load_incidents(tenant_id=tenant_id, limit=limit):
        if source_engine and inc.get("source_engine") != source_engine:
            continue
        ev = inc.get("evidence") or {}
        if finding_id and (
            inc.get("id") == finding_id
            or ev.get("finding_id") == finding_id
            or ev.get("event_id") == finding_id
        ):
            return inc
        if correlation_id and (
            ev.get("correlation_id") == correlation_id
            or ev.get("correlationId") == correlation_id
        ):
            return inc
    return None
