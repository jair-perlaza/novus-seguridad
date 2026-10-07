#!/usr/bin/env python3
"""
Persistencia SDL — SQLite (WAL) + archivo JSONL rotado.
Registros inmutables: UPDATE de contenido prohibido; solo versionado.
"""
from __future__ import annotations
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "sdl")
DB_PATH = os.path.join(DATA_DIR, "security_data_lake.db")
ARCHIVE_DIR = os.path.join(DATA_DIR, "archive")
QUERY_LOG = os.path.join(DATA_DIR, "query_history.jsonl")
_lock = threading.RLock()

# Soft rotation threshold (hot store). Archive older rows; does not delete evidence chain.
DEFAULT_HOT_LIMIT = 500_000


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)


def _conn() -> sqlite3.Connection:
    ensure_dirs()
    c = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("PRAGMA temp_store=MEMORY")
    return c


def init_db():
    with _lock:
        c = _conn()
        try:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    uuid TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    timestamp_utc TEXT NOT NULL,
                    source TEXT,
                    engine TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    severity TEXT,
                    confidence TEXT,
                    status TEXT,
                    asset TEXT,
                    user_ref TEXT,
                    client_ref TEXT,
                    device TEXT,
                    network TEXT,
                    server_ref TEXT,
                    endpoint_ref TEXT,
                    branch TEXT,
                    ioc TEXT,
                    cve TEXT,
                    mitre TEXT,
                    campaign TEXT,
                    malware TEXT,
                    ransomware TEXT,
                    apt TEXT,
                    incident_id TEXT,
                    playbook_id TEXT,
                    risk TEXT,
                    payload_json TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    ed25519_sig TEXT,
                    key_id TEXT,
                    prev_uuid TEXT,
                    immutable INTEGER NOT NULL DEFAULT 1,
                    invented INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_uuid ON records(uuid);
                CREATE INDEX IF NOT EXISTS idx_ts ON records(timestamp_utc);
                CREATE INDEX IF NOT EXISTS idx_engine ON records(engine);
                CREATE INDEX IF NOT EXISTS idx_type ON records(record_type);
                CREATE INDEX IF NOT EXISTS idx_asset ON records(asset);
                CREATE INDEX IF NOT EXISTS idx_user ON records(user_ref);
                CREATE INDEX IF NOT EXISTS idx_ioc ON records(ioc);
                CREATE INDEX IF NOT EXISTS idx_cve ON records(cve);
                CREATE INDEX IF NOT EXISTS idx_mitre ON records(mitre);
                CREATE INDEX IF NOT EXISTS idx_incident ON records(incident_id);
                CREATE INDEX IF NOT EXISTS idx_playbook ON records(playbook_id);
                CREATE INDEX IF NOT EXISTS idx_malware ON records(malware);
                CREATE INDEX IF NOT EXISTS idx_severity ON records(severity);
                CREATE INDEX IF NOT EXISTS idx_client ON records(client_ref);
                CREATE INDEX IF NOT EXISTS idx_device ON records(device);
                CREATE INDEX IF NOT EXISTS idx_engine_ts ON records(engine, timestamp_utc);
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            c.commit()
        finally:
            c.close()


def insert_record(row: Dict[str, Any]) -> int:
    """Inserta registro inmutable. Nunca actualiza filas existentes de contenido."""
    init_db()
    cols = [
        "uuid", "version", "timestamp_utc", "source", "engine", "record_type",
        "severity", "confidence", "status", "asset", "user_ref", "client_ref",
        "device", "network", "server_ref", "endpoint_ref", "branch",
        "ioc", "cve", "mitre", "campaign", "malware", "ransomware", "apt",
        "incident_id", "playbook_id", "risk", "payload_json", "sha256",
        "ed25519_sig", "key_id", "prev_uuid", "immutable", "invented",
    ]
    values = [row.get(k) for k in cols]
    with _lock:
        c = _conn()
        try:
            cur = c.execute(
                f"INSERT INTO records ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                values,
            )
            c.commit()
            return int(cur.lastrowid)
        finally:
            c.close()


def get_by_uuid(uuid: str) -> Optional[Dict[str, Any]]:
    init_db()
    with _lock:
        c = _conn()
        try:
            # latest version
            cur = c.execute(
                "SELECT * FROM records WHERE uuid=? ORDER BY version DESC LIMIT 1",
                (uuid,),
            )
            r = cur.fetchone()
            return dict(r) if r else None
        finally:
            c.close()


def get_versions(uuid: str) -> List[Dict[str, Any]]:
    init_db()
    with _lock:
        c = _conn()
        try:
            cur = c.execute(
                "SELECT * FROM records WHERE uuid=? ORDER BY version ASC",
                (uuid,),
            )
            return [dict(x) for x in cur.fetchall()]
        finally:
            c.close()


def count_records() -> int:
    init_db()
    with _lock:
        c = _conn()
        try:
            return int(c.execute("SELECT COUNT(*) FROM records").fetchone()[0])
        finally:
            c.close()


def count_by_engine() -> Dict[str, int]:
    init_db()
    with _lock:
        c = _conn()
        try:
            cur = c.execute("SELECT engine, COUNT(*) AS n FROM records GROUP BY engine")
            return {r["engine"]: r["n"] for r in cur.fetchall()}
        finally:
            c.close()


def count_today() -> int:
    init_db()
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with _lock:
        c = _conn()
        try:
            return int(
                c.execute(
                    "SELECT COUNT(*) FROM records WHERE timestamp_utc LIKE ?",
                    (day + "%",),
                ).fetchone()[0]
            )
        finally:
            c.close()


def storage_stats() -> Dict[str, Any]:
    ensure_dirs()
    db_size = os.path.getsize(DB_PATH) if os.path.isfile(DB_PATH) else 0
    archive_files = []
    if os.path.isdir(ARCHIVE_DIR):
        for name in os.listdir(ARCHIVE_DIR):
            p = os.path.join(ARCHIVE_DIR, name)
            if os.path.isfile(p):
                archive_files.append({"file": name, "bytes": os.path.getsize(p)})
    return {
        "db_path": DB_PATH,
        "db_bytes": db_size,
        "archive_files": archive_files,
        "archive_bytes": sum(f["bytes"] for f in archive_files),
        "hot_records": count_records(),
        "timestamp_utc": _utc(),
    }


def log_query(entry: Dict[str, Any]):
    ensure_dirs()
    row = dict(entry)
    row.setdefault("timestamp_utc", _utc())
    with _lock:
        with open(QUERY_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def recent_queries(limit: int = 30) -> List[Dict[str, Any]]:
    if not os.path.isfile(QUERY_LOG):
        return []
    try:
        with open(QUERY_LOG, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except Exception:
        return []
    out = []
    for line in lines[-max(1, limit):]:
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return list(reversed(out))


def rotate_if_needed(hot_limit: int = DEFAULT_HOT_LIMIT) -> Dict[str, Any]:
    """
    Archiva registros antiguos a JSONL si se supera hot_limit.
    Mantiene integridad: no reescribe hashes; mueve filas a archive.
    PARCIAL a escala: adecuado para hot store local, no cluster.
    """
    init_db()
    total = count_records()
    if total <= hot_limit:
        return {"rotated": False, "hot_records": total, "threshold": hot_limit}
    excess = total - hot_limit
    with _lock:
        c = _conn()
        try:
            cur = c.execute(
                "SELECT * FROM records ORDER BY id ASC LIMIT ?",
                (excess,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            if not rows:
                return {"rotated": False, "hot_records": total}
            archive_name = f"archive_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.jsonl"
            archive_path = os.path.join(ARCHIVE_DIR, archive_name)
            with open(archive_path, "a", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")
            ids = [r["id"] for r in rows]
            c.executemany("DELETE FROM records WHERE id=?", [(i,) for i in ids])
            c.commit()
            return {
                "rotated": True,
                "archived": len(rows),
                "archive_file": archive_name,
                "hot_records": count_records(),
            }
        finally:
            c.close()


def search_sql(
    where_clauses: List[str],
    params: List[Any],
    limit: int = 100,
    offset: int = 0,
    order: str = "timestamp_utc DESC",
) -> Tuple[List[Dict[str, Any]], int]:
    init_db()
    where = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    with _lock:
        c = _conn()
        try:
            total = int(c.execute(f"SELECT COUNT(*) FROM records{where}", params).fetchone()[0])
            cur = c.execute(
                f"SELECT * FROM records{where} ORDER BY {order} LIMIT ? OFFSET ?",
                params + [limit, offset],
            )
            return [dict(r) for r in cur.fetchall()], total
        finally:
            c.close()
