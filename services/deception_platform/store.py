#!/usr/bin/env python3
"""Persistencia local DPE — aislada en data/deception_platform/."""
from __future__ import annotations
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "deception_platform")
HONEYFILES_DIR = os.path.join(DATA_DIR, "honeyfiles")
TOKENS_PATH = os.path.join(DATA_DIR, "honeytokens.jsonl")
FILES_PATH = os.path.join(DATA_DIR, "honeyfiles.jsonl")
CREDS_PATH = os.path.join(DATA_DIR, "honeycredentials.jsonl")
HONEYPOTS_PATH = os.path.join(DATA_DIR, "honeypots.json")
SHARES_PATH = os.path.join(DATA_DIR, "honeyshares.json")
DBS_PATH = os.path.join(DATA_DIR, "honeydatabases.json")
DECOYS_PATH = os.path.join(DATA_DIR, "decoy_servers.json")
EVENTS_PATH = os.path.join(DATA_DIR, "events.jsonl")
IOCS_PATH = os.path.join(DATA_DIR, "iocs.jsonl")
SEALS_PATH = os.path.join(DATA_DIR, "seals.jsonl")
QUERIES_PATH = os.path.join(DATA_DIR, "queries.jsonl")
_lock = threading.Lock()


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(HONEYFILES_DIR, exist_ok=True)


def append_jsonl(path: str, entry: Dict[str, Any]) -> None:
    ensure_dir()
    row = dict(entry)
    row.setdefault("timestamp_utc", _utc())
    with _lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def read_jsonl(path: str, limit: int = 500) -> List[Dict[str, Any]]:
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for line in lines[-max(1, limit):]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def load_json(path: str, default: Optional[Any] = None) -> Any:
    if default is None:
        default = {}
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def save_json(path: str, data: Any) -> None:
    ensure_dir()
    with _lock:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, default=str)


def save_seal(e: Dict[str, Any]) -> None:
    append_jsonl(SEALS_PATH, e)


def load_seals(n: int = 30) -> List[Dict[str, Any]]:
    return read_jsonl(SEALS_PATH, n)


def log_query(e: Dict[str, Any]) -> None:
    append_jsonl(QUERIES_PATH, e)


def load_queries(n: int = 30) -> List[Dict[str, Any]]:
    return list(reversed(read_jsonl(QUERIES_PATH, n)))


def save_event(e: Dict[str, Any]) -> None:
    append_jsonl(EVENTS_PATH, e)


def load_events(n: int = 200) -> List[Dict[str, Any]]:
    return list(reversed(read_jsonl(EVENTS_PATH, n)))


def save_ioc(e: Dict[str, Any]) -> None:
    append_jsonl(IOCS_PATH, e)


def load_iocs(n: int = 200) -> List[Dict[str, Any]]:
    return list(reversed(read_jsonl(IOCS_PATH, n)))
