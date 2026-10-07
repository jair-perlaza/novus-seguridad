#!/usr/bin/env python3
"""Persistencia de IOC, feeds, inteligencia propia — todo cifrable vía CryptoVault."""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "threat_intelligence_enterprise")
IOC_PATH = os.path.join(DATA_DIR, "ioc_store.jsonl")
FEED_LOG = os.path.join(DATA_DIR, "feed_log.jsonl")
INTERNAL_INTEL = os.path.join(DATA_DIR, "internal_intelligence.jsonl")
ENRICHMENT_LOG = os.path.join(DATA_DIR, "enrichment_log.jsonl")
SWARM_IOC_OUTBOX = os.path.join(DATA_DIR, "swarm_ioc_outbox.jsonl")
LAST_SNAPSHOT = os.path.join(DATA_DIR, "last_snapshot.json")

_lock = threading.Lock()
NA = "NO DISPONIBLE"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def append_jsonl(path: str, entry: Dict[str, Any]) -> None:
    ensure_dir()
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
    for line in lines[-max(1, limit):]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def save_snapshot(payload: Dict[str, Any]) -> None:
    ensure_dir()
    with _lock:
        with open(LAST_SNAPSHOT, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, default=str)


def load_snapshot() -> Optional[Dict[str, Any]]:
    if not os.path.isfile(LAST_SNAPSHOT):
        return None
    try:
        with open(LAST_SNAPSHOT, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def store_ioc(ioc: Dict[str, Any]) -> None:
    append_jsonl(IOC_PATH, ioc)


def store_feed_result(result: Dict[str, Any]) -> None:
    append_jsonl(FEED_LOG, result)


def store_internal_intel(intel: Dict[str, Any]) -> None:
    append_jsonl(INTERNAL_INTEL, intel)


def store_enrichment(enrichment: Dict[str, Any]) -> None:
    append_jsonl(ENRICHMENT_LOG, enrichment)


def store_swarm_ioc(ioc: Dict[str, Any]) -> None:
    append_jsonl(SWARM_IOC_OUTBOX, ioc)


def load_iocs(limit: int = 500) -> List[Dict[str, Any]]:
    return read_jsonl_tail(IOC_PATH, limit=limit)


def load_feed_log(limit: int = 100) -> List[Dict[str, Any]]:
    return read_jsonl_tail(FEED_LOG, limit=limit)


def load_internal_intel(limit: int = 200) -> List[Dict[str, Any]]:
    return read_jsonl_tail(INTERNAL_INTEL, limit=limit)


def load_enrichments(limit: int = 200) -> List[Dict[str, Any]]:
    return read_jsonl_tail(ENRICHMENT_LOG, limit=limit)


def load_swarm_outbox(limit: int = 100) -> List[Dict[str, Any]]:
    return read_jsonl_tail(SWARM_IOC_OUTBOX, limit=limit)
