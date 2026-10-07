#!/usr/bin/env python3
"""Persistencia local SDACE (sellos/consultas). NO escribe en el SDL."""
from __future__ import annotations
import json, os, threading
from datetime import datetime, timezone
from typing import Any, Dict, List

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "sdace")
SEALS_PATH = os.path.join(DATA_DIR, "correlation_seals.jsonl")
QUERY_PATH = os.path.join(DATA_DIR, "queries.jsonl")
_lock = threading.Lock()

def _utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def ensure_dir(): os.makedirs(DATA_DIR, exist_ok=True)

def append_jsonl(path, entry):
    ensure_dir()
    row = dict(entry)
    row.setdefault("timestamp_utc", _utc())
    with _lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

def read_tail(path, limit=100):
    if not os.path.isfile(path): return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except Exception:
        return []
    out = []
    for line in lines[-max(1, limit):]:
        line = line.strip()
        if line:
            try: out.append(json.loads(line))
            except Exception: pass
    return out

def save_seal(entry): append_jsonl(SEALS_PATH, entry)
def load_seals(limit=50): return read_tail(SEALS_PATH, limit)
def log_query(entry): append_jsonl(QUERY_PATH, entry)
def load_queries(limit=30): return list(reversed(read_tail(QUERY_PATH, limit)))
