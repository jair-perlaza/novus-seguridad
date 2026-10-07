#!/usr/bin/env python3
"""Persistencia VIEM."""
from __future__ import annotations
import json, os, threading
from datetime import datetime, timezone
from typing import Any, Dict, List

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "viem")
VULNS_PATH = os.path.join(DATA_DIR, "vulnerabilities.jsonl")
HISTORY_PATH = os.path.join(DATA_DIR, "history.jsonl")
REMEDIATION_PATH = os.path.join(DATA_DIR, "remediations.jsonl")
SNAPSHOT_PATH = os.path.join(DATA_DIR, "last_snapshot.json")
_lock = threading.Lock()

def _utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def ensure_dir(): os.makedirs(DATA_DIR, exist_ok=True)

def append_jsonl(path, entry):
    ensure_dir(); row = dict(entry); row.setdefault("timestamp_utc", _utc())
    with _lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

def read_jsonl_tail(path, limit=300):
    if not os.path.isfile(path): return []
    try:
        with open(path, "r", encoding="utf-8") as fh: lines = fh.readlines()
    except: return []
    out = []
    for line in lines[-max(1, limit):]:
        line = line.strip()
        if line:
            try: out.append(json.loads(line))
            except: pass
    return out

def save_snapshot(data):
    ensure_dir()
    with _lock:
        with open(SNAPSHOT_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2, default=str)

def load_snapshot():
    if not os.path.isfile(SNAPSHOT_PATH): return None
    try:
        with open(SNAPSHOT_PATH, "r", encoding="utf-8") as fh: return json.load(fh)
    except: return None

def record_vuln(v): append_jsonl(VULNS_PATH, v)
def record_history(e): append_jsonl(HISTORY_PATH, e)
def record_remediation(r): append_jsonl(REMEDIATION_PATH, r)
def load_vulns(limit=500): return read_jsonl_tail(VULNS_PATH, limit)
def load_history(limit=300): return read_jsonl_tail(HISTORY_PATH, limit)
def load_remediations(limit=300): return read_jsonl_tail(REMEDIATION_PATH, limit)
