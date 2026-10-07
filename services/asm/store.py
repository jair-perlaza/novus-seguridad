#!/usr/bin/env python3
"""Persistencia ASM — inventario, historial, cambios."""
from __future__ import annotations
import json, os, threading
from datetime import datetime, timezone
from typing import Any, Dict, List

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "asm")
INVENTORY_PATH = os.path.join(DATA_DIR, "inventory.json")
HISTORY_PATH = os.path.join(DATA_DIR, "history.jsonl")
SHADOW_IT_PATH = os.path.join(DATA_DIR, "shadow_it.jsonl")
_lock = threading.Lock()

def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)

def append_jsonl(path, entry):
    ensure_dir()
    row = dict(entry); row.setdefault("timestamp_utc", _utc())
    with _lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

def read_jsonl_tail(path, limit=200):
    if not os.path.isfile(path): return []
    try:
        with open(path, "r", encoding="utf-8") as fh: lines = fh.readlines()
    except Exception: return []
    out = []
    for line in lines[-max(1, limit):]:
        line = line.strip()
        if line:
            try: out.append(json.loads(line))
            except: pass
    return out

def save_inventory(inv):
    ensure_dir()
    with _lock:
        with open(INVENTORY_PATH, "w", encoding="utf-8") as fh:
            json.dump(inv, fh, ensure_ascii=False, indent=2, default=str)

def load_inventory():
    if not os.path.isfile(INVENTORY_PATH): return None
    try:
        with open(INVENTORY_PATH, "r", encoding="utf-8") as fh: return json.load(fh)
    except: return None

def record_history(entry): append_jsonl(HISTORY_PATH, entry)
def record_shadow_it(entry): append_jsonl(SHADOW_IT_PATH, entry)
def load_history(limit=200): return read_jsonl_tail(HISTORY_PATH, limit)
def load_shadow_it(limit=200): return read_jsonl_tail(SHADOW_IT_PATH, limit)
