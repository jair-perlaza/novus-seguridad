#!/usr/bin/env python3
"""Persistencia local IIUEBA — no muta motores externos."""
from __future__ import annotations
import json, os, threading, uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "identity_intelligence")
IDENTITIES_PATH = os.path.join(DATA_DIR, "identities.json")
BASELINES_PATH = os.path.join(DATA_DIR, "baselines.json")
ANOMALIES_PATH = os.path.join(DATA_DIR, "anomalies.jsonl")
RISK_PATH = os.path.join(DATA_DIR, "risk_history.jsonl")
SEALS_PATH = os.path.join(DATA_DIR, "seals.jsonl")
OBS_PATH = os.path.join(DATA_DIR, "observations.jsonl")
PROCESS_FREEZE_PATH = os.path.join(DATA_DIR, "process_baseline_freeze.json")
_lock = threading.RLock()

def _utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def ensure_dir(): os.makedirs(DATA_DIR, exist_ok=True)

def _read_json(path, default):
    if not os.path.isfile(path): return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default

def _write_json(path, data):
    ensure_dir()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, default=str)
    os.replace(tmp, path)

def append_jsonl(path, entry):
    ensure_dir()
    row = dict(entry)
    row.setdefault("timestamp_utc", _utc())
    with _lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

def read_jsonl_tail(path, limit=200):
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

def new_uuid() -> str:
    return str(uuid.uuid4())

def load_identities() -> Dict[str, Any]:
    with _lock:
        return _read_json(IDENTITIES_PATH, {"identities": {}, "updated_at_utc": None})

def save_identities(data: Dict[str, Any]):
    data["updated_at_utc"] = _utc()
    with _lock:
        _write_json(IDENTITIES_PATH, data)

def load_baselines() -> Dict[str, Any]:
    with _lock:
        return _read_json(BASELINES_PATH, {"baselines": {}, "updated_at_utc": None})

def save_baselines(data: Dict[str, Any]):
    data["updated_at_utc"] = _utc()
    with _lock:
        _write_json(BASELINES_PATH, data)

def save_observation(entry): append_jsonl(OBS_PATH, entry)
def load_observations(limit=500): return read_jsonl_tail(OBS_PATH, limit)
def save_anomaly(entry): append_jsonl(ANOMALIES_PATH, entry)
def load_anomalies(limit=200): return read_jsonl_tail(ANOMALIES_PATH, limit)
def save_risk(entry): append_jsonl(RISK_PATH, entry)
def load_risk_history(limit=100): return read_jsonl_tail(RISK_PATH, limit)
def save_seal(entry): append_jsonl(SEALS_PATH, entry)
def load_seals(limit=50): return read_jsonl_tail(SEALS_PATH, limit)

def load_process_freeze() -> Dict[str, Any]:
    with _lock:
        return _read_json(PROCESS_FREEZE_PATH, {"processes": [], "updated_at_utc": None})

def save_process_freeze(processes: List[str]):
    with _lock:
        _write_json(PROCESS_FREEZE_PATH, {
            "processes": sorted(set(processes)),
            "updated_at_utc": _utc(),
            "invented": False,
        })
