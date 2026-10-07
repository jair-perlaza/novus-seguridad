#!/usr/bin/env python3
"""Persistencia local CSV/BAS — data/csv_bas/."""
from __future__ import annotations
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "csv_bas")
RUNS_PATH = os.path.join(DATA_DIR, "runs.jsonl")
RESULTS_PATH = os.path.join(DATA_DIR, "results.jsonl")
SEALS_PATH = os.path.join(DATA_DIR, "seals.jsonl")
QUERIES_PATH = os.path.join(DATA_DIR, "queries.jsonl")
COVERAGE_PATH = os.path.join(DATA_DIR, "coverage_snapshot.json")
_lock = threading.Lock()


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


def save_json(path: str, data: Any) -> None:
    ensure_dir()
    with _lock:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, default=str)


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


def save_run(e: Dict[str, Any]) -> None:
    append_jsonl(RUNS_PATH, e)


def load_runs(n: int = 100) -> List[Dict[str, Any]]:
    return list(reversed(read_jsonl(RUNS_PATH, n)))


def save_result(e: Dict[str, Any]) -> None:
    append_jsonl(RESULTS_PATH, e)


def load_results(n: int = 200) -> List[Dict[str, Any]]:
    return list(reversed(read_jsonl(RESULTS_PATH, n)))


def save_seal(e: Dict[str, Any]) -> None:
    append_jsonl(SEALS_PATH, e)


def load_seals(n: int = 30) -> List[Dict[str, Any]]:
    return read_jsonl(SEALS_PATH, n)


def log_query(e: Dict[str, Any]) -> None:
    append_jsonl(QUERIES_PATH, e)


def load_queries(n: int = 30) -> List[Dict[str, Any]]:
    return list(reversed(read_jsonl(QUERIES_PATH, n)))


def save_coverage(data: Dict[str, Any]) -> None:
    save_json(COVERAGE_PATH, data)


def load_coverage() -> Dict[str, Any]:
    return load_json(COVERAGE_PATH, {})
