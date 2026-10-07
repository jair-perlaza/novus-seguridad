#!/usr/bin/env python3
"""Persistencia SOPE — decisiones, ejecuciones, historial forense."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "sope")
DECISIONS_LOG = os.path.join(DATA_DIR, "decisions.jsonl")
EXECUTIONS_LOG = os.path.join(DATA_DIR, "executions.jsonl")
APPROVALS_LOG = os.path.join(DATA_DIR, "approvals.jsonl")
FORENSIC_LOG = os.path.join(DATA_DIR, "forensic_chain.jsonl")

_lock = threading.Lock()


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dir():
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
    out = []
    for line in lines[-max(1, limit):]:
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def record_decision(decision: Dict[str, Any]) -> None:
    append_jsonl(DECISIONS_LOG, decision)


def record_execution(execution: Dict[str, Any]) -> None:
    append_jsonl(EXECUTIONS_LOG, execution)


def record_approval(approval: Dict[str, Any]) -> None:
    append_jsonl(APPROVALS_LOG, approval)


def record_forensic(entry: Dict[str, Any]) -> None:
    append_jsonl(FORENSIC_LOG, entry)


def load_decisions(limit: int = 200) -> List[Dict[str, Any]]:
    return read_jsonl_tail(DECISIONS_LOG, limit)


def load_executions(limit: int = 200) -> List[Dict[str, Any]]:
    return read_jsonl_tail(EXECUTIONS_LOG, limit)


def load_approvals(limit: int = 200) -> List[Dict[str, Any]]:
    return read_jsonl_tail(APPROVALS_LOG, limit)


def load_forensic(limit: int = 200) -> List[Dict[str, Any]]:
    return read_jsonl_tail(FORENSIC_LOG, limit)
