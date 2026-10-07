"""
Lectura acotada de archivos JSONL — evita cargar archivos completos en memoria.
"""
from __future__ import annotations

import json
import os
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional

RowPredicate = Callable[[Dict[str, Any]], bool]


def _parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        return None
    return row if isinstance(row, dict) else None


def stream_jsonl_tail(
    path: str,
    limit: int = 50,
    *,
    predicate: Optional[RowPredicate] = None,
) -> List[Dict[str, Any]]:
    """Devuelve las últimas `limit` filas que cumplen `predicate` (streaming, deque acotado)."""
    if not os.path.isfile(path) or limit <= 0:
        return []
    cap = max(1, int(limit))
    buf: Deque[Dict[str, Any]] = deque(maxlen=cap)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                row = _parse_line(line)
                if row is None:
                    continue
                if predicate is not None and not predicate(row):
                    continue
                buf.append(row)
    except OSError:
        return []
    return list(buf)


def count_jsonl(
    path: str,
    *,
    predicate: Optional[RowPredicate] = None,
) -> int:
    """Cuenta filas JSONL sin acumular objetos en memoria."""
    if not os.path.isfile(path):
        return 0
    total = 0
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                row = _parse_line(line)
                if row is None:
                    continue
                if predicate is not None and not predicate(row):
                    continue
                total += 1
    except OSError:
        return 0
    return total


def count_jsonl_groups(
    path: str,
    key: str,
    *,
    allowed: Optional[tuple] = None,
    predicate: Optional[RowPredicate] = None,
) -> Dict[str, int]:
    """Agrupa conteos por campo sin almacenar filas."""
    counts: Dict[str, int] = {k: 0 for k in (allowed or ())}
    if not os.path.isfile(path):
        return counts
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                row = _parse_line(line)
                if row is None:
                    continue
                if predicate is not None and not predicate(row):
                    continue
                val = row.get(key)
                if allowed is not None:
                    if val in counts:
                        counts[val] += 1
                elif val is not None:
                    counts[str(val)] = counts.get(str(val), 0) + 1
    except OSError:
        pass
    return counts
