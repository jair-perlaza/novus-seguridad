"""
Persistencia de aprendizaje del buscador global (sin datos sensibles innecesarios).
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List, Optional

_STORE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data",
    "global_search_learning.json",
)
_lock = threading.Lock()
_TIMING: List[float] = []


def _load() -> dict:
    os.makedirs(os.path.dirname(_STORE_PATH), exist_ok=True)
    if not os.path.isfile(_STORE_PATH):
        return {"users": {}, "global_queries": {}, "metrics": {"search_count": 0, "timing_ms": []}}
    try:
        with open(_STORE_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {"users": {}, "global_queries": {}, "metrics": {"search_count": 0, "timing_ms": []}}


def _save(data: dict) -> None:
    os.makedirs(os.path.dirname(_STORE_PATH), exist_ok=True)
    with open(_STORE_PATH, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def _user_key(email: Optional[str]) -> str:
    return (email or "anonymous").strip().lower()


def record_search(email: Optional[str], query: str, sector: Optional[str] = None) -> None:
    q = (query or "").strip().lower()
    if not q:
        return
    with _lock:
        data = _load()
        users = data.setdefault("users", {})
        u = users.setdefault(_user_key(email), {"queries": {}, "clicks": {}, "sector": sector or ""})
        if sector:
            u["sector"] = sector
        u.setdefault("queries", {})
        u["queries"][q] = int(u["queries"].get(q, 0)) + 1
        gq = data.setdefault("global_queries", {})
        gq[q] = int(gq.get(q, 0)) + 1
        data.setdefault("metrics", {})["search_count"] = int(data["metrics"].get("search_count", 0)) + 1
        _save(data)


def record_click(email: Optional[str], item_id: str) -> None:
    if not item_id:
        return
    with _lock:
        data = _load()
        users = data.setdefault("users", {})
        u = users.setdefault(_user_key(email), {"queries": {}, "clicks": {}, "sector": ""})
        u.setdefault("clicks", {})
        u["clicks"][item_id] = int(u["clicks"].get(item_id, 0)) + 1
        _save(data)


def record_timing_ms(ms: float) -> None:
    with _lock:
        data = _load()
        metrics = data.setdefault("metrics", {})
        timings = metrics.setdefault("timing_ms", [])
        timings.append(round(ms, 2))
        if len(timings) > 500:
            metrics["timing_ms"] = timings[-500:]
        _save(data)


def click_boost(email: Optional[str], item_id: str) -> int:
    data = _load()
    u = data.get("users", {}).get(_user_key(email), {})
    return int(u.get("clicks", {}).get(item_id, 0))


def query_boost(email: Optional[str], query: str) -> int:
    q = (query or "").strip().lower()
    data = _load()
    u = data.get("users", {}).get(_user_key(email), {})
    return int(u.get("queries", {}).get(q, 0))


def frequent_queries(email: Optional[str], limit: int = 8) -> List[str]:
    data = _load()
    u = data.get("users", {}).get(_user_key(email), {})
    queries = u.get("queries") or {}
    ranked = sorted(queries.items(), key=lambda x: -x[1])
    return [q for q, _ in ranked[:limit]]


def user_sector(email: Optional[str]) -> str:
    data = _load()
    u = data.get("users", {}).get(_user_key(email), {})
    return u.get("sector") or ""


def audit_snapshot() -> Dict[str, Any]:
    data = _load()
    timings = data.get("metrics", {}).get("timing_ms") or []
    avg = sum(timings) / len(timings) if timings else 0.0
    return {
        "users_tracked": len(data.get("users") or {}),
        "global_distinct_queries": len(data.get("global_queries") or {}),
        "total_searches": int(data.get("metrics", {}).get("search_count", 0)),
        "avg_timing_ms": round(avg, 2),
        "sample_timings_count": len(timings),
    }
