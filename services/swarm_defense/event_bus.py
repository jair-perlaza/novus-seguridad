"""
Bus interno de eventos — Swarm Defense Engine (Fase 1 Enterprise).
Pub/sub in-process thread-safe; handlers aislados (fallo de uno no tumba el bus).
"""
from __future__ import annotations

import threading
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from utils.logger import logger

Subscriber = Callable[[Dict[str, Any]], None]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SwarmEventBus:
    """Bus de eventos interno — orientación a eventos, no polling entre motores."""

    def __init__(self, *, handler_timeout_sec: float = 8.0) -> None:
        import os

        self._lock = threading.RLock()
        self._subs: Dict[str, List[Subscriber]] = {}
        self._recent: List[Dict[str, Any]] = []
        self._max_recent = int(os.environ.get("NOVUS_SWARM_BUS_RECENT_MAX", "128"))
        self._handler_timeout = handler_timeout_sec
        self._metrics = Counter()
        self._handler_failures: List[Dict[str, Any]] = []
        # Pool pequeño: no competir con Waitress. Publish es fire-and-forget.
        workers = int(os.environ.get("NOVUS_SWARM_BUS_WORKERS", "4"))
        self._pool = ThreadPoolExecutor(max_workers=max(2, workers), thread_name_prefix="swarm-bus")
        self._pending = 0
        self._pending_cap = int(os.environ.get("NOVUS_SWARM_BUS_PENDING_CAP", "64"))

    def subscribe(self, topic: str, handler: Subscriber) -> None:
        with self._lock:
            self._subs.setdefault(topic, []).append(handler)
            self._metrics["subscriptions"] += 1

    def unsubscribe(self, topic: str, handler: Subscriber) -> None:
        with self._lock:
            handlers = self._subs.get(topic) or []
            self._subs[topic] = [h for h in handlers if h is not handler]

    def publish(self, topic: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        event = {
            "event_id": f"SWARM-{uuid.uuid4().hex[:12]}",
            "topic": topic,
            "published_at": _utc_now(),
            "payload": dict(payload or {}),
        }
        with self._lock:
            self._recent.append(event)
            if len(self._recent) > self._max_recent:
                self._recent = self._recent[-self._max_recent :]
            handlers = list(self._subs.get(topic, [])) + list(self._subs.get("*", []))
            self._metrics["published"] += 1
            self._metrics[f"topic:{topic}"] += 1

        for handler in handlers:
            self._invoke_isolated(handler, event, topic)
        return event

    def _invoke_isolated(self, handler: Subscriber, event: Dict[str, Any], topic: str) -> None:
        """
        Fire-and-forget: NUNCA bloquear al publisher (antes fut.result(8s) saturaba Waitress/GIL).
        Si la cola está llena, se descarta con métrica (motores siguen vivos; evento no crítico de path HTTP).
        """
        with self._lock:
            if self._pending >= self._pending_cap:
                self._metrics["handler_dropped"] += 1
                return
            self._pending += 1

        def _run() -> None:
            t0 = time.perf_counter()
            try:
                handler(event)
                self._metrics["handler_ok"] += 1
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                self._metrics["handler_time_ms_sum"] += int(elapsed_ms)
            except Exception as exc:
                self._metrics["handler_error"] += 1
                self._record_failure(topic, str(exc)[:160], event.get("event_id"))
                logger.debug("swarm bus handler error topic=%s: %s", topic, exc)
            finally:
                with self._lock:
                    self._pending = max(0, self._pending - 1)

        try:
            self._pool.submit(_run)
        except Exception as exc:
            with self._lock:
                self._pending = max(0, self._pending - 1)
            self._metrics["handler_error"] += 1
            logger.debug("swarm bus submit failed topic=%s: %s", topic, exc)

    def _record_failure(self, topic: str, error: str, event_id: Optional[str]) -> None:
        with self._lock:
            self._handler_failures.append(
                {"ts": _utc_now(), "topic": topic, "error": error, "event_id": event_id}
            )
            self._handler_failures = self._handler_failures[-50:]

    def recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._recent[-limit:])

    def topics(self) -> List[str]:
        with self._lock:
            return sorted(self._subs.keys())

    def health(self) -> Dict[str, Any]:
        with self._lock:
            m = dict(self._metrics)
            failures = list(self._handler_failures[-10:])
            published = int(m.get("published") or 0)
            ok = int(m.get("handler_ok") or 0)
            err = int(m.get("handler_error") or 0) + int(m.get("handler_timeout") or 0)
            avg_ms = None
            if ok > 0:
                avg_ms = round(float(m.get("handler_time_ms_sum") or 0) / ok, 2)
        mesh_note = None
        try:
            from services.swarm_defense.mesh import mesh_status

            ms = mesh_status()
            mesh_note = {
                "mode": ms.get("mode"),
                "peers_connected": ms.get("peers_connected"),
                "implemented": True,
            }
        except Exception:
            mesh_note = {"implemented": False}
        return {
            "ok": True,
            "mode": "in_process_pub_sub+http_peer_mesh",
            "published": published,
            "handler_ok": ok,
            "handler_failures": err,
            "avg_handler_ms": avg_ms,
            "topics": self.topics(),
            "recent_failures": failures,
            "mesh": mesh_note,
            "limitation": (
                "Bus local in-process; colmena multi-nodo vía Swarm Mesh HTTP peer-to-peer "
                "(Ed25519+AES-GCM). Redis opcional no requerido."
            ),
        }


swarm_event_bus = SwarmEventBus()

TOPIC_ANOMALY = "anomaly.detected"
TOPIC_CORRELATED = "swarm.correlated"
TOPIC_ACTION = "swarm.action"
TOPIC_PRIORITY = "swarm.priority"
TOPIC_MEMORY = "swarm.memory"
