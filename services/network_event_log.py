"""
Real-time network event log — only records events produced by NOVUS scanners.
"""
import threading
from datetime import datetime


class NetworkEventLog:
    _events = []
    _lock = threading.Lock()
    _max_events = 200

    @classmethod
    def record(cls, message, level="info"):
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "message": message,
            "level": level,
        }
        with cls._lock:
            cls._events.insert(0, entry)
            cls._events = cls._events[: cls._max_events]

    @classmethod
    def purge_processed(cls):
        """Elimina eventos informativos ya procesados; conserva alertas."""
        removed = 0
        with cls._lock:
            kept = []
            for entry in cls._events:
                if entry.get("level") == "alert":
                    kept.append(entry)
                else:
                    removed += 1
            cls._events = kept
        return removed

    @classmethod
    def get_recent(cls, limit=50):
        with cls._lock:
            return list(cls._events[:limit])


network_event_log = NetworkEventLog
