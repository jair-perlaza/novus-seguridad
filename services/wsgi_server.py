"""
Servidor WSGI de producción para NOVUS (Windows/Linux).
Waitress: pool de threads dimensionado por CPU/RAM — no workers=600.
"""
from __future__ import annotations

import os
import socket

from utils.logger import logger


def _cpu_count() -> int:
    return os.cpu_count() or 4


def recommended_threads() -> int:
    explicit = os.environ.get("NOVUS_WAITRESS_THREADS", "").strip()
    if explicit.isdigit():
        return max(4, min(int(explicit), 256))
    # 4 hilos por núcleo + margen I/O; techo 64 para evitar thrashing SQLite/GIL
    return max(8, min(64, (_cpu_count() * 4) + 4))


def recommended_connection_limit(threads: int) -> int:
    explicit = os.environ.get("NOVUS_WAITRESS_CONNECTION_LIMIT", "").strip()
    if explicit.isdigit():
        return max(threads, int(explicit))
    # Windows select()-based asyncore hits FD limits (~512); keep headroom for DB/files.
    if os.name == "nt":
        return min(400, max(threads * 4, threads + 32))
    return min(1024, threads * 16)


def serve_flask_app(app, *, host: str, port: int) -> None:
    try:
        from waitress import serve
    except ImportError as exc:
        logger.error("Waitress no instalado — pip install waitress. Fallback Flask dev server.")
        raise exc

    threads = recommended_threads()
    conn_limit = recommended_connection_limit(threads)
    channel_timeout = int(os.environ.get("NOVUS_WAITRESS_CHANNEL_TIMEOUT", "120"))
    if os.environ.get("NOVUS_LOADTEST_MODE", "").strip().lower() in ("1", "true", "yes", "on"):
        # Liberar canales ociosos antes bajo soak — reduce buffers retenidos en thrash.
        channel_timeout = int(os.environ.get("NOVUS_WAITRESS_CHANNEL_TIMEOUT", "60"))
    cleanup_interval = int(os.environ.get("NOVUS_WAITRESS_CLEANUP_INTERVAL", "30"))
    if os.environ.get("NOVUS_LOADTEST_MODE", "").strip().lower() in ("1", "true", "yes", "on"):
        cleanup_interval = int(os.environ.get("NOVUS_WAITRESS_CLEANUP_INTERVAL", "15"))

    logger.info(
        "Waitress WSGI — host=%s port=%s threads=%s connection_limit=%s channel_timeout=%s",
        host,
        port,
        threads,
        conn_limit,
        channel_timeout,
    )
    logger.info("Nodo: %s", os.environ.get("NODE_ID", socket.gethostname()))

    serve(
        app,
        host=host,
        port=port,
        threads=threads,
        connection_limit=conn_limit,
        channel_timeout=channel_timeout,
        cleanup_interval=cleanup_interval,
        asyncore_use_poll=True,
        ident="NOVUS-Waitress",
    )
