"""
Instrumentación temporal de latencia HTTP — solo activa con NOVUS_HTTP_PROFILE=1.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict

from flask import Flask, g, request


class _WsgiRequestTimer:
    """Marca entrada WSGI antes de cualquier before_request Flask."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        environ["novus.wsgi_entry_ts"] = time.perf_counter()
        return self.app(environ, start_response)


def register_http_profiler(app: Flask) -> None:
    if os.environ.get("NOVUS_HTTP_PROFILE") != "1":
        return

    app.wsgi_app = _WsgiRequestTimer(app.wsgi_app)

    @app.before_request
    def _http_prof_flask_entry():
        wsgi_ts = request.environ.get("novus.wsgi_entry_ts")
        now = time.perf_counter()
        g._http_prof = {
            "t0": now,
            "wsgi_entry_ts": wsgi_ts,
            "wsgi_to_flask_ms": round((now - wsgi_ts) * 1000, 2) if wsgi_ts else None,
            "marks": [],
        }
        if wsgi_ts:
            g._http_prof["marks"].append(
                {"phase": "wsgi_to_flask", "ms": round((now - wsgi_ts) * 1000, 2)}
            )

    def mark(phase: str) -> None:
        if not hasattr(g, "_http_prof"):
            return
        g._http_prof["marks"].append(
            {"phase": phase, "ms": round((time.perf_counter() - g._http_prof["t0"]) * 1000, 2)}
        )

    app._novus_http_prof_mark = mark  # type: ignore[attr-defined]

    @app.after_request
    def _http_prof_after(response):
        mark("after_request")
        if hasattr(g, "_http_prof"):
            prof = g._http_prof
            wsgi_ts = prof.get("wsgi_entry_ts")
            total_from_wsgi = round((time.perf_counter() - wsgi_ts) * 1000, 2) if wsgi_ts else None
            prof["total_ms"] = round((time.perf_counter() - prof["t0"]) * 1000, 2)
            prof["total_from_wsgi_ms"] = total_from_wsgi
            payload = {
                "path": request.path,
                "marks": prof["marks"],
                "total_ms": prof["total_ms"],
                "total_from_wsgi_ms": total_from_wsgi,
                "wsgi_to_flask_ms": prof.get("wsgi_to_flask_ms"),
            }
            response.headers["X-Novus-Profile"] = json.dumps(payload, ensure_ascii=False)[:4000]
        return response

    @app.teardown_request
    def _http_prof_teardown(exc):
        mark("teardown")
