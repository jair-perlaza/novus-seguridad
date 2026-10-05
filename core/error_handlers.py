"""Registro central de manejadores HTTP — recuperación automática; sin pantallas de error al usuario."""
from __future__ import annotations

from flask import Flask, Request, request
from werkzeug.exceptions import HTTPException

from core.recovery_middleware import (
    handle_http_exception_for_recovery,
    recovery_html_response,
    recovery_json_response,
)


def _wants_json(req: Request) -> bool:
    if req.path.startswith("/api/"):
        return True
    if req.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    best = req.accept_mimetypes.best_match(["application/json", "text/html"])
    if best == "application/json" and req.accept_mimetypes[best] > req.accept_mimetypes["text/html"]:
        return True
    return False


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(HTTPException)
    def http_exception_handler(error: HTTPException):
        return handle_http_exception_for_recovery(error)

    @app.errorhandler(Exception)
    def unhandled_exception(error):
        if isinstance(error, HTTPException):
            return handle_http_exception_for_recovery(error)
        if _wants_json(request) or request.path.startswith("/api/"):
            return recovery_json_response(error, status_code=500)
        return recovery_html_response(error, status_code=500)
