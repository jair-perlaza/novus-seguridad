"""Middleware de recuperación — normaliza respuestas HTTP de error antes de llegar al navegador."""
from __future__ import annotations

import json
from typing import Optional

from flask import Flask, Request, Response, request
from werkzeug.exceptions import HTTPException

from services.novus_recovery_service import (
    RECOVERY_USER_MESSAGE,
    build_recovery_api_payload,
    schedule_recovery_for_request,
)


def _current_user_email() -> Optional[str]:
    try:
        from flask_login import current_user

        if current_user.is_authenticated:
            return getattr(current_user, "email", None)
    except Exception:
        pass
    return None


AUTH_FORM_PATHS = frozenset({
    "/login",
    "/registro-empresa",
    "/sector-auth",
})


def _should_normalize(req: Request, response: Response) -> bool:
    if response.status_code < 400:
        return False
    if req.path.rstrip("/") in AUTH_FORM_PATHS or req.path in AUTH_FORM_PATHS:
        return False
    if req.path.startswith("/static/"):
        return False
    if response.status_code in (301, 302, 303, 307, 308):
        return False
    return True


def _wants_json(req: Request) -> bool:
    if req.path.startswith("/api/"):
        return True
    if req.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    ct = (req.headers.get("Accept") or "").lower()
    if "application/json" in ct and "text/html" not in ct:
        return True
    return False


def _render_recovery_html(
    *,
    message: str,
    retry_url: str,
    reference: str,
    login_required: bool,
) -> str:
    from flask import current_app

    tpl = current_app.jinja_env.get_template("novus_recovery.html")
    return tpl.render(
        message=message,
        retry_url=retry_url,
        reference=reference,
        login_required=login_required,
    )


def register_recovery_middleware(app: Flask) -> None:
    @app.after_request
    def _normalize_client_errors(response: Response):
        if not _should_normalize(request, response):
            return response

        user = _current_user_email()
        original_status = response.status_code
        login_required = original_status == 401

        ref = schedule_recovery_for_request(
            path=request.path,
            method=request.method,
            user=user,
            original_status=original_status,
            exc=None,
        )

        try:
            from services.remote_access_error_service import record_http_error
            from core.security import get_client_ip

            record_http_error(
                route=request.path,
                method=request.method,
                status_code=original_status,
                error=Exception(f"normalized_http_{original_status}"),
                ip=get_client_ip(),
                user=user,
                user_agent=request.headers.get("User-Agent"),
                extra={"recovery_reference": ref, "normalized": True},
            )
        except Exception:
            pass

        if _wants_json(request) or request.path.startswith("/api/"):
            payload = build_recovery_api_payload(
                reference=ref,
                retry_url=request.url,
                login_required=login_required,
            )
            out = Response(
                json.dumps(payload, ensure_ascii=False),
                status=200,
                mimetype="application/json",
            )
            out.headers["X-Novus-Recovery"] = "1"
            out.headers["X-Novus-Original-Status"] = str(original_status)
            return out

        html = _render_recovery_html(
            message=RECOVERY_USER_MESSAGE,
            retry_url=request.url,
            reference=ref,
            login_required=login_required,
        )
        out = Response(html, status=200, mimetype="text/html; charset=utf-8")
        out.headers["X-Novus-Recovery"] = "1"
        out.headers["X-Novus-Original-Status"] = str(original_status)
        return out


def recovery_html_response(
    exc: Optional[BaseException] = None,
    *,
    retry_url: Optional[str] = None,
    login_required: bool = False,
) -> tuple:
    user = _current_user_email()
    ref = schedule_recovery_for_request(
        path=request.path,
        method=request.method,
        user=user,
        original_status=500,
        exc=exc,
    )
    return (
        _render_recovery_html(
            message=RECOVERY_USER_MESSAGE,
            retry_url=retry_url or request.url,
            reference=ref,
            login_required=login_required,
        ),
        200,
    )


def recovery_json_response(
    exc: Optional[BaseException] = None,
    *,
    login_required: bool = False,
) -> tuple:
    user = _current_user_email()
    ref = schedule_recovery_for_request(
        path=request.path,
        method=request.method,
        user=user,
        original_status=500,
        exc=exc,
    )
    payload = build_recovery_api_payload(
        reference=ref,
        retry_url=request.url,
        login_required=login_required,
    )
    from flask import jsonify

    return jsonify(payload), 200


def handle_http_exception_for_recovery(error: HTTPException):
    """Usado por errorhandlers — nunca devuelve código >= 400 al cliente."""
    if error.code == 401:
        return recovery_json_response(error, login_required=True) if _wants_json(request) else recovery_html_response(
            error, login_required=True
        )
    if _wants_json(request) or request.path.startswith("/api/"):
        return recovery_json_response(error)
    return recovery_html_response(error)
