"""
Decoradores RBAC para rutas Flask y APIs NOVUS.
"""
from __future__ import annotations

from functools import wraps
from typing import Callable, Optional, Sequence

from flask import jsonify, render_template, request
from flask_login import current_user


def _is_api_request() -> bool:
    return request.path.startswith("/api/") or (
        request.accept_mimetypes.best == "application/json"
        and request.accept_mimetypes["application/json"] > request.accept_mimetypes["text/html"]
    )


def _deny(module: Optional[str], resource: Optional[str], detail: str):
    from services.rbac_service import record_access_denied

    record_access_denied(
        current_user if current_user.is_authenticated else None,
        module=module,
        resource=resource,
        route=request.path,
        detail=detail,
    )
    payload = {
        "status": "error",
        "message": "Acceso denegado — permisos insuficientes",
        "code": "RBAC_FORBIDDEN",
    }
    if _is_api_request():
        return jsonify(payload), 403
    return (
        render_template(
            "rbac_access_denied.html",
            message=payload["message"],
            detail=detail,
            path=request.path,
        ),
        403,
    )


def require_roles(*roles: str):
    """Exige uno de los roles indicados."""

    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from services.rbac_service import get_user_role, record_access_denied, role_label

            if not current_user.is_authenticated:
                return jsonify({"status": "error", "message": "Autenticación requerida"}), 401
            if get_user_role(current_user) not in roles:
                detail = (
                    f"Se requiere rol {[role_label(r) for r in roles]}; "
                    f"actual: {role_label(get_user_role(current_user))}"
                )
                record_access_denied(
                    current_user,
                    route=request.path,
                    detail=detail,
                )
                return _deny(None, None, detail)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def require_module(module: str):
    """Exige acceso al módulo según MODULE_ACCESS."""

    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from services.rbac_service import check_module_access

            if not current_user.is_authenticated:
                if _is_api_request():
                    return jsonify({"status": "error", "message": "Autenticación requerida"}), 401
                from flask import redirect, url_for
                return redirect(url_for("auth.login"))

            ok, reason = check_module_access(current_user, module)
            if not ok:
                return _deny(module, None, reason)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def require_api_resource(resource: str):
    """Exige acceso al recurso API según API_ACCESS."""

    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from services.rbac_service import check_api_access

            if not current_user.is_authenticated:
                return jsonify({"status": "error", "message": "Autenticación requerida"}), 401
            ok, reason = check_api_access(current_user, resource)
            if not ok:
                return _deny(None, resource, reason)
            return fn(*args, **kwargs)

        return wrapper

    return decorator
