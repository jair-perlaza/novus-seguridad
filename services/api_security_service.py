"""
Endurecimiento centralizado de APIs NOVUS — reutiliza db_security, defense_registry, ADE.
Sin motores paralelos.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple

from flask import jsonify, request
from flask_login import current_user

from database import db_security
from utils.logger import logger

MAX_JSON_BYTES = 1_048_576
MAX_STRING_FIELD = 8_192
MAX_QUERY_PARAM_LEN = 512

SENSITIVE_PATH_FRAGMENTS = (
    "/remediate",
    "/kill",
    "/mitigate",
    "/execute",
    "/investigate",
    "/launch-tool",
    "/scan/file",
    "/ai/command",
    "/clean",
    "/sync",
    "/config/save",
    "/processes/kill",
    "/incidents/mitigate",
)


def is_sensitive_path(path: str) -> bool:
    p = (path or "").lower()
    return any(frag in p for frag in SENSITIVE_PATH_FRAGMENTS)


def _client_ip() -> str:
    from core.security import get_client_ip
    return get_client_ip()


def _user_email() -> Optional[str]:
    try:
        if current_user.is_authenticated:
            return getattr(current_user, "email", None)
    except Exception:
        pass
    return None


def scan_input(value: str, context: str = "API") -> Optional[Dict[str, Any]]:
    """SQLi / entrada maliciosa — usa DatabaseSecurityLayer existente."""
    if not value or not isinstance(value, str):
        return None
    if len(value) > MAX_QUERY_PARAM_LEN:
        return {"reason": "input_too_long", "length": len(value)}
    result = db_security.sanitize_and_validate_query(value, context=context)
    if result.get("status") == "INTERCEPTED":
        return result.get("log") or {"reason": "sqli_intercepted"}
    return None


def scan_query_params() -> Optional[Tuple[dict, int]]:
    """Escanea parámetros GET; retorna (response_json, status) si bloqueado."""
    for key, val in request.args.items():
        if not isinstance(val, str):
            continue
        hit = scan_input(val, context=f"QUERY:{key}")
        if hit:
            _log_blocked("query_param", key, hit)
            return ({"status": "error", "message": "Parámetro de consulta rechazado"}, 400)
    return None


def scan_json_shallow(data: Any, depth: int = 0) -> Optional[Dict[str, Any]]:
    """Escaneo superficial de strings en JSON (sin alterar estructura)."""
    if depth > 6:
        return {"reason": "json_depth_exceeded"}
    if isinstance(data, str):
        if len(data) > MAX_STRING_FIELD:
            return {"reason": "field_too_long"}
        return scan_input(data, context="JSON_BODY")
    if isinstance(data, dict):
        if len(data) > 80:
            return {"reason": "too_many_keys"}
        for k, v in data.items():
            if isinstance(k, str):
                hit = scan_input(k, context="JSON_KEY")
                if hit:
                    return hit
            hit = scan_json_shallow(v, depth + 1)
            if hit:
                return hit
    if isinstance(data, list):
        if len(data) > 200:
            return {"reason": "array_too_large"}
        for item in data[:200]:
            hit = scan_json_shallow(item, depth + 1)
            if hit:
                return hit
    return None


def validate_json_body(required: Optional[List[str]] = None, *, force: bool = False) -> Tuple[Optional[dict], Optional[Tuple[dict, int]]]:
    """
    Parsea y valida JSON. Retorna (payload, None) o (None, (error_response, status)).
    """
    if request.method not in ("POST", "PUT", "PATCH"):
        return None, None
    ct = (request.content_type or "").lower()
    if not force and "json" not in ct:
        return None, None
    if "json" not in ct and request.data:
        return None, ({"status": "error", "message": "Content-Type application/json requerido"}, 415)
    cl = request.content_length or 0
    if cl > MAX_JSON_BYTES:
        return None, ({"status": "error", "message": "Cuerpo de solicitud demasiado grande"}, 413)
    try:
        payload = request.get_json(silent=True)
    except Exception:
        payload = None
    if payload is None and request.data:
        return None, ({"status": "error", "message": "JSON malformado"}, 400)
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        return None, ({"status": "error", "message": "Se esperaba objeto JSON"}, 400)
    hit = scan_json_shallow(payload)
    if hit:
        _log_blocked("json_body", request.path, hit)
        return None, ({"status": "error", "message": "Cuerpo JSON rechazado por validación"}, 400)
    if required:
        missing = [f for f in required if f not in payload or payload[f] in (None, "")]
        if missing:
            return None, ({"status": "error", "message": f"Campos requeridos: {', '.join(missing)}"}, 400)
    return payload, None


def sanitize_ip_param(ip: str) -> Optional[str]:
    """Valida IP para rutas de red/topology."""
    if not ip or len(ip) > 64:
        return None
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip.split("%")[0])
        return ip
    except ValueError:
        return None


def sanitize_identifier(value: str, max_len: int = 128, pattern: str = r"^[a-zA-Z0-9_\-\.]+$") -> Optional[str]:
    if not value or len(value) > max_len:
        return None
    if re.match(pattern, str(value)):
        return str(value)
    return None


def _log_blocked(kind: str, detail: str, evidence: dict) -> None:
    try:
        from services.defense_evidence_registry import record_defense_event
        record_defense_event(
            phase="prevent",
            action="api_input_blocked",
            motor="api_security_service",
            outcome="blocked",
            threat_type="injection_attempt",
            evidence={"kind": kind, "detail": detail[:200], "hit": evidence},
            user_email=_user_email(),
            detail=f"{request.method} {request.path}",
            confidence="Alta",
        )
    except Exception as exc:
        logger.debug("api_security log blocked: %s", exc)


def log_api_access(action: str, outcome: str = "success", evidence: Optional[dict] = None) -> None:
    try:
        from services.defense_evidence_registry import record_defense_event
        record_defense_event(
            phase="audit",
            action=action,
            motor="api_security_service",
            outcome=outcome,
            evidence=evidence or {},
            user_email=_user_email(),
            detail=f"{request.method} {request.path}",
        )
    except Exception:
        pass


# Anti-flood: no serializar cada 401 en el request path (SQLite + evidence I/O).
_AUTH_FAIL_LAST: dict[str, float] = {}
_AUTH_FAIL_LOCK = threading.Lock()
_AUTH_FAIL_MIN_INTERVAL_SEC = float(os.environ.get("NOVUS_API_AUTH_FAIL_LOG_INTERVAL_SEC", "5"))


def log_api_auth_failure() -> None:
    """
    Auditoría de 401 sin bloquear Waitress: muestreo por IP+path y escritura en pool acotado.
    No elimina el control — solo evita que un flood de cookies inválidas sature SQLite.
    """
    try:
        ip = _client_ip()
        path = (request.path or "")[:200]
        method = request.method
        key = f"{ip}|{path}"
        now = time.time()
        with _AUTH_FAIL_LOCK:
            last = _AUTH_FAIL_LAST.get(key, 0.0)
            if now - last < _AUTH_FAIL_MIN_INTERVAL_SEC:
                return
            _AUTH_FAIL_LAST[key] = now
            if len(_AUTH_FAIL_LAST) > 4000:
                cutoff = now - 300
                stale = [k for k, ts in _AUTH_FAIL_LAST.items() if ts < cutoff]
                for k in stale[:2000]:
                    _AUTH_FAIL_LAST.pop(k, None)

        def _persist():
            try:
                from database import SessionLocal, registrar_log_seguridad
                from services.defense_evidence_registry import record_defense_event

                db = SessionLocal()
                try:
                    registrar_log_seguridad(db, "API_AUTH_FAILED", f"path={path} ip={ip}")
                    db.commit()
                finally:
                    db.close()
                record_defense_event(
                    phase="prevent",
                    action="api_auth_failed",
                    motor="api_security_service",
                    outcome="blocked",
                    threat_type="unauthorized_access",
                    evidence={"path": path, "ip": ip, "method": method},
                    detail=f"Acceso API sin autenticación: {path}",
                    confidence="Alta",
                )
            except Exception as exc:
                logger.debug("log_api_auth_failure persist: %s", exc)

        from services.bounded_background import submit_background

        submit_background(_persist, name="ApiAuthFailLog")
    except Exception as exc:
        logger.debug("log_api_auth_failure: %s", exc)


def check_sensitive_rate_limit(path: str) -> Optional[Tuple[dict, int]]:
    if not is_sensitive_path(path):
        return None
    from flask import current_app
    rl = db_security.check_rate_limit(
        f"sensitive:{_client_ip()}:{path.split('/')[-1]}",
        max_requests=int(current_app.config.get("SENSITIVE_API_RATE_LIMIT", 30)),
        window_seconds=60,
    )
    if rl.get("status") == "RATE_LIMITED":
        log_api_access("sensitive_rate_limited", outcome="rate_limited")
        return ({"status": "error", "message": "Límite de operaciones sensibles alcanzado"}, 429)
    return None


def guard_api_request(*, require_json: bool = False, required_fields: Optional[List[str]] = None) -> Optional[Tuple[Any, int]]:
    """
    Validación previa para handlers sensibles.
    Retorna Flask response tuple si debe abortar.
    """
    blocked = scan_query_params()
    if blocked:
        return blocked
    sens = check_sensitive_rate_limit(request.path)
    if sens:
        return sens
    if require_json or request.method in ("POST", "PUT", "PATCH"):
        payload, err = validate_json_body(required_fields if require_json else None, force=require_json)
        if err:
            return err
        return None
    return None


def api_hardened(
    *,
    sensitive: bool = False,
    require_json: bool = False,
    required_fields: Optional[List[str]] = None,
    action_name: Optional[str] = None,
):
    """Decorador de endurecimiento — sin duplicar lógica por endpoint."""

    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if sensitive or is_sensitive_path(request.path):
                err = check_sensitive_rate_limit(request.path)
                if err:
                    return jsonify(err[0]), err[1]
            err = scan_query_params()
            if err:
                return jsonify(err[0]), err[1]
            if require_json or request.method in ("POST", "PUT", "PATCH"):
                _, jerr = validate_json_body(
                    required_fields if require_json else None,
                    force=require_json,
                )
                if jerr:
                    return jsonify(jerr[0]), jerr[1]
            result = fn(*args, **kwargs)
            if action_name:
                log_api_access(action_name, outcome="success")
            return result

        return wrapper

    return decorator
