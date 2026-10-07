"""
Endurecimiento operativo en entornos hostiles — listas IP, rate limits por usuario/ruta,
degradación controlada de rutas no críticas, telemetría real (sin simulación).
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "hostile_environment")
EVENTS_FILE = os.path.join(EVIDENCE_DIR, "events.jsonl")

# Rutas que no se degradan bajo presión (disponibilidad crítica)
CRITICAL_PREFIXES = (
    "/api/dashboard/",
    "/api/security/",
    "/api/network/",
    "/api/ai/",
    "/api/system/platform-health",
    "/api/system/auth-protection",
    "/api/system/blocked-ips",
    "/api/system/hostile-environment",
    "/dashboard",
    "/xdr",
    "/network",
    "/topology",
    "/incidentes",
    "/login",
    "/logout",
)

# GET list — solo lectura de índice JSON por tenant; no scans ni PDF
REPORTS_LIST_PATHS = frozenset({"/api/reports", "/api/reports/list"})

_rate_events: List[Dict[str, Any]] = []
_last_resource_sample: Dict[str, Any] = {}


def _cfg() -> dict:
    from services.hostile_hardening_config import get_hostile_hardening_config
    return get_hostile_hardening_config()


def _ensure_dir() -> None:
    os.makedirs(EVIDENCE_DIR, exist_ok=True)


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _normalize_ip(ip: str) -> str:
    return (ip or "").strip()


def _ip_in_list(ip: str, entries: List[str]) -> bool:
    ip = _normalize_ip(ip)
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip in entries
    for item in entries:
        item = (item or "").strip()
        if not item:
            continue
        if item == ip:
            return True
        try:
            if "/" in item:
                if addr in ipaddress.ip_network(item, strict=False):
                    return True
            elif ipaddress.ip_address(item) == addr:
                return True
        except ValueError:
            continue
    return False


def append_event(event_type: str, detail: dict) -> None:
    _ensure_dir()
    row = {"timestamp": _now_str(), "type": event_type, **detail}
    try:
        with open(EVENTS_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.debug("hostile_environment event: %s", exc)
    _rate_events.append(row)
    if len(_rate_events) > 500:
        del _rate_events[:200]


def is_ip_whitelisted(ip: str) -> bool:
    return _ip_in_list(ip, _cfg().get("ip_whitelist") or [])


def is_ip_blacklisted(ip: str) -> bool:
    return _ip_in_list(ip, _cfg().get("ip_blacklist") or [])


def check_ip_access(ip: str) -> Optional[Tuple[dict, int]]:
    if is_ip_whitelisted(ip):
        return None
    if is_ip_blacklisted(ip):
        append_event("ip_blacklist_block", {"ip": ip, "verified": True})
        try:
            from services.defense_evidence_registry import record_defense_event
            record_defense_event(
                phase="prevent",
                action="ip_blacklist_block",
                motor="hostile_environment_service",
                outcome="blocked",
                threat_type="unauthorized_access",
                evidence={"ip": ip, "verified": True},
                detail=f"IP en lista negra configurada: {ip}",
                confidence="Alta",
            )
        except Exception:
            pass
        return ({"status": "error", "message": "Acceso denegado desde este origen"}, 403)
    return None


def check_user_api_rate_limit(user_email: str, path: str = "") -> Optional[Tuple[dict, int]]:
    if not user_email:
        return None
    from database import db_security

    p = (path or "").split("?")[0].rstrip("/")
    if p in (
        "/api/dashboard/live",
        "/api/security/summary",
        "/api/tenant/scope",
        "/api/manual-defense/summary",
        "/api/notifications",
        "/api/security/threats",
        "/api/security/vulnerabilities",
        "/api/network/nodes",
    ):
        limit = int(_cfg().get("user_dashboard_read_rate_limit_per_minute") or 900)
        bucket = f"user_dash_api:{user_email}"
        try:
            from flask import has_request_context, session as flask_session

            if has_request_context():
                sid = flask_session.get("_novus_login_session_id")
                if sid:
                    bucket = f"user_dash_api:{user_email}:{sid}"
        except Exception:
            pass
    else:
        limit = int(_cfg().get("user_api_rate_limit_per_minute") or 180)
        bucket = f"user_api:{user_email}"
    rl = db_security.check_rate_limit(
        bucket,
        max_requests=limit,
        window_seconds=60,
    )
    if rl.get("status") == "RATE_LIMITED":
        append_event("user_rate_limit", {"email": user_email, "limit": limit, "path": p})
        return (
            {
                "status": "error",
                "message": "Límite de solicitudes por usuario alcanzado",
                "code": "USER_RATE_LIMIT",
                "bucket": bucket,
            },
            429,
        )
    return None


def check_path_api_rate_limit(path: str, client_id: str) -> Optional[Tuple[dict, int]]:
    limits = _cfg().get("api_path_limits") or {}
    if not isinstance(limits, dict):
        return None
    path = path.split("?")[0]
    matched = None
    for prefix, rule in limits.items():
        if path.startswith(prefix):
            matched = rule
            break
    if not matched:
        return None
    from database import db_security

    max_r = int(matched.get("max_requests", 30))
    window = int(matched.get("window_seconds", 60))
    rl = db_security.check_rate_limit(
        f"api_path:{client_id}:{path}",
        max_requests=max_r,
        window_seconds=window,
    )
    if rl.get("status") == "RATE_LIMITED":
        append_event("api_path_rate_limit", {"path": path, "client": client_id, "max": max_r})
        return ({"status": "error", "message": "Límite de API alcanzado para esta ruta"}, 429)
    return None


def _sample_resources() -> Dict[str, Any]:
    global _last_resource_sample
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.05)
        mem = psutil.virtual_memory()
        sample = {
            "cpu_percent": round(cpu, 1),
            "ram_percent": round(mem.percent, 1),
            "ram_used_mb": round(mem.used / (1024 * 1024), 1),
            "sampled_at": _now_str(),
        }
        _last_resource_sample = sample
        return sample
    except Exception as exc:
        logger.debug("hostile resource sample: %s", exc)
        return _last_resource_sample or {"cpu_percent": None, "ram_percent": None}


def check_load_shedding(path: str) -> Optional[Tuple[dict, int]]:
    cfg = _cfg().get("load_shedding") or {}
    if not cfg.get("enabled"):
        return None
    path_norm = ((path or "").split("?")[0].rstrip("/")) or "/"
    if path_norm in REPORTS_LIST_PATHS:
        return None
    for crit in CRITICAL_PREFIXES:
        if path_norm.startswith(crit):
            return None
    prefixes = cfg.get("degraded_path_prefixes") or []
    if not any(path_norm.startswith(p) for p in prefixes):
        return None
    sample = _sample_resources()
    cpu_th = float(cfg.get("cpu_percent_threshold", 92))
    ram_th = float(cfg.get("ram_percent_threshold", 93))
    cpu = sample.get("cpu_percent")
    ram = sample.get("ram_percent")
    if cpu is None and ram is None:
        return None
    if (cpu is not None and cpu >= cpu_th) or (ram is not None and ram >= ram_th):
        append_event(
            "load_shedding",
            {
                "path": path_norm,
                "cpu_percent": cpu,
                "ram_percent": ram,
                "verified": True,
            },
        )
        return (
            {
                "status": "degraded",
                "message": "Servicio temporalmente degradado por alta carga del sistema",
                "retry_after": 30,
            },
            503,
        )
    return None


def evaluate_login_pattern_escalation(db, ip: str, email: Optional[str]) -> Optional[dict]:
    """
    Refuerzo en tiempo real: muchas cuentas desde una IP (stuffing) o misma cuenta desde muchas IP (spray).
    Solo cuenta AuthAccessEvent fallidos reales.
    """
    from database import AuthAccessEvent

    cfg = _cfg()
    window_min = 15
    since = (datetime.now() - timedelta(minutes=window_min)).strftime("%Y-%m-%d %H:%M:%S")
    fails_ip = (
        db.query(AuthAccessEvent)
        .filter(
            AuthAccessEvent.success.is_(False),
            AuthAccessEvent.timestamp >= since,
            AuthAccessEvent.ip_address == ip,
        )
        .all()
    )
    emails = {r.email for r in fails_ip if r.email and r.email != "unknown"}
    stuff_th = int(cfg.get("credential_stuffing_emails_per_ip") or 8)
    if len(emails) >= stuff_th:
        append_event(
            "credential_stuffing_detected",
            {"ip": ip, "unique_emails": len(emails), "window_minutes": window_min, "verified": True},
        )
        return {
            "pattern": "credential_stuffing",
            "unique_emails": len(emails),
            "threshold": stuff_th,
        }

    if email and email != "unknown":
        spray_th = int(cfg.get("password_spray_ips_per_email") or 4)
        rows = (
            db.query(AuthAccessEvent)
            .filter(
                AuthAccessEvent.success.is_(False),
                AuthAccessEvent.timestamp >= since,
                AuthAccessEvent.email == email,
            )
            .all()
        )
        ips = {r.ip_address for r in rows if r.ip_address}
        if len(ips) >= spray_th:
            append_event(
                "password_spraying_detected",
                {"email": email, "unique_ips": len(ips), "window_minutes": window_min, "verified": True},
            )
            return {
                "pattern": "password_spraying",
                "unique_ips": len(ips),
                "threshold": spray_th,
            }
    return None


def build_csp_header() -> str:
    """
    CSP alineada con dependencias reales de templates NOVUS (Tailwind CDN, Chart.js, Font Awesome, Google Fonts).
    'unsafe-inline' permanece por ~60 templates con <script> inline y ~247 onclick —
    eliminarlo requiere migración a nonce/archivos externos (hardening gap documentado).
    Endurecido: worker-src, manifest-src, media-src; sin ampliar script-src.
    """
    return (
        "default-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'self'; "
        "object-src 'none'; "
        "worker-src 'self'; "
        "manifest-src 'self'; "
        "media-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "connect-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
    )


def get_operational_status() -> Dict[str, Any]:
    sample = _sample_resources()
    protection = {}
    try:
        from services.auth_protection_service import auth_protection
        protection = auth_protection.get_protection_status()
    except Exception:
        protection = {}

    recent_access: List[dict] = []
    blocked_count = 0
    try:
        from database import SessionLocal, AuthAccessEvent, IPBloqueada

        db = SessionLocal()
        try:
            since = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
            rows = (
                db.query(AuthAccessEvent)
                .filter(AuthAccessEvent.timestamp >= since)
                .order_by(AuthAccessEvent.id.desc())
                .limit(50)
                .all()
            )
            for r in rows:
                recent_access.append(
                    {
                        "timestamp": r.timestamp,
                        "ip": r.ip_address,
                        "email": r.email,
                        "success": r.success,
                        "route": r.route,
                        "sanction_level": r.sanction_level,
                    }
                )
            blocked_count = (
                db.query(IPBloqueada)
                .filter(IPBloqueada.status.in_(("active", "pending_admin")))
                .count()
            )
        finally:
            db.close()
    except Exception as exc:
        logger.debug("hostile status auth events: %s", exc)

    cfg = _cfg()
    return {
        "status": "ok",
        "timestamp": _now_str(),
        "config_path": os.path.join("config", "hostile_hardening.json"),
        "mechanisms_active": {
            "ip_whitelist": len(cfg.get("ip_whitelist") or []),
            "ip_blacklist": len(cfg.get("ip_blacklist") or []),
            "user_api_rate_limit_per_minute": cfg.get("user_api_rate_limit_per_minute"),
            "api_path_limits": list((cfg.get("api_path_limits") or {}).keys()),
            "load_shedding_enabled": (cfg.get("load_shedding") or {}).get("enabled"),
            "csrf_protection_enabled": cfg.get("csrf_protection_enabled"),
            "csp_enabled": cfg.get("csp_enabled"),
        },
        "resources": sample,
        "auth_protection": protection,
        "blocked_ips_active": blocked_count,
        "recent_access_attempts": recent_access[:25],
        "recent_hostile_events": list(reversed(_rate_events[-25:])),
    }
