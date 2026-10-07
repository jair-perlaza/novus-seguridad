"""
Protección HTTP a nivel aplicación — flood, bots, circuit breaker.
Buckets independientes: IP, sesión autenticada, login/email — coexisten sin colapsar NAT legítimo.
"""
from __future__ import annotations

import hashlib
import re
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from utils.logger import logger

_windows: Dict[str, list] = defaultdict(list)
_circuit_open_until: Dict[str, float] = {}
_violation_streak: Dict[str, int] = defaultdict(int)
_BOT_UA = re.compile(
    r"(bot|crawler|spider|scrapy|curl/|wget/|go-http-client|masscan|nikto|sqlmap)",
    re.I,
)
_cpu_sample_ts: float = 0.0
_cpu_adaptive_mult: float = 1.0


def _cfg() -> dict:
    from services.hostile_hardening_config import get_hostile_hardening_config
    return get_hostile_hardening_config()


def _adaptive_multiplier(cfg: dict) -> float:
    global _cpu_sample_ts, _cpu_adaptive_mult
    base = float(cfg.get("adaptive_rate_multiplier") or 1.0)
    now = time.time()
    if now - _cpu_sample_ts < 2.0:
        return max(0.5, base * _cpu_adaptive_mult)
    mult = 1.0
    try:
        import psutil

        if psutil.cpu_percent(interval=0) > 85:
            mult = 0.7
    except Exception:
        mult = 1.0
    _cpu_sample_ts = now
    _cpu_adaptive_mult = mult
    return max(0.5, base * mult)


def _prune(key: str, window: float) -> None:
    now = time.time()
    bucket = [t for t in _windows[key] if now - t < window]
    if bucket:
        _windows[key] = bucket
    else:
        _windows.pop(key, None)


def prune_stale_windows(*, window: float = 10.0, max_keys: int = 4096) -> int:
    """
    Barrido global — evita retención indefinida de buckets IP/sess no reutilizados.
    No debilita límites; solo libera memoria de claves frías.
    """
    now = time.time()
    removed = 0
    keys = list(_windows.keys())
    for key in keys:
        bucket = [t for t in _windows.get(key, []) if now - t < window]
        if bucket:
            _windows[key] = bucket
        else:
            _windows.pop(key, None)
            removed += 1
    # Hard cap: drop oldest keys by last timestamp
    if len(_windows) > max_keys:
        ranked = sorted(
            ((k, max(v) if v else 0.0) for k, v in _windows.items()),
            key=lambda kv: kv[1],
        )
        for k, _ in ranked[: max(0, len(_windows) - max_keys)]:
            _windows.pop(k, None)
            removed += 1
    # Circuit / streak hygiene
    for k in list(_circuit_open_until.keys()):
        if _circuit_open_until[k] <= now:
            _circuit_open_until.pop(k, None)
    for k in list(_violation_streak.keys()):
        if k not in _windows and k not in _circuit_open_until:
            _violation_streak.pop(k, None)
    return removed


def _is_dashboard_read_path(path: str) -> bool:
    p = (path or "").split("?")[0].rstrip("/")
    return p in (
        "/api/dashboard/live",
        "/api/security/summary",
        "/api/tenant/scope",
        "/api/manual-defense/summary",
        "/api/notifications",
        "/api/security/threats",
        "/api/security/vulnerabilities",
        "/api/network/nodes",
    )


def _session_cookie_names() -> tuple:
    """Nombres de cookie de sesión Flask — config SESSION_COOKIE_NAME, no app.session_cookie_name."""
    try:
        from flask import has_request_context, request

        if not has_request_context():
            return ("session",)
        cfg_name = (request.app.config.get("SESSION_COOKIE_NAME") or "session").strip()
        names = [cfg_name] if cfg_name else []
        if "session" not in names:
            names.append("session")
        return tuple(names)
    except Exception:
        return ("session",)


def _has_session_cookie() -> bool:
    try:
        from flask import has_request_context, request

        if not has_request_context():
            return False
        for name in _session_cookie_names():
            if request.cookies.get(name):
                return True
    except Exception:
        pass
    return False


def _session_bucket_key() -> Optional[str]:
    try:
        from flask import has_request_context, request

        if not has_request_context():
            return None
        for name in _session_cookie_names():
            val = request.cookies.get(name)
            if val:
                digest = hashlib.sha256(val.encode("utf-8", errors="ignore")).hexdigest()[:20]
                return f"sess:{digest}"
    except Exception:
        pass
    return None


def _login_email_bucket() -> Optional[str]:
    try:
        from flask import has_request_context, request

        if not has_request_context() or request.method != "POST":
            return None
        if request.endpoint != "auth.login":
            return None
        email = (request.form.get("email") or "").strip().lower()
        if not email and request.is_json:
            payload = request.get_json(silent=True) or {}
            email = (payload.get("email") or "").strip().lower()
        if email:
            return f"login:{email}"
    except Exception:
        pass
    return None


def _is_login_page_get() -> bool:
    try:
        from flask import has_request_context, request

        return (
            has_request_context()
            and request.method == "GET"
            and request.endpoint == "auth.login"
        )
    except Exception:
        return False


def _resolve_flood_buckets(ip: str) -> List[Tuple[str, int]]:
    """
    Retorna [(bucket_key, limit_per_10s), ...] — todos deben pasar.
    Sesión autenticada en lecturas críticas: bucket por sesión (NAT corporativo).
    Login: bucket por email. Siempre incluye bucket IP con límite acorde.
    """
    cfg = _cfg()
    mult = _adaptive_multiplier(cfg)
    buckets: List[Tuple[str, int]] = []

    if _is_login_page_get():
        page_lim = int(cfg.get("http_flood_login_page_per_ip_per_10s") or 600)
        buckets.append((f"login-page:{ip}", max(50, int(page_lim * mult))))
        return buckets

    login_key = _login_email_bucket()
    if login_key:
        per_email = int(cfg.get("http_flood_login_per_email_per_10s") or 30)
        buckets.append((login_key, max(10, int(per_email * mult))))

    sess_key = _session_bucket_key()
    try:
        from flask import has_request_context, request

        if sess_key and has_request_context() and request.method == "GET":
            path = (request.path or "").split("?")[0].rstrip("/")
            if _is_dashboard_read_path(path):
                per_sess = int(cfg.get("http_flood_session_dashboard_per_10s") or 180)
                buckets.append((sess_key, max(30, int(per_sess * mult))))
                nat_limit = int(cfg.get("http_flood_nat_dashboard_per_ip_per_10s") or 5000)
                buckets.append((f"ip-nat:{ip}", max(500, nat_limit)))
                return buckets
            if path.startswith("/api/"):
                per_sess = int(cfg.get("http_flood_session_authed_per_10s") or 90)
                buckets.append((sess_key, max(20, int(per_sess * mult))))
                nat_api = int(cfg.get("http_flood_nat_api_per_ip_per_10s") or 3000)
                buckets.append((f"ip-nat-api:{ip}", max(200, nat_api)))
                return buckets
    except Exception as exc:
        logger.debug("_resolve_flood_buckets: %s", exc)

    if sess_key and _has_session_cookie():
        per_sess = int(cfg.get("http_flood_session_authed_per_10s") or 90)
        buckets.append((sess_key, max(20, int(per_sess * mult))))

    base = int(cfg.get("http_flood_per_ip_per_10s") or 80)
    buckets.append((f"ip:{ip}", max(20, int(base * mult))))
    return buckets


def check_http_flood(ip: str, cfg: Optional[dict] = None) -> Optional[Tuple[dict, int]]:
    cfg = cfg or _cfg()
    window = 10.0
    now = time.time()
    # Occasional global prune (amortized) — keeps bucket map bounded under soak
    if int(now) % 37 == 0:
        try:
            prune_stale_windows(window=window, max_keys=4096)
        except Exception:
            pass

    for bucket_key, limit in _resolve_flood_buckets(ip):
        _prune(bucket_key, window)
        _windows[bucket_key].append(now)
        if len(_windows[bucket_key]) > limit:
            _trip_circuit(bucket_key, cfg)
            from services.hostile_environment_service import append_event
            append_event(
                "http_flood_limit",
                {
                    "bucket": bucket_key,
                    "ip": ip,
                    "count": len(_windows[bucket_key]),
                    "limit": limit,
                },
            )
            return (
                {
                    "status": "error",
                    "message": "Tráfico HTTP excesivo desde este origen. Intente más tarde.",
                    "code": "HTTP_FLOOD",
                    "bucket": bucket_key,
                },
                429,
            )
    return None


def _trip_circuit(bucket_key: str, cfg: dict) -> None:
    """
    Abre circuit solo tras rechazos repetidos por flood — no por volumen legítimo NAT/sesión.
    Buckets sess:/ip-nat: solo rechazo puntual, sin cooldown global (evita falsos positivos 600 users).
    """
    if bucket_key.startswith("ip-nat") or bucket_key.startswith("sess:") or bucket_key.startswith("login:"):
        return
    _violation_streak[bucket_key] += 1
    thr = int(cfg.get("circuit_breaker_violations") or 12)
    if _violation_streak[bucket_key] >= thr:
        cooldown = int(cfg.get("circuit_breaker_cooldown_sec") or 45)
        _circuit_open_until[bucket_key] = time.time() + cooldown
        _violation_streak[bucket_key] = 0


def reset_abuse_guard_state() -> None:
    """Limpia contadores — uso interno diagnóstico / entre niveles de benchmark."""
    _windows.clear()
    _circuit_open_until.clear()
    _violation_streak.clear()
    try:
        from database import db_security

        db_security.reset_rate_limit_buckets()
    except Exception as exc:
        logger.debug("reset db rate limits: %s", exc)


def check_circuit_breaker(ip: str) -> Optional[Tuple[dict, int]]:
    keys = [b[0] for b in _resolve_flood_buckets(ip)]
    for key in keys:
        until = _circuit_open_until.get(key)
        if until and time.time() < until:
            return (
                {
                    "status": "error",
                    "message": "Origen en enfriamiento por abuso repetido.",
                    "code": "CIRCUIT_BREAKER",
                    "bucket": key,
                },
                429,
            )
        if until and time.time() >= until:
            _circuit_open_until.pop(key, None)
    return None


def check_bot_user_agent(user_agent: str, ip: str, cfg: Optional[dict] = None) -> Optional[Tuple[dict, int]]:
    cfg = cfg or _cfg()
    if not cfg.get("bot_detection_enabled", True):
        return None
    ua = (user_agent or "").strip()
    if not ua:
        return None
    if _BOT_UA.search(ua):
        allow = cfg.get("bot_allowlist_patterns") or []
        for pat in allow:
            if pat.lower() in ua.lower():
                return None
        from services.hostile_environment_service import append_event
        append_event("bot_ua_detected", {"ip": ip, "ua": ua[:120]})
        if cfg.get("bot_block_enabled", False):
            return ({"status": "error", "message": "Cliente automatizado no permitido en esta ruta."}, 403)
    return None


def check_slow_request(content_length: Optional[int], method: str, cfg: Optional[dict] = None) -> Optional[Tuple[dict, int]]:
    cfg = cfg or _cfg()
    if not cfg.get("slowloris_guard_enabled", True):
        return None
    if method in ("POST", "PUT", "PATCH") and content_length is None:
        return ({"status": "error", "message": "Solicitud incompleta o inválida."}, 400)
    max_body = int(cfg.get("max_body_bytes") or 2_097_152)
    if content_length is not None and content_length > max_body:
        return ({"status": "error", "message": "Cuerpo demasiado grande."}, 413)
    return None


def run_pre_request_checks(ip: str, user_agent: str, method: str, content_length: Optional[int]) -> Optional[Tuple[dict, int]]:
    hit = check_circuit_breaker(ip)
    if hit:
        return hit
    cfg = _cfg()
    hit = check_http_flood(ip, cfg)
    if hit:
        return hit
    hit = check_bot_user_agent(user_agent, ip, cfg)
    if hit:
        return hit
    return check_slow_request(content_length, method, cfg)


# Compatibilidad con scripts de diagnóstico
_ip_windows = _windows
