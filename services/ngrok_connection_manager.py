"""
NGROK Connection Manager — gestión automática del túnel remoto NOVUS.
Arranque, supervisión continua, recuperación y registro de eventos reales.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

NGROK_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ngrok")
STATUS_FILE = os.path.join(NGROK_DIR, "manager_status.json")
EVENTS_FILE = os.path.join(NGROK_DIR, "events.jsonl")
REMOTE_INFO = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "remote_access.json")

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "enabled": False,
    "manager_active": False,
    "novus_status": "unknown",
    "ngrok_status": "unknown",
    "connection_status": "unknown",
    "local_url": None,
    "public_url": None,
    "login_url": None,
    "last_tunnel_restart": None,
    "last_check_at": None,
    "reconnect_count": 0,
    "reserved_domain": None,
    "reserved_domain_active": False,
    "plan_limitation": None,
    "last_error": None,
    "started_at": None,
}
_monitor_thread: Optional[threading.Thread] = None
_running = False
_boot_logged = False


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _cfg_bool(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _port() -> int:
    return int(os.environ.get("PORT", os.environ.get("NOVUS_PORT", 5000)))


def _ensure_dirs() -> None:
    os.makedirs(NGROK_DIR, exist_ok=True)


def _log_event(event_type: str, detail: str, *, extra: Optional[dict] = None) -> None:
    _ensure_dirs()
    entry = {
        "timestamp": _now(),
        "event_type": event_type,
        "detail": detail,
        "extra": extra or {},
    }
    try:
        with open(EVENTS_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.debug("ngrok manager event log: %s", exc)

    if event_type in ("tunnel_error", "tunnel_reconnect", "url_changed"):
        try:
            from services.evidence_center_service import record_evidence
            record_evidence(
                motor="ngrok_connection_manager",
                description=f"{event_type}: {detail[:400]}",
                categoria="auditoria",
                nivel_riesgo="medio" if "error" in event_type else "bajo",
                accion_ejecutada=event_type,
                evidence=entry,
            )
        except Exception:
            pass


def _save_status() -> None:
    _ensure_dirs()
    try:
        with open(STATUS_FILE, "w", encoding="utf-8") as fh:
            json.dump(dict(_state), fh, ensure_ascii=False, indent=2)
    except Exception as exc:
        logger.debug("ngrok manager status save: %s", exc)


def _save_remote_info(public_url: str, port: int) -> None:
    info = {
        "timestamp": _now(),
        "public_url": public_url,
        "local_url": f"http://127.0.0.1:{port}",
        "login_url": f"{public_url}/login",
        "sector_login_url": f"{public_url}/sector-login",
        "managed_by": "ngrok_connection_manager",
        "proxy_required_env": {
            "NOVUS_BEHIND_PROXY": "True",
            "NOVUS_TRUSTED_PROXY_COUNT": "1",
            "NOVUS_PUBLIC_URL": public_url,
            "SESSION_COOKIE_SECURE": "True",
            "PREFERRED_URL_SCHEME": "https",
        },
    }
    os.makedirs(os.path.dirname(REMOTE_INFO), exist_ok=True)
    with open(REMOTE_INFO, "w", encoding="utf-8") as fh:
        json.dump(info, fh, ensure_ascii=False, indent=2)


def _http_check(url: str, timeout: float = 8.0, headers: Optional[dict] = None) -> bool:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except Exception:
        return False


def _port_listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            return True
    except OSError:
        return False


def _check_novus(port: int) -> bool:
    if not _port_listening(port):
        return False
    return _http_check(f"http://127.0.0.1:{port}/login", timeout=5)


def _fetch_ngrok_api() -> Optional[dict]:
    for api_port in (4040, 4041, 4042):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{api_port}/api/tunnels", timeout=3) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            continue
    return None


def _tunnel_for_port(data: Optional[dict], port: int) -> Optional[dict]:
    if not data:
        return None
    for t in data.get("tunnels") or []:
        addr = str((t.get("config") or {}).get("addr") or "")
        if str(port) in addr and t.get("public_url"):
            return t
    for t in data.get("tunnels") or []:
        if str(t.get("public_url", "")).startswith("https://"):
            return t
    return None


def _apply_public_url(public_url: str, port: int) -> None:
    prev = _state.get("public_url")
    _state["public_url"] = public_url
    _state["login_url"] = f"{public_url}/login"
    _state["local_url"] = f"http://127.0.0.1:{port}"
    os.environ["NOVUS_PUBLIC_URL"] = public_url
    os.environ.setdefault("NOVUS_BEHIND_PROXY", "True")
    _save_remote_info(public_url, port)
    if prev and prev != public_url:
        _log_event(
            "url_changed",
            f"URL pública cambiada: {prev} -> {public_url}",
            extra={"previous": prev, "current": public_url},
        )


def _connect_ngrok(port: int) -> Optional[str]:
    reserved = (os.environ.get("NGROK_DOMAIN") or os.environ.get("NGROK_RESERVED_DOMAIN") or "").strip()
    try:
        from pyngrok import ngrok

        auth = os.environ.get("NGROK_AUTHTOKEN") or os.environ.get("NGROK_AUTH_TOKEN")
        if auth:
            ngrok.set_auth_token(auth)

        kwargs: Dict[str, Any] = {}
        if reserved:
            kwargs["domain"] = reserved
            _state["reserved_domain"] = reserved

        tunnel = ngrok.connect(port, "http", **kwargs)
        return tunnel.public_url
    except Exception as exc:
        err = str(exc)
        _state["last_error"] = err
        if "ERR_NGROK_334" in err or "already online" in err.lower():
            data = _fetch_ngrok_api()
            t = _tunnel_for_port(data, port)
            if t:
                return t.get("public_url")
        if reserved:
            _state["plan_limitation"] = (
                "El dominio reservado configurado no está disponible en el plan ngrok actual. "
                "Se gestionará una URL dinámica automáticamente."
            )
            _log_event("reserved_domain_unavailable", _state["plan_limitation"], extra={"domain": reserved, "error": err})
            try:
                from pyngrok import ngrok
                tunnel = ngrok.connect(port, "http")
                return tunnel.public_url
            except Exception as exc2:
                _state["last_error"] = str(exc2)
                return None
        _log_event("tunnel_error", err)
        return None


def _verify_public_url(public_url: str) -> bool:
    headers = {"ngrok-skip-browser-warning": "69420", "User-Agent": "NOVUS-NgrokManager/1.0"}
    return _http_check(f"{public_url}/login", timeout=15, headers=headers)


def _ensure_tunnel(port: int, *, force_reconnect: bool = False) -> bool:
    if not _check_novus(port):
        _state["novus_status"] = "detenido"
        _state["ngrok_status"] = "esperando_novus"
        _state["connection_status"] = "novus_no_disponible"
        _save_status()
        return False

    _state["novus_status"] = "activo"

    data = None if force_reconnect else _fetch_ngrok_api()
    tunnel = _tunnel_for_port(data, port)
    public_url = tunnel.get("public_url") if tunnel else None

    if not public_url or force_reconnect:
        if force_reconnect:
            _state["reconnect_count"] = int(_state.get("reconnect_count") or 0) + 1
            _state["last_tunnel_restart"] = _now()
            _log_event("tunnel_reconnect", f"Reintento #{_state['reconnect_count']} de túnel ngrok")
        public_url = _connect_ngrok(port)
        if public_url:
            _state["last_tunnel_restart"] = _state.get("last_tunnel_restart") or _now()
            _log_event("tunnel_started", f"Túnel ngrok activo: {public_url}")

    if not public_url:
        _state["ngrok_status"] = "error"
        _state["connection_status"] = "sin_tunel"
        _save_status()
        return False

    _apply_public_url(public_url, port)
    reserved = _state.get("reserved_domain")
    _state["reserved_domain_active"] = bool(reserved and reserved in public_url)
    if not _state.get("plan_limitation") and not reserved:
        _state["plan_limitation"] = (
            "Plan ngrok sin dominio reservado configurado (NGROK_DOMAIN). "
            "La URL pública puede cambiar al recrear el túnel."
        )

    if _verify_public_url(public_url):
        _state["ngrok_status"] = "activo"
        _state["connection_status"] = "conectado"
        _state["last_error"] = None
        _save_status()
        return True

    _state["ngrok_status"] = "degradado"
    _state["connection_status"] = "publico_no_responde"
    _state["last_error"] = "La URL pública no respondió en verificación HTTP"
    _log_event("tunnel_error", _state["last_error"], extra={"public_url": public_url})
    _save_status()
    return False


def _monitor_loop() -> None:
    global _running
    port = _port()
    interval = max(15, int(os.environ.get("NGROK_MONITOR_INTERVAL_SEC", 30)))
    fail_streak = 0

    logger.info("Ngrok Connection Manager: supervisión iniciada (puerto %s)", port)

    while _running:
        try:
            ok = _ensure_tunnel(port)
            _state["last_check_at"] = _now()
            if ok:
                fail_streak = 0
            else:
                fail_streak += 1
                if fail_streak >= 2 and _check_novus(port):
                    _ensure_tunnel(port, force_reconnect=True)
            _save_status()
        except Exception as exc:
            logger.debug("ngrok monitor cycle: %s", exc)
            _state["last_error"] = str(exc)
            _log_event("monitor_error", str(exc))
            _save_status()
        for _ in range(interval):
            if not _running:
                break
            time.sleep(1)

    logger.info("Ngrok Connection Manager: supervisión detenida")


def get_manager_status() -> Dict[str, Any]:
    with _lock:
        status = dict(_state)
    history = list_recent_events(30)
    status["recent_events"] = history
    status["history_count"] = len(history)
    return status


def list_recent_events(limit: int = 50) -> List[Dict[str, Any]]:
    if not os.path.exists(EVENTS_FILE):
        return []
    rows: List[Dict[str, Any]] = []
    try:
        with open(EVENTS_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return rows[-limit:]


def start_ngrok_connection_manager() -> Dict[str, Any]:
    """Inicia el gestor en segundo plano (idempotente)."""
    global _monitor_thread, _running, _boot_logged

    if not _cfg_bool("NOVUS_AUTO_NGROK", True):
        with _lock:
            _state["enabled"] = False
            _state["manager_active"] = False
            _state["plan_limitation"] = "NOVUS_AUTO_NGROK=False — gestión automática deshabilitada"
        _save_status()
        return {"status": "disabled", "reason": "NOVUS_AUTO_NGROK=False"}

    with _lock:
        if _monitor_thread and _monitor_thread.is_alive():
            return {"status": "already_running"}

        _running = True
        _state["enabled"] = True
        _state["manager_active"] = True
        _state["started_at"] = _state.get("started_at") or _now()
        port = _port()
        _state["local_url"] = f"http://127.0.0.1:{port}"

        if not _boot_logged:
            _log_event("server_boot", f"NOVUS arrancó — gestor ngrok activo en puerto {port}")
            _boot_logged = True

        _monitor_thread = threading.Thread(
            target=_monitor_loop,
            daemon=True,
            name="NgrokConnectionManager",
        )
        _monitor_thread.start()

    return get_manager_status()


def stop_ngrok_connection_manager() -> None:
    global _running
    _running = False
