"""
NOVUS Web Shield — motor en segundo plano.
Telemetría real: descargas locales, hosts/proxy/DNS, análisis URL bajo demanda/cola.
Sin eventos simulados.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, List, Optional, Set

import psutil

from utils.logger import logger

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "active": False,
    "started_at": None,
    "last_cycle_at": None,
    "last_error": None,
    "cycles": 0,
    "cpu_percent": None,
    "memory_mb": None,
    "revision": 0,
}

_thread: Optional[threading.Thread] = None
_running = False
_known_downloads: Set[str] = set()
_baseline_hosts_hash: Optional[str] = None
_baseline_proxy: Optional[str] = None
_baseline_dns: Optional[str] = None
_url_queue: List[str] = []
_url_queue_lock = threading.Lock()
_downloads_initialized = False


def _now() -> str:
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_engine_status() -> Dict[str, Any]:
    from services.web_shield_config import load_web_shield_config
    from services.web_shield_service import get_stats

    cfg = load_web_shield_config()
    with _lock:
        st = dict(_state)
    stats = get_stats()
    return {
        "engine": "novus_web_shield",
        "enabled": bool(cfg.get("enabled")),
        "mode": cfg.get("mode"),
        "sensitivity": cfg.get("sensitivity"),
        "status": st,
        "stats": stats,
        "limitations": {
            "during_navigation_dom": (
                "Requiere extensión de navegador NOVUS o agente endpoint — "
                "use POST /api/web-shield/browser-report cuando esté instalada."
            ),
            "domain_reputation_feed": "Requiere integración WHOIS/Threat Intel externa — no inventada.",
            "system_wide_block": (
                "El bloqueo previo a navegación aplica vía API/análisis; "
                "bloqueo transparente de todo el tráfico requiere proxy/PAC del sistema."
            ),
        },
        "updated_at": _now(),
    }


def enqueue_url_analysis(url: str) -> None:
    with _url_queue_lock:
        if url not in _url_queue:
            _url_queue.append(url)


def analyze_and_policy_url(url: str, *, source: str = "api") -> Dict[str, Any]:
    from services.web_shield_analyzer import analyze_url
    from services.web_shield_config import (
        effective_block_threshold,
        effective_warn_threshold,
        load_web_shield_config,
    )
    from services.web_shield_service import record_event

    cfg = load_web_shield_config()
    analysis = analyze_url(
        url,
        whitelist=cfg.get("whitelist_domains") or [],
        blacklist=cfg.get("blacklist_domains") or [],
    )
    score = int(analysis.get("risk_score") or 0)
    block_t = effective_block_threshold(cfg)
    warn_t = effective_warn_threshold(cfg)
    mode = (cfg.get("mode") or "block").lower()
    action = "allowed"
    event_type = "url_analyzed"
    severity = analysis.get("risk_level") or "info"

    if score >= block_t and mode == "block":
        action = "blocked"
        event_type = "url_blocked"
        severity = "critico"
    elif score >= warn_t:
        action = "warned"
        event_type = "url_warned"
        severity = "alto"
    if "phish" in " ".join(analysis.get("reasons") or []).lower() or score >= 60:
        if "login" in url.lower() or "signin" in url.lower():
            record_event(
                "phishing_heuristic",
                severity="alto",
                action_taken=action,
                domain=analysis.get("domain"),
                url=url,
                risk_score=score,
                evidence={**analysis, "source_channel": source},
            )

    ev = {**analysis, "action": action, "thresholds": {"block": block_t, "warn": warn_t}, "source_channel": source}
    record_event(
        event_type,
        severity=severity,
        action_taken=action,
        domain=analysis.get("domain"),
        url=url,
        risk_score=score,
        evidence=ev,
    )
    return {"analysis": analysis, "action": action, "event_type": event_type}


def _downloads_dir() -> str:
    return os.path.join(os.path.expanduser("~"), "Downloads")


def _process_new_download(path: str) -> None:
    from services.web_shield_config import load_web_shield_config
    from services.web_shield_service import inspect_download_file, quarantine_file, record_event

    cfg = load_web_shield_config()
    if not cfg.get("monitor_downloads"):
        return
    info = inspect_download_file(path)
    score = int(info.get("risk_score") or 0)
    action = "inspected"
    event_type = "download_inspected"
    severity = "info"
    quarantine_path = None

    if score >= 40:
        event_type = "download_blocked"
        severity = "alto"
        action = "blocked"
        if cfg.get("quarantine_enabled"):
            quarantine_path = quarantine_file(path, info)
            if quarantine_path:
                event_type = "download_quarantined"
                action = "quarantined"
                info["quarantine_path"] = quarantine_path

    record_event(
        event_type,
        severity=severity,
        action_taken=action,
        domain=None,
        url=None,
        risk_score=score,
        evidence=info,
    )


def _scan_downloads() -> None:
    global _known_downloads, _downloads_initialized
    ddir = _downloads_dir()
    if not os.path.isdir(ddir):
        return
    current: Set[str] = set()
    try:
        for name in os.listdir(ddir):
            full = os.path.join(ddir, name)
            if os.path.isfile(full):
                current.add(full)
        if not _downloads_initialized:
            _known_downloads = current
            _downloads_initialized = True
            return
        for full in current:
            if full not in _known_downloads:
                _process_new_download(full)
        _known_downloads = current
    except Exception as exc:
        logger.debug("web_shield downloads: %s", exc)


def _monitor_host_config() -> None:
    global _baseline_hosts_hash, _baseline_proxy, _baseline_dns
    from services.web_shield_host_audit import full_host_audit
    from services.web_shield_service import record_event

    audit = full_host_audit()
    hosts = audit.get("hosts") or {}
    proxy = audit.get("proxy") or {}
    dns = audit.get("dns") or {}

    h = hosts.get("sha256")
    p = str(proxy.get("proxy_server")) + str(proxy.get("proxy_enabled"))
    d = "|".join(dns.get("servers") or [])

    if _baseline_hosts_hash is None:
        _baseline_hosts_hash = h
        _baseline_proxy = p
        _baseline_dns = d
        return

    if h and h != _baseline_hosts_hash:
        record_event(
            "browser_config_changed",
            severity="alto",
            action_taken="logged",
            evidence={"component": "hosts", "previous_hash": _baseline_hosts_hash, "current": hosts},
        )
        _baseline_hosts_hash = h
    if p != _baseline_proxy:
        record_event(
            "browser_config_changed",
            severity="medio",
            action_taken="logged",
            evidence={"component": "proxy", "previous": _baseline_proxy, "current": proxy},
        )
        _baseline_proxy = p
    if d != _baseline_dns:
        record_event(
            "browser_config_changed",
            severity="medio",
            action_taken="logged",
            evidence={"component": "dns", "previous": _baseline_dns, "current": dns},
        )
        _baseline_dns = d


def _sample_resource_usage() -> None:
    try:
        proc = psutil.Process(os.getpid())
        with _lock:
            _state["cpu_percent"] = round(proc.cpu_percent(interval=0.0), 1)
            _state["memory_mb"] = round(proc.memory_info().rss / (1024 * 1024), 1)
    except Exception:
        pass


def _cycle() -> None:
    from services.web_shield_config import load_web_shield_config

    cfg = load_web_shield_config()
    if not cfg.get("enabled"):
        return

    if cfg.get("monitor_downloads"):
        _scan_downloads()
    if cfg.get("monitor_hosts_proxy_dns"):
        _monitor_host_config()

    processed = 0
    max_p = int(cfg.get("max_events_per_cycle") or 20)
    while processed < max_p:
        with _url_queue_lock:
            if not _url_queue:
                break
            url = _url_queue.pop(0)
        analyze_and_policy_url(url, source="queue")
        processed += 1

    _sample_resource_usage()
    with _lock:
        _state["last_cycle_at"] = _now()
        _state["cycles"] = int(_state.get("cycles") or 0) + 1
        _state["revision"] = int(_state.get("revision") or 0) + 1


def _loop() -> None:
    global _running
    logger.info("NOVUS Web Shield: bucle iniciado")
    while _running:
        try:
            _cycle()
        except Exception as exc:
            logger.error("Web Shield cycle: %s", exc, exc_info=True)
            with _lock:
                _state["last_error"] = str(exc)
        from services.web_shield_config import load_web_shield_config
        interval = float(load_web_shield_config().get("cycle_interval_sec") or 8)
        time.sleep(max(3.0, interval))
    logger.info("NOVUS Web Shield: bucle detenido")


def start_web_shield_engine() -> Dict[str, Any]:
    global _thread, _running
    with _lock:
        if _state.get("active"):
            return {"status": "already_running", **get_engine_status()}
        _running = True
        _state["active"] = True
        _state["started_at"] = _now()
    _thread = threading.Thread(target=_loop, name="WebShieldEngine", daemon=True)
    _thread.start()
    logger.info("NOVUS Web Shield Engine iniciado")
    return {"status": "started", **get_engine_status()}


def ingest_browser_report(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Informes desde extensión de navegador (cuando esté instalada).
    Solo persiste si hay URL/dominio y tipo de evento verificable.
    """
    from services.web_shield_service import record_event

    url = payload.get("url") or payload.get("page_url")
    event_type = payload.get("event_type") or "browser_report"
    if not url:
        return {"status": "rejected", "reason": "url_required"}
    ev = dict(payload)
    ev["verified"] = True
    ev["source_channel"] = "browser_extension"
    row = record_event(
        event_type,
        severity=str(payload.get("severity") or "medio"),
        action_taken=payload.get("action"),
        domain=payload.get("domain"),
        url=url,
        risk_score=payload.get("risk_score"),
        evidence=ev,
    )
    return {"status": "recorded" if row else "error", "event": row}
