"""
Coordinador central de descubrimiento ARP/red — evita escaneos simultáneos duplicados.
Asocia cada snapshot al contexto de red (SSID, BSSID, interfaz, IP, subred, gateway).
"""
from __future__ import annotations

import hashlib
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils.logger import logger

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "scan_in_progress": False,
    "last_scan_at_utc": None,
    "last_scan_duration_ms": None,
    "last_consumer": None,
    "scan_count": 0,
    "context_invalidations": 0,
    "scan_started_at_utc": None,
    "scan_completed_at_utc": None,
    "scan_error": None,
}
_current_fp: Optional[str] = None
_bound_context: Optional[Dict[str, Any]] = None
_MIN_SCAN_INTERVAL_SEC = 60.0


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_network_context() -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "ssid": None,
        "bssid": None,
        "interface": None,
        "local_ip": None,
        "subnet": None,
        "gateway": None,
        "observed_at_utc": _utc(),
    }
    try:
        from utils.network_identity import get_wifi_association

        wifi = get_wifi_association()
        ctx["ssid"] = wifi.get("ssid")
        ctx["bssid"] = wifi.get("bssid")
    except Exception as exc:
        logger.debug("network context wifi: %s", exc)

    try:
        from utils.host_data import get_local_ip, get_primary_network_interface
        from utils.network_helpers import get_default_gateway, get_network_range

        primary = get_primary_network_interface() or {}
        gateway = get_default_gateway()
        ctx["interface"] = primary.get("adapter")
        ctx["local_ip"] = primary.get("local_ip") or get_local_ip()
        ctx["subnet"] = get_network_range(gateway)
        ctx["gateway"] = gateway
    except Exception as exc:
        logger.debug("network context iface: %s", exc)

    return ctx


def context_fingerprint(ctx: Optional[Dict[str, Any]] = None) -> str:
    c = ctx or get_network_context()
    parts = [
        str(c.get("ssid") or ""),
        str(c.get("bssid") or ""),
        str(c.get("interface") or ""),
        str(c.get("local_ip") or ""),
        str(c.get("subnet") or ""),
        str(c.get("gateway") or ""),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def get_bound_context() -> Optional[Dict[str, Any]]:
    with _lock:
        return dict(_bound_context) if _bound_context else None


def invalidate_on_context_change(force_clear_scanner: bool = True) -> bool:
    """Invalida cachés si el contexto de red cambió. Retorna True si hubo invalidación."""
    global _current_fp, _bound_context
    ctx = get_network_context()
    fp = context_fingerprint(ctx)
    with _lock:
        previous = _current_fp
        if previous and fp != previous:
            _state["context_invalidations"] = int(_state.get("context_invalidations") or 0) + 1
            _current_fp = fp
            _bound_context = dict(ctx)
            changed = True
        elif not previous:
            _current_fp = fp
            _bound_context = dict(ctx)
            changed = False
        else:
            changed = False

    if changed and force_clear_scanner:
        try:
            from services.network_scanner import network_scanner

            network_scanner.clear_cache()
        except Exception as exc:
            logger.debug("coordinator clear scanner: %s", exc)
        try:
            from services.network_ndr_service import invalidate_ndr_cache

            invalidate_ndr_cache()
        except Exception as exc:
            logger.debug("coordinator invalidate ndr: %s", exc)
        try:
            from services.performance_cache import invalidate

            invalidate("topology_payload")
            invalidate("network_nodes")
        except Exception as exc:
            logger.debug("coordinator invalidate perf: %s", exc)
        logger.info(
            "Network context changed (%s -> %s) — caches invalidated",
            previous,
            fp,
        )
        _schedule_background_arp_repopulate()
    return changed


def _schedule_background_arp_repopulate() -> None:
    """Tras invalidación por cambio de red, repoblar caché ARP en background."""
    schedule_network_discovery(consumer="context_repopulate", force=False)


def annotate_snapshot(nodes: List[dict], meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ctx = get_bound_context() or get_network_context()
    return {
        "network_context": ctx,
        "context_fingerprint": context_fingerprint(ctx),
        "nodes": nodes,
        "node_count": len(nodes or []),
        "meta": meta or {},
        "snapshot_at_utc": _utc(),
    }


def coordinated_scan(
    runner: Callable[[], List[dict]],
    *,
    consumer: str,
    mode: str = "arp",
    force: bool = False,
) -> Tuple[List[dict], Dict[str, Any]]:
    """
    Ejecuta runner() bajo coordinación única.
    Si ya hay escaneo en curso, devuelve caché del scanner sin lanzar ARP paralelo.
    """
    invalidate_on_context_change(force_clear_scanner=True)

    with _lock:
        if _state.get("scan_in_progress") and not force:
            logger.debug("ARP coordinator: reusing in-flight/cache (%s) consumer=%s", mode, consumer)
            try:
                from services.network_scanner import network_scanner

                cached = network_scanner.get_cached_nodes()
            except Exception:
                cached = []
            ctx = get_bound_context() or get_network_context()
            return cached, {
                "consumer": consumer,
                "mode": mode,
                "reused_inflight": True,
                "context_fingerprint": context_fingerprint(ctx),
            }
        _state["scan_in_progress"] = True
        _state["last_consumer"] = consumer

    t0 = time.perf_counter()
    try:
        nodes = runner() or []
        duration_ms = round((time.perf_counter() - t0) * 1000, 2)
        ctx = get_bound_context() or get_network_context()
        meta = {
            "consumer": consumer,
            "mode": mode,
            "duration_ms": duration_ms,
            "forced": force,
            "context_fingerprint": context_fingerprint(ctx),
        }
        with _lock:
            _state["last_scan_at_utc"] = _utc()
            _state["last_scan_duration_ms"] = duration_ms
            _state["scan_count"] = int(_state.get("scan_count") or 0) + 1
        return nodes, meta
    finally:
        with _lock:
            _state["scan_in_progress"] = False


def get_coordinator_status(*, include_network_context: bool = True) -> Dict[str, Any]:
    with _lock:
        st = dict(_state)
    if include_network_context:
        ctx = get_bound_context() or get_network_context()
        st["context_fingerprint"] = context_fingerprint(ctx)
        st["network_context"] = ctx
    else:
        st["context_fingerprint"] = _current_fp
    return st


_discovery_thread_running = False


def _seconds_since_last_scan() -> Optional[float]:
    last = _state.get("last_scan_at_utc") or _state.get("scan_completed_at_utc")
    if not last:
        return None
    try:
        ts = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts).total_seconds()
    except Exception:
        return None


def discovery_recommended(*, min_interval_sec: Optional[float] = None) -> bool:
    """True si conviene encolar discovery (no in-flight, intervalo, backpressure)."""
    if is_discovery_paused():
        return False
    interval = float(min_interval_sec if min_interval_sec is not None else _MIN_SCAN_INTERVAL_SEC)
    with _lock:
        if _state.get("scan_in_progress") or _discovery_thread_running:
            return False
    elapsed = _seconds_since_last_scan()
    if elapsed is not None and elapsed < interval:
        return False
    try:
        from services.resource_backpressure_service import CAT_NETWORK, should_run_background

        if not should_run_background(CAT_NETWORK):
            return False
    except Exception:
        pass
    return True


def schedule_network_discovery(*, consumer: str = "api", force: bool = False) -> bool:
    """
    Single-flight ARP discovery en background.
    HTTP nunca espera aquí — solo encola trabajo si no hay scan en curso.
    """
    global _discovery_thread_running
    if not force:
        if not discovery_recommended():
            logger.debug("network discovery skipped — not recommended (consumer=%s)", consumer)
            return False
        try:
            from services.network_snapshot_service import _in_boot_grace

            if _in_boot_grace():
                logger.debug("network discovery skipped — boot grace (consumer=%s)", consumer)
                return False
        except Exception:
            pass

    with _lock:
        if _state.get("scan_in_progress") or _discovery_thread_running:
            logger.debug("network discovery skipped — already in flight (consumer=%s)", consumer)
            return False
        _discovery_thread_running = True

    def _worker() -> None:
        global _discovery_thread_running
        try:
            try:
                from services.network_snapshot_service import update_context_scan_status

                update_context_scan_status(scan_status="scanning")
            except Exception as exc:
                logger.debug("context scan_status scanning: %s", exc)
            with _lock:
                _state["scan_started_at_utc"] = _utc()
                _state["scan_error"] = None

            from services.network_scanner import network_scanner

            if force:
                network_scanner.scan_network(force=True)
            else:
                network_scanner.scan_arp_light()
            try:
                from services.network_snapshot_service import persist_after_discovery

                persist_after_discovery()
            except Exception as exc:
                logger.warning("post-discovery snapshot persist: %s", exc)
            with _lock:
                _state["scan_completed_at_utc"] = _utc()
        except Exception as exc:
            logger.warning("network discovery worker failed: %s", exc, exc_info=True)
            with _lock:
                _state["scan_error"] = str(exc)[:200]
            try:
                from services.network_snapshot_service import update_context_scan_status

                update_context_scan_status(scan_status="error", scan_error=str(exc)[:200])
            except Exception:
                pass
        finally:
            with _lock:
                _discovery_thread_running = False

    threading.Thread(
        target=_worker,
        daemon=True,
        name=f"NetDiscovery-{consumer}",
    ).start()
    logger.info("Network discovery scheduled (consumer=%s force=%s)", consumer, force)
    return True
