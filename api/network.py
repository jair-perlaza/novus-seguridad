"""
Network API endpoints for NOVUS
Network scanning and device discovery APIs — real data only.
"""
from flask import Blueprint, jsonify, request
import threading
from flask_login import login_required, current_user
from services.network_scanner import network_scanner
from services.network_event_log import network_event_log
from services.tenant_api_gate import check_tenant_monitoring_or_response
from utils.host_data import get_local_ip, get_primary_network_interface, format_ip_or_unavailable
from utils.logger import logger
from services.api_security_service import api_hardened, sanitize_ip_param


network_api_bp = Blueprint('network_api', __name__, url_prefix='/api/network')


def _schedule_background_arp_if_needed() -> None:
    """Encola descubrimiento ARP en background — nunca bloquea el request HTTP."""
    try:
        from services.network_scan_coordinator import schedule_network_discovery

        schedule_network_discovery(consumer="nodes_api", force=False)
    except Exception as exc:
        logger.debug("schedule background discovery: %s", exc)


def _build_network_info_payload():
    meta = network_scanner.get_network_meta()
    primary = get_primary_network_interface() or {}
    cache_info = network_scanner.get_cache_info()
    from utils.network_helpers import get_hostname

    local_ip = meta.get("local_ip") or primary.get("local_ip") or get_local_ip()
    hostname = get_hostname()
    return {
        "status": "success",
        "local_ip": format_ip_or_unavailable(local_ip),
        "gateway": meta.get("gateway") or primary.get("gateway") or "Sin datos disponibles",
        "netmask": meta.get("netmask") or primary.get("netmask") or "Sin datos disponibles",
        "network_range": meta.get("network_range") or "Sin datos disponibles",
        "adapter": meta.get("adapter") or primary.get("adapter") or "Sin datos disponibles",
        "mac": meta.get("mac") or primary.get("mac") or "Sin datos disponibles",
        "connection_type": meta.get("connection_type") or primary.get("connection_type") or "Sin datos disponibles",
        "speed_mbps": meta.get("speed_mbps") or primary.get("speed_mbps") or "Sin datos disponibles",
        "hostname": hostname if hostname != "Unknown" else "Sin datos disponibles",
        "node_count": cache_info.get("node_count", 0),
        "last_scan": cache_info.get("last_scan") or "Sin datos disponibles",
        "scan_status": "Escaneando..." if network_scanner._scanning else "Monitorizando",
    }


@network_api_bp.route('/info', methods=['GET'])
@login_required
def get_network_info():
    """Return real network metadata for UI widgets — snapshot de contexto, sin ARP."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="network")
        if blocked:
            return blocked
        from services.network_snapshot_service import read_context_snapshot

        ctx = read_context_snapshot()
        if ctx and ctx.get("body"):
            body = dict(ctx["body"])
            body["status"] = "success"
            body["source_type"] = "network_context_snapshot"
            return jsonify(body)
        return jsonify(_build_network_info_payload())
    except Exception as e:
        logger.error(f"Error in network info API: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Error retrieving network info",
        }), 500


@network_api_bp.route('/events', methods=['GET'])
@login_required
def get_network_events():
    """Return real network event log entries produced by NOVUS scanners."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="network")
        if blocked:
            return blocked
        limit = request.args.get('limit', 50, type=int)
        events = network_event_log.get_recent(limit=limit)
        from services.network_ndr_service import enrich_events_with_explanations
        events = enrich_events_with_explanations(events)
        return jsonify({
            "status": "success",
            "events": events,
            "count": len(events),
        })
    except Exception as e:
        logger.error(f"Error in network events API: {e}", exc_info=True)
        return jsonify({"status": "error", "events": []}), 500


@network_api_bp.route('/nodes', methods=['GET'])
@login_required
def get_network_nodes():
    """Nodos de red desde snapshot — descubrimiento ARP solo en background."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="network")
        if blocked:
            return blocked
        from services.network_snapshot_service import read_nodes_api

        trigger = request.args.get("trigger_discovery", "false").lower() in ("1", "true", "yes")
        include_ctx = request.args.get("include_context", "false").lower() in ("1", "true", "yes")
        return jsonify(read_nodes_api(trigger_discovery=trigger, include_context=include_ctx))

    except Exception as e:
        logger.error(f"Error in network nodes API: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "nodes": [],
            "message": "Error retrieving network nodes",
        }), 500


@network_api_bp.route('/refresh', methods=['POST'])
@login_required
def refresh_network():
    """Force a network scan refresh."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="network")
        if blocked:
            return blocked
        logger.info("Forcing network scan refresh")
        network_event_log.record("Escaneo manual solicitado")

        def scan_and_return():
            network_scanner.scan_network(force=True)

        thread = threading.Thread(target=scan_and_return, daemon=True)
        thread.start()

        return jsonify({
            "status": "scanning",
            "message": "Escaneo de red iniciado",
        })

    except Exception as e:
        logger.error(f"Error in network refresh API: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Error initiating network scan"}), 500


@network_api_bp.route('/scan', methods=['POST'])
@login_required
def scan_network():
    """Encola escaneo de red en background — nunca bloquea HTTP."""
    try:
        force = request.json.get('force', False) if request.is_json else False

        def _bg_scan():
            try:
                from services.network_scan_coordinator import schedule_network_discovery

                schedule_network_discovery(consumer="api_scan_post", force=bool(force))
            except Exception as exc:
                logger.warning("background scan POST /scan: %s", exc)

        threading.Thread(target=_bg_scan, daemon=True, name="NetworkScanPost").start()
        from services.network_snapshot_service import read_nodes_api

        return jsonify(read_nodes_api(trigger_discovery=False))

    except Exception as e:
        logger.error(f"Error in network scan API: {e}", exc_info=True)
        return jsonify({"status": "error", "nodes": [], "message": "Error performing network scan"}), 500


@network_api_bp.route('/monitor/status', methods=['GET'])
@login_required
def get_network_monitor_status():
    """Estado del Network Monitor Engine en tiempo real."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="network")
        if blocked:
            return blocked
        from services.network_monitor_engine import get_monitor_status
        return jsonify({"status": "success", "monitor": get_monitor_status()}), 200
    except Exception as e:
        logger.error(f"Network monitor status error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@network_api_bp.route('/topology', methods=['GET'])
@login_required
def get_network_topology():
    """Topología profesional — nodos, categorías y conexiones reales."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="topology")
        if blocked:
            return blocked
        force = request.args.get('force', 'false').lower() == 'true'
        if force:
            from services.network_scan_coordinator import schedule_network_discovery
            from services.network_snapshot_service import read_topology_api

            schedule_network_discovery(consumer="api_topology_force", force=True)
            return jsonify(read_topology_api(trigger_discovery=False))
        from services.network_snapshot_service import read_topology_api
        return jsonify(read_topology_api(trigger_discovery=True))
    except Exception as e:
        logger.error(f"Error in network topology API: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@network_api_bp.route('/topology/device/<path:ip>', methods=['GET'])
@login_required
def get_topology_device(ip):
    """Panel lateral de dispositivo en Topology."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="topology")
        if blocked:
            return blocked
        from services.topology_service import get_topology_device
        result = get_topology_device(ip)
        if result.get("status") == "not_found":
            return jsonify(result), 404
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in topology device API: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@network_api_bp.route('/ndr', methods=['GET'])
@login_required
def get_network_ndr():
    """Radar NDR — payload completo con inventario, alertas y telemetría real."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="ndr")
        if blocked:
            return blocked
        force = request.args.get('force', 'false').lower() == 'true'
        if force:
            from services.network_scan_coordinator import schedule_network_discovery
            from services.network_snapshot_service import read_ndr_api

            schedule_network_discovery(consumer="api_ndr_force", force=True)
            return jsonify(read_ndr_api(trigger_discovery=False))
        from services.network_snapshot_service import read_ndr_api
        return jsonify(read_ndr_api(trigger_discovery=True))
    except Exception as e:
        logger.error(f"Error in network NDR API: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@network_api_bp.route('/ndr/device/<path:ip>', methods=['GET'])
@login_required
def get_network_ndr_device(ip):
    """Detalle de dispositivo para panel NDR."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="ndr")
        if blocked:
            return blocked
        from services.network_ndr_service import get_device_detail
        result = get_device_detail(ip)
        if result.get("status") == "not_found":
            return jsonify(result), 404
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in network NDR device API: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@network_api_bp.route('/ndr/device/<path:ip>/investigate', methods=['POST'])
@login_required
@api_hardened(sensitive=True, action_name="ndr_investigate")
def investigate_network_ndr_device(ip):
    """Re-análisis de dispositivo desconocido con motores NDR."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="ndr")
        if blocked:
            return blocked
        safe_ip = sanitize_ip_param(ip)
        if not safe_ip:
            return jsonify({"status": "error", "message": "IP inválida"}), 400
        from services.network_ndr_service import investigate_device
        result = investigate_device(safe_ip)
        if result.get("status") == "not_found":
            return jsonify(result), 404
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error investigating NDR device: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@network_api_bp.route('/cache/clear', methods=['POST'])
@login_required
def clear_network_cache():
    """Clear network scan cache."""
    try:
        network_scanner.clear_cache()
        network_event_log.record("Caché de red limpiada")
        return jsonify({"status": "success", "message": "Network cache cleared"})
    except Exception as e:
        logger.error(f"Error clearing network cache: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Error clearing cache"}), 500


@network_api_bp.route('/assets/inventory', methods=['GET'])
@login_required
def get_asset_inventory():
    """Inventario AIE — activos descubiertos con clasificación y trust score."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="network")
        if blocked:
            return blocked
        from services.asset_intelligence_engine import list_inventory, get_inventory_summary
        limit = min(request.args.get("limit", 200, type=int), 500)
        status_filter = request.args.get("status")
        items = list_inventory(limit=limit)
        if status_filter:
            items = [i for i in items if i.get("asset_status") == status_filter]
        return jsonify({
            "status": "success",
            "count": len(items),
            "summary": get_inventory_summary(),
            "assets": items,
            "source": "asset_intelligence_engine",
        })
    except Exception as e:
        logger.error("AIE inventory API: %s", e, exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@network_api_bp.route('/assets/<path:mac>/action', methods=['POST'])
@login_required
@api_hardened(sensitive=True, action_name="aie_admin_action")
def asset_admin_action(mac):
    """Acción administrativa sobre un activo (aprobar, rechazar, bloquear, etc.)."""
    try:
        from flask_login import current_user
        from services.asset_intelligence_engine import apply_admin_action

        data = request.get_json(silent=True) or {}
        action = data.get("action") or request.form.get("action")
        notes = data.get("notes")
        user_email = getattr(current_user, "email", None) if current_user.is_authenticated else None
        result = apply_admin_action(mac, action, user_email=user_email, notes=notes)
        code = 200 if result.get("status") == "success" else (404 if result.get("status") == "not_found" else 400)
        return jsonify(result), code
    except Exception as e:
        logger.error("AIE admin action: %s", e, exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500
