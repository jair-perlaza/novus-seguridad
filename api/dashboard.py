"""
Dashboard API endpoints for NOVUS
Real-time dashboard data APIs
"""
from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from services.system_monitor import system_monitor
from services.network_scanner import network_scanner
from services.novus_security_integration import novus_security
from services.dashboard_priority_service import get_current_priority
from services.tenant_api_gate import check_tenant_monitoring_or_response
from utils.logger import logger


dashboard_api_bp = Blueprint('dashboard_api', __name__, url_prefix='/api/dashboard')


def _live_metric(value, decimals=1):
    if value is None:
        return "Sin datos disponibles"
    try:
        return round(float(value), decimals)
    except (TypeError, ValueError):
        return "Sin datos disponibles"


def _count_detected_threats():
    """Count threats from the last background scan (no synchronous full scan)."""
    try:
        return novus_security.get_cached_threat_count()
    except Exception as e:
        logger.error(f"Error counting detected threats: {e}")
        return None


@dashboard_api_bp.route('/live', methods=['GET'])
@login_required
def dashboard_live():
    """
    Real-time dashboard metrics API
    Returns current system status
    """
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked

        from services.dashboard_live_service import get_dashboard_live_payload
        from services.http_endpoint_cache import get_or_build
        from services.tenant_scope_service import resolve_tenant_id

        tenant_id = resolve_tenant_id(current_user)
        user_id = str(getattr(current_user, "id", "") or "")

        def _build():
            return get_dashboard_live_payload(tenant_id=getattr(current_user, "company_id", None))

        response = get_or_build(
            "/api/dashboard/live",
            _build,
            tenant_id=str(tenant_id) if tenant_id else None,
            user_id=user_id or None,
        )
        logger.debug("Dashboard live API: CPU=%s RAM=%s pending=%s", response.get("cpu"), response.get("ram"), response.get("counters_pending"))
        return jsonify(response)

    except Exception as e:
        logger.error(f"Error in dashboard live API: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Error retrieving dashboard data"
        }), 500


@dashboard_api_bp.route('/connections-detail', methods=['GET'])
@login_required
def dashboard_connections_detail():
    """Desglose verificable de conexiones del host NOVUS."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked
        from services.connections_metrics_service import analyze_host_connections

        payload = analyze_host_connections()
        from services.runtime_environment_service import get_telemetry_scope_payload
        return jsonify({
            "status": "success",
            "connections": payload,
            "telemetry_scope": get_telemetry_scope_payload(),
        }), 200
    except Exception as e:
        logger.error("connections-detail: %s", e, exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@dashboard_api_bp.route('/priority', methods=['GET'])
@login_required
def dashboard_priority():
    """Prioridad actual del dashboard — un solo hallazgo real de mayor riesgo."""
    try:
        email = getattr(current_user, "email", None)
        payload = get_current_priority(email)
        return jsonify(payload)
    except Exception as e:
        logger.error(f"Error in dashboard priority API: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Error al obtener prioridad actual",
        }), 500


@dashboard_api_bp.route('/metrics', methods=['GET'])
@login_required
def dashboard_metrics():
    """
    Detailed dashboard metrics API
    Returns comprehensive system metrics
    """
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked

        status = system_monitor.get_system_status()

        response = {
            "status": "success",
            "metrics": status
        }

        return jsonify(response)

    except Exception as e:
        logger.error(f"Error in dashboard metrics API: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Error retrieving metrics"
        }), 500
