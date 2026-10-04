"""API NOVUS Web Shield — telemetría y políticas reales."""
from __future__ import annotations

from datetime import datetime

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from services.tenant_api_gate import check_tenant_monitoring_or_response
from utils.logger import logger

web_shield_api_bp = Blueprint("web_shield_api", __name__, url_prefix="/api/web-shield")


@web_shield_api_bp.route("/status", methods=["GET"])
@login_required
def web_shield_status():
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked
        from services.web_shield_engine import get_engine_status
        return jsonify({"status": "ok", **get_engine_status()}), 200
    except Exception as exc:
        logger.error("web_shield status: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@web_shield_api_bp.route("/events", methods=["GET"])
@login_required
def web_shield_events():
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked
        from services.web_shield_service import list_events

        limit = min(int(request.args.get("limit", 50)), 200)
        event_type = request.args.get("type")
        return jsonify({
            "status": "ok",
            "events": list_events(limit=limit, event_type=event_type),
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@web_shield_api_bp.route("/analyze-url", methods=["POST"])
@login_required
def web_shield_analyze_url():
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify({"status": "error", "message": "url requerida"}), 400
        from services.web_security_auth_enterprise.ssrf_guard import is_url_safe

        safe, reason = is_url_safe(url)
        if not safe:
            return jsonify({
                "status": "error",
                "message": "URL no permitida (SSRF guard)",
                "code": "SSRF_BLOCKED",
                "reason": reason,
            }), 400
        from services.web_shield_engine import analyze_and_policy_url

        result = analyze_and_policy_url(url, source="api")
        return jsonify({"status": "ok", **result}), 200
    except Exception as exc:
        logger.error("analyze-url: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "Error al analizar URL"}), 500


@web_shield_api_bp.route("/browser-report", methods=["POST"])
@login_required
def web_shield_browser_report():
    """Extensión de navegador NOVUS (integración pendiente de instalación en cliente)."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked
        data = request.get_json(silent=True) or {}
        from services.web_shield_engine import ingest_browser_report

        return jsonify(ingest_browser_report(data)), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@web_shield_api_bp.route("/config", methods=["GET", "POST"])
@login_required
def web_shield_config_route():
    try:
        from services.rbac_service import get_user_role, ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN

        role = get_user_role(current_user)
        if role not in (ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN):
            return jsonify({"status": "forbidden", "message": "Solo administradores"}), 403

        from services.web_shield_config import load_web_shield_config, save_web_shield_config

        if request.method == "GET":
            return jsonify({"status": "ok", "config": load_web_shield_config()}), 200
        data = request.get_json(silent=True) or {}
        saved = save_web_shield_config(data)
        return jsonify({"status": "ok", "config": saved}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@web_shield_api_bp.route("/host-audit", methods=["GET"])
@login_required
def web_shield_host_audit():
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked
        from services.web_shield_host_audit import full_host_audit

        return jsonify({"status": "ok", "audit": full_host_audit()}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@web_shield_api_bp.route("/kernel-explain/<int:event_id>", methods=["GET"])
@login_required
def web_shield_kernel_explain(event_id: int):
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked
        from services.web_shield_service import explain_incident_for_kernel

        payload = explain_incident_for_kernel(event_id)
        if not payload:
            return jsonify({"status": "not_found"}), 404
        return jsonify({"status": "ok", "explanation": payload}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500
