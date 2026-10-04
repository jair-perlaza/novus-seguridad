"""API de Auditoría Integral de Seguridad NOVUS."""
from flask import Blueprint, jsonify, request, session
from flask_login import login_required, current_user

from services.data_audit_registry import get_audit_summary
from services.integral_security_audit_service import (
    run_quick_audit,
    start_deep_audit,
    get_deep_audit_status,
    build_deep_audit_report,
    get_integral_audit_summary,
)
from utils.logger import logger

audit_api_bp = Blueprint("audit_api", __name__, url_prefix="/api/audit")


@audit_api_bp.route("/data-sources", methods=["GET"])
@login_required
def api_audit_data_sources():
    """Compatibilidad — trazabilidad de fuentes de datos."""
    summary = get_audit_summary()
    summary["audit_display_name"] = "Auditoría Integral de Seguridad"
    summary["legacy_name"] = "Auditoría de Datos Reales"
    return jsonify({"status": "success", **summary})


@audit_api_bp.route("/integral/summary", methods=["GET"])
@login_required
def api_integral_summary():
    return jsonify({"status": "success", **get_integral_audit_summary()})


@audit_api_bp.route("/integral/run", methods=["POST"])
@login_required
def api_integral_run():
    """Ejecuta auditoría rápida (sync) o inicia profunda (async)."""
    try:
        payload = request.get_json(silent=True) or {}
        mode = (payload.get("mode") or request.args.get("mode") or "quick").lower()
        email = getattr(current_user, "email", None)
        if mode == "deep":
            sid = session.get("ai_session_id", "")
            uid = getattr(current_user, "id", None)
            result = start_deep_audit(email, session_id=sid, user_id=uid)
            return jsonify({"status": "success", **result})
        result = run_quick_audit(email)
        audit_state = result.pop("status", "completed")
        return jsonify({"status": "success", "audit_state": audit_state, **result})
    except Exception as exc:
        logger.error(f"Integral audit error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@audit_api_bp.route("/integral/deep/<scan_id>/status", methods=["GET"])
@login_required
def api_integral_deep_status(scan_id):
    st = get_deep_audit_status(scan_id)
    if not st:
        return jsonify({"status": "error", "message": "Escaneo no encontrado"}), 404
    return jsonify({"status": "success", **st})


@audit_api_bp.route("/integral/deep/<scan_id>/report", methods=["GET"])
@login_required
def api_integral_deep_report(scan_id):
    report = build_deep_audit_report(scan_id)
    if not report:
        return jsonify({"status": "error", "message": "Informe no disponible"}), 404
    if report.get("status") == "running":
        return jsonify({"status": "pending", **report}), 202
    return jsonify({"status": "success", **report})
