"""API — Captura forense PCAP (tráfico real, sin simulación)."""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from services.rbac_service import ROLE_COMPANY_ADMIN, ROLE_SUPER_ADMIN, SOC_ROLES, user_has_any_role

forensic_pcap_bp = Blueprint("forensic_pcap_api", __name__, url_prefix="/api/forensic-pcap")


def _allowed() -> bool:
    return user_has_any_role(current_user, SOC_ROLES + (ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN))


def _tenant_id() -> str | None:
    tid = getattr(current_user, "tenant_id", None)
    return str(tid) if tid is not None else None


@forensic_pcap_bp.route("/capability", methods=["GET"])
@login_required
def api_capability():
    if not _allowed():
        return jsonify({"status": "error", "message": "Acceso denegado"}), 403
    from services.forensic_pcap_capture_service import capture_capability, ensure_metadata_monitor

    ensure_metadata_monitor()
    return jsonify({"status": "success", **capture_capability()}), 200


@forensic_pcap_bp.route("/interfaces", methods=["GET"])
@login_required
def api_interfaces():
    if not _allowed():
        return jsonify({"status": "error", "message": "Acceso denegado"}), 403
    from services.forensic_pcap_capture_service import list_capture_interfaces

    return jsonify({"status": "success", "interfaces": list_capture_interfaces()}), 200


@forensic_pcap_bp.route("/start", methods=["POST"])
@login_required
def api_start():
    if not _allowed():
        return jsonify({"status": "error", "message": "Acceso denegado"}), 403
    body = request.get_json(silent=True) or {}
    from services.forensic_pcap_capture_service import ensure_metadata_monitor, start_capture

    ensure_metadata_monitor()
    result = start_capture(
        user_email=getattr(current_user, "email", None),
        tenant_id=_tenant_id(),
        equipment=getattr(current_user, "hostname", None),
        interface=body.get("interface"),
        duration_sec=float(body.get("duration_sec") or 30),
        max_mb=float(body.get("max_mb") or 25),
        incident_id=body.get("incident_id"),
        case_id=body.get("case_id"),
        trigger=body.get("trigger") or "manual_api",
    )
    code = 200 if result.get("status") == "started" else 400
    return jsonify({"status": "success" if code == 200 else "error", **result}), code


@forensic_pcap_bp.route("/stop", methods=["POST"])
@login_required
def api_stop():
    if not _allowed():
        return jsonify({"status": "error", "message": "Acceso denegado"}), 403
    body = request.get_json(silent=True) or {}
    cid = body.get("capture_id")
    if not cid:
        return jsonify({"status": "error", "message": "capture_id requerido"}), 400
    from services.forensic_pcap_capture_service import stop_capture

    return jsonify({"status": "success", **stop_capture(cid)}), 200


@forensic_pcap_bp.route("/status", methods=["GET"])
@login_required
def api_status():
    if not _allowed():
        return jsonify({"status": "error", "message": "Acceso denegado"}), 403
    from services.forensic_pcap_capture_service import get_capture_status

    cid = request.args.get("capture_id")
    return jsonify({"status": "success", **get_capture_status(cid)}), 200


@forensic_pcap_bp.route("/list", methods=["GET"])
@login_required
def api_list():
    if not _allowed():
        return jsonify({"status": "error", "message": "Acceso denegado"}), 403
    limit = min(int(request.args.get("limit", 30)), 200)
    from services.forensic_pcap_capture_service import list_captures

    return jsonify({"status": "success", "captures": list_captures(limit)}), 200
