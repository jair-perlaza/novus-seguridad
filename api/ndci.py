"""API NOVUS Digital Case Intelligence (NDCI)."""
from __future__ import annotations

import os

from flask import Blueprint, jsonify, request, send_file
from flask_login import current_user, login_required

from services.ndci_service import ndci_service
from utils.logger import logger
from utils.rbac import require_api_resource

ndci_api_bp = Blueprint("ndci_api", __name__, url_prefix="/api/ndci")


@ndci_api_bp.route("/cases", methods=["GET"])
@login_required
@require_api_resource("ndci")
def api_ndci_list():
    try:
        q = request.args.get("q")
        sector = request.args.get("sector")
        limit = min(int(request.args.get("limit", 50)), 200)
        cases = ndci_service.list_cases(limit=limit, sector=sector, q=q)
        return jsonify({"status": "success", "cases": cases, "total": len(cases)})
    except Exception as exc:
        logger.error("NDCI list: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ndci_api_bp.route("/cases/<case_id>", methods=["GET"])
@login_required
@require_api_resource("ndci")
def api_ndci_get(case_id):
    try:
        case = ndci_service.get_case(case_id)
        if not case:
            return jsonify({"status": "error", "message": "Caso no encontrado"}), 404
        return jsonify({"status": "success", "case": case})
    except Exception as exc:
        logger.error("NDCI get: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ndci_api_bp.route("/cases/create", methods=["POST"])
@login_required
@require_api_resource("ndci")
def api_ndci_create():
    try:
        payload = request.get_json(silent=True) or {}
        email = getattr(current_user, "email", None)
        case = ndci_service.create_from_scan(
            scan_id=payload.get("scan_id"),
            operation_id=payload.get("operation_id"),
            user_email=email,
            message=payload.get("message"),
        )
        return jsonify({
            "status": "success",
            "case": case,
            "message": f"Caso de estudio {case.get('id')} creado permanentemente.",
            "url": f"/casos-estudio?id={case.get('id')}",
        })
    except Exception as exc:
        logger.error("NDCI create: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ndci_api_bp.route("/cases/manual", methods=["POST"])
@login_required
@require_api_resource("ndci")
def api_ndci_create_manual():
    """Generación manual de caso de estudio con telemetría real."""
    try:
        payload = request.get_json(silent=True) or {}
        analysis_type = (payload.get("analysis_type") or "").strip()
        if not analysis_type:
            return jsonify({"status": "error", "message": "analysis_type requerido"}), 400
        email = getattr(current_user, "email", None)
        case = ndci_service.create_manual_case(
            analysis_type=analysis_type,
            user_email=email,
            device_ip=payload.get("device_ip"),
            vulnerability_id=payload.get("vulnerability_id"),
            incident_id=payload.get("incident_id"),
            compare_case_id=payload.get("compare_case_id"),
            custom_message=payload.get("custom_message"),
        )
        return jsonify({
            "status": "success",
            "case": case,
            "message": f"Caso manual {case.get('id')} generado y almacenado permanentemente.",
            "url": f"/casos-estudio?id={case.get('id')}",
        })
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        logger.error("NDCI manual create: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ndci_api_bp.route("/manual/options", methods=["GET"])
@login_required
@require_api_resource("ndci")
def api_ndci_manual_options():
    """Datos reales para el asistente de creación manual."""
    try:
        return jsonify({"status": "success", **ndci_service.get_manual_options()})
    except Exception as exc:
        logger.error("NDCI manual options: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ndci_api_bp.route("/cases/compare", methods=["GET"])
@login_required
@require_api_resource("ndci")
def api_ndci_compare():
    try:
        a = request.args.get("a")
        b = request.args.get("b")
        if not a or not b:
            return jsonify({"status": "error", "message": "Parámetros a y b requeridos"}), 400
        result = ndci_service.compare_cases(a, b)
        return jsonify({"status": "success", "comparison": result})
    except Exception as exc:
        logger.error("NDCI compare: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ndci_api_bp.route("/cases/<case_id>/pdf", methods=["GET"])
@login_required
@require_api_resource("ndci")
def api_ndci_pdf(case_id):
    try:
        case = ndci_service.get_case(case_id)
        if not case:
            return jsonify({"status": "error", "message": "Caso no encontrado"}), 404
        pdf_path = case.get("pdf_path")
        if not pdf_path or not os.path.isfile(pdf_path):
            from services.ndci_pdf import generate_ndci_pdf
            exp = case.get("expediente") or case
            pdf_path = generate_ndci_pdf(exp)
        return send_file(pdf_path, as_attachment=True, download_name=f"{case_id}.pdf")
    except Exception as exc:
        logger.error("NDCI pdf: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500
