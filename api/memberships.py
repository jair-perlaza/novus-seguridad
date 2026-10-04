"""
API de membresías NOVUS — catálogo verificable (requiere sesión).
"""
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from services.membership_catalog_service import (
    build_plan_payload,
    compare_plans,
    explain_plan_for_kernel,
    get_catalog_payload,
)
from utils.logger import logger

memberships_api_bp = Blueprint("memberships_api", __name__, url_prefix="/api/memberships")


@memberships_api_bp.route("/catalog", methods=["GET"])
@login_required
def api_memberships_catalog():
    try:
        return jsonify(get_catalog_payload()), 200
    except Exception as exc:
        logger.error("memberships catalog: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@memberships_api_bp.route("/compare", methods=["GET"])
@login_required
def api_memberships_compare():
    try:
        return jsonify({"status": "success", "rows": compare_plans()}), 200
    except Exception as exc:
        logger.error("memberships compare: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@memberships_api_bp.route("/plan/<plan_id>", methods=["GET"])
@login_required
def api_memberships_plan(plan_id):
    try:
        payload = build_plan_payload(plan_id)
        if not payload:
            return jsonify({"status": "error", "message": "Plan no encontrado"}), 404
        return jsonify({"status": "success", "plan": payload}), 200
    except Exception as exc:
        logger.error("memberships plan: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@memberships_api_bp.route("/kernel-explain", methods=["GET", "POST"])
@login_required
def api_memberships_kernel_explain():
    """Explicación verificable del plan; opcionalmente ejecuta Kernel IA."""
    try:
        payload = request.get_json(silent=True) or {}
        plan_id = request.args.get("plan") or payload.get("plan") or "essential"
        question = request.args.get("q") or payload.get("question") or ""

        explanation = explain_plan_for_kernel(plan_id, question)

        if request.method == "POST" and (payload.get("execute") or request.args.get("execute") == "1"):
            from services.ai_kernel import ai_kernel
            from api.ai import _session_id
            from services.membership_catalog_service import build_kernel_consult_prompt

            prompt = build_kernel_consult_prompt(plan_id)
            if question.strip():
                prompt += f"\n\nPregunta del operador: {question.strip()}"
            chat = ai_kernel.process_message(
                _session_id(),
                prompt,
                user_email=getattr(current_user, "email", None),
                user_id=getattr(current_user, "id", None),
            )
            return jsonify({"status": "success", **explanation, **chat}), 200

        return jsonify(explanation), 200
    except Exception as exc:
        logger.error("memberships kernel explain: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500
