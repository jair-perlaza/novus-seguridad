"""
AI Kernel chat API — extends existing AIKernel without replacing it.
"""
from flask import Blueprint, jsonify, request, session
from flask_login import login_required, current_user

from services.ai_kernel import ai_kernel
from utils.logger import logger
from services.api_security_service import api_hardened

ai_api_bp = Blueprint("ai_api", __name__, url_prefix="/api/ai")


def _session_id():
    if not session.get("ai_session_id"):
        import uuid
        session["ai_session_id"] = str(uuid.uuid4())
    return session["ai_session_id"]


@ai_api_bp.route("/status", methods=["GET"])
@login_required
def api_ai_status():
    try:
        return jsonify({"status": "success", **ai_kernel.get_status()})
    except Exception as exc:
        logger.error(f"AI status error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ai_api_bp.route("/context", methods=["GET"])
@login_required
def api_ai_context():
    try:
        from services.sector_profile_service import get_kernel_context_for_user
        ctx = ai_kernel.get_context(_session_id(), refresh=request.args.get("refresh") == "1")
        sector_ctx = get_kernel_context_for_user(getattr(current_user, "email", None))
        from services.ai_kernel_brain.kernel_prompt import get_kernel_brain
        brain = get_kernel_brain()
        return jsonify({
            "status": "success",
            "context": ctx,
            "sector": sector_ctx,
            "system_prompt": brain.get_system_prompt(),
            "greeting": brain.get_time_based_greeting(),
            "executes_actions_default": False,
        })
    except Exception as exc:
        logger.error(f"AI context error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ai_api_bp.route("/module-consult", methods=["GET", "POST"])
@login_required
def api_ai_module_consult():
    """Contexto + prompt automático para Consultar Kernel IA desde cualquier módulo."""
    try:
        from services.module_kernel_context import build_consult_prompt

        payload = request.get_json(silent=True) or {}
        module = request.args.get("module") or payload.get("module")
        extra = payload.get("extra") or {}
        if request.args.get("finding_id"):
            extra["finding_id"] = request.args.get("finding_id")
        if request.args.get("ip"):
            extra["ip"] = request.args.get("ip")
        if request.args.get("case_id"):
            extra["case_id"] = request.args.get("case_id")
        if request.args.get("incident_id"):
            extra["incident_id"] = request.args.get("incident_id")
        if request.args.get("report_id"):
            extra["report_id"] = request.args.get("report_id")
        if payload.get("extra"):
            extra.update(payload.get("extra") or {})

        email = getattr(current_user, "email", None)
        module_key = (module or "").replace("-", "_")
        if module_key == "casos_estudio":
            from services.rbac_service import check_module_access, record_access_denied
            ok, reason = check_module_access(current_user, "casos_estudio")
            if not ok:
                record_access_denied(current_user, module="casos_estudio", route=request.path, detail=reason)
                return jsonify({"status": "error", "message": reason, "code": "RBAC_FORBIDDEN"}), 403

        result = build_consult_prompt(module, email, extra)

        if request.method == "POST" and (payload.get("execute") or request.args.get("execute") == "1"):
            chat = ai_kernel.process_message(
                _session_id(),
                result["prompt"],
                user_email=email,
                user_id=getattr(current_user, "id", None),
            )
            return jsonify({"status": "success", **result, **chat})

        return jsonify({"status": "success", **result})
    except Exception as exc:
        logger.error(f"AI module consult error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ai_api_bp.route("/chat", methods=["POST"])
@login_required
@api_hardened(require_json=True, required_fields=["message"], action_name="ai_chat")
def api_ai_chat():
    try:
        payload = request.get_json(silent=True) or {}
        message = (payload.get("message") or "").strip()
        if not message:
            return jsonify({"status": "error", "message": "Mensaje vacío"}), 400

        result = ai_kernel.process_message(
            _session_id(),
            message,
            user_email=getattr(current_user, "email", None),
            user_id=getattr(current_user, "id", None),
            confirm_token=payload.get("confirm_token"),
        )
        return jsonify({"status": "success", **result})
    except Exception as exc:
        logger.error(f"AI chat error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ai_api_bp.route("/deep-scan/<scan_id>/status", methods=["GET"])
@login_required
def api_deep_scan_status(scan_id):
    try:
        from services.deep_scan_engine import deep_scan_engine
        status = deep_scan_engine.get_status(scan_id)
        if not status:
            return jsonify({"status": "error", "message": "Escaneo no encontrado"}), 404
        scan_state = status.pop("status", "unknown")
        return jsonify({"status": "success", "scan_state": scan_state, **status})
    except Exception as exc:
        logger.error(f"Deep scan status error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ai_api_bp.route("/deep-scan/<scan_id>/report", methods=["GET"])
@login_required
def api_deep_scan_report(scan_id):
    try:
        from services.deep_scan_engine import deep_scan_engine
        report = deep_scan_engine.get_report(scan_id)
        if not report:
            st = deep_scan_engine.get_status(scan_id)
            if st and st.get("status") == "running":
                return jsonify({"status": "pending", "message": "Escaneo en progreso"}), 202
            return jsonify({"status": "error", "message": "Informe no disponible"}), 404
        return jsonify({"status": "success", "report": report})
    except Exception as exc:
        logger.error(f"Deep scan report error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ai_api_bp.route("/operation/<operation_id>/status", methods=["GET"])
@login_required
def api_operation_status(operation_id):
    try:
        from services.kernel_coordinator import kernel_coordinator
        status = kernel_coordinator.get_status(operation_id)
        if not status:
            return jsonify({"status": "error", "message": "Operación no encontrada"}), 404
        op_state = status.pop("status", "unknown")
        return jsonify({"status": "success", "operation_status": op_state, **status})
    except Exception as exc:
        logger.error(f"Operation status error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ai_api_bp.route("/operation/<operation_id>/result", methods=["GET"])
@login_required
def api_operation_result(operation_id):
    try:
        from services.kernel_coordinator import kernel_coordinator
        result = kernel_coordinator.get_result(operation_id)
        if not result:
            st = kernel_coordinator.get_status(operation_id)
            if st and st.get("status") != "completed":
                return jsonify({"status": "pending", "message": "Operación en progreso", **st}), 202
            return jsonify({"status": "error", "message": "Resultado no disponible"}), 404
        return jsonify({"status": "success", **result})
    except Exception as exc:
        logger.error(f"Operation result error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ai_api_bp.route("/history", methods=["GET"])
@login_required
def api_ai_history():
    try:
        return jsonify({
            "status": "success",
            "history": ai_kernel.get_history(_session_id()),
        })
    except Exception as exc:
        logger.error(f"AI history error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ai_api_bp.route("/kernel/analyze-event", methods=["POST"])
@login_required
def api_ai_kernel_analyze_event():
    """Analiza evento real con taxonomía enterprise — sin mitigaciones simuladas como ejecutadas."""
    try:
        from services.enterprise_knowledge_bridge import analyze_event, get_knowledge_status

        payload = request.get_json(silent=True) or {}
        event = payload.get("event") or payload
        result = analyze_event(event)
        return jsonify({"status": "success", "analysis": result, "knowledge": get_knowledge_status()}), 200
    except Exception as exc:
        logger.error("AI kernel analyze-event error: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ai_api_bp.route("/kernel/knowledge-status", methods=["GET"])
@login_required
def api_ai_kernel_knowledge_status():
    try:
        from services.enterprise_knowledge_bridge import get_knowledge_status

        return jsonify({"status": "success", **get_knowledge_status()}), 200
    except Exception as exc:
        logger.error("AI knowledge status error: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@ai_api_bp.route("/kernel/process", methods=["POST"])
@login_required
@api_hardened(require_json=True, action_name="ai_kernel_process")
def api_ai_kernel_process():
    """Procesa ActionPayload o mensaje libre — esquema validado, motores canónicos."""
    try:
        from services.ai_kernel_core.action_payload import (
            execute_action_payload,
            infer_intent_from_text,
            validate_action_payload,
        )
        from services.ai_kernel_core.ws_kernel_bridge import process_kernel_ws_message

        payload = request.get_json(silent=True) or {}
        if payload.get("action_payload"):
            v = validate_action_payload(payload["action_payload"])
            if not v.get("valid"):
                return jsonify({
                    "status": "error",
                    "message": "ActionPayload inválido",
                    "errors": v.get("errors"),
                }), 400
            out = execute_action_payload(v["payload"], payload.get("context"))
            return jsonify({"status": "success", **out})

        result = process_kernel_ws_message(payload)
        return jsonify({"status": "success", **result})
    except Exception as exc:
        logger.error(f"AI kernel process error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500
