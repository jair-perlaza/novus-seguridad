"""
Playbooks REST API — CRUD and execution against real database.
"""
from flask import Blueprint, jsonify, request
from flask_login import login_required

from services import playbook_service
from utils.logger import logger
from services.api_security_service import api_hardened, sanitize_identifier

playbooks_api_bp = Blueprint("playbooks_api", __name__, url_prefix="/api/playbooks")


@playbooks_api_bp.route("", methods=["GET", "POST"])
@playbooks_api_bp.route("/", methods=["GET", "POST"])
@login_required
def api_playbooks_collection():
    if request.method == "GET":
        try:
            from flask_login import current_user
            from services.sector_shield_service import resolve_sector_for_user
            active_only = request.args.get("active") == "1"
            sector_key = resolve_sector_for_user(getattr(current_user, "email", None))
            items = playbook_service.list_playbooks(active_only=active_only, sector_key=sector_key)
            return jsonify({
                "status": "success",
                "playbooks": items,
                "count": len(items),
                "sector_key": sector_key,
            })
        except Exception as exc:
            logger.error(f"List playbooks error: {exc}", exc_info=True)
            return jsonify({"status": "error", "message": str(exc)}), 500
    try:
        data = request.get_json(silent=True) or {}
        if not data.get("nombre") or not data.get("trigger") or not data.get("accion"):
            return jsonify({"status": "error", "message": "nombre, trigger y accion son requeridos"}), 400
        item = playbook_service.create_playbook(data)
        return jsonify({"status": "success", "message": "Playbook creado", "playbook": item}), 201
    except Exception as exc:
        logger.error(f"Create playbook error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@playbooks_api_bp.route("/<playbook_id>", methods=["GET", "PUT", "DELETE"])
@login_required
def api_playbook_item(playbook_id):
    if request.method == "GET":
        item = playbook_service.get_playbook(playbook_id)
        if not item:
            return jsonify({"status": "error", "message": "Playbook no encontrado"}), 404
        return jsonify({"status": "success", "playbook": item})
    if request.method == "PUT":
        try:
            data = request.get_json(silent=True) or {}
            item = playbook_service.update_playbook(playbook_id, data)
            if not item:
                return jsonify({"status": "error", "message": "Playbook no encontrado"}), 404
            return jsonify({"status": "success", "message": "Playbook actualizado", "playbook": item})
        except Exception as exc:
            logger.error(f"Update playbook error: {exc}", exc_info=True)
            return jsonify({"status": "error", "message": str(exc)}), 500
    try:
        if not playbook_service.delete_playbook(playbook_id):
            return jsonify({"status": "error", "message": "Playbook no encontrado"}), 404
        return jsonify({"status": "success", "message": "Playbook eliminado"})
    except Exception as exc:
        logger.error(f"Delete playbook error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@playbooks_api_bp.route("/<playbook_id>/duplicate", methods=["POST"])
@login_required
def api_duplicate_playbook(playbook_id):
    try:
        item = playbook_service.duplicate_playbook(playbook_id)
        if not item:
            return jsonify({"status": "error", "message": "Playbook no encontrado"}), 404
        return jsonify({"status": "success", "message": "Playbook duplicado", "playbook": item})
    except Exception as exc:
        logger.error(f"Duplicate playbook error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@playbooks_api_bp.route("/<playbook_id>/toggle", methods=["POST"])
@login_required
def api_toggle_playbook(playbook_id):
    try:
        payload = request.get_json(silent=True) or {}
        item = playbook_service.toggle_playbook(playbook_id, payload.get("active"))
        if not item:
            return jsonify({"status": "error", "message": "Playbook no encontrado"}), 404
        return jsonify({"status": "success", "message": f"Estado: {item['estado']}", "playbook": item})
    except Exception as exc:
        logger.error(f"Toggle playbook error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@playbooks_api_bp.route("/<playbook_id>/execute", methods=["POST"])
@login_required
@api_hardened(sensitive=True, action_name="execute_playbook")
def api_execute_playbook(playbook_id):
    try:
        safe_id = sanitize_identifier(playbook_id)
        if not safe_id:
            return jsonify({"status": "error", "message": "ID de playbook inválido"}), 400
        from flask_login import current_user
        result = playbook_service.execute_playbook(
            safe_id, user_email=getattr(current_user, "email", None)
        )
        code = 200 if result.get("status") == "success" else 500
        return jsonify(result), code
    except Exception as exc:
        logger.error(f"Execute playbook error: {exc}", exc_info=True)
        from core.http_responses import api_error_response
        resp, code = api_error_response(exc, context="playbooks.execute")
        data = resp.get_json()
        data["steps"] = []
        return jsonify(data), code


@playbooks_api_bp.route("/defense-mechanisms", methods=["GET"])
@login_required
def api_playbooks_defense_mechanisms():
    """Catálogo del Centro de Defensa para procedimientos guiados en Playbooks."""
    try:
        from flask_login import current_user
        from services.defense_center_service import get_playbooks_defense_payload
        from services.rbac_service import can_access_module

        if not can_access_module(current_user, "centro_defensa") and not can_access_module(
            current_user, "manual_defense_center"
        ):
            return jsonify({"status": "error", "message": "Sin acceso al Centro de Defensa"}), 403
        uid = getattr(current_user, "id", None)
        return jsonify({"status": "success", **get_playbooks_defense_payload(uid)}), 200
    except Exception as exc:
        logger.error("playbooks defense-mechanisms: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@playbooks_api_bp.route("/executions", methods=["GET"])
@login_required
def api_list_executions():
    try:
        playbook_id = request.args.get("playbook_id")
        limit = min(int(request.args.get("limit", 50)), 200)
        items = playbook_service.list_executions(playbook_id=playbook_id, limit=limit)
        return jsonify({"status": "success", "executions": items, "count": len(items)})
    except Exception as exc:
        logger.error(f"List executions error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@playbooks_api_bp.route("/executions/<execution_id>", methods=["GET"])
@login_required
def api_get_execution(execution_id):
    item = playbook_service.get_execution(execution_id)
    if not item:
        return jsonify({"status": "error", "message": "Ejecución no encontrada"}), 404
    report = None
    if item.get("report_id"):
        from services.security_report_service import get_report
        report = get_report(item["report_id"])
    return jsonify({"status": "success", "execution": item, "report": report})
