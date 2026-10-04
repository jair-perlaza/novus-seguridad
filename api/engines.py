"""API — estado y lazy-start de motores P2."""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import login_required

from utils.logger import logger

engines_api_bp = Blueprint("engines_api", __name__, url_prefix="/api/engines")


@engines_api_bp.route("/status", methods=["GET"])
@login_required
def api_engines_status():
    try:
        from services.lazy_engine_manager import list_engine_statuses

        priority = request.args.get("priority")
        payload = list_engine_statuses(priority=priority or None)
        from services.resource_backpressure_service import get_status as bp_status

        payload["backpressure"] = bp_status()
        return jsonify({"ok": True, **payload}), 200
    except Exception as exc:
        logger.error("engines status: %s", exc, exc_info=True)
        return jsonify({"ok": False, "error": str(exc)[:200]}), 500


@engines_api_bp.route("/status/<engine_name>", methods=["GET"])
@login_required
def api_engine_status(engine_name: str):
    try:
        from services.lazy_engine_manager import engine_status

        return jsonify({"ok": True, **engine_status(engine_name)}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)[:200]}), 500


@engines_api_bp.route("/start/<engine_name>", methods=["POST"])
@login_required
def api_engine_start(engine_name: str):
    """Inicio bajo demanda — no bloquea HTTP (devuelve STARTING)."""
    try:
        from services.lazy_engine_manager import start_if_needed

        result = start_if_needed(engine_name)
        code = 202 if result.get("state") == "STARTING" else 200
        return jsonify({"ok": True, **result}), code
    except Exception as exc:
        logger.error("engine start %s: %s", engine_name, exc, exc_info=True)
        return jsonify({"ok": False, "error": str(exc)[:200]}), 500


@engines_api_bp.route("/stop/<engine_name>", methods=["POST"])
@login_required
def api_engine_stop(engine_name: str):
    try:
        from services.lazy_engine_manager import stop_engine

        result = stop_engine(engine_name)
        return jsonify({"ok": True, **result}), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)[:200]}), 500
