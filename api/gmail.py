"""
Gmail OAuth 2.0 and email security API for NOVUS Kernel IA.
"""
from flask import Blueprint, jsonify, request, redirect, url_for
from flask_login import login_required, current_user

from services.gmail_oauth_service import (
    start_oauth, complete_oauth, disconnect,
    get_connection_status, get_setup_instructions, is_oauth_configured,
)
from services.gmail_analyzer_service import (
    sync_new_messages, get_history, get_stats, execute_action,
)
from utils.logger import logger

gmail_api_bp = Blueprint("gmail_api", __name__, url_prefix="/api/gmail")


def _uid():
    return getattr(current_user, "id", None)


@gmail_api_bp.route("/setup", methods=["GET"])
@login_required
def api_gmail_setup():
    return jsonify({"status": "success", **get_setup_instructions()})


@gmail_api_bp.route("/status", methods=["GET"])
@login_required
def api_gmail_status():
    stats = get_stats(_uid())
    conn = get_connection_status(_uid())
    return jsonify({"status": "success", "connection": conn, "stats": stats})


@gmail_api_bp.route("/oauth/start", methods=["GET"])
@login_required
def api_gmail_oauth_start():
    if not is_oauth_configured():
        return jsonify({
            "status": "error",
            "message": "OAuth no configurado. Defina GOOGLE_CLIENT_ID y GOOGLE_CLIENT_SECRET.",
            "setup": get_setup_instructions(),
        }), 503

    url, err = start_oauth(_uid())
    if err:
        return jsonify({"status": "error", "message": err}), 400
    return redirect(url)


@gmail_api_bp.route("/oauth/callback", methods=["GET"])
@login_required
def api_gmail_oauth_callback():
    ok, msg = complete_oauth(_uid(), request.url)
    if ok:
        sync_new_messages(_uid())
        return redirect(url_for("dashboard.dashboard_principal") + "?gmail=connected")
    return jsonify({"status": "error", "message": msg}), 400


@gmail_api_bp.route("/disconnect", methods=["POST"])
@login_required
def api_gmail_disconnect():
    disconnect(_uid())
    return jsonify({"status": "success", "message": "Gmail desconectado."})


@gmail_api_bp.route("/sync", methods=["POST"])
@login_required
def api_gmail_sync():
    result = sync_new_messages(_uid())
    return jsonify(result)


@gmail_api_bp.route("/history", methods=["GET"])
@login_required
def api_gmail_history():
    limit = min(int(request.args.get("limit", 30)), 100)
    records = get_history(_uid(), limit)
    return jsonify({"status": "success", "records": records})


@gmail_api_bp.route("/action", methods=["POST"])
@login_required
def api_gmail_action():
    payload = request.get_json(silent=True) or {}
    action_id = payload.get("action")
    message_id = payload.get("message_id")
    confirmed = payload.get("confirmed") is True

    if not action_id or not message_id:
        return jsonify({"status": "error", "message": "action y message_id requeridos"}), 400

    result = execute_action(_uid(), action_id, message_id, confirmed=confirmed)
    return jsonify(result)
