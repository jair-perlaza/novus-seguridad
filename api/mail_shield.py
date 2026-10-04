"""API NOVUS Mail Shield — OAuth oficial, métricas reales."""
from __future__ import annotations

from datetime import datetime

from flask import Blueprint, jsonify, redirect, request, url_for
from flask_login import login_required, current_user

from services.tenant_api_gate import check_tenant_monitoring_or_response
from utils.logger import logger

mail_shield_api_bp = Blueprint("mail_shield_api", __name__, url_prefix="/api/mail-shield")


def _uid():
    return getattr(current_user, "id", None)


@mail_shield_api_bp.route("/status", methods=["GET"])
@login_required
def mail_shield_status():
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked
        from services.mail_shield_engine import get_engine_status
        return jsonify({"status": "ok", **get_engine_status(_uid())}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@mail_shield_api_bp.route("/events", methods=["GET"])
@login_required
def mail_shield_events():
    _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
    if blocked:
        return blocked
    from services.mail_shield_service import list_events
    limit = min(int(request.args.get("limit", 50)), 200)
    provider = request.args.get("provider")
    return jsonify({"status": "ok", "events": list_events(limit=limit, provider=provider)})


@mail_shield_api_bp.route("/quarantine", methods=["GET"])
@login_required
def mail_shield_quarantine():
    _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
    if blocked:
        return blocked
    from services.mail_shield_service import list_quarantine
    return jsonify({"status": "ok", "items": list_quarantine(limit=50)})


@mail_shield_api_bp.route("/integrations", methods=["GET"])
@login_required
def mail_shield_integrations():
    from services.mail_shield_service import get_integration_status
    return jsonify({"status": "ok", **get_integration_status(_uid())})


@mail_shield_api_bp.route("/sync", methods=["POST"])
@login_required
def mail_shield_sync():
    _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
    if blocked:
        return blocked
    from services.mail_shield_engine import sync_now
    return jsonify(sync_now(_uid()))


@mail_shield_api_bp.route("/report", methods=["GET"])
@login_required
def mail_shield_report():
    from services.mail_shield_service import executive_report
    return jsonify(executive_report())


@mail_shield_api_bp.route("/config", methods=["GET", "POST"])
@login_required
def mail_shield_config_route():
    from services.rbac_service import ROLE_COMPANY_ADMIN, ROLE_SUPER_ADMIN, get_user_role
    if get_user_role(current_user) not in (ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN):
        return jsonify({"status": "forbidden"}), 403
    from services.mail_shield_config import load_mail_shield_config, save_mail_shield_config
    if request.method == "GET":
        return jsonify({"status": "ok", "config": load_mail_shield_config()})
    data = request.get_json(silent=True) or {}
    return jsonify({"status": "ok", "config": save_mail_shield_config(data)})


@mail_shield_api_bp.route("/google/oauth/start", methods=["GET"])
@login_required
def mail_shield_google_oauth_start():
    from services.gmail_oauth_service import start_oauth, is_oauth_configured, get_setup_instructions
    if not is_oauth_configured():
        return jsonify({"status": "error", "message": "Integración no configurada", "setup": get_setup_instructions()}), 503
    url, err = start_oauth(_uid())
    if err:
        return jsonify({"status": "error", "message": err}), 400
    return redirect(url)


@mail_shield_api_bp.route("/m365/oauth/start", methods=["GET"])
@login_required
def mail_shield_m365_oauth_start():
    from services.microsoft365_oauth_service import start_oauth, get_setup_instructions, is_oauth_configured
    if not is_oauth_configured():
        return jsonify({"status": "error", "message": "Integración no configurada", "setup": get_setup_instructions()}), 503
    url, err = start_oauth(_uid())
    if err:
        return jsonify({"status": "error", "message": err}), 400
    return redirect(url)


@mail_shield_api_bp.route("/m365/oauth/callback", methods=["GET"])
@login_required
def mail_shield_m365_oauth_callback():
    code = request.args.get("code")
    if not code:
        return jsonify({"status": "error", "message": "code OAuth ausente"}), 400
    from services.microsoft365_oauth_service import complete_oauth
    ok, msg = complete_oauth(_uid(), code)
    if ok:
        return redirect(url_for("main.ruta_mail_shield") + "?m365=connected")
    return jsonify({"status": "error", "message": msg}), 400


@mail_shield_api_bp.route("/kernel-explain/<int:event_id>", methods=["GET"])
@login_required
def mail_shield_kernel_explain(event_id: int):
    from services.mail_shield_service import explain_for_kernel
    payload = explain_for_kernel(event_id)
    if not payload:
        return jsonify({"status": "not_found"}), 404
    return jsonify({"status": "ok", "explanation": payload})


@mail_shield_api_bp.route("/architecture", methods=["GET"])
@login_required
def mail_shield_architecture():
    from services.shield_platform_registry import list_shields
    return jsonify({"status": "ok", "shields": list_shields()})
