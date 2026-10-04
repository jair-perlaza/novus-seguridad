"""API Endpoint Scan / Endpoint Shield — escaneo del host local."""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from services.api_security_service import api_hardened
from utils.logger import logger

endpoint_scan_api_bp = Blueprint("endpoint_scan_api", __name__, url_prefix="/api/endpoint-scan")


@endpoint_scan_api_bp.route("/engine/status", methods=["GET"])
@login_required
def api_endpoint_engine_status():
    try:
        from services.endpoint_scan_engine import endpoint_scan_engine

        return jsonify({"status": "success", **endpoint_scan_engine.engine_status()}), 200
    except Exception as exc:
        logger.error("endpoint engine status: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@endpoint_scan_api_bp.route("/start", methods=["POST"])
@login_required
@api_hardened(sensitive=True, action_name="endpoint_scan_start")
def api_endpoint_scan_start():
    try:
        from services.endpoint_scan_engine import endpoint_scan_engine

        payload = request.get_json(silent=True) or {}
        mode = (payload.get("mode") or "quick").strip().lower()
        paths = payload.get("paths") or payload.get("custom_paths")
        if paths and not isinstance(paths, list):
            paths = [str(paths)]
        uid = getattr(current_user, "id", None)
        result = endpoint_scan_engine.start_scan(
            mode=mode,
            custom_paths=paths,
            user_id=int(uid) if uid else None,
        )
        if result.get("status") == "error":
            return jsonify(result), 400
        return jsonify({"status": "success", **result}), 200
    except Exception as exc:
        logger.error("endpoint scan start: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@endpoint_scan_api_bp.route("/status/<scan_id>", methods=["GET"])
@login_required
def api_endpoint_scan_status(scan_id):
    try:
        from services.endpoint_scan_engine import endpoint_scan_engine

        st = endpoint_scan_engine.get_scan_status(scan_id)
        if not st:
            return jsonify({"status": "error", "message": "Escaneo no encontrado"}), 404
        return jsonify({"status": "success", "scan": st}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@endpoint_scan_api_bp.route("/report/<scan_id>", methods=["GET"])
@login_required
def api_endpoint_scan_report(scan_id):
    try:
        from services.endpoint_scan_engine import endpoint_scan_engine

        report = endpoint_scan_engine.get_scan_report(scan_id)
        if not report:
            return jsonify({"status": "error", "message": "Informe no disponible"}), 404
        return jsonify({"status": "success", "report": report}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@endpoint_scan_api_bp.route("/monitor/events", methods=["GET"])
@login_required
def api_endpoint_monitor_events():
    try:
        from services.endpoint_realtime_monitor import list_monitor_events

        limit = min(int(request.args.get("limit", 50)), 200)
        return jsonify({"status": "success", "events": list_monitor_events(limit=limit)}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@endpoint_scan_api_bp.route("/monitor/status", methods=["GET"])
@login_required
def api_endpoint_monitor_status():
    try:
        from services.lazy_engine_manager import start_if_needed, engine_status

        boot = start_if_needed("endpoint")
        monitor = engine_status("endpoint_realtime").get("live") or {}
        return jsonify({"status": "success", "monitor": monitor, "engine": boot}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@endpoint_scan_api_bp.route("/quarantine", methods=["POST"])
@login_required
@api_hardened(sensitive=True, action_name="endpoint_quarantine")
def api_endpoint_quarantine_action():
    try:
        from services.endpoint_quarantine_service import (
            delete_file_confirmed,
            ignore_finding,
            quarantine_file,
        )

        payload = request.get_json(silent=True) or {}
        action = (payload.get("action") or "").strip().lower()
        path = (payload.get("path") or payload.get("finding_ref") or "").strip()
        email = getattr(current_user, "email", None)
        if action == "ignore":
            result = ignore_finding(path, requested_by=email)
        elif action == "quarantine":
            result = quarantine_file(path, requested_by=email)
        elif action == "delete":
            result = delete_file_confirmed(path, requested_by=email, confirm=bool(payload.get("confirm")))
        else:
            return jsonify({"status": "error", "message": "Acción: ignore, quarantine o delete"}), 400
        code = 200 if result.get("status") == "success" else 400
        return jsonify(result), code
    except Exception as exc:
        logger.error("endpoint quarantine: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@endpoint_scan_api_bp.route("/quarantine/list", methods=["GET"])
@login_required
def api_endpoint_quarantine_list():
    try:
        from services.endpoint_quarantine_service import list_quarantine

        return jsonify({"status": "success", "items": list_quarantine()}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500
