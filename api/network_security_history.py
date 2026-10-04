"""API — Historial de seguridad de la red."""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import login_required

from utils.logger import logger

network_history_api_bp = Blueprint("network_history_api", __name__, url_prefix="/api/network-security-history")


@network_history_api_bp.route("/summary", methods=["GET"])
@login_required
def api_summary():
    try:
        from services.performance_cache import get_or_compute
        from core.config import Config
        from services.network_security_history_service import get_network_history_summary

        ttl = float(getattr(Config, "PANEL_CACHE_TTL", 45) or 45)

        def _build():
            return get_network_history_summary()

        payload = get_or_compute("network_history_summary_api", ttl, _build)
        return jsonify({"status": "success", **payload}), 200
    except Exception as exc:
        logger.error("network history summary: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "No se pudo cargar el historial"}), 500


@network_history_api_bp.route("/events", methods=["GET"])
@login_required
def api_events():
    try:
        from services.network_security_history_service import list_network_security_events

        limit = min(int(request.args.get("limit", 100)), 300)
        et = (request.args.get("type") or "").strip() or None
        events = list_network_security_events(limit=limit, event_type=et)
        return jsonify({"status": "success", "events": events, "count": len(events)}), 200
    except Exception as exc:
        logger.error("network history events: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "Error al listar eventos"}), 500


@network_history_api_bp.route("/profile", methods=["GET"])
@login_required
def api_profile():
    try:
        from services.network_security_history_service import get_network_profile

        return jsonify({"status": "success", **get_network_profile()}), 200
    except Exception as exc:
        logger.error("network history profile: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "No se pudo cargar el perfil de red"}), 500


@network_history_api_bp.route("/sessions", methods=["GET"])
@login_required
def api_sessions():
    try:
        from services.network_security_history_service import list_analysis_sessions

        limit = min(int(request.args.get("limit", 50)), 100)
        sessions = list_analysis_sessions(limit=limit)
        return jsonify({"status": "success", "sessions": sessions, "count": len(sessions)}), 200
    except Exception as exc:
        logger.error("network history sessions: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "Error al listar sesiones de análisis"}), 500


@network_history_api_bp.route("/kernel-insights", methods=["GET"])
@login_required
def api_kernel_insights():
    try:
        from services.network_security_history_service import build_kernel_network_insights

        return jsonify({"status": "success", **build_kernel_network_insights()}), 200
    except Exception as exc:
        logger.error("network history kernel insights: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "No se pudieron calcular conclusiones"}), 500
