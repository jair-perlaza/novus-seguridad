#!/usr/bin/env python3
"""API Health Monitoring & Self-Healing Engine."""
from __future__ import annotations

from flask import Blueprint, jsonify, request, session

health_api_bp = Blueprint("health_api", __name__, url_prefix="/api/health")


def _require_login() -> bool:
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


@health_api_bp.route("/status", methods=["GET"])
def health_status():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.health_engine.engine import get_health_status_response

    # GET = solo lectura de snapshot persistido; refresh pesado vía POST /api/health/cycle.
    payload = get_health_status_response(trigger_refresh=False)
    return jsonify({"ok": True, "engine": payload, "orchestrator": payload.get("orchestrator")})


@health_api_bp.route("/dashboard", methods=["GET"])
def health_dashboard():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.health_engine import get_health_dashboard
    from services.enterprise_snapshot_service import read_dashboard_api
    from services.lazy_engine_manager import start_if_needed

    start_if_needed("health_engine")
    dashboard = read_dashboard_api(
        "health",
        get_health_dashboard,
        source="services.health_engine.get_health_dashboard",
        stale_sec=60.0,
    )
    return jsonify({"ok": True, "dashboard": dashboard})


@health_api_bp.route("/cycle", methods=["POST"])
def health_cycle():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    body = request.get_json(silent=True) or {}
    publish = body.get("publish", True)
    self_heal = body.get("self_heal", True)
    from services.health_engine import run_health_cycle

    result = run_health_cycle(publish=bool(publish), self_heal=bool(self_heal), persist=True)
    from services.performance_cache import invalidate
    invalidate("health_status_api")
    slim = {
        "ok": result.get("ok"),
        "cycle_id": result.get("cycle_id"),
        "timestamp_utc": result.get("timestamp_utc"),
        "duration_ms": result.get("duration_ms"),
        "summary": result.get("summary"),
        "host": result.get("host"),
        "components": result.get("components"),
        "issues": result.get("issues"),
        "alerts": result.get("alerts"),
        "self_heal": result.get("self_heal"),
        "published": result.get("published"),
        "fault_inject_active": result.get("fault_inject_active"),
        "fake_telemetry": False,
        "invented_alerts": False,
        "error": result.get("error"),
    }
    return jsonify(slim)


@health_api_bp.route("/history", methods=["GET"])
def health_history():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    limit = int(request.args.get("limit") or 100)
    from services.health_engine.store import HISTORY_PATH, read_jsonl_tail

    return jsonify({"ok": True, "history": read_jsonl_tail(HISTORY_PATH, limit=limit)})


@health_api_bp.route("/alerts", methods=["GET"])
def health_alerts():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    limit = int(request.args.get("limit") or 100)
    from services.health_engine.store import ALERTS_PATH, read_jsonl_tail

    return jsonify({"ok": True, "alerts": read_jsonl_tail(ALERTS_PATH, limit=limit)})


@health_api_bp.route("/kernel", methods=["GET", "POST"])
def health_kernel():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.health_engine.kernel_insights import answer_kernel_query, build_kernel_health_context

    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        q = str(body.get("question") or "")
        return jsonify({"ok": True, "answer": answer_kernel_query(q), "context": build_kernel_health_context()})
    return jsonify({"ok": True, "context": build_kernel_health_context()})
