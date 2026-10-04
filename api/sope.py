#!/usr/bin/env python3
"""API — NOVUS Security Orchestration & Playbook Engine (SOPE)."""
from __future__ import annotations

from flask import Blueprint, jsonify, request, session

sope_api_bp = Blueprint("sope_api", __name__, url_prefix="/api/sope")


def _auth():
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


@sope_api_bp.route("/dashboard", methods=["GET"])
def sope_dashboard():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from core.config import Config
    from services.enterprise_snapshot_service import read_dashboard_api
    from services.sope import get_dashboard

    dashboard = read_dashboard_api(
        "sope",
        get_dashboard,
        source="services.sope.get_dashboard",
        stale_sec=float(Config.SOPE_DASHBOARD_SNAPSHOT_STALE_SEC),
    )
    return jsonify({"ok": True, "dashboard": dashboard})


@sope_api_bp.route("/stats", methods=["GET"])
def sope_stats():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sope import stats
    return jsonify({"ok": True, "stats": stats()})


@sope_api_bp.route("/orchestrate", methods=["POST"])
def sope_orchestrate():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sope import orchestrate
    data = request.get_json(silent=True) or {}
    threat_type = data.get("threat_type", "critical_threat")
    threat_context = data.get("context", {})
    user_email = session.get("email") or session.get("user_email")
    override_level = data.get("automation_level")
    if override_level is not None:
        override_level = int(override_level)
    from services.enterprise_snapshot_service import invalidate_module

    result = orchestrate(threat_type, threat_context, user_email, override_level)
    invalidate_module("sope")
    return jsonify({"ok": True, "result": result})


@sope_api_bp.route("/playbooks", methods=["GET"])
def sope_playbooks():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sope import PLAYBOOKS, PLAYBOOK_IDS
    return jsonify({"ok": True, "playbooks": PLAYBOOKS, "ids": PLAYBOOK_IDS})


@sope_api_bp.route("/playbook/<playbook_id>", methods=["GET"])
def sope_playbook(playbook_id):
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sope import get_playbook
    pb = get_playbook(playbook_id)
    if not pb:
        return jsonify({"ok": False, "error": "playbook not found"}), 404
    return jsonify({"ok": True, "playbook": pb})


@sope_api_bp.route("/level", methods=["GET"])
def sope_get_level():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sope import get_automation_level
    return jsonify({"ok": True, **get_automation_level()})


@sope_api_bp.route("/level", methods=["POST"])
def sope_set_level():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sope import set_automation_level
    data = request.get_json(silent=True) or {}
    level = int(data.get("level", 1))
    return jsonify(set_automation_level(level))


@sope_api_bp.route("/history", methods=["GET"])
def sope_history():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sope.store import load_decisions, load_executions, load_forensic, load_approvals
    limit = int(request.args.get("limit", 100))
    return jsonify({
        "ok": True,
        "decisions": load_decisions(limit),
        "executions": load_executions(limit),
        "forensic": load_forensic(limit),
        "approvals": load_approvals(limit),
    })
