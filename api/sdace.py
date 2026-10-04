#!/usr/bin/env python3
"""API — Security Data Analytics & Correlation Engine (SDACE)."""
from __future__ import annotations
from flask import Blueprint, jsonify, request, session

sdace_api_bp = Blueprint("sdace_api", __name__, url_prefix="/api/sdace")


def _auth():
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


@sdace_api_bp.route("/analytics", methods=["GET"])
def sdace_analytics():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace import get_dashboard, analytics_summary
    from services.enterprise_snapshot_service import read_dashboard_api

    dashboard = read_dashboard_api("sdace", get_dashboard, source="services.sdace.get_dashboard", stale_sec=90.0)
    return jsonify({"ok": True, "dashboard": dashboard, "analytics": analytics_summary()})


@sdace_api_bp.route("/dashboard", methods=["GET"])
def sdace_dashboard():
    """Alias para auditoría / clientes que esperan /dashboard."""
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace import get_dashboard
    from services.enterprise_snapshot_service import read_dashboard_api
    dashboard = read_dashboard_api("sdace", get_dashboard, source="services.sdace.get_dashboard", stale_sec=90.0)
    return jsonify({"ok": True, "dashboard": dashboard})


@sdace_api_bp.route("/consult", methods=["GET", "POST"])
def sdace_consult():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace import consult
    data = request.get_json(silent=True) if request.method == "POST" else request.args.to_dict()
    data = data or {}
    topic = data.get("topic") or data.get("q") or "analytics"
    return jsonify({"ok": True, "result": consult(topic, **{k: v for k, v in data.items() if k not in ("topic", "q")})})


@sdace_api_bp.route("/search", methods=["GET", "POST"])
def sdace_search():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace.readers import sdl_search
    from services.sdace.store import log_query
    data = request.get_json(silent=True) if request.method == "POST" else request.args.to_dict()
    data = data or {}
    for k in ("days", "limit", "offset"):
        if k in data and data[k] not in (None, ""):
            try: data[k] = int(data[k])
            except Exception: pass
    allowed = {"q", "engine", "record_type", "asset", "user_ref", "ioc", "cve", "mitre",
               "malware", "ransomware", "apt", "incident_id", "playbook_id", "severity", "days", "limit", "offset"}
    filters = {k: data[k] for k in allowed if k in data and data[k] not in (None, "")}
    log_query({"action": "search", "filters": filters})
    return jsonify({"ok": True, "result": sdl_search(**filters)})


@sdace_api_bp.route("/timeline", methods=["GET"])
def sdace_timeline():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace import build_attack_timeline
    return jsonify({"ok": True, "timeline": build_attack_timeline(request.args.get("incident_id"))})


@sdace_api_bp.route("/graph", methods=["GET"])
def sdace_graph():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace import build_attack_graph
    return jsonify({"ok": True, "graph": build_attack_graph(request.args.get("incident_id"))})


@sdace_api_bp.route("/ioc", methods=["GET"])
def sdace_ioc():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace import ioc_correlate
    return jsonify({"ok": True, "ioc": ioc_correlate()})


@sdace_api_bp.route("/cve", methods=["GET"])
def sdace_cve():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace import cve_correlate
    return jsonify({"ok": True, "cve": cve_correlate()})


@sdace_api_bp.route("/attack-path", methods=["GET"])
def sdace_attack_path():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace import attack_path
    return jsonify({"ok": True, "attack_path": attack_path(request.args.get("incident_id"))})


@sdace_api_bp.route("/history", methods=["GET"])
def sdace_history():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace import historical_analysis
    return jsonify({"ok": True, "history": historical_analysis(request.args.get("incident_id"))})


@sdace_api_bp.route("/relations", methods=["GET"])
def sdace_relations():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace import relations
    return jsonify({"ok": True, "relations": relations(request.args.get("incident_id"))})


@sdace_api_bp.route("/kernel", methods=["GET", "POST"])
def sdace_kernel():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace import ask_kernel
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        q = data.get("question") or data.get("q") or ""
    else:
        q = request.args.get("q") or request.args.get("question") or ""
    return jsonify({"ok": True, "kernel": ask_kernel(q), "executes_actions": False})


@sdace_api_bp.route("/swarm-summary", methods=["GET"])
def sdace_swarm_summary():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdace import swarm_analytic_summary
    return jsonify({"ok": True, "summary": swarm_analytic_summary()})
