#!/usr/bin/env python3
"""API — Identity Attack Path Analysis (IAPA)."""
from __future__ import annotations
from flask import Blueprint, jsonify, request, session

iapa_api_bp = Blueprint("iapa_api", __name__, url_prefix="/api/iapa")

def _auth():
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


@iapa_api_bp.route("/dashboard", methods=["GET"])
def iapa_dashboard():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.iapa import get_dashboard
    from services.enterprise_snapshot_service import read_dashboard_api
    dashboard = read_dashboard_api("iapa", get_dashboard, source="services.iapa.get_dashboard", stale_sec=90.0)
    return jsonify({"ok": True, "dashboard": dashboard})


@iapa_api_bp.route("/graph", methods=["GET"])
def iapa_graph():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.iapa import build_attack_graph
    return jsonify({"ok": True, "graph": build_attack_graph(int(request.args.get("limit", 500)))})


@iapa_api_bp.route("/path", methods=["GET", "POST"])
def iapa_path():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.iapa import find_paths, compute_path_scores
    data = request.get_json(silent=True) if request.method == "POST" else request.args.to_dict()
    data = data or {}
    if str(data.get("scored", "")).lower() in ("1", "true", "yes"):
        return jsonify({"ok": True, "result": compute_path_scores(int(data.get("max_paths", 20)))})
    return jsonify({"ok": True, "result": find_paths(
        source_kind=data.get("source_kind"),
        max_depth=int(data.get("max_depth", 6)),
        max_paths=int(data.get("max_paths", 30)),
    )})


@iapa_api_bp.route("/assets", methods=["GET"])
def iapa_assets():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.iapa import build_attack_graph
    g = build_attack_graph()
    assets = [n for n in (g.get("nodes") or []) if n.get("kind") in ("activo", "equipo") or n.get("high_value")]
    return jsonify({"ok": True, "assets": assets, "high_value": [a for a in assets if a.get("high_value")], "invented": False})


@iapa_api_bp.route("/users", methods=["GET"])
def iapa_users():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.iapa import build_attack_graph, privilege_analysis
    g = build_attack_graph()
    users = [n for n in (g.get("nodes") or []) if n.get("kind") == "usuario"]
    return jsonify({"ok": True, "users": users, "privilege": privilege_analysis(), "invented": False})


@iapa_api_bp.route("/incidents", methods=["GET"])
def iapa_incidents():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.iapa import build_attack_graph, compute_path_scores
    g = build_attack_graph()
    incs = [n for n in (g.get("nodes") or []) if n.get("kind") == "incidente"]
    scored = compute_path_scores(max_paths=30)
    related = [p for p in (scored.get("scored_paths") or []) if "incidente" in (p.get("kinds") or [])]
    return jsonify({"ok": True, "incidents": incs, "paths_with_incident": related[:20], "invented": False})


@iapa_api_bp.route("/search", methods=["GET", "POST"])
def iapa_search():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.iapa import search
    data = request.get_json(silent=True) if request.method == "POST" else request.args.to_dict()
    data = data or {}
    return jsonify({"ok": True, "result": search(data.get("q") or "", int(data.get("limit", 50)))})


@iapa_api_bp.route("/critical", methods=["GET"])
def iapa_critical():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.iapa import critical_paths, pivot_nodes
    return jsonify({"ok": True, "critical": critical_paths(), "pivots": pivot_nodes()})


@iapa_api_bp.route("/stats", methods=["GET"])
def iapa_stats():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.iapa import stats
    return jsonify({"ok": True, "stats": stats()})


@iapa_api_bp.route("/kernel", methods=["GET", "POST"])
def iapa_kernel():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.iapa import ask_kernel
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        q = data.get("question") or data.get("q") or ""
    else:
        q = request.args.get("q") or ""
    return jsonify({"ok": True, "kernel": ask_kernel(q), "executes_actions": False})


@iapa_api_bp.route("/swarm-summary", methods=["GET"])
def iapa_swarm():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.iapa import swarm_anonymous_summary
    return jsonify({"ok": True, "summary": swarm_anonymous_summary()})


@iapa_api_bp.route("/lateral", methods=["GET"])
def iapa_lateral():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.iapa import lateral_movement_evidence
    return jsonify({"ok": True, "result": lateral_movement_evidence()})
