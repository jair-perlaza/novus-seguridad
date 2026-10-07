#!/usr/bin/env python3
"""API Flask — Identity Intelligence & UEBA Enterprise."""
from __future__ import annotations
from flask import Blueprint, jsonify, request, session

identity_intelligence_api_bp = Blueprint(
    "identity_intelligence_api",
    __name__,
    url_prefix="/api/identity-intelligence",
)

def _auth():
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


@identity_intelligence_api_bp.route("/dashboard", methods=["GET"])
def ii_dashboard():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.identity_intelligence.dashboard import get_dashboard
    from services.enterprise_snapshot_service import read_dashboard_api
    dashboard = read_dashboard_api(
        "identity_intel",
        get_dashboard,
        source="services.identity_intelligence.dashboard.get_dashboard",
        stale_sec=90.0,
    )
    return jsonify({"ok": True, "dashboard": dashboard})


@identity_intelligence_api_bp.route("/cycle", methods=["POST"])
def ii_cycle():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.identity_intelligence.dashboard import run_cycle
    return jsonify({"ok": True, "result": run_cycle()})


@identity_intelligence_api_bp.route("/identities", methods=["GET"])
def ii_identities():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.identity_intelligence.identity_engine import list_identities
    itype = request.args.get("type")
    items = list_identities(itype)
    return jsonify({"ok": True, "identities": items, "count": len(items), "invented": False})


@identity_intelligence_api_bp.route("/identity/<uuid>", methods=["GET"])
def ii_identity(uuid):
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.identity_intelligence.identity_engine import get_identity
    from services.identity_intelligence.behavior_baseline import get_baseline
    from services.identity_intelligence.risk_engine import compute_risk_score
    ident = get_identity(uuid)
    if not ident:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({
        "ok": True,
        "identity": ident,
        "baseline": get_baseline(uuid),
        "risk": compute_risk_score(uuid),
    })


@identity_intelligence_api_bp.route("/baseline/<uuid>", methods=["GET"])
def ii_baseline(uuid):
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.identity_intelligence.behavior_baseline import get_baseline
    return jsonify({"ok": True, "baseline": get_baseline(uuid)})


@identity_intelligence_api_bp.route("/risk/<uuid>", methods=["GET"])
def ii_risk(uuid):
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.identity_intelligence.risk_engine import compute_risk_score
    return jsonify({"ok": True, "risk": compute_risk_score(uuid)})


@identity_intelligence_api_bp.route("/anomalies", methods=["GET"])
def ii_anomalies():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.identity_intelligence.store import load_anomalies
    from services.identity_intelligence.risk_engine import detect_anomalies_for_identity
    uuid = request.args.get("identity_uuid")
    if uuid:
        return jsonify({"ok": True, "result": detect_anomalies_for_identity(uuid)})
    return jsonify({"ok": True, "anomalies": load_anomalies(100)})


@identity_intelligence_api_bp.route("/graph", methods=["GET"])
def ii_graph():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.identity_intelligence.identity_graph import build_identity_graph
    return jsonify({"ok": True, "graph": build_identity_graph(request.args.get("identity_uuid"))})


@identity_intelligence_api_bp.route("/timeline", methods=["GET"])
def ii_timeline():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.identity_intelligence.timeline import build_identity_timeline
    return jsonify({"ok": True, "timeline": build_identity_timeline(request.args.get("identity_uuid"))})


@identity_intelligence_api_bp.route("/rank", methods=["GET"])
def ii_rank():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.identity_intelligence.risk_engine import rank_identities_by_risk
    return jsonify({"ok": True, "result": rank_identities_by_risk(int(request.args.get("limit", 20)))})


@identity_intelligence_api_bp.route("/kernel", methods=["GET", "POST"])
def ii_kernel():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.identity_intelligence.dashboard import ask_kernel
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        q = data.get("question") or data.get("q") or ""
    else:
        q = request.args.get("q") or ""
    return jsonify({"ok": True, "kernel": ask_kernel(q), "executes_actions": False})


@identity_intelligence_api_bp.route("/swarm-summary", methods=["GET"])
def ii_swarm():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.identity_intelligence.dashboard import swarm_anonymous_summary
    return jsonify({"ok": True, "summary": swarm_anonymous_summary()})
