#!/usr/bin/env python3
"""API — NOVUS Threat Intelligence Enterprise (TIE)."""
from __future__ import annotations

from flask import Blueprint, jsonify, request, session

tie_api_bp = Blueprint("tie_api", __name__, url_prefix="/api/tie")


def _auth():
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


@tie_api_bp.route("/dashboard", methods=["GET"])
def tie_dashboard():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from core.config import Config
    from services.enterprise_snapshot_service import read_dashboard_api
    from services.threat_intelligence_enterprise import get_dashboard

    dashboard = read_dashboard_api(
        "tie",
        get_dashboard,
        source="services.threat_intelligence_enterprise.get_dashboard",
        stale_sec=float(Config.TIE_DASHBOARD_SNAPSHOT_STALE_SEC),
    )
    return jsonify({"ok": True, "dashboard": dashboard})


@tie_api_bp.route("/stats", methods=["GET"])
def tie_stats():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.threat_intelligence_enterprise import stats
    return jsonify({"ok": True, "stats": stats()})


@tie_api_bp.route("/cycle", methods=["POST"])
def tie_cycle():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.enterprise_snapshot_service import invalidate_module
    from services.threat_intelligence_enterprise import run_full_cycle

    result = run_full_cycle()
    invalidate_module("tie")
    return jsonify({"ok": True, "result": result})


@tie_api_bp.route("/feeds", methods=["POST"])
def tie_fetch_feeds():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.threat_intelligence_enterprise import fetch_all_feeds
    limit = int(request.args.get("limit", 15))
    result = fetch_all_feeds(limit_per_feed=limit)
    return jsonify({"ok": True, "result": result})


@tie_api_bp.route("/iocs", methods=["GET"])
def tie_search_iocs():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.threat_intelligence_enterprise import search_iocs
    iocs = search_iocs(
        ioc_type=request.args.get("type"),
        value=request.args.get("value") or request.args.get("q"),
        source=request.args.get("source"),
        threat_type=request.args.get("threat_type"),
        limit=int(request.args.get("limit", 100)),
    )
    return jsonify({"ok": True, "iocs": iocs, "count": len(iocs)})


@tie_api_bp.route("/enrich", methods=["GET", "POST"])
def tie_enrich():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.threat_intelligence_enterprise import enrich_for_kernel
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
    else:
        data = dict(request.args)
    indicator = data.get("indicator") or data.get("value") or data.get("q", "")
    indicator_type = data.get("type", "hash")
    if not indicator:
        return jsonify({"ok": False, "error": "indicator required"}), 400
    result = enrich_for_kernel(indicator, indicator_type)
    return jsonify({"ok": True, "enrichment": result})


@tie_api_bp.route("/lookup/hash/<hash_val>", methods=["GET"])
def tie_lookup_hash(hash_val):
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.threat_intelligence_enterprise import enrich_for_kernel
    return jsonify({"ok": True, "enrichment": enrich_for_kernel(hash_val, "hash")})


@tie_api_bp.route("/lookup/ip/<ip_val>", methods=["GET"])
def tie_lookup_ip(ip_val):
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.threat_intelligence_enterprise import enrich_for_kernel
    return jsonify({"ok": True, "enrichment": enrich_for_kernel(ip_val, "ip")})


@tie_api_bp.route("/lookup/domain/<domain_val>", methods=["GET"])
def tie_lookup_domain(domain_val):
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.threat_intelligence_enterprise import enrich_for_kernel
    return jsonify({"ok": True, "enrichment": enrich_for_kernel(domain_val, "domain")})


@tie_api_bp.route("/lookup/url", methods=["GET", "POST"])
def tie_lookup_url():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.threat_intelligence_enterprise import enrich_for_kernel
    if request.method == "POST":
        url_val = (request.get_json(silent=True) or {}).get("url", "")
    else:
        url_val = request.args.get("url", "")
    if not url_val:
        return jsonify({"ok": False, "error": "url required"}), 400
    return jsonify({"ok": True, "enrichment": enrich_for_kernel(url_val, "url")})


@tie_api_bp.route("/internal/intelligence", methods=["GET"])
def tie_internal_intel():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.threat_intelligence_enterprise import generate_anonymized_intelligence
    return jsonify({"ok": True, "intelligence": generate_anonymized_intelligence()})


@tie_api_bp.route("/swarm/publish", methods=["POST"])
def tie_swarm_publish():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.threat_intelligence_enterprise import publish_to_swarm_mesh
    return jsonify({"ok": True, "result": publish_to_swarm_mesh()})


@tie_api_bp.route("/history", methods=["GET"])
def tie_history():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.threat_intelligence_enterprise.store import load_iocs, load_feed_log, load_enrichments
    limit = int(request.args.get("limit", 100))
    return jsonify({
        "ok": True,
        "iocs": load_iocs(limit=limit),
        "feeds": load_feed_log(limit=limit),
        "enrichments": load_enrichments(limit=limit),
    })
