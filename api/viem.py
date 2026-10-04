#!/usr/bin/env python3
"""API — NOVUS Vulnerability Intelligence & Exposure Management (VIEM)."""
from __future__ import annotations
from flask import Blueprint, jsonify, request, session

viem_api_bp = Blueprint("viem_api", __name__, url_prefix="/api/viem")

def _auth():
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()

@viem_api_bp.route("/dashboard", methods=["GET"])
def viem_dashboard():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.viem import get_dashboard
    from services.enterprise_snapshot_service import read_dashboard_api
    dashboard = read_dashboard_api("viem", get_dashboard, source="services.viem.get_dashboard", stale_sec=90.0)
    return jsonify({"ok": True, "dashboard": dashboard})

@viem_api_bp.route("/stats", methods=["GET"])
def viem_stats():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.viem import stats
    return jsonify({"ok": True, "stats": stats()})

@viem_api_bp.route("/scan", methods=["POST"])
def viem_scan():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.viem import run_full_scan
    r = run_full_scan()
    return jsonify({"ok": True, "summary": r.get("summary"), "scanned_at_utc": r.get("scanned_at_utc")})

@viem_api_bp.route("/search", methods=["GET"])
def viem_search():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.viem import search_vulns
    results = search_vulns(
        risk_level=request.args.get("risk"), vuln_type=request.args.get("type"),
        status=request.args.get("status"), keyword=request.args.get("q"),
        limit=int(request.args.get("limit", 100)),
    )
    return jsonify({"ok": True, "vulnerabilities": results, "count": len(results)})

@viem_api_bp.route("/assets", methods=["GET"])
def viem_assets():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.asm import stats as asm_stats
    return jsonify({"ok": True, "asm": asm_stats()})

@viem_api_bp.route("/cve", methods=["GET"])
def viem_cve():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.viem import search_vulns
    return jsonify({"ok": True, "vulnerabilities": search_vulns(keyword=request.args.get("q"))})

@viem_api_bp.route("/history", methods=["GET"])
def viem_history():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.viem.store import load_history, load_remediations
    return jsonify({"ok": True, "history": load_history(int(request.args.get("limit", 100))), "remediations": load_remediations(100)})

@viem_api_bp.route("/remediation", methods=["POST"])
def viem_remediation():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.viem import propose_remediation, verify_remediation
    data = request.get_json(silent=True) or {}
    action = data.get("action", "propose")
    vuln_id = data.get("vuln_id", "")
    if action == "verify":
        r = verify_remediation(vuln_id, data.get("evidence", ""), session.get("email"))
    else:
        r = propose_remediation(vuln_id, data.get("proposal", ""), session.get("email"))
    return jsonify({"ok": True, "result": r})
