#!/usr/bin/env python3
"""API — Continuous Security Validation / BAS (CSV)."""
from __future__ import annotations
from flask import Blueprint, jsonify, request, session

csv_api_bp = Blueprint("csv_api", __name__, url_prefix="/api/csv")


def _auth():
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


@csv_api_bp.route("/dashboard", methods=["GET"])
def csv_dashboard():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.csv_bas import get_dashboard
    from services.enterprise_snapshot_service import read_dashboard_api
    dashboard = read_dashboard_api("csv_bas", get_dashboard, source="services.csv_bas.get_dashboard", stale_sec=90.0)
    return jsonify({"ok": True, "dashboard": dashboard})


@csv_api_bp.route("/scenarios", methods=["GET"])
def csv_scenarios():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.csv_bas import list_scenarios, get_scenario
    sid = request.args.get("id")
    if sid:
        sc = get_scenario(sid)
        if not sc:
            return jsonify({"ok": False, "error": "not_found"}), 404
        return jsonify({"ok": True, "scenario": sc})
    return jsonify({"ok": True, "result": list_scenarios()})


@csv_api_bp.route("/run", methods=["POST"])
def csv_run():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.csv_bas import run_scenario, run_all
    data = request.get_json(silent=True) or {}
    if data.get("all"):
        limit = data.get("limit")
        return jsonify({"ok": True, "result": run_all(limit=limit)})
    sid = data.get("scenario_id") or data.get("id") or ""
    if not sid:
        return jsonify({"ok": False, "error": "scenario_id_required"}), 400
    return jsonify({"ok": True, "result": run_scenario(sid)})


@csv_api_bp.route("/results", methods=["GET"])
def csv_results():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.csv_bas.store import load_results
    run_id = request.args.get("run_id")
    rows = load_results(int(request.args.get("limit", 100)))
    if run_id:
        rows = [r for r in rows if r.get("run_id") == run_id]
    return jsonify({"ok": True, "results": rows, "count": len(rows), "invented": False})


@csv_api_bp.route("/coverage", methods=["GET"])
def csv_coverage():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.csv_bas import compute_coverage
    return jsonify({"ok": True, "coverage": compute_coverage()})


@csv_api_bp.route("/history", methods=["GET"])
def csv_history():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.csv_bas import history
    return jsonify({"ok": True, "history": history(int(request.args.get("limit", 50)))})


@csv_api_bp.route("/search", methods=["GET", "POST"])
def csv_search():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.csv_bas import search
    data = request.get_json(silent=True) if request.method == "POST" else request.args.to_dict()
    data = data or {}
    return jsonify({"ok": True, "result": search(data.get("q") or "", int(data.get("limit", 50)))})


@csv_api_bp.route("/stats", methods=["GET"])
def csv_stats():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.csv_bas import stats
    return jsonify({"ok": True, "stats": stats()})


@csv_api_bp.route("/kernel", methods=["GET", "POST"])
def csv_kernel():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.csv_bas import ask_kernel
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        q = data.get("question") or data.get("q") or ""
    else:
        q = request.args.get("q") or ""
    return jsonify({"ok": True, "kernel": ask_kernel(q), "executes_actions": False})
