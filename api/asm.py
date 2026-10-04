#!/usr/bin/env python3
"""API — NOVUS Asset Intelligence & Attack Surface Management (ASM)."""
from __future__ import annotations
from flask import Blueprint, jsonify, request, session

asm_api_bp = Blueprint("asm_api", __name__, url_prefix="/api/asm")

def _auth():
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()

@asm_api_bp.route("/dashboard", methods=["GET"])
def asm_dashboard():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.asm import get_dashboard
    from services.enterprise_snapshot_service import read_dashboard_api
    dashboard = read_dashboard_api(
        "asm",
        get_dashboard,
        source="services.asm.get_dashboard",
        stale_sec=90.0,
    )
    return jsonify({"ok": True, "dashboard": dashboard})

@asm_api_bp.route("/stats", methods=["GET"])
def asm_stats():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.asm import stats
    return jsonify({"ok": True, "stats": stats()})

@asm_api_bp.route("/scan", methods=["POST"])
def asm_scan():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.asm import run_full_scan
    result = run_full_scan()
    return jsonify({"ok": True, "result": {"summary": result.get("summary"), "scanned_at_utc": result.get("scanned_at_utc"), "scan_duration_ms": result.get("scan_duration_ms")}})

@asm_api_bp.route("/inventory", methods=["GET"])
def asm_inventory():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.asm.store import load_inventory
    inv = load_inventory()
    if not inv: return jsonify({"ok": False, "error": "no scan yet"}), 404
    return jsonify({"ok": True, "inventory": inv})

@asm_api_bp.route("/software", methods=["GET"])
def asm_software():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.asm import discover_installed_software
    return jsonify({"ok": True, "software": discover_installed_software()})

@asm_api_bp.route("/services", methods=["GET"])
def asm_services():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.asm import discover_services
    return jsonify({"ok": True, "services": discover_services()})

@asm_api_bp.route("/certificates", methods=["GET"])
def asm_certificates():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.asm import discover_certificates
    return jsonify({"ok": True, "certificates": discover_certificates()})

@asm_api_bp.route("/ports", methods=["GET"])
def asm_ports():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.asm import discover_open_ports_local
    return jsonify({"ok": True, "ports": discover_open_ports_local()})

@asm_api_bp.route("/shadow-it", methods=["GET"])
def asm_shadow_it():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.asm.store import load_shadow_it
    return jsonify({"ok": True, "shadow_it": load_shadow_it()})

@asm_api_bp.route("/history", methods=["GET"])
def asm_history():
    if not _auth(): return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.asm.store import load_history
    return jsonify({"ok": True, "history": load_history(int(request.args.get("limit", 100)))})
