#!/usr/bin/env python3
"""API — Deception Platform Enterprise (DPE)."""
from __future__ import annotations
from flask import Blueprint, jsonify, request, session

deception_api_bp = Blueprint("deception_api", __name__, url_prefix="/api/deception")


def _auth():
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


@deception_api_bp.route("/dashboard", methods=["GET"])
def dpe_dashboard():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.deception_platform import get_dashboard
    from services.enterprise_snapshot_service import read_dashboard_api
    dashboard = read_dashboard_api("deception", get_dashboard, source="services.deception_platform.get_dashboard", stale_sec=90.0)
    return jsonify({"ok": True, "dashboard": dashboard})


@deception_api_bp.route("/status", methods=["GET"])
def dpe_status():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.deception_platform import get_status
    return jsonify({"ok": True, "status": get_status()})


@deception_api_bp.route("/events", methods=["GET"])
def dpe_events():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.deception_platform.store import load_events
    events = load_events(int(request.args.get("limit", 100)))
    return jsonify({
        "ok": True,
        "events": events,
        "count": len(events),
        "invented": False,
        "simulated": False,
        "message": None if events else "NO DISPONIBLE",
    })


@deception_api_bp.route("/honeypots", methods=["GET", "POST"])
def dpe_honeypots():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.deception_platform import list_honeypots, configure_honeypot, activate_honeypot
    if request.method == "GET":
        return jsonify({"ok": True, "result": list_honeypots()})
    data = request.get_json(silent=True) or {}
    action = (data.get("action") or "configure").lower()
    proto = data.get("protocol") or ""
    if action == "activate":
        return jsonify({"ok": True, "result": activate_honeypot(proto)})
    return jsonify({"ok": True, "result": configure_honeypot(
        proto,
        bind_host=data.get("bind_host", "127.0.0.1"),
        bind_port=data.get("bind_port"),
    )})


@deception_api_bp.route("/honeytokens", methods=["GET", "POST"])
def dpe_honeytokens():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.deception_platform import list_honeytokens, mint_honeytoken
    if request.method == "GET":
        return jsonify({"ok": True, "result": list_honeytokens(int(request.args.get("limit", 200)))})
    data = request.get_json(silent=True) or {}
    return jsonify({"ok": True, "result": mint_honeytoken(
        data.get("tipo") or "api_key",
        origen=data.get("origen") or "dpe_api",
    )})


@deception_api_bp.route("/honeyfiles", methods=["GET", "POST"])
def dpe_honeyfiles():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.deception_platform import list_honeyfiles, create_honeyfile, mark_opened
    if request.method == "GET":
        return jsonify({"ok": True, "result": list_honeyfiles(int(request.args.get("limit", 200)))})
    data = request.get_json(silent=True) or {}
    if data.get("action") == "open":
        # Real canary open only — never invent attacker
        return jsonify({"ok": True, "result": mark_opened(
            data.get("uuid") or "",
            source_ip=data.get("source_ip"),
            actor=data.get("actor"),
        )})
    return jsonify({"ok": True, "result": create_honeyfile(
        data.get("tipo") or "txt",
        classification=data.get("clasificacion") or "CONFIDENCIAL_DECOY",
        owner_ficticio=data.get("propietario_ficticio"),
    )})


@deception_api_bp.route("/search", methods=["GET", "POST"])
def dpe_search():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.deception_platform import search
    data = request.get_json(silent=True) if request.method == "POST" else request.args.to_dict()
    data = data or {}
    return jsonify({"ok": True, "result": search(data.get("q") or "", int(data.get("limit", 50)))})


@deception_api_bp.route("/stats", methods=["GET"])
def dpe_stats():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.deception_platform import stats
    return jsonify({"ok": True, "stats": stats()})


@deception_api_bp.route("/kernel", methods=["GET", "POST"])
def dpe_kernel():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.deception_platform import ask_kernel
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        q = data.get("question") or data.get("q") or ""
    else:
        q = request.args.get("q") or ""
    return jsonify({"ok": True, "kernel": ask_kernel(q), "executes_actions": False})


@deception_api_bp.route("/swarm-summary", methods=["GET"])
def dpe_swarm():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.deception_platform import swarm_anonymous_summary
    return jsonify({"ok": True, "summary": swarm_anonymous_summary()})


@deception_api_bp.route("/credentials", methods=["GET", "POST"])
def dpe_credentials():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.deception_platform import list_honeycredentials, create_honeycredential
    if request.method == "GET":
        return jsonify({"ok": True, "result": list_honeycredentials()})
    data = request.get_json(silent=True) or {}
    return jsonify({"ok": True, "result": create_honeycredential(data.get("role") or "usuario")})
