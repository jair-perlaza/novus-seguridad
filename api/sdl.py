#!/usr/bin/env python3
"""API — NOVUS Security Data Lake Enterprise."""
from __future__ import annotations
from flask import Blueprint, jsonify, request, session, send_file
import os

sdl_api_bp = Blueprint("sdl_api", __name__, url_prefix="/api/security-data-lake")


def _auth():
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


@sdl_api_bp.route("/dashboard", methods=["GET"])
def sdl_dashboard():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdl import get_dashboard
    from services.enterprise_snapshot_service import read_dashboard_api
    dashboard = read_dashboard_api("sdl", get_dashboard, source="services.sdl.get_dashboard", stale_sec=90.0)
    return jsonify({"ok": True, "dashboard": dashboard})


@sdl_api_bp.route("/stats", methods=["GET"])
def sdl_stats():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdl import stats
    return jsonify({"ok": True, "stats": stats()})


@sdl_api_bp.route("/ingest", methods=["POST"])
def sdl_ingest():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdl import run_ingest
    data = request.get_json(silent=True) or {}
    limit = int(data.get("limit_per_source", 50))
    return jsonify({"ok": True, "result": run_ingest(limit_per_source=limit)})


@sdl_api_bp.route("/search", methods=["GET", "POST"])
def sdl_search():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdl import search
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
    else:
        data = request.args.to_dict()
    # coerce ints
    for k in ("days", "limit", "offset"):
        if k in data and data[k] not in (None, ""):
            try:
                data[k] = int(data[k])
            except Exception:
                pass
    allowed = {
        "q", "engine", "record_type", "asset", "user_ref", "ioc", "cve", "mitre",
        "campaign", "malware", "ransomware", "apt", "incident_id", "playbook_id",
        "risk", "client_ref", "device", "network", "server_ref", "endpoint_ref",
        "branch", "severity", "days", "since", "until", "limit", "offset",
    }
    filters = {k: data[k] for k in allowed if k in data and data[k] not in (None, "")}
    return jsonify({"ok": True, "result": search(**filters)})


@sdl_api_bp.route("/correlate", methods=["POST", "GET"])
def sdl_correlate():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdl import correlate
    data = request.get_json(silent=True) if request.method == "POST" else request.args.to_dict()
    data = data or {}
    keys = {k: data.get(k) for k in ("ioc", "cve", "asset", "user_ref", "incident_id", "malware", "mitre") if data.get(k)}
    return jsonify({"ok": True, "result": correlate(keys, limit=int(data.get("limit", 100)))})


@sdl_api_bp.route("/record/<uuid>", methods=["GET"])
def sdl_record(uuid):
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdl import get_by_uuid, get_versions
    row = get_by_uuid(uuid)
    if not row:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "record": row, "versions": get_versions(uuid)})


@sdl_api_bp.route("/integrity/<uuid>", methods=["GET"])
def sdl_integrity(uuid):
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdl import verify_uuid
    return jsonify(verify_uuid(uuid))


@sdl_api_bp.route("/history", methods=["GET"])
def sdl_history():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdl.store import recent_queries
    return jsonify({"ok": True, "queries": recent_queries(int(request.args.get("limit", 50)))})


@sdl_api_bp.route("/export", methods=["POST"])
def sdl_export():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdl import search, export_json, export_csv, export_zip, export_pdf
    data = request.get_json(silent=True) or {}
    fmt = (data.get("format") or "json").lower()
    filters = data.get("filters") or {}
    result = search(**{k: v for k, v in filters.items() if v not in (None, "")}, limit=int(data.get("limit", 500)))
    records = result.get("records") or []
    exporters = {"json": export_json, "csv": export_csv, "zip": export_zip, "pdf": export_pdf}
    if fmt not in exporters:
        return jsonify({"ok": False, "error": "format_unsupported"}), 400
    out = exporters[fmt](records)
    return jsonify({"ok": out.get("ok", True), "export": out})


@sdl_api_bp.route("/feed/<consumer>", methods=["GET"])
def sdl_feed(consumer):
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdl import get_feed_for
    return jsonify({"ok": True, "feed": get_feed_for(consumer, limit=int(request.args.get("limit", 50)))})


@sdl_api_bp.route("/rotate", methods=["POST"])
def sdl_rotate():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdl import rotate_if_needed
    data = request.get_json(silent=True) or {}
    return jsonify({"ok": True, "result": rotate_if_needed(int(data.get("hot_limit", 500000)))})


@sdl_api_bp.route("/write", methods=["POST"])
def sdl_write():
    """Escritura explicita desde motor autorizado — no inventa campos."""
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.sdl import build_and_insert
    data = request.get_json(silent=True) or {}
    engine = data.get("engine")
    record_type = data.get("record_type")
    payload = data.get("payload")
    if not engine or not record_type or not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "engine_record_type_payload_required"}), 400
    r = build_and_insert(
        engine=engine,
        record_type=record_type,
        payload=payload,
        source=data.get("source"),
        severity=data.get("severity"),
        confidence=data.get("confidence"),
        status=data.get("status"),
        asset=data.get("asset"),
        user_ref=data.get("user_ref"),
        ioc=data.get("ioc"),
        cve=data.get("cve"),
        mitre=data.get("mitre"),
        incident_id=data.get("incident_id"),
        playbook_id=data.get("playbook_id"),
        malware=data.get("malware"),
        ransomware=data.get("ransomware"),
        apt=data.get("apt"),
    )
    return jsonify({"ok": True, "result": r})
