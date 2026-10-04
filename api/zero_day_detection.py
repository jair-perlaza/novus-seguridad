#!/usr/bin/env python3
"""API Zero-Day Detection Engine Enterprise (ZDDE)."""
from __future__ import annotations

from flask import Blueprint, jsonify, request, session

zdde_api_bp = Blueprint("zdde_api", __name__, url_prefix="/api/zdde")


def _require_login() -> bool:
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


@zdde_api_bp.route("/status", methods=["GET"])
def zdde_status():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.zero_day_detection import get_zdde_orchestrator_status, get_zdde_status
    from services.lazy_engine_manager import start_if_needed, engine_status

    boot = start_if_needed("zdde")

    return jsonify(
        {
            "ok": True,
            "engine": get_zdde_status(),
            "orchestrator": get_zdde_orchestrator_status(),
            "lazy_engine": boot,
            "engine_status": engine_status("zdde"),
        }
    )


@zdde_api_bp.route("/dashboard", methods=["GET"])
def zdde_dashboard():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.zero_day_detection import get_zdde_dashboard

    return jsonify({"ok": True, "dashboard": get_zdde_dashboard()})


@zdde_api_bp.route("/cycle", methods=["POST"])
def zdde_cycle():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    body = request.get_json(silent=True) or {}
    heavy = bool(body.get("heavy"))
    publish = body.get("publish", True)
    from services.zero_day_detection import run_zdde_cycle

    result = run_zdde_cycle(heavy=heavy, publish=bool(publish))
    # No exponer payload completo de capas sensibles al cliente si no hay datos
    slim = {
        "ok": result.get("ok"),
        "classification": result.get("classification"),
        "risk": result.get("risk"),
        "confidence_level": result.get("confidence_level"),
        "correlation_reason": (result.get("correlation") or {}).get("correlation_reason"),
        "signal_motors": (result.get("correlation") or {}).get("signal_motors"),
        "participating": (result.get("bundle") or {}).get("participating"),
        "proposals": result.get("proposals"),
        "duration_ms": result.get("duration_ms"),
        "events_analyzed": result.get("events_analyzed"),
        "sealed": result.get("sealed"),
        "published": result.get("published"),
        "zero_day_cve_confirmed": False,
        "explanation": (result.get("explanation") or {}).get("reasoning_chain"),
        "timestamp_utc": result.get("timestamp_utc"),
        "error": result.get("error"),
    }
    return jsonify(slim)


@zdde_api_bp.route("/kernel", methods=["GET", "POST"])
def zdde_kernel():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.zero_day_detection.kernel_insights import answer_kernel_query, build_kernel_zdde_context

    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        q = str(body.get("question") or "")
        return jsonify({"ok": True, "answer": answer_kernel_query(q), "context": build_kernel_zdde_context()})
    return jsonify({"ok": True, "context": build_kernel_zdde_context()})


@zdde_api_bp.route("/limitations", methods=["GET"])
def zdde_limitations():
    """Público autenticado — limitaciones honestas."""
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.zero_day_detection import CLASSIFICATION, LIMITATIONS

    return jsonify({"ok": True, "limitations": LIMITATIONS, "classifications": CLASSIFICATION})
