#!/usr/bin/env python3
"""API — NOVUS Security Operations Center Enterprise."""
from __future__ import annotations

import json
import time

from flask import Blueprint, Response, jsonify, request
from flask_login import current_user

soc_api_bp = Blueprint("soc_api", __name__, url_prefix="/api/soc")


def _auth():
    from services.enterprise_api_auth import enterprise_api_authenticated

    return enterprise_api_authenticated()


def _tenant_id():
    from services.tenant_isolation_service import require_user_tenant_id

    return require_user_tenant_id(current_user)


def _tenant_error(exc: Exception):
    from services.tenant_isolation_service import TenantAccessDenied

    if isinstance(exc, TenantAccessDenied):
        return jsonify({"ok": False, "error": "tenant_access_denied"}), 403
    raise exc


def _monitoring_gate(scope: str = "security"):
    from services.tenant_api_gate import check_tenant_monitoring_or_response

    ctx, blocked = check_tenant_monitoring_or_response(current_user, scope=scope)
    if blocked is not None:
        return None, blocked
    return ctx, None


@soc_api_bp.route("/overview", methods=["GET"])
def soc_overview():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    ctx, blocked = _monitoring_gate("security")
    if blocked is not None:
        return blocked
    from services.soc import get_overview
    from services.enterprise_snapshot_service import read_dashboard_api

    overview = read_dashboard_api(
        f"soc:{tid}",
        lambda: get_overview(tenant_id=tid),
        source="services.soc.get_overview",
        stale_sec=45.0,
    )
    return jsonify({"ok": True, "overview": overview})


@soc_api_bp.route("/dashboard", methods=["GET"])
def soc_dashboard():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    _, blocked = _monitoring_gate("security")
    if blocked is not None:
        return blocked
    from services.soc import get_overview, stats

    return jsonify({"ok": True, "overview": get_overview(tenant_id=tid), "stats": stats(tenant_id=tid)})


@soc_api_bp.route("/tactical", methods=["GET"])
def soc_tactical():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    _, blocked = _monitoring_gate("network")
    if blocked is not None:
        return blocked
    from services.soc import get_tactical_map

    return jsonify({"ok": True, "tactical": get_tactical_map(tenant_id=tid)})


@soc_api_bp.route("/executive", methods=["GET"])
def soc_executive():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    _, blocked = _monitoring_gate("security")
    if blocked is not None:
        return blocked
    from services.soc import get_executive_kpis

    return jsonify({"ok": True, "executive": get_executive_kpis(tenant_id=tid)})


@soc_api_bp.route("/analyst", methods=["GET"])
def soc_analyst():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    _, blocked = _monitoring_gate("security")
    if blocked is not None:
        return blocked
    from services.soc import get_analyst_view

    return jsonify({"ok": True, "analyst": get_analyst_view(tenant_id=tid)})


@soc_api_bp.route("/hunt", methods=["GET", "POST"])
def soc_hunt():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    _, blocked = _monitoring_gate("security")
    if blocked is not None:
        return blocked
    from services.soc import hunt

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        q = data.get("q") or data.get("query") or ""
        cat = data.get("category")
        limit = int(data.get("limit", 50))
    else:
        q = request.args.get("q") or request.args.get("query") or ""
        cat = request.args.get("category")
        limit = int(request.args.get("limit", 50))
    return jsonify({"ok": True, "hunt": hunt(q, cat, limit, tenant_id=tid)})


@soc_api_bp.route("/forensic", methods=["GET"])
def soc_forensic():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.soc import get_forensic_view

    return jsonify({"ok": True, "forensic": get_forensic_view(request.args.get("incident_id"), tenant_id=tid)})


@soc_api_bp.route("/health", methods=["GET"])
def soc_health():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.soc import get_health_view

    return jsonify({"ok": True, "health": get_health_view(tenant_id=tid)})


@soc_api_bp.route("/swarm", methods=["GET"])
def soc_swarm():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.soc import get_swarm_mesh_view

    return jsonify({"ok": True, "swarm": get_swarm_mesh_view(tenant_id=tid)})


@soc_api_bp.route("/kernel", methods=["POST", "GET"])
def soc_kernel():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.soc import ask_kernel

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        q = data.get("question") or data.get("q") or ""
    else:
        q = request.args.get("q") or request.args.get("question") or ""
    result = ask_kernel(q, tenant_id=tid)
    return jsonify({"ok": True, "kernel": result, "executes_actions": False})


@soc_api_bp.route("/stats", methods=["GET"])
def soc_stats():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.soc import stats

    return jsonify({"ok": True, "stats": stats(tenant_id=tid)})


@soc_api_bp.route("/stream", methods=["GET"])
def soc_stream():
    """SSE — actualizacion automatica del overview sin recargar pagina."""
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)

    def generate():
        last_sig = None
        ticks = 0
        while ticks < 600:
            ticks += 1
            try:
                from services.soc import get_overview

                ov = get_overview(tenant_id=tid)
                sig = json.dumps(
                    {
                        "risk": ov.get("risk_global"),
                        "activos": ov.get("incidentes_activos"),
                        "criticos": ov.get("incidentes_criticos"),
                        "engines": {k: v.get("available") for k, v in (ov.get("engines") or {}).items()},
                    },
                    sort_keys=True,
                    default=str,
                )
                if sig != last_sig:
                    last_sig = sig
                    yield f"event: soc\ndata: {json.dumps({'ok': True, 'overview': ov}, ensure_ascii=False, default=str)}\n\n"
                yield ": ping\n\n"
            except GeneratorExit:
                break
            except Exception as exc:
                yield f"event: error\ndata: {json.dumps({'ok': False, 'error': str(exc)[:200]})}\n\n"
            time.sleep(3)

    return Response(
        generate(),
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
