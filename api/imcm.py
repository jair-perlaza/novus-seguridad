#!/usr/bin/env python3
"""API — NOVUS Incident Management & Case Management Enterprise (IMCM)."""
from __future__ import annotations

from flask import Blueprint, jsonify, request, session
from flask_login import current_user

imcm_api_bp = Blueprint("imcm_api", __name__, url_prefix="/api/imcm")


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


@imcm_api_bp.route("/dashboard", methods=["GET"])
def imcm_dashboard():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from core.config import Config
    from services.enterprise_snapshot_service import read_dashboard_api
    from services.imcm import get_dashboard_summary

    cache_key = f"imcm:{tid}"

    def _factory():
        return get_dashboard_summary(tenant_id=tid)

    dashboard = read_dashboard_api(
        cache_key,
        _factory,
        source="services.imcm.get_dashboard_summary",
        stale_sec=float(Config.IMCM_DASHBOARD_SNAPSHOT_STALE_SEC),
    )
    return jsonify({"ok": True, "dashboard": dashboard})


@imcm_api_bp.route("/incidents", methods=["GET"])
def imcm_incidents():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm import search_incidents

    results = search_incidents(
        tenant_id=tid,
        state=request.args.get("state"),
        severity=request.args.get("severity"),
        threat_type=request.args.get("threat_type"),
        keyword=request.args.get("q"),
        limit=int(request.args.get("limit", 100)),
    )
    return jsonify({"ok": True, "incidents": results, "count": len(results)})


@imcm_api_bp.route("/incident/<incident_id>", methods=["GET"])
def imcm_incident_detail(incident_id):
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm import get_incident

    inc = get_incident(incident_id, tenant_id=tid)
    if not inc:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "incident": inc})


@imcm_api_bp.route("/search", methods=["GET"])
def imcm_search():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm import search_incidents

    results = search_incidents(tenant_id=tid, keyword=request.args.get("q"), limit=int(request.args.get("limit", 50)))
    return jsonify({"ok": True, "incidents": results, "count": len(results)})


@imcm_api_bp.route("/stats", methods=["GET"])
def imcm_stats():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm import stats

    return jsonify({"ok": True, "stats": stats(tenant_id=tid)})


@imcm_api_bp.route("/timeline", methods=["GET"])
def imcm_timeline():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm.store import load_timeline

    limit = min(int(request.args.get("limit", 50)), 200)
    incident_id = request.args.get("incident_id")
    entries = load_timeline(tenant_id=tid, limit=min(limit * 4, 500))
    payload = {"generated_at_utc": None, "source_type": "live", "snapshot_pending": False, "status": "ok"}
    if incident_id:
        entries = [e for e in entries if e.get("incident_id") == incident_id]
    return jsonify(
        {
            "ok": True,
            "timeline": entries,
            "meta": {
                "generated_at_utc": payload.get("generated_at_utc"),
                "source_type": payload.get("source_type"),
                "snapshot_pending": payload.get("snapshot_pending", False),
                "status": payload.get("status"),
            },
        }
    )


@imcm_api_bp.route("/assign", methods=["POST"])
def imcm_assign():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm import assign_analyst
    from services.enterprise_snapshot_service import invalidate_module

    data = request.get_json(silent=True) or {}
    r = assign_analyst(data.get("incident_id", ""), data.get("analyst", ""), session.get("email"), tenant_id=tid)
    if not r.get("ok"):
        return jsonify({"ok": False, "error": r.get("error", "not_found")}), 404
    invalidate_module(f"imcm:{tid}")
    invalidate_module(f"imcm_timeline:{tid}")
    return jsonify({"ok": True, "result": r})


@imcm_api_bp.route("/state", methods=["POST"])
def imcm_state():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm import update_state
    from services.enterprise_snapshot_service import invalidate_module

    data = request.get_json(silent=True) or {}
    r = update_state(data.get("incident_id", ""), data.get("state", ""), session.get("email"), tenant_id=tid)
    if not r.get("ok"):
        return jsonify({"ok": False, "error": r.get("error", "not_found")}), 404
    invalidate_module(f"imcm:{tid}")
    invalidate_module(f"imcm_timeline:{tid}")
    return jsonify({"ok": True, "result": r})


@imcm_api_bp.route("/comments", methods=["GET", "POST"])
def imcm_comments():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    if request.method == "POST":
        from services.imcm import add_incident_comment

        data = request.get_json(silent=True) or {}
        r = add_incident_comment(data.get("incident_id", ""), data.get("comment", ""), session.get("email"), tenant_id=tid)
        if not r.get("ok"):
            return jsonify({"ok": False, "error": r.get("error", "not_found")}), 404
        return jsonify({"ok": True, "result": r})
    from services.imcm.store import load_comments

    incident_id = request.args.get("incident_id")
    comments = load_comments(tenant_id=tid, limit=200)
    if incident_id:
        comments = [c for c in comments if c.get("incident_id") == incident_id]
    return jsonify({"ok": True, "comments": comments})


@imcm_api_bp.route("/evidence", methods=["GET"])
def imcm_evidence():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm import get_incident

    inc = get_incident(request.args.get("incident_id", ""), tenant_id=tid)
    if not inc:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "forensic": inc.get("forensic"), "evidence": inc.get("evidence")})


@imcm_api_bp.route("/export", methods=["GET"])
def imcm_export():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm import get_incident

    inc = get_incident(request.args.get("incident_id", ""), tenant_id=tid)
    if not inc:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "export": inc})


@imcm_api_bp.route("/related", methods=["GET"])
def imcm_related():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm import get_incident

    inc = get_incident(request.args.get("incident_id", ""), tenant_id=tid)
    if not inc:
        return jsonify({"ok": True, "related": []})
    return jsonify({"ok": True, "related": inc.get("related_incidents", [])})


@imcm_api_bp.route("/playbook", methods=["GET"])
def imcm_playbook():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm import get_incident

    inc = get_incident(request.args.get("incident_id", ""), tenant_id=tid)
    if not inc:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "sope": inc.get("sope")})


@imcm_api_bp.route("/kernel", methods=["GET"])
def imcm_kernel():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm import get_incident

    inc = get_incident(request.args.get("incident_id", ""), tenant_id=tid)
    if not inc:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "kernel_ia": inc.get("kernel_ia")})


@imcm_api_bp.route("/swarm", methods=["GET"])
def imcm_swarm():
    if not _auth():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        tid = _tenant_id()
    except Exception as exc:
        return _tenant_error(exc)
    from services.imcm import get_incident

    inc = get_incident(request.args.get("incident_id", ""), tenant_id=tid)
    if not inc:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "swarm": inc.get("evidence", {}).get("swarm", "NO DISPONIBLE")})
