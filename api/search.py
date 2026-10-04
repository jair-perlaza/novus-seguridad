"""
Global search API for NOVUS platform.
"""
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from services.tenant_isolation_service import TenantAccessDenied, require_canonical_tenant_id
from utils.logger import logger

search_api_bp = Blueprint("search_api", __name__, url_prefix="/api/search")


def _user_context():
    email = getattr(current_user, "email", None)
    sector = getattr(current_user, "sector", None)
    return email, sector


@search_api_bp.route("", methods=["GET"])
@search_api_bp.route("/", methods=["GET"])
@login_required
def api_global_search():
    try:
        query = (request.args.get("q") or "").strip()
        limit = min(int(request.args.get("limit", 25)), 50)
        email, sector = _user_context()
        # P0-3: identidad canónica nit/company — no email-domain.
        tenant_id = require_canonical_tenant_id(current_user)
        from services.global_search_kernel_service import run_global_search

        payload = run_global_search(
            query,
            limit=limit,
            user_email=email,
            sector=sector,
            tenant_id=tenant_id,
        )
        return jsonify(payload)
    except TenantAccessDenied:
        return jsonify({
            "status": "error",
            "message": "NO_TENANT_CONTEXT",
            "reason": "tenant_not_configured",
            "results": [],
            "count": 0,
        }), 403
    except Exception as exc:
        logger.error(f"Global search error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc), "results": []}), 500


@search_api_bp.route("/click", methods=["POST"])
@login_required
def api_search_click():
    try:
        body = request.get_json(silent=True) or {}
        item_id = body.get("item_id") or body.get("id")
        if not item_id:
            return jsonify({"status": "error", "message": "item_id requerido"}), 400
        from services.global_search_learning_store import record_click

        email, _ = _user_context()
        record_click(email, str(item_id))
        return jsonify({"status": "success"})
    except Exception as exc:
        logger.error("Search click record error: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@search_api_bp.route("/index", methods=["GET"])
@login_required
def api_search_index():
    try:
        from services.global_search_index import get_index_stats, get_static_index, get_dynamic_index_counts

        tenant_id = require_canonical_tenant_id(current_user)
        stats = get_index_stats(tenant_id=tenant_id)
        return jsonify({
            "status": "success",
            "tenant_id": tenant_id,
            "stats": stats,
            "dynamic": get_dynamic_index_counts(tenant_id=tenant_id),
            "items": [{k: v for k, v in i.items() if k != "search_text"} for i in get_static_index()],
        })
    except TenantAccessDenied:
        return jsonify({
            "status": "error",
            "message": "NO_TENANT_CONTEXT",
            "reason": "tenant_not_configured",
        }), 403
    except Exception as exc:
        logger.error(f"Search index error: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@search_api_bp.route("/audit", methods=["GET"])
@login_required
def api_search_audit():
    try:
        from services.global_search_kernel_service import build_audit_report

        tenant_id = require_canonical_tenant_id(current_user)
        return jsonify({"status": "success", **build_audit_report(tenant_id=tenant_id)})
    except TenantAccessDenied:
        return jsonify({
            "status": "error",
            "message": "NO_TENANT_CONTEXT",
            "reason": "tenant_not_configured",
        }), 403
    except Exception as exc:
        logger.error("Search audit error: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500
