"""
API de alcance multi-tenant — estado de monitoreo por empresa autenticada.
"""
from flask import Blueprint, jsonify
from flask_login import login_required, current_user

tenant_api_bp = Blueprint("tenant_api", __name__, url_prefix="/api/tenant")


@tenant_api_bp.route("/scope", methods=["GET"])
@login_required
def tenant_scope():
    from services.http_endpoint_cache import get_or_build
    from services.tenant_scope_service import resolve_tenant_id, get_tenant_context

    tenant_id = resolve_tenant_id(current_user)

    def _build():
        ctx = get_tenant_context(current_user)
        return {
            "status": "ok",
            "tenant_id": ctx.get("tenant_id"),
            "monitoring_enabled": ctx.get("monitoring_enabled"),
            "monitoring_mode": ctx.get("monitoring_mode"),
            "node_id": ctx.get("node_id"),
            "platform_tenant_id": ctx.get("platform_tenant_id"),
            "message": ctx.get("message"),
        }

    body = get_or_build(
        "/api/tenant/scope",
        _build,
        tenant_id=str(tenant_id) if tenant_id else None,
    )
    return jsonify(body)
