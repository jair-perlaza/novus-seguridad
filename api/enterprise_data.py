"""API — arquitectura de datos empresarial y acceso soporte."""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from services.enterprise_access_control import is_novus_creator
from services.rbac_service import check_api_access, get_user_role
from services.tenant_scope_service import resolve_tenant_id

enterprise_data_bp = Blueprint("enterprise_data_api", __name__, url_prefix="/api/enterprise")


@enterprise_data_bp.route("/architecture/status", methods=["GET"])
@login_required
def api_architecture_status():
    ok, msg = check_api_access(current_user, "enterprise.architecture")
    if not ok and not is_novus_creator(current_user):
        return jsonify({"status": "error", "message": msg}), 403
    from services.enterprise_data_service import get_architecture_status

    return jsonify({"status": "success", **get_architecture_status()}), 200


@enterprise_data_bp.route("/study-cases", methods=["GET"])
@login_required
def api_study_cases_list():
    ok, msg = check_api_access(current_user, "enterprise.study_cases")
    if not ok and not is_novus_creator(current_user):
        return jsonify({"status": "error", "message": msg}), 403
    from services.enterprise_data_service import list_anonymized_study_cases

    limit = min(int(request.args.get("limit", 50)), 100)
    return jsonify({"status": "success", "cases": list_anonymized_study_cases(limit=limit)}), 200


@enterprise_data_bp.route("/support-access/token", methods=["POST"])
@login_required
def api_create_support_token():
    """Cliente autoriza acceso temporal de soporte NOVUS a su tenant."""
    from services.rbac_service import ROLE_COMPANY_ADMIN, user_has_any_role

    if not user_has_any_role(current_user, (ROLE_COMPANY_ADMIN,)):
        role = get_user_role(current_user)
        if role not in ("super_admin", "company_admin"):
            return jsonify({"status": "error", "message": "Solo administradores de empresa pueden autorizar soporte"}), 403
    tenant_id = resolve_tenant_id(current_user)
    if not tenant_id:
        return jsonify({"status": "error", "message": "Tenant no resuelto"}), 400
    body = request.get_json(silent=True) or {}
    purpose = (body.get("purpose") or "Soporte NOVUS autorizado por cliente").strip()
    ttl = int(body.get("ttl_minutes") or 60)
    from services.enterprise_data_service import create_support_access_token

    tok = create_support_access_token(
        tenant_id=tenant_id,
        authorized_by_email=current_user.email,
        purpose=purpose,
        ttl_minutes=ttl,
    )
    return jsonify({"status": "success", **tok}), 201


@enterprise_data_bp.route("/support-access/validate", methods=["POST"])
@login_required
def api_validate_support_token():
    from services.enterprise_access_control import is_novus_support
    from services.rbac_service import ROLE_SUPER_ADMIN, user_has_any_role

    if not is_novus_support(current_user) and not user_has_any_role(current_user, (ROLE_SUPER_ADMIN,)):
        return jsonify({"status": "error", "message": "Solo personal de soporte NOVUS"}), 403
    body = request.get_json(silent=True) or {}
    token = (body.get("token") or "").strip()
    if not token:
        return jsonify({"status": "error", "message": "Token requerido"}), 400
    from services.enterprise_data_service import validate_support_token

    result = validate_support_token(token, current_user.email)
    code = 200 if result.get("valid") else 403
    return jsonify({"status": "success" if result.get("valid") else "error", **result}), code
