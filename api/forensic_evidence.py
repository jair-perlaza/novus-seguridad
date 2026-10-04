"""API — Sistema forense de integridad de evidencias."""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from core.security import get_client_ip
from services.rbac_service import ROLE_COMPANY_ADMIN, ROLE_SUPER_ADMIN, SOC_ROLES, user_has_any_role

forensic_evidence_bp = Blueprint("forensic_evidence_api", __name__, url_prefix="/api/forensic-evidence")


def _log_access(action: str, *, forensic_id=None, source_id=None, **kwargs):
    from services.forensic_evidence_integrity_service import log_evidence_access

    log_evidence_access(
        action=action,
        forensic_id=forensic_id,
        source_id=source_id,
        user_email=getattr(current_user, "email", None),
        ip_address=get_client_ip(),
        **kwargs,
    )


@forensic_evidence_bp.route("/summary", methods=["GET"])
@login_required
def api_summary():
    if not user_has_any_role(current_user, SOC_ROLES + (ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN)):
        return jsonify({"status": "error", "message": "Acceso denegado"}), 403
    from services.forensic_evidence_integrity_service import get_system_summary

    summary = get_system_summary()
    _log_access("view_summary", outcome="ok", detail=summary)
    return jsonify({"status": "success", **summary}), 200


@forensic_evidence_bp.route("/verify-all", methods=["POST", "GET"])
@login_required
def api_verify_all():
    if not user_has_any_role(current_user, SOC_ROLES + (ROLE_SUPER_ADMIN,)):
        return jsonify({"status": "error", "message": "Acceso denegado"}), 403
    from services.forensic_evidence_integrity_service import run_full_verifier

    result = run_full_verifier()
    _log_access("verify_all", outcome="ok" if result.get("compromised", 0) == 0 else "compromised_found", detail={
        "total": result.get("total"),
        "verified": result.get("verified"),
        "compromised": result.get("compromised"),
    })
    return jsonify({"status": "success", **result}), 200


@forensic_evidence_bp.route("/verify/<forensic_id>", methods=["GET"])
@login_required
def api_verify_one(forensic_id: str):
    if not user_has_any_role(current_user, SOC_ROLES + (ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN)):
        return jsonify({"status": "error", "message": "Acceso denegado"}), 403
    from services.forensic_evidence_integrity_service import verify_single

    result = verify_single(forensic_id)
    _log_access("verify_one", forensic_id=forensic_id, outcome="ok" if result.get("ok") else "fail", detail=result)
    return jsonify({"status": "success", **result}), 200


@forensic_evidence_bp.route("/migrate", methods=["POST"])
@login_required
def api_migrate():
    if not user_has_any_role(current_user, (ROLE_SUPER_ADMIN,)):
        return jsonify({"status": "error", "message": "Solo super administrador"}), 403
    limit = min(int(request.args.get("limit", 500)), 5000)
    from services.forensic_evidence_integrity_service import migrate_defense_registry_batch

    stats = migrate_defense_registry_batch(max_lines=limit)
    _log_access("migrate_legacy", outcome="ok", detail=stats)
    return jsonify({"status": "success", **stats}), 200


@forensic_evidence_bp.route("/consult/<forensic_id>", methods=["GET"])
@login_required
def api_consult(forensic_id: str):
    """Consulta con verificación automática — alerta crítica si hay alteración."""
    if not user_has_any_role(current_user, SOC_ROLES + (ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN)):
        return jsonify({"status": "error", "message": "Acceso denegado"}), 403
    from services.forensic_custody_phase1 import get_evidence_auto_verify

    result = get_evidence_auto_verify(
        forensic_id,
        user_email=getattr(current_user, "email", None),
        ip_address=get_client_ip(),
        action="consult",
    )
    code = 200 if result.get("ok") or result.get("reason") != "not_found" else 404
    return jsonify({"status": "success" if result.get("ok") else "integrity_alert", **result}), code


@forensic_evidence_bp.route("/seal-close/<forensic_id>", methods=["POST"])
@login_required
def api_seal_close(forensic_id: str):
    if not user_has_any_role(current_user, SOC_ROLES + (ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN)):
        return jsonify({"status": "error", "message": "Acceso denegado"}), 403
    from services.forensic_custody_phase1 import close_seal_evidence

    reason = (request.json or {}).get("reason") if request.is_json else request.args.get("reason")
    result = close_seal_evidence(
        forensic_id,
        user_email=getattr(current_user, "email", None),
        reason=reason or "case_closed",
        ip_address=get_client_ip(),
    )
    _log_access("seal_close", forensic_id=forensic_id, outcome="ok" if result.get("ok") else "fail", detail=result)
    return jsonify({"status": "success" if result.get("ok") else "error", **result}), 200 if result.get("ok") else 400


@forensic_evidence_bp.route("/repair-custody", methods=["POST"])
@login_required
def api_repair_custody():
    if not user_has_any_role(current_user, (ROLE_SUPER_ADMIN,)):
        return jsonify({"status": "error", "message": "Solo super administrador"}), 403
    from services.forensic_custody_phase1 import repair_custody_chain

    dry = str(request.args.get("dry_run", "false")).lower() in ("1", "true", "yes")
    result = repair_custody_chain(
        actor=getattr(current_user, "email", None) or "super_admin",
        dry_run=dry,
    )
    _log_access("repair_custody", outcome="ok" if result.get("ok") else "partial", detail={
        "dry_run": dry,
        "post_verify": result.get("post_verify") or result.get("pre_stats"),
    })
    return jsonify({"status": "success", **result}), 200


@forensic_evidence_bp.route("/export-package", methods=["POST"])
@login_required
def api_export_package():
    if not user_has_any_role(current_user, SOC_ROLES + (ROLE_SUPER_ADMIN, ROLE_COMPANY_ADMIN)):
        return jsonify({"status": "error", "message": "Acceso denegado"}), 403
    from services.forensic_custody_phase1 import export_forensic_package

    body = request.get_json(silent=True) or {}
    result = export_forensic_package(
        case_id=body.get("case_id") or request.args.get("case_id"),
        forensic_ids=body.get("forensic_ids"),
        limit=min(int(body.get("limit") or request.args.get("limit") or 200), 2000),
        actor=getattr(current_user, "email", None) or "system",
        ip_address=get_client_ip(),
    )
    _log_access(
        "export_package",
        outcome="ok" if result.get("ok") else "fail",
        detail={"file": result.get("file"), "reason": result.get("reason")},
    )
    return jsonify({"status": "success" if result.get("ok") else "error", **result}), 200 if result.get("ok") else 400
