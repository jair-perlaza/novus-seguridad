"""
API NOVUS Compliance Center — controles técnicos verificables.
"""
from flask import Blueprint, jsonify, request, send_file
from flask_login import login_required, current_user

from utils.logger import logger

compliance_api_bp = Blueprint("compliance_api", __name__, url_prefix="/api/compliance")


def _email():
    return getattr(current_user, "email", None) or ""


@compliance_api_bp.route("/sectors", methods=["GET"])
@login_required
def api_compliance_sectors():
    from services.compliance_catalog import SECTORS, FRAMEWORK_MAP
    return jsonify({"status": "success", "sectors": SECTORS, "frameworks": FRAMEWORK_MAP})


@compliance_api_bp.route("/profile", methods=["POST"])
@login_required
def api_compliance_profile():
    from services.compliance_center_service import build_profile
    payload = request.get_json(silent=True) or {}
    profile = build_profile(
        sector_id=payload.get("sector_id") or "otros",
        country=payload.get("country") or "",
        company_size=payload.get("company_size") or "",
        data_types=payload.get("data_types") or "",
        infrastructure=payload.get("infrastructure") or "",
        sites=payload.get("sites") or "",
        services_used=payload.get("services_used") or "",
    )
    return jsonify({"status": "success", "profile": profile})


@compliance_api_bp.route("/evaluate", methods=["POST"])
@login_required
def api_compliance_evaluate():
    try:
        from services.compliance_center_service import build_profile, evaluate_controls, save_audit
        payload = request.get_json(silent=True) or {}
        profile = build_profile(
            sector_id=payload.get("sector_id") or "otros",
            country=payload.get("country") or "",
            company_size=payload.get("company_size") or "",
            data_types=payload.get("data_types") or "",
            infrastructure=payload.get("infrastructure") or "",
            sites=payload.get("sites") or "",
            services_used=payload.get("services_used") or "",
        )
        evaluation = evaluate_controls(profile=profile, user=current_user)
        record = None
        if payload.get("save", True):
            record = save_audit(
                evaluation,
                user_email=_email(),
                company=payload.get("company") or "",
                audit_type="compliance",
            )
        return jsonify({
            "status": "success",
            "evaluation": evaluation,
            "audit": record,
        })
    except Exception as exc:
        logger.error("compliance evaluate: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@compliance_api_bp.route("/dashboard", methods=["GET"])
@login_required
def api_compliance_dashboard():
    try:
        from services.compliance_center_service import build_profile, evaluate_controls, list_audits
        sector = request.args.get("sector_id") or "otros"
        profile = build_profile(sector_id=sector)
        evaluation = evaluate_controls(profile=profile, user=current_user)
        return jsonify({
            "status": "success",
            "evaluation": evaluation,
            "history": list_audits(limit=20),
        })
    except Exception as exc:
        logger.error("compliance dashboard: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@compliance_api_bp.route("/history", methods=["GET"])
@login_required
def api_compliance_history():
    from services.compliance_center_service import list_audits
    return jsonify({"status": "success", "audits": list_audits(limit=int(request.args.get("limit", 50)))})


@compliance_api_bp.route("/history/<audit_id>", methods=["GET"])
@login_required
def api_compliance_history_detail(audit_id):
    from services.compliance_center_service import get_audit
    audit = get_audit(audit_id)
    if not audit:
        return jsonify({"status": "error", "message": "Auditoría no encontrada"}), 404
    return jsonify({"status": "success", "audit": audit})


@compliance_api_bp.route("/control/<control_id>/explain", methods=["GET", "POST"])
@login_required
def api_compliance_control_explain(control_id):
    try:
        from services.compliance_center_service import (
            build_profile,
            evaluate_controls,
            explain_control_for_kernel,
        )
        payload = request.get_json(silent=True) or {}
        sector = request.args.get("sector_id") or payload.get("sector_id") or "otros"
        evaluation = evaluate_controls(profile=build_profile(sector_id=sector), user=current_user)
        item = next((c for c in evaluation.get("controls", []) if c["id"] == control_id), None)
        explanation = explain_control_for_kernel(control_id, item)

        if request.method == "POST" and (payload.get("execute") or request.args.get("execute") == "1"):
            from services.ai_kernel import ai_kernel
            from flask import session
            if not session.get("ai_session_id"):
                import uuid
                session["ai_session_id"] = str(uuid.uuid4())
            prompt = (
                f"Control de cumplimiento NOVUS: {explanation.get('title')}.\n"
                f"Significado: {explanation.get('meaning')}\n"
                f"Riesgo que reduce: {explanation.get('risk_reduced')}\n"
                f"Estado: {explanation.get('status_label')}\n"
                f"Hallazgo: {explanation.get('finding')}\n"
                f"Evidencia: {explanation.get('evidence_used')}\n"
                f"Recomendación: {explanation.get('recommendation')}\n"
                f"Acciones NOVUS: {explanation.get('novus_actions')}\n"
                f"Requiere manual: {explanation.get('manual_needed')}\n"
                "Explica en español sin inventar cumplimiento ni certificaciones."
            )
            chat = ai_kernel.process_message(
                session["ai_session_id"],
                prompt,
                user_email=_email(),
                user_id=getattr(current_user, "id", None),
            )
            return jsonify({"status": "success", **explanation, **chat})

        return jsonify(explanation)
    except Exception as exc:
        logger.error("compliance explain: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@compliance_api_bp.route("/report", methods=["POST"])
@login_required
def api_compliance_report():
    try:
        from services.compliance_center_service import (
            build_profile,
            evaluate_controls,
            save_audit,
            build_report_dict,
            generate_compliance_pdf,
        )
        payload = request.get_json(silent=True) or {}
        profile = build_profile(
            sector_id=payload.get("sector_id") or "otros",
            country=payload.get("country") or "",
            company_size=payload.get("company_size") or "",
            data_types=payload.get("data_types") or "",
            infrastructure=payload.get("infrastructure") or "",
            sites=payload.get("sites") or "",
            services_used=payload.get("services_used") or "",
        )
        evaluation = evaluate_controls(profile=profile, user=current_user)
        record = save_audit(
            evaluation,
            user_email=_email(),
            company=payload.get("company") or "",
            audit_type="compliance_report",
        )
        report = build_report_dict(
            evaluation,
            user_email=_email(),
            company=payload.get("company") or "",
            audit_id=record["id"],
        )
        pdf_path = generate_compliance_pdf(report)
        return jsonify({
            "status": "success",
            "audit_id": record["id"],
            "report_id": report["id"],
            "pdf_path": pdf_path,
            "download_url": f"/api/compliance/report/{report['id']}/pdf",
            "score": evaluation.get("score"),
        })
    except Exception as exc:
        logger.error("compliance report: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@compliance_api_bp.route("/report/<report_id>/pdf", methods=["GET"])
@login_required
def api_compliance_report_pdf(report_id):
    import os
    from flask import current_app
    reports_dir = os.path.join(current_app.root_path, "data", "reports")
    pdf_path = os.path.join(reports_dir, f"{report_id}.pdf")
    html_path = os.path.join(reports_dir, f"{report_id}.html")
    if os.path.isfile(pdf_path):
        return send_file(pdf_path, as_attachment=True, download_name=f"{report_id}.pdf")
    if os.path.isfile(html_path):
        return send_file(html_path, as_attachment=True, download_name=f"{report_id}.html")
    # try regenerate from audit
    from services.compliance_center_service import get_audit, generate_compliance_pdf
    audit = get_audit(report_id)
    if audit and audit.get("report"):
        path = generate_compliance_pdf(audit["report"])
        return send_file(path, as_attachment=True)
    if audit and audit.get("evaluation"):
        from services.compliance_center_service import build_report_dict
        report = build_report_dict(
            audit["evaluation"],
            user_email=audit.get("user") or "",
            company=audit.get("company") or "",
            audit_id=report_id,
        )
        path = generate_compliance_pdf(report)
        return send_file(path, as_attachment=True)
    return jsonify({"status": "error", "message": "Informe PDF no encontrado"}), 404


@compliance_api_bp.route("/audit-novus", methods=["POST"])
@login_required
def api_audit_novus():
    try:
        from services.compliance_center_service import audit_novus_platform
        result = audit_novus_platform(
            user=current_user,
            user_email=_email(),
            company=(request.get_json(silent=True) or {}).get("company") or "NOVUS / CIBERINNOVATECH",
        )
        return jsonify(result)
    except Exception as exc:
        logger.error("audit novus: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@compliance_api_bp.route("/dsar-export", methods=["GET"])
@login_required
def api_dsar_export():
    """
    P0-5 — Exportación mínima DSAR / acceso a datos del tenant canónico.
    Soporte técnico únicamente — no constituye declaración de cumplimiento legal.
    Ignora cualquier tenant_id / nit / company de query (anti-escalation).
    """
    try:
        from services.rbac_service import ADMIN_ROLES, ROLE_NOVUS_CREATOR, get_user_role
        from services.tenant_isolation_service import TenantAccessDenied, require_canonical_tenant_id
        from services.dsar_export_service import build_dsar_export, record_dsar_audit

        role = get_user_role(current_user)
        allowed = set(ADMIN_ROLES) | {ROLE_NOVUS_CREATOR}
        if role not in allowed:
            return jsonify({
                "status": "error",
                "message": "Acceso denegado — permisos insuficientes",
                "code": "RBAC_FORBIDDEN",
            }), 403

        # Canonical tenant only — never trust request args for tenant authority
        try:
            tenant_id = require_canonical_tenant_id(current_user)
        except TenantAccessDenied:
            return jsonify({
                "status": "error",
                "message": "NO_TENANT_CONTEXT",
                "reason": "tenant_not_configured",
                "code": "NO_TENANT_CONTEXT",
            }), 403

        try:
            limit = min(int(request.args.get("limit", 100)), 200)
        except Exception:
            limit = 100

        package = build_dsar_export(
            tenant_id=tenant_id,
            requested_by_email=_email(),
            limit_per_category=limit,
        )
        record_dsar_audit(
            tenant_id=tenant_id,
            user_email=_email(),
            export_id=package.get("export_id") or "",
            counts=package.get("counts") or {},
        )
        return jsonify(package)
    except Exception as exc:
        logger.error("dsar export: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "export_failed"}), 500
