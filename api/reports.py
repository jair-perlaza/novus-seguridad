"""
Security reports and remediation API for NOVUS.
"""
import os
from flask import Blueprint, jsonify, request, send_file
from flask_login import login_required, current_user

from services.security_report_service import (
    list_reports,
    get_report,
    get_report_by_finding,
    auto_generate_for_findings,
    build_report_from_finding,
    save_report,
)
from services.remediation_engine import remediate_vulnerability, remediate_incident
from services.remediation_orchestrator import verify_manual_remediation
from services.manual_remediation_guide import build_manual_guide, get_manual_step
from services.report_pdf_service import generate_pdf, export_report
from utils.logger import logger
from services.api_security_service import api_hardened
from core.http_responses import api_error_response, api_not_found, export_download_error_response

reports_api_bp = Blueprint("reports_api", __name__, url_prefix="/api/reports")


@reports_api_bp.route("", methods=["GET"])
@reports_api_bp.route("/", methods=["GET"])
@reports_api_bp.route("/list", methods=["GET"])
@login_required
def api_list_reports():
    try:
        from services.tenant_isolation_service import require_user_tenant_id

        tenant_id = require_user_tenant_id(current_user)
        reports = list_reports(tenant_id=tenant_id)
        return jsonify({"status": "success", "reports": reports, "count": len(reports)})
    except Exception as exc:
        from services.tenant_isolation_service import TenantAccessDenied
        if isinstance(exc, TenantAccessDenied):
            return jsonify({"status": "error", "message": "Acceso no autorizado"}), 403
        logger.error(f"List reports error: {exc}", exc_info=True)
        return api_error_response(exc, context="reports.list")


@reports_api_bp.route("/center", methods=["GET"])
@login_required
def api_reports_center():
    try:
        from services.reports_center_service import get_reports_center_payload
        from services.tenant_isolation_service import require_user_tenant_id

        tenant_id = require_user_tenant_id(current_user)
        return jsonify({"status": "success", **get_reports_center_payload(tenant_id=tenant_id)}), 200
    except Exception as exc:
        logger.error("Reports center error: %s", exc, exc_info=True)
        return api_error_response(exc, context="reports.center")


@reports_api_bp.route("/network-history/export", methods=["GET"])
@login_required
def api_export_network_history():
    """Export CSV del historial de red verificable."""
    try:
        from services.reports_center_service import get_network_history_report
        import csv
        import tempfile

        data = get_network_history_report()
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Historial de red NOVUS"])
            writer.writerow(["Aviso", data.get("disclaimer") or ""])
            ctx = data.get("contexto") or {}
            writer.writerow(["Gateway", ctx.get("gateway")])
            writer.writerow(["Subred", ctx.get("subred")])
            writer.writerow([])
            writer.writerow(["fecha_hora", "tipo", "titulo", "motor", "severidad"])
            for e in data.get("eventos") or []:
                writer.writerow([
                    e.get("fecha_hora"),
                    e.get("tipo"),
                    e.get("titulo"),
                    e.get("motor"),
                    e.get("severidad"),
                ])
        return send_file(
            path,
            as_attachment=True,
            download_name="historial_red_novus.csv",
            mimetype="text/csv",
        )
    except Exception as exc:
        logger.error("Network history export: %s", exc, exc_info=True)
        return api_error_response(exc, context="reports.network_history_export")


@reports_api_bp.route("/generate", methods=["POST"])
@login_required
def api_generate_enterprise():
    """Generación manual de informe empresarial con secciones seleccionables."""
    try:
        from services.enterprise_report_service import build_enterprise_report, SECTION_KEYS

        payload = request.get_json(silent=True) or {}
        sections = payload.get("sections") or payload.get("secciones") or ["completo"]
        report = build_enterprise_report(
            sections=sections,
            user_email=getattr(current_user, "email", None),
        )
        pdf_path = generate_pdf(report)
        return jsonify({
            "status": "success",
            "report": report,
            "report_id": report["id"],
            "pdf_ready": pdf_path.endswith(".pdf"),
            "download_url": f"/api/reports/{report['id']}/export?format=pdf",
            "available_sections": SECTION_KEYS,
            "message": f"Informe {report['id']} generado correctamente.",
        })
    except Exception as exc:
        logger.error(f"Enterprise generate error: {exc}", exc_info=True)
        return api_error_response(exc, context="reports.generate_enterprise")


@reports_api_bp.route("/<report_id>/detail-view", methods=["GET"])
@login_required
def api_report_detail_view(report_id):
    """Vista profesional del informe persistido (misma fuente que export PDF)."""
    try:
        from services.tenant_isolation_service import require_user_tenant_id

        tenant_id = require_user_tenant_id(current_user)
        report = get_report(report_id, tenant_id=tenant_id)
        if not report:
            return api_not_found("Informe no encontrado")
        from services.reports_view_service import build_detail_view

        role = getattr(current_user, "role", "") or ""
        is_admin = role in ("super_admin", "company_admin")
        view = build_detail_view(report, include_technical=is_admin)
        return jsonify({
            "status": "success",
            "report_id": report_id,
            "view": view,
            "pdf_url": view.get("pdf_url"),
            "is_admin": is_admin,
        })
    except Exception as exc:
        logger.error("Report detail view error: %s", exc, exc_info=True)
        return api_error_response(exc, context="reports.detail_view")


@reports_api_bp.route("/<report_id>/export", methods=["GET"])
@login_required
def api_export_report(report_id):
    """Exportar informe en PDF, HTML, JSON o CSV."""
    fmt = (request.args.get("format") or "pdf").lower()
    try:
        from services.tenant_isolation_service import require_user_tenant_id

        tenant_id = require_user_tenant_id(current_user)
        report = get_report(report_id, tenant_id=tenant_id)
        if not report:
            return api_not_found("Informe no encontrado")
        path = export_report(report, fmt)
        ext = os.path.splitext(path)[1].lstrip(".")
        mimetypes = {
            "pdf": "application/pdf",
            "html": "text/html",
            "json": "application/json",
            "csv": "text/csv",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "excel": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }
        return send_file(
            path,
            as_attachment=True,
            download_name=f"{report_id}.{ext}",
            mimetype=mimetypes.get(ext, "application/octet-stream"),
        )
    except ValueError as exc:
        return api_error_response(exc, context="reports.export")
    except Exception as exc:
        logger.error(f"Export error: {exc}", exc_info=True)
        if fmt == "pdf" or request.path.endswith("/pdf"):
            return export_download_error_response(exc, context=f"reports.export:{report_id}")
        return api_error_response(exc, context=f"reports.export:{report_id}")


@reports_api_bp.route("/<report_id>", methods=["GET"])
@login_required
def api_get_report(report_id):
    from services.tenant_isolation_service import require_user_tenant_id

    tenant_id = require_user_tenant_id(current_user)
    report = get_report(report_id, tenant_id=tenant_id)
    if not report:
        return api_not_found("Informe no encontrado")
    return jsonify({"status": "success", "report": report})


@reports_api_bp.route("/finding/<finding_id>", methods=["GET"])
@login_required
def api_get_report_for_finding(finding_id):
    from services.tenant_isolation_service import require_user_tenant_id

    tenant_id = require_user_tenant_id(current_user)
    report = get_report_by_finding(finding_id, tenant_id=tenant_id)
    if not report:
        return jsonify({"status": "no_data", "message": "Sin informe generado para este hallazgo"}), 200
    return jsonify({"status": "success", "report": report})


@reports_api_bp.route("/generate-from-finding", methods=["POST"])
@login_required
def api_generate_from_finding():
    try:
        from services.tenant_isolation_service import require_user_tenant_id

        tenant_id = require_user_tenant_id(current_user)
        payload = request.get_json(silent=True) or {}
        finding = payload.get("finding")
        if not finding:
            return jsonify({"status": "error", "message": "finding requerido"}), 400
        existing = get_report_by_finding(finding.get("id"), tenant_id=tenant_id)
        if existing:
            return jsonify({"status": "success", "report": existing, "created": False})
        report = save_report(build_report_from_finding(finding), tenant_id=tenant_id)
        return jsonify({"status": "success", "report": report, "created": True})
    except Exception as exc:
        logger.error(f"Generate report error: {exc}", exc_info=True)
        return api_error_response(exc, context="reports.list")


@reports_api_bp.route("/remediate", methods=["POST"])
@login_required
@api_hardened(sensitive=True, require_json=True, action_name="reports_remediate")
def api_remediate():
    try:
        payload = request.get_json(silent=True) or {}
        target_id = payload.get("target_id") or payload.get("vulnerability_id") or payload.get("incident_id")
        target_type = payload.get("target_type", "vulnerability")
        if not target_id:
            return jsonify({"status": "error", "message": "target_id requerido"}), 400

        if target_type == "incident" or str(target_id).startswith(("INC-", "RT-")):
            result = remediate_incident(target_id, executed_by=getattr(current_user, "email", None))
        else:
            result = remediate_vulnerability(target_id, executed_by=getattr(current_user, "email", None))
        return jsonify({"status": result.get("status", "success"), **result})
    except Exception as exc:
        logger.error(f"Remediation API error: {exc}", exc_info=True)
        resp, code = api_error_response(exc, context="reports.remediate")
        data = resp.get_json()
        data["steps"] = []
        return jsonify(data), code


def _resolve_finding(finding_id: str) -> dict:
    try:
        from services.novus_security_integration import novus_security
        for finding in novus_security.scan_vulnerabilities():
            if finding.get("id") == finding_id:
                return finding
    except Exception:
        pass
    return {"id": finding_id}


@reports_api_bp.route("/remediate/manual-guide/<finding_id>", methods=["GET"])
@login_required
def api_manual_guide(finding_id):
    try:
        finding = _resolve_finding(finding_id)
        guide = build_manual_guide(finding)
        return jsonify({"status": "success", "finding_id": finding_id, "manual_guide": guide})
    except Exception as exc:
        logger.error(f"Manual guide error: {exc}", exc_info=True)
        return api_error_response(exc, context="reports.list")


@reports_api_bp.route("/remediate/verify-manual", methods=["POST"])
@login_required
@api_hardened(sensitive=True, require_json=True, action_name="verify_manual_remediation")
def api_verify_manual():
    try:
        payload = request.get_json(silent=True) or {}
        finding_id = payload.get("finding_id") or payload.get("target_id") or payload.get("vulnerability_id")
        if not finding_id:
            return jsonify({"status": "error", "message": "finding_id requerido"}), 400
        finding = _resolve_finding(finding_id)
        result = verify_manual_remediation(
            finding_id, finding, executed_by=getattr(current_user, "email", None),
        )
        return jsonify({"status": result.get("status", "success"), **result})
    except Exception as exc:
        logger.error(f"Verify manual error: {exc}", exc_info=True)
        return api_error_response(exc, context="reports.list")


@reports_api_bp.route("/remediate/manual-step", methods=["POST"])
@login_required
def api_manual_step():
    try:
        payload = request.get_json(silent=True) or {}
        finding_id = payload.get("finding_id") or payload.get("target_id")
        step_index = int(payload.get("step_index", 0))
        if not finding_id:
            return jsonify({"status": "error", "message": "finding_id requerido"}), 400
        finding = _resolve_finding(finding_id)
        step_data = get_manual_step(finding, step_index)
        return jsonify({"status": "success", **step_data})
    except Exception as exc:
        logger.error(f"Manual step error: {exc}", exc_info=True)
        return api_error_response(exc, context="reports.list")


@reports_api_bp.route("/<report_id>/pdf", methods=["GET"])
@login_required
def api_download_pdf(report_id):
    try:
        from services.tenant_isolation_service import require_user_tenant_id

        tenant_id = require_user_tenant_id(current_user)
        report = get_report(report_id, tenant_id=tenant_id)
        if not report:
            return api_not_found("Informe no encontrado")
        path = generate_pdf(report)
        download_name = f"{report_id}.pdf" if path.endswith(".pdf") else f"{report_id}.html"
        return send_file(path, as_attachment=True, download_name=download_name)
    except Exception as exc:
        logger.error(f"PDF export error: {exc}", exc_info=True)
        return export_download_error_response(exc, context=f"reports.pdf:{report_id}")


@reports_api_bp.route("/sync", methods=["POST"])
@login_required
def api_sync_reports():
    """Generate reports for all current findings and refresh integration metrics."""
    try:
        from services.novus_security_integration import novus_security
        from services.security_report_service import list_reports, auto_generate_for_findings
        from services.tenant_isolation_service import require_user_tenant_id

        findings = novus_security.scan_vulnerabilities()
        findings_count = len(findings)
        tenant_id = require_user_tenant_id(current_user)
        created = auto_generate_for_findings(findings, tenant_id=tenant_id)

        try:
            from services.alert_channel_service import maybe_generate_daily_email_report
            maybe_generate_daily_email_report(getattr(current_user, "email", None))
        except Exception as email_exc:
            logger.debug("daily email report: %s", email_exc)

        threats = novus_security.detect_threats_realtime()
        threat_count = len(threats.get("suspicious_processes") or [])

        recommendations = []
        if findings_count == 0:
            recommendations.append("Ejecute un escaneo de red desde Network/Topology para detectar nuevos nodos.")
        if threat_count > 0:
            recommendations.append(f"Revise {threat_count} proceso(s) sospechoso(s) en XDR/Incidentes.")
        if len(created) > 0:
            recommendations.append("Consulte los informes generados en Reportes y remediaciones disponibles.")

        return jsonify({
            "status": "success",
            "created": len(created),
            "findings_count": findings_count,
            "threat_count": threat_count,
            "total_reports": len(list_reports(tenant_id=tenant_id)),
            "reports": [r["id"] for r in created],
            "message": f"Sincronización completada: {len(created)} informe(s) nuevo(s) de {findings_count} hallazgo(s).",
            "recommendations": recommendations,
            "steps": [
                {"label": "Escaneo de vulnerabilidades", "detail": f"{findings_count} hallazgos", "status": "done"},
                {"label": "Generación de informes", "detail": f"{len(created)} creados", "status": "done"},
                {"label": "Motor de amenazas", "detail": f"{threat_count} procesos sospechosos", "status": "done" if threat_count == 0 else "warning"},
            ],
        })
    except Exception as exc:
        logger.error(f"Sync reports error: {exc}", exc_info=True)
        return api_error_response(exc, context="reports.list")
