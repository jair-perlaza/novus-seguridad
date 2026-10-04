"""API Centro de Defensa Manual."""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from services.tenant_api_gate import check_tenant_monitoring_or_response
from utils.logger import logger
from core.http_responses import api_error_response


def _api_err(exc, context="manual_defense"):
    return api_error_response(exc, context=context)

manual_defense_api_bp = Blueprint("manual_defense_api", __name__, url_prefix="/api/manual-defense")


def _uid():
    return getattr(current_user, "id", None)


def _email():
    return getattr(current_user, "email", None)


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr) or ""


@manual_defense_api_bp.route("/summary", methods=["GET"])
@login_required
def api_manual_defense_summary():
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked
        from services.defense_center_service import get_dashboard_summary
        from services.http_endpoint_cache import get_or_build
        from services.tenant_scope_service import resolve_tenant_id

        tenant_id = resolve_tenant_id(current_user)
        user_id = str(getattr(current_user, "id", "") or "")

        def _build():
            return {"status": "ok", "summary": get_dashboard_summary(_uid())}

        body = get_or_build(
            "/api/manual-defense/summary",
            _build,
            tenant_id=str(tenant_id) if tenant_id else None,
            user_id=user_id or None,
        )
        return jsonify(body), 200
    except Exception as exc:
        logger.error("manual-defense summary: %s", exc, exc_info=True)
        return _api_err(exc)


@manual_defense_api_bp.route("/engines", methods=["GET"])
@login_required
def api_manual_defense_engines():
    try:
        from services.defense_center_service import get_engines_panel
        return jsonify({"status": "ok", "engines": get_engines_panel(_uid())}), 200
    except Exception as exc:
        return _api_err(exc)


@manual_defense_api_bp.route("/full-defense", methods=["POST"])
@login_required
def api_manual_defense_full_defense_alias():
    return api_manual_defense_full()


@manual_defense_api_bp.route("/catalog", methods=["GET"])
@login_required
def api_manual_defense_catalog():
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked
        from services.manual_defense_catalog import build_catalog, audit_capabilities

        cat = build_catalog(_uid())
        return jsonify({
            "status": "ok",
            "catalog": cat,
            "audit": audit_capabilities(_uid()),
        }), 200
    except Exception as exc:
        logger.error("manual-defense catalog: %s", exc, exc_info=True)
        return _api_err(exc)


@manual_defense_api_bp.route("/kernel/<mechanism_id>", methods=["GET", "POST"])
@login_required
def api_manual_defense_kernel(mechanism_id):
    try:
        from services.manual_defense_service import build_kernel_consult
        from services.ai_kernel import ai_kernel
        from flask import session
        import uuid

        payload = request.get_json(silent=True) or {}
        ctx = build_kernel_consult(mechanism_id, _email())
        if request.method == "POST" and (payload.get("execute") or request.args.get("execute") == "1"):
            if not session.get("ai_session_id"):
                session["ai_session_id"] = str(uuid.uuid4())
            chat = ai_kernel.process_message(
                session["ai_session_id"],
                ctx.get("mechanism_prompt") or ctx.get("prompt", ""),
                user_email=_email(),
                user_id=_uid(),
            )
            return jsonify({"status": "ok", **ctx, **chat}), 200
        return jsonify({"status": "ok", **ctx}), 200
    except Exception as exc:
        logger.error("manual-defense kernel: %s", exc, exc_info=True)
        return _api_err(exc)


@manual_defense_api_bp.route("/execute", methods=["POST"])
@login_required
def api_manual_defense_execute():
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked
        data = request.get_json(silent=True) or {}
        mid = (data.get("mechanism_id") or "").strip()
        if not mid:
            return jsonify({"status": "error", "message": "mechanism_id requerido"}), 400
        from services.manual_defense_service import start_execute_job, persist_history
        import socket
        import time

        t0 = time.time()
        started = start_execute_job(
            mid,
            data.get("params") or {},
            user_id=_uid(),
            user_email=_email(),
        )
        if started.get("status") in ("error", "unavailable", "needs_params"):
            return jsonify(started), 400 if started.get("status") == "needs_params" else 200

        if not started.get("async"):
            hist_id = persist_history(
                user_email=_email() or "",
                hostname=socket.gethostname(),
                client_ip=_client_ip(),
                mechanism_ids=[mid],
                duration_sec=time.time() - t0,
                aggregate={
                    "started_at": (started.get("result") or {}).get("timestamp"),
                    "findings_count": len((started.get("result") or {}).get("findings") or []),
                    "evidence": (started.get("result") or {}).get("evidence"),
                    "mechanism_id": mid,
                    "report_id": started.get("report_id"),
                },
                report_id=started.get("report_id"),
            )
            started["history_id"] = hist_id

        return jsonify({"status": "success", **started}), 200
    except Exception as exc:
        logger.error("manual-defense execute: %s", exc, exc_info=True)
        return _api_err(exc)


@manual_defense_api_bp.route("/job/<job_id>", methods=["GET"])
@login_required
def api_manual_defense_job(job_id):
    try:
        from services.manual_defense_service import get_execute_job
        payload = get_execute_job(job_id)
        if not payload:
            return jsonify({"status": "error", "message": "job no encontrado"}), 404
        st = payload.get("status")
        api_status = "success" if st in ("completed", "running") else "error"
        return jsonify({"status": api_status, **payload}), 200
    except Exception as exc:
        return _api_err(exc)


@manual_defense_api_bp.route("/full-protection", methods=["POST"])
@login_required
def api_manual_defense_full():
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="dashboard")
        if blocked:
            return blocked
        data = request.get_json(silent=True) or {}
        from services.manual_defense_service import start_full_protection

        started = start_full_protection(
            _uid(),
            _email(),
            _client_ip(),
            data.get("mechanism_ids"),
        )
        return jsonify({"status": "ok", **started}), 200
    except Exception as exc:
        logger.error("manual-defense full: %s", exc, exc_info=True)
        return _api_err(exc)


@manual_defense_api_bp.route("/full-protection/<run_id>", methods=["GET"])
@login_required
def api_manual_defense_full_status(run_id):
    try:
        from services.manual_defense_service import get_full_protection_status

        st = get_full_protection_status(run_id)
        if not st:
            return jsonify({"status": "error", "message": "run_id no encontrado"}), 404
        return jsonify({"status": "ok", **st}), 200
    except Exception as exc:
        return _api_err(exc)


@manual_defense_api_bp.route("/report/<report_id>", methods=["GET"])
@login_required
def api_manual_defense_report_view(report_id):
    """Vista HTML o metadatos del informe MDR (sin volcar JSON crudo al usuario final en UI)."""
    try:
        from services.security_report_service import get_report
        from services.manual_defense_report_html import render_manual_defense_report_html
        from flask import Response

        report = get_report(report_id)
        if not report or report.get("tipo") != "Centro de Defensa":
            return jsonify({"status": "error", "message": "Informe no encontrado"}), 404
        fmt = (request.args.get("format") or "html").lower()
        if fmt == "html":
            body = render_manual_defense_report_html(report)
            return Response(body, mimetype="text/html; charset=utf-8")
        if fmt == "meta":
            dr = (report.get("technical") or {}).get("defense_report") or {}
            return jsonify({
                "status": "ok",
                "report_id": report_id,
                "mechanism_title": dr.get("mechanism_title"),
                "category": dr.get("category"),
                "severidad": report.get("severidad"),
                "fecha": report.get("fecha"),
            }), 200
        return jsonify({"status": "error", "message": "format debe ser html o meta"}), 400
    except Exception as exc:
        logger.error("manual-defense report view: %s", exc, exc_info=True)
        return _api_err(exc)


@manual_defense_api_bp.route("/report/<report_id>/share", methods=["POST"])
@login_required
def api_manual_defense_report_share(report_id):
    """Enlace compartible (requiere sesión NOVUS autenticada)."""
    try:
        from services.security_report_service import get_report

        report = get_report(report_id)
        if not report or report.get("tipo") != "Centro de Defensa":
            return jsonify({"status": "error", "message": "Informe no encontrado"}), 404
        base = request.host_url.rstrip("/")
        url = f"{base}/api/manual-defense/report/{report_id}?format=html"
        return jsonify({
            "status": "ok",
            "share_url": url,
            "message": "Enlace listo para copiar. Requiere inicio de sesión NOVUS.",
        }), 200
    except Exception as exc:
        return _api_err(exc)


@manual_defense_api_bp.route("/history", methods=["GET"])
@login_required
def api_manual_defense_history():
    try:
        from services.manual_defense_service import list_history

        limit = min(int(request.args.get("limit", 30)), 100)
        return jsonify({"status": "ok", "history": list_history(limit)}), 200
    except Exception as exc:
        return _api_err(exc)


@manual_defense_api_bp.route("/audit", methods=["GET"])
@login_required
def api_manual_defense_audit():
    try:
        from services.manual_defense_catalog import audit_capabilities

        return jsonify({"status": "ok", "audit": audit_capabilities(_uid())}), 200
    except Exception as exc:
        return _api_err(exc)
