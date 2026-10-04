"""API Behavior Baseline + Centro de Notificaciones."""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from utils.logger import logger

behavior_notif_api_bp = Blueprint("behavior_notif_api", __name__)


@behavior_notif_api_bp.route("/api/btde/status", methods=["GET"])
@login_required
def api_btde_status():
    """Estado LIVE BTDE — lazy start bajo demanda."""
    try:
        from services.behavioral_threat_detection import get_btde_orchestrator_status, get_btde_status
        from services.lazy_engine_manager import start_if_needed, engine_status

        boot = start_if_needed("btde")

        return jsonify({
            "ok": True,
            "status": get_btde_status(),
            "orchestrator": get_btde_orchestrator_status(),
            "lazy_engine": boot,
            "engine_status": engine_status("btde"),
            "source": "services.behavioral_threat_detection",
            "source_type": "LIVE",
        }), 200
    except Exception as exc:
        logger.error("btde status: %s", exc, exc_info=True)
        return jsonify({"ok": False, "status": "NOT VERIFIED", "error": str(exc)[:200]}), 500


@behavior_notif_api_bp.route("/api/behavior/summary", methods=["GET"])
@login_required
def api_behavior_summary():
    """No expone aprendizaje interno al cliente."""
    return jsonify({
        "status": "success",
        "visible": False,
        "message": "Motor interno activo — sin panel de usuario",
    }), 200


@behavior_notif_api_bp.route("/api/behavior/rebuild", methods=["POST"])
@login_required
def api_behavior_rebuild():
    """Reconstrucción solo como operación interna autenticada (sin devolver perfil)."""
    try:
        from services.adaptive_profile_engine import rebuild_defense_profile

        email = getattr(current_user, "email", None) or ""
        result = rebuild_defense_profile(email)
        return jsonify({
            "status": "success",
            "ok": bool(result.get("ok", True)),
            "events_count": result.get("events_count"),
            "enough_data": result.get("enough_data"),
            # Sin profile_json / patrones
        }), 200
    except Exception as exc:
        logger.error("behavior rebuild: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "No se pudo actualizar el perfil interno"}), 500


@behavior_notif_api_bp.route("/api/internal/adaptive-profile/status", methods=["GET"])
@login_required
def api_adaptive_profile_status():
    """Estado operativo del motor (sin baseline ni patrones)."""
    try:
        from services.adaptive_profile_engine import engine_status, kernel_adaptive_context

        email = getattr(current_user, "email", None) or ""
        st = engine_status()
        ctx = kernel_adaptive_context(email)
        return jsonify({
            "status": "success",
            "engine": st,
            "kernel_context_available": bool((ctx.get("adaptive_profile") or {}).get("available")),
            "enough_data": (ctx.get("adaptive_profile") or {}).get("enough_data"),
            "events_count": (ctx.get("adaptive_profile") or {}).get("events_count"),
            "visible_to_user": False,
        }), 200
    except Exception as exc:
        logger.error("APE status: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "Estado no disponible"}), 500


@behavior_notif_api_bp.route("/api/notifications", methods=["GET"])
@login_required
def api_notifications_list():
    try:
        from services.notification_center_service import list_notifications
        from services.http_endpoint_cache import get_or_build
        from services.tenant_scope_service import resolve_tenant_id

        email = getattr(current_user, "email", None) or ""
        tenant_id = resolve_tenant_id(current_user)
        user_id = str(getattr(current_user, "id", "") or "")
        kind = request.args.get("kind") or request.args.get("notification_kind") or "security"
        nk = None if kind == "all" else (kind if kind in ("security", "system") else "security")
        status = request.args.get("status")
        category = request.args.get("category")
        priority = request.args.get("priority")
        limit = int(request.args.get("limit") or 50)
        offset = int(request.args.get("offset") or 0)
        variant = f"{nk or 'all'}:{status or 'all'}:{category or 'all'}:{priority or 'all'}:{limit}:{offset}"

        def _build():
            return list_notifications(
                email,
                tenant_id=str(tenant_id) if tenant_id else None,
                status=status,
                category=category,
                priority=priority,
                notification_kind=nk,
                limit=limit,
                offset=offset,
            )

        body = get_or_build(
            "/api/notifications",
            _build,
            tenant_id=str(tenant_id) if tenant_id else None,
            user_id=user_id or None,
            variant=variant,
        )
        return jsonify(body), 200
    except Exception as exc:
        logger.error("notifications list: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "No se pudieron listar notificaciones"}), 500


@behavior_notif_api_bp.route("/api/notifications/unread-count", methods=["GET"])
@login_required
def api_notifications_unread():
    try:
        from services.notification_center_service import unread_count
        from services.tenant_scope_service import resolve_tenant_id

        email = getattr(current_user, "email", None) or ""
        tenant_id = resolve_tenant_id(current_user)
        kind = request.args.get("kind") or "security"
        if kind not in ("security", "system", "all"):
            kind = "security"
        count_arg = None if kind == "all" else kind
        return jsonify({
            "status": "success",
            "unread_count": unread_count(
                email,
                tenant_id=str(tenant_id) if tenant_id else None,
                notification_kind=count_arg,
            ),
            "kind": kind,
        }), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)[:120]}), 500


@behavior_notif_api_bp.route("/api/notifications/<notification_id>", methods=["GET"])
@login_required
def api_notification_detail(notification_id: str):
    try:
        from services.notification_center_service import get_notification
        from services.tenant_scope_service import resolve_tenant_id

        email = getattr(current_user, "email", None) or ""
        tenant_id = resolve_tenant_id(current_user)
        item = get_notification(notification_id, email, tenant_id=str(tenant_id) if tenant_id else None)
        if not item:
            return jsonify({"status": "error", "message": "No encontrada"}), 404
        return jsonify({"status": "success", "notification": item}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)[:120]}), 500


@behavior_notif_api_bp.route("/api/notifications/<notification_id>/read", methods=["POST"])
@login_required
def api_notification_read(notification_id: str):
    try:
        from services.notification_center_service import mark_read
        from services.tenant_scope_service import resolve_tenant_id

        email = getattr(current_user, "email", None) or ""
        tenant_id = resolve_tenant_id(current_user)
        result = mark_read(notification_id, email, tenant_id=str(tenant_id) if tenant_id else None)
        code = 200 if result.get("ok") else 404
        return jsonify({"status": "success" if result.get("ok") else "error", **result}), code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)[:120]}), 500


@behavior_notif_api_bp.route("/api/notifications/<notification_id>/archive", methods=["POST"])
@login_required
def api_notification_archive(notification_id: str):
    try:
        from services.notification_center_service import archive_notification
        from services.tenant_scope_service import resolve_tenant_id

        email = getattr(current_user, "email", None) or ""
        tenant_id = resolve_tenant_id(current_user)
        result = archive_notification(notification_id, email, tenant_id=str(tenant_id) if tenant_id else None)
        code = 200 if result.get("ok") else 404
        return jsonify({"status": "success" if result.get("ok") else "error", **result}), code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)[:120]}), 500
