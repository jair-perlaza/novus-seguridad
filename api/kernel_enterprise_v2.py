"""
API Kernel IA Enterprise V2.0 — endpoints aditivos bajo /api/ai/enterprise/v2.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request, session

from utils.logger import logger

enterprise_v2_bp = Blueprint(
    "kernel_enterprise_v2_api",
    __name__,
    url_prefix="/api/ai/enterprise/v2",
)


def _require_login():
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


def _user_ctx():
    email = session.get("user_email") or session.get("email")
    role = session.get("role") or session.get("user_role")
    uid = session.get("user_id")
    if email and not role:
        try:
            from database import SessionLocal, Usuario
            from services.rbac_service import normalize_role

            db = SessionLocal()
            try:
                u = db.query(Usuario).filter(Usuario.email == str(email).strip().lower()).first()
                role = normalize_role(getattr(u, "role", None) if u else None)
            finally:
                db.close()
        except Exception:
            pass
    return email, role, uid


@enterprise_v2_bp.route("/status", methods=["GET"])
def v2_status():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.kernel_enterprise_v2 import kernel_enterprise_v2

    return jsonify(kernel_enterprise_v2.status())


@enterprise_v2_bp.route("/knowledge", methods=["GET"])
def v2_knowledge_list():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.kernel_enterprise_v2 import kernel_enterprise_v2

    category = request.args.get("category")
    packs = kernel_enterprise_v2.list_knowledge(category=category)
    return jsonify({"ok": True, "count": len(packs), "packs": packs})


@enterprise_v2_bp.route("/knowledge/<pack_id>", methods=["GET", "POST"])
def v2_knowledge_collect(pack_id: str):
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.kernel_enterprise_v2 import kernel_enterprise_v2

    body = request.get_json(silent=True) or {}
    query = body.get("query") or request.args.get("query") or ""
    result = kernel_enterprise_v2.collect_knowledge(pack_id, query=query)
    return jsonify({"ok": True, "result": result})


@enterprise_v2_bp.route("/actions", methods=["GET"])
def v2_actions_list():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.kernel_enterprise_v2 import kernel_enterprise_v2

    category = request.args.get("category")
    wired_only = request.args.get("wired_only", "0") in ("1", "true", "yes")
    actions = kernel_enterprise_v2.list_actions(category=category, wired_only=wired_only)
    return jsonify({"ok": True, "count": len(actions), "actions": actions})


@enterprise_v2_bp.route("/actions/<action_id>/execute", methods=["POST"])
def v2_action_execute(action_id: str):
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.kernel_enterprise_v2 import kernel_enterprise_v2

    body = request.get_json(silent=True) or {}
    email, role, _uid = _user_ctx()
    result = kernel_enterprise_v2.execute_action(
        action_id,
        user_email=email,
        user_role=role,
        params=body.get("params") or {},
        confirmed=bool(body.get("confirmed")),
        reason=str(body.get("reason") or ""),
    )
    code = 200 if result.get("ok") or result.get("status") in ("needs_confirm", "not_wired", "denied") else 400
    if result.get("status") == "denied":
        code = 403
    return jsonify({"ok": bool(result.get("ok")), "result": result}), code


@enterprise_v2_bp.route("/engines", methods=["GET"])
def v2_engines_list():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.kernel_enterprise_v2.registry import ensure_bootstrapped

    reg = ensure_bootstrapped()
    return jsonify({"ok": True, "engines": reg.list_engines()})


@enterprise_v2_bp.route("/engines/<engine_id>/run", methods=["POST"])
def v2_engine_run(engine_id: str):
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.kernel_enterprise_v2 import kernel_enterprise_v2

    body = request.get_json(silent=True) or {}
    email, role, uid = _user_ctx()
    payload = dict(body)
    payload.setdefault("user_email", email)
    payload.setdefault("user_role", role)
    payload.setdefault("user_id", uid)
    result = kernel_enterprise_v2.run_engine(engine_id, payload)
    return jsonify({"ok": True, "result": result})


@enterprise_v2_bp.route("/audit/recent", methods=["GET"])
def v2_audit_recent():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    try:
        from services.rbac_service import can_access_module_by_email

        email, _role, _ = _user_ctx()
        if email and not can_access_module_by_email(email, "centro_evidencias"):
            # fallback: allow SOC via platform_health / incidentes
            if not (
                can_access_module_by_email(email, "incidentes")
                or can_access_module_by_email(email, "platform_health")
            ):
                return jsonify({"ok": False, "error": "forbidden"}), 403
    except Exception as exc:
        logger.debug("KE-V2 audit rbac: %s", exc)
    from services.kernel_enterprise_v2.audit import recent_audits

    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify({"ok": True, "entries": recent_audits(limit)})
