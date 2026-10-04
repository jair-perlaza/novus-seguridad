"""API WSAE — MFA, sesiones, OAuth status, refresh, fingerprint."""
from __future__ import annotations

from flask import Blueprint, jsonify, request, session
from flask_login import current_user, login_required

from utils.logger import logger

wsae_api_bp = Blueprint("wsae_api", __name__, url_prefix="/api/wsae")


@wsae_api_bp.route("/status", methods=["GET"])
@login_required
def wsae_status():
    from services.web_security_auth_enterprise.mfa_totp import engine_available, mfa_status
    from services.web_security_auth_enterprise.oauth_oidc import provider_status
    from services.web_security_auth_enterprise.limitations import LIMITATIONS
    from services.web_security_auth_enterprise.rate_limit_dynamic import get_hardening_status

    return jsonify(
        {
            "ok": True,
            "mfa": mfa_status(current_user.email),
            "mfa_engine_available": engine_available(),
            "oauth_oidc": provider_status(),
            "rate_hardening": get_hardening_status(),
            "limitations": LIMITATIONS,
            "csrf_header": "X-CSRF-Token",
        }
    )


@wsae_api_bp.route("/mfa/enroll", methods=["POST"])
@login_required
def mfa_enroll():
    from services.web_security_auth_enterprise.mfa_totp import begin_enrollment

    data = request.get_json(silent=True) or {}
    regenerate = bool(data.get("regenerate"))
    manual = bool(data.get("manual"))
    out = begin_enrollment(
        current_user.email,
        regenerate=regenerate,
        include_sensitive=manual,
    )
    return jsonify(out)


@wsae_api_bp.route("/mfa/enable", methods=["POST"])
@login_required
def mfa_enable():
    data = request.get_json(silent=True) or {}
    from flask import session as flask_session
    from services.web_security_auth_enterprise.mfa_policy import (
        complete_enrollment_session,
        user_requires_mfa,
    )
    from services.web_security_auth_enterprise.mfa_totp import verify_and_enable

    policy_lock = bool(
        user_requires_mfa(current_user) or flask_session.get("_wsae_mfa_enrollment_required")
    )
    out = verify_and_enable(
        current_user.email,
        str(data.get("code") or ""),
        policy_lock=policy_lock,
    )
    if not out.get("ok"):
        return jsonify(out)
    try:
        if flask_session.get("_wsae_mfa_enrollment_required"):
            complete_enrollment_session(current_user, route="mfa_enrollment_complete")
    except Exception as exc:
        logger.debug("mfa enable complete session: %s", exc)
    return jsonify(out)


@wsae_api_bp.route("/mfa/disable", methods=["POST"])
@login_required
def mfa_disable():
    data = request.get_json(silent=True) or {}
    from services.web_security_auth_enterprise.mfa_totp import disable_mfa

    return jsonify(
        disable_mfa(
            current_user.email,
            code=data.get("code"),
            recovery_code=data.get("recovery_code"),
        )
    )


@wsae_api_bp.route("/mfa/status", methods=["GET"])
@login_required
def mfa_status_route():
    from services.web_security_auth_enterprise.mfa_totp import mfa_status

    return jsonify(mfa_status(current_user.email))


@wsae_api_bp.route("/sessions", methods=["GET"])
@login_required
def list_sessions():
    from services.web_security_auth_enterprise.session_manager import list_active_sessions

    return jsonify({"ok": True, "sessions": list_active_sessions(current_user.email)})


@wsae_api_bp.route("/sessions/revoke", methods=["POST"])
@login_required
def revoke_one():
    data = request.get_json(silent=True) or {}
    sid = data.get("session_id")
    if not sid:
        return jsonify({"ok": False, "error": "session_id_required"}), 400
    from services.web_security_auth_enterprise.session_manager import revoke_session

    return jsonify(revoke_session(str(sid), reason="user_remote_logout"))


@wsae_api_bp.route("/sessions/logout-all", methods=["POST"])
@login_required
def logout_all():
    from services.web_security_auth_enterprise.session_manager import revoke_all_user_sessions

    return jsonify(revoke_all_user_sessions(current_user.email, reason="logout_global"))


@wsae_api_bp.route("/refresh", methods=["POST"])
@login_required
def refresh_rotate():
    data = request.get_json(silent=True) or {}
    tok = data.get("refresh_token") or session.get("_wsae_refresh_token")
    if not tok:
        return jsonify({"ok": False, "error": "refresh_token_required"}), 400
    from services.web_security_auth_enterprise.session_manager import rotate_refresh_token

    out = rotate_refresh_token(str(tok))
    if out.get("ok") and out.get("refresh_token"):
        session["_wsae_refresh_token"] = out["refresh_token"]
        session.modified = True
    return jsonify(out)


@wsae_api_bp.route("/oauth/status", methods=["GET"])
@login_required
def oauth_status():
    from services.web_security_auth_enterprise.oauth_oidc import provider_status

    return jsonify(provider_status())


@wsae_api_bp.route("/ssrf/check", methods=["POST"])
@login_required
def ssrf_check():
    data = request.get_json(silent=True) or {}
    from services.web_security_auth_enterprise.ssrf_guard import assert_url_safe

    return jsonify(assert_url_safe(str(data.get("url") or "")))


@wsae_api_bp.route("/csrf-token", methods=["GET"])
@login_required
def csrf_token_api():
    from services.csrf_service import issue_csrf_token

    return jsonify({"ok": True, "csrf_token": issue_csrf_token()})
