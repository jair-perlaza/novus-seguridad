"""
Seguridad centralizada NOVUS — auth global, cabeceras, proxy inverso, rate limits.
"""
from __future__ import annotations

import os

from flask import jsonify, redirect, request, url_for
from flask_login import current_user
from werkzeug.middleware.proxy_fix import ProxyFix

from utils.logger import logger

PUBLIC_ROUTE_ENDPOINTS = frozenset({
    "auth.login",
    "auth.logout",
    "auth.sector_login_page",
    "auth.sector_auth",
    "healthz.healthz",  # CLOUD-P1 Cloud Run probe — no auth, no scanners
    "static",
})

BLOCKED_PATHS = frozenset({
    "/test-sector-auth",
    "/test_sector_auth",
    "/test_sector_auth.html",
    # Sensitive filenames must never resolve via catch-all / static confusion.
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.example",
    "/secret.key",
    "/master_aes.key",
    "/ecc_private.key",
    "/ecc_private.key.wrap",
    "/ecc_public.key",
    "/config.py",
    "/novus_vault_v2.db",
    "/novus_vault_v2.db-wal",
    "/novus_vault_v2.db-shm",
    "/data/novus_vault_v2.db",
    "/data/novus_vault_v2.db-wal",
    "/data/novus_vault_v2.db-shm",
    "/novus.db",
    "/seguridad.db",
})


def _http_prof_mark(app, phase: str) -> None:
    if os.environ.get("NOVUS_HTTP_PROFILE") != "1":
        return
    try:
        mark = getattr(app, "_novus_http_prof_mark", None)
        if mark:
            mark(phase)
    except Exception:
        pass


def get_client_ip() -> str:
    """IP del cliente; X-Forwarded-For solo desde proxy confiable explícito."""
    from flask import current_app, has_request_context, request

    if not has_request_context():
        return "unknown"

    from services.trusted_proxy_service import extract_client_ip

    return extract_client_ip(
        remote_addr=request.remote_addr or "unknown",
        x_forwarded_for=request.headers.get("X-Forwarded-For"),
        behind_proxy=bool(current_app.config.get("BEHIND_PROXY")),
    )


def apply_proxy_fix(app):
    """Prepara NOVUS detrás de Nginx, Caddy o Cloudflare Tunnel."""
    if not app.config.get("BEHIND_PROXY"):
        return
    trusted = int(app.config.get("TRUSTED_PROXY_COUNT", 1))
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=trusted,
        x_proto=trusted,
        x_host=trusted,
        x_prefix=trusted,
    )
    logger.info("ProxyFix activo (trusted hops=%s)", trusted)


def register_security(app):
    """Registra hooks de seguridad en la aplicación Flask."""
    apply_proxy_fix(app)

    @app.before_request
    def require_login():
        from services.hostile_environment_service import (
            check_ip_access,
            check_load_shedding,
            check_path_api_rate_limit,
            check_user_api_rate_limit,
            is_ip_whitelisted,
        )

        _http_prof_mark(app, "security:start")
        client_id = get_client_ip()
        _http_prof_mark(app, "security:get_client_ip")

        # Bench-only reset: bind to TCP peer address ONLY (never X-Forwarded-For).
        # Disabled unless LOADTEST / explicit allow — not reachable as remote admin API.
        if (
            request.path == "/api/system/internal/benchmark/reset-abuse-guard"
            and request.method == "POST"
        ):
            allow_reset = os.environ.get("NOVUS_LOADTEST_MODE", "").strip().lower() in (
                "1", "true", "yes", "on",
            ) or os.environ.get("NOVUS_ALLOW_ABUSE_RESET", "").strip().lower() in (
                "1", "true", "yes", "on",
            )
            peer = (request.remote_addr or "").strip()
            if peer.startswith("::ffff:"):
                peer = peer.split("::ffff:", 1)[-1]
            if allow_reset and peer in ("127.0.0.1", "::1"):
                from services.http_abuse_guard import reset_abuse_guard_state

                reset_abuse_guard_state()
                return jsonify({"status": "ok", "reset": True, "bound": "remote_addr"})
            return jsonify({"status": "error", "message": "forbidden"}), 403

        ip_block = check_ip_access(client_id)
        _http_prof_mark(app, "security:check_ip_access")
        if ip_block:
            if request.path.startswith("/api/"):
                return jsonify(ip_block[0]), ip_block[1]
            from flask import abort
            abort(ip_block[1])

        # CLOUD-P1: probe path must stay cheap; does not weaken Abuse Guard for other routes.
        if (request.path or "").rstrip("/") == "/healthz" and request.method == "GET":
            return None

        from services.http_abuse_guard import run_pre_request_checks
        abuse = run_pre_request_checks(
            client_id,
            request.headers.get("User-Agent", ""),
            request.method,
            request.content_length,
        )
        if abuse:
            if request.path.startswith("/api/"):
                return jsonify(abuse[0]), abuse[1]
            from flask import abort
            abort(abuse[1])
        _http_prof_mark(app, "security:http_abuse_guard")

        path_norm = (request.path or "").lower().rstrip("/")
        if path_norm in {p.lower().rstrip("/") for p in BLOCKED_PATHS}:
            # Return from before_request (do not abort) so recovery HTML cannot
            # rewrite the status to 200 and obscure blocked sensitive paths.
            return jsonify({"status": "error", "message": "Recurso no disponible"}), 404

        # Host header allowlist (opcional NOVUS_ALLOWED_HOSTS=host1,host2)
        allowed_hosts = os.environ.get("NOVUS_ALLOWED_HOSTS", "").strip()
        if allowed_hosts:
            host = (request.host or "").split(":")[0].lower()
            ok_hosts = {h.strip().lower() for h in allowed_hosts.split(",") if h.strip()}
            if host and host not in ok_hosts:
                if request.path.startswith("/api/"):
                    return jsonify({"status": "error", "message": "Host no permitido", "code": "HOST_REJECTED"}), 400
                from flask import abort
                abort(400)

        if request.endpoint is None:
            return None

        def _public_post_needs_hardening() -> bool:
            if request.method != "POST":
                return False
            return request.endpoint in {
                "auth.login",
                "auth.registro_empresa",
                "auth.sector_auth",
            }

        if request.endpoint in PUBLIC_ROUTE_ENDPOINTS or request.endpoint.startswith("static"):
            if not _public_post_needs_hardening():
                return None

        if request.endpoint == "auth.membresias":
            if request.method == "GET":
                return None

        if request.endpoint == "auth.registro_empresa":
            if not app.config.get("ALLOW_PUBLIC_REGISTRATION", False):
                if request.path.startswith("/api/"):
                    return jsonify({
                        "status": "error",
                        "message": "Registro público deshabilitado en beta privada",
                    }), 403
                return redirect(url_for("auth.login"))
            if request.method == "GET":
                return None

        # Token-gated registration completion — no session yet; CSRF required on POST.
        # Works even when public registration is disabled (approved applicants only).
        if request.endpoint == "auth.completar_registro":
            if request.method == "GET":
                return None
            if request.method == "POST":
                from flask import render_template
                from services.csrf_service import issue_csrf_token, validate_csrf_token

                csrf_ok = validate_csrf_token(
                    request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
                )
                if not csrf_ok:
                    return (
                        render_template(
                            "completar_registro.html",
                            error="Solicitud rechazada (CSRF). Recargue e intente de nuevo.",
                            csrf_token=issue_csrf_token(),
                            token=(request.form.get("token") or "").strip(),
                        ),
                        403,
                    )
                return None

        if request.method == "POST" and not request.path.startswith("/api/"):
            from flask import render_template
            from services.hostile_hardening_config import get_hostile_hardening_config
            from services.csrf_service import validate_csrf_token

            hcfg = get_hostile_hardening_config()
            if hcfg.get("csrf_protection_enabled"):
                public_csrf_endpoints = {"auth.registro_empresa", "auth.sector_auth"}
                if request.endpoint in public_csrf_endpoints:
                    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
                    if not validate_csrf_token(token):
                        from services.csrf_service import issue_csrf_token
                        if request.endpoint == "auth.registro_empresa":
                            from routes.auth import _build_registration_config
                            return (
                                render_template(
                                    "registro_empresa.html",
                                    config=_build_registration_config(),
                                    error="Solicitud rechazada (CSRF). Recargue la página e intente de nuevo.",
                                    csrf_token=issue_csrf_token(),
                                ),
                                403,
                            )
                        if request.path.startswith("/api/"):
                            return jsonify({"status": "error", "message": "Token CSRF inválido"}), 403
                        return (
                            render_template(
                                "login.html",
                                error="Solicitud rechazada (CSRF). Recargue la página e intente de nuevo.",
                                csrf_token=issue_csrf_token(),
                            ),
                            403,
                        )

        if request.endpoint == "auth.login" and request.method == "POST":
            from services.auth_protection_service import auth_protection

            if not is_ip_whitelisted(client_id):
                gate = auth_protection.check_login_allowed()
                if not gate.get("allowed"):
                    if request.path.startswith("/api/"):
                        return jsonify({
                            "status": "error",
                            "message": gate.get("message"),
                            "blocked_until": gate.get("blocked_until"),
                        }), 429
                    from flask import render_template
                    from services.csrf_service import issue_csrf_token
                    return render_template(
                        "login.html",
                        error=gate.get("message"),
                        csrf_token=issue_csrf_token(),
                    )

            from database import db_security
            login_email = (request.form.get("email") or "").strip().lower()
            if not login_email and request.is_json:
                payload = request.get_json(silent=True) or {}
                login_email = (payload.get("email") or "").strip().lower()
            rl_key = f"login:{client_id}:{login_email}" if login_email else f"login:{client_id}"
            rl = db_security.check_rate_limit(
                rl_key,
                max_requests=app.config.get("LOGIN_RATE_LIMIT", 15),
                window_seconds=60,
            )
            if rl.get("status") == "RATE_LIMITED":
                if request.path.startswith("/api/"):
                    return jsonify({
                        "status": "error",
                        "message": "Demasiados intentos de login. Espere un momento.",
                    }), 429
                from flask import render_template
                from services.csrf_service import issue_csrf_token
                return render_template(
                    "login.html",
                    error="Demasiados intentos de login. Espere un momento.",
                    csrf_token=issue_csrf_token(),
                )

        if _public_post_needs_hardening():
            return None

        shed = check_load_shedding(request.path)
        if shed:
            return jsonify(shed[0]), shed[1]

        if request.path.startswith("/api/"):
            from database import db_security
            from services.api_security_service import (
                check_sensitive_rate_limit,
                log_api_auth_failure,
                scan_query_params,
            )
            from services.web_security_auth_enterprise.rate_limit_dynamic import effective_limit

            if not is_ip_whitelisted(client_id):
                dash_read = request.method == "GET" and (request.path or "").split("?")[0].rstrip("/") in (
                    "/api/dashboard/live",
                    "/api/security/summary",
                    "/api/tenant/scope",
                    "/api/notifications",
                    "/api/manual-defense/summary",
                    "/api/security/threats",
                    "/api/security/vulnerabilities",
                    "/api/network/nodes",
                )
                if not dash_read:
                    base_lim = app.config.get("API_RATE_LIMIT", 120)
                    lim = effective_limit(base_lim, key=f"ip:{client_id}")
                    from flask import session as _sess

                    sid = _sess.get("_novus_login_session_id")
                    if sid:
                        lim = min(lim, effective_limit(base_lim, key=f"session:{sid}"))
                    rl = db_security.check_rate_limit(
                        client_id,
                        max_requests=lim,
                        window_seconds=60,
                    )
                    if rl.get("status") == "RATE_LIMITED":
                        return jsonify({"status": "error", "message": rl.get("message")}), 429

            _http_prof_mark(app, "security:api_rate_limits")

            dash_read_path = request.method == "GET" and (request.path or "").split("?")[0].rstrip("/") in (
                "/api/dashboard/live",
                "/api/security/summary",
                "/api/tenant/scope",
                "/api/notifications",
                "/api/manual-defense/summary",
                "/api/security/threats",
                "/api/security/vulnerabilities",
                "/api/network/nodes",
            )
            if not dash_read_path:
                path_rl = check_path_api_rate_limit(request.path, client_id)
                if path_rl:
                    return jsonify(path_rl[0]), path_rl[1]

            sens = check_sensitive_rate_limit(request.path)
            if sens:
                return jsonify(sens[0]), sens[1]

            if request.content_length and request.content_length > app.config.get("API_JSON_MAX_BYTES", 1048576):
                return jsonify({"status": "error", "message": "Cuerpo de solicitud demasiado grande"}), 413

            qblock = scan_query_params()
            if qblock:
                return jsonify(qblock[0]), qblock[1]

        _http_prof_mark(app, "security:api_scan_complete")

        if not current_user.is_authenticated:
            if request.path.startswith("/api/"):
                log_api_auth_failure()
                return jsonify({"status": "error", "message": "Autenticación requerida"}), 401
            return redirect(url_for("auth.login"))

        _http_prof_mark(app, "security:auth_loaded")

        # MFA obligatorio — sesión restringida hasta inscripción TOTP
        from flask import session as flask_session

        if flask_session.get("_wsae_mfa_enrollment_required"):
            from services.web_security_auth_enterprise.mfa_policy import enrollment_route_allowed
            from services.web_security_auth_enterprise.mfa_totp import is_mfa_enabled

            email = getattr(current_user, "email", None)
            if email and is_mfa_enabled(email):
                from services.web_security_auth_enterprise.mfa_policy import complete_enrollment_session

                complete_enrollment_session(current_user)
            elif not enrollment_route_allowed(path=request.path, endpoint=request.endpoint):
                if request.path.startswith("/api/"):
                    return jsonify({
                        "status": "error",
                        "message": "Debe activar MFA (TOTP) antes de acceder a NOVUS.",
                        "code": "MFA_ENROLLMENT_REQUIRED",
                        "setup_url": url_for("auth.mfa_setup"),
                    }), 403
                return redirect(url_for("auth.mfa_setup"))

        # CSRF en APIs JSON cookie-auth (métodos mutadores)
        if request.path.startswith("/api/"):
            try:
                from services.web_security_auth_enterprise.csrf_api import validate_api_csrf

                ok_csrf, why = validate_api_csrf()
                if not ok_csrf:
                    return jsonify({
                        "status": "error",
                        "message": "Token CSRF inválido o ausente (X-CSRF-Token)",
                        "code": "CSRF_FAILED",
                        "detail": why,
                    }), 403
            except Exception:
                pass

        # Sesión Flask-Login sin auditoría NOVUS (p.ej. remember-me antiguo) → forzar Login
        # Excepción: inscripción MFA obligatoria (sin _novus_login_session_id hasta completar TOTP)
        if not flask_session.get("_novus_login_session_id"):
            if flask_session.get("_wsae_mfa_enrollment_required"):
                _http_prof_mark(app, "security:before_request_end")
                return None
            try:
                from flask_login import logout_user

                logout_user()
            except Exception:
                pass
            flask_session.clear()
            if request.path.startswith("/api/"):
                return jsonify({
                    "status": "error",
                    "message": "Sesión inválida o expirada. Inicie sesión.",
                    "login_required": True,
                }), 401
            return redirect(url_for("auth.login"))

        # Revocación server-side: lista Swarm + auditoría LoginSessionAudit.active
        # (logout marca active=False y revoca session_id — cookie firmada previa no debe valer)
        try:
            from services.swarm_defense.session_revoke import is_session_revoked
            from services.login_session_audit_service import is_login_session_active

            email = getattr(current_user, "email", None)
            sid = flask_session.get("_novus_login_session_id")
            revoked = is_session_revoked(user_email=email, session_id=sid)
            closed = bool(sid) and not is_login_session_active(sid)
            if revoked or closed:
                try:
                    from flask_login import logout_user

                    logout_user()
                except Exception:
                    pass
                flask_session.clear()
                if request.path.startswith("/api/"):
                    return jsonify({
                        "status": "error",
                        "message": "Sesión revocada o cerrada. Inicie sesión.",
                        "login_required": True,
                        "revoked": True,
                    }), 401
                return redirect(url_for("auth.login"))
        except Exception:
            pass

        if request.path.startswith("/api/") and not is_ip_whitelisted(client_id):
            user_email = getattr(current_user, "email", None) or ""
            user_rl = check_user_api_rate_limit(user_email, request.path)
            if user_rl:
                return jsonify(user_rl[0]), user_rl[1]

        _http_prof_mark(app, "security:before_request_end")
        return None

    @app.after_request
    def security_headers(response):
        _http_prof_mark(app, "security:after_request_headers_start")
        from services.hostile_hardening_config import get_hostile_hardening_config
        from services.hostile_environment_service import build_csp_header

        hcfg = get_hostile_hardening_config()
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        if hcfg.get("csp_enabled"):
            response.headers.setdefault("Content-Security-Policy", build_csp_header())
        force_hsts = os.environ.get("NOVUS_FORCE_HSTS", "").lower() == "true"
        behind = app.config.get("BEHIND_PROXY") or app.config.get("SESSION_COOKIE_SECURE")
        if force_hsts or (hcfg.get("hsts_when_proxy") and behind):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        # CORS explícito: deny-by-default; solo orígenes en NOVUS_CORS_ORIGINS
        cors_raw = os.environ.get("NOVUS_CORS_ORIGINS", "").strip()
        if cors_raw:
            origin = request.headers.get("Origin")
            allowed = {o.strip() for o in cors_raw.split(",") if o.strip()}
            if origin and origin in allowed:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
                response.headers.setdefault(
                    "Access-Control-Allow-Headers",
                    "Content-Type, X-CSRF-Token, Authorization",
                )
            # si Origin no está en allowlist, no se emite ACAO (deny)
        else:
            response.headers.setdefault("X-NOVUS-CORS-Policy", "deny-by-default")
        return response
