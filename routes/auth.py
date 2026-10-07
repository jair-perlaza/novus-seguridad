"""
Authentication routes for NOVUS
Login, logout, and user management
"""
from datetime import datetime, timedelta

from flask import Blueprint, render_template, request, redirect, url_for, session
from flask_login import login_user, logout_user, current_user
from werkzeug.security import generate_password_hash

from core.config import Config
from database import SessionLocal, Usuario, Log, registrar_log_seguridad
from models.user import User
from utils.logger import logger


auth_bp = Blueprint('auth', __name__)


def _build_registration_config():
    return {
        "nodo_id": Config.NODE_ID,
        "licencia_status": "Sin datos disponibles",
        "version_kernel": Config.VERSION,
        "pyme_mode": Config.ENABLE_MULTI_TENANT,
        "timestamp_actual": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


@auth_bp.route('/login', methods=['GET', 'POST'], endpoint='login')
def login():
    """Login route with database-backed authentication."""
    logger.info(f"Login attempt - Method: {request.method}")

    if current_user.is_authenticated:
        # Solo redirigir al Dashboard si la sesión NOVUS sigue activa (no revocada/cerrada)
        sid = session.get("_novus_login_session_id")
        if sid:
            try:
                from services.login_session_audit_service import is_login_session_active

                if is_login_session_active(sid):
                    logger.info(f"User already authenticated: {current_user.email}")
                    return redirect(url_for('dashboard.dashboard_principal'))
            except Exception:
                pass
        logout_user()
        session.clear()

    if request.method == 'POST':
        from services.csrf_service import validate_csrf_token, issue_csrf_token
        from services.hostile_hardening_config import get_hostile_hardening_config

        if get_hostile_hardening_config().get("csrf_protection_enabled"):
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not validate_csrf_token(token):
                return render_template(
                    "login.html",
                    error="Solicitud rechazada (CSRF). Recargue la página e intente de nuevo.",
                    csrf_token=issue_csrf_token(),
                ), 403

        # Segundo paso MFA (pendiente en sesión)
        pending_email = session.get("_wsae_mfa_pending_email")
        if pending_email and (request.form.get("mfa_code") or request.form.get("mfa_recovery")):
            from services.web_security_auth_enterprise.mfa_totp import verify_code
            from services.login_session_audit_service import finalize_successful_login
            from services.csrf_service import rotate_session_security
            from services.auth_protection_service import auth_protection

            vr = verify_code(
                pending_email,
                code=request.form.get("mfa_code"),
                recovery_code=request.form.get("mfa_recovery"),
            )
            if not vr.get("ok"):
                try:
                    from services.auth_protection_service import auth_protection
                    auth_protection.record_auth_attempt(success=False, email=pending_email, route="login_mfa")
                except Exception:
                    pass
                return render_template(
                    "login.html",
                    error="Código MFA inválido",
                    mfa_required=True,
                    email=pending_email,
                    csrf_token=issue_csrf_token(),
                )
            user = User.get_by_id(session.get("_wsae_mfa_pending_uid"))
            if not user:
                session.pop("_wsae_mfa_pending_email", None)
                session.pop("_wsae_mfa_pending_uid", None)
                return render_template("login.html", error="Sesión MFA expirada", csrf_token=issue_csrf_token())
            session.pop("_wsae_mfa_pending_email", None)
            session.pop("_wsae_mfa_pending_uid", None)
            session.permanent = False
            login_user(user, remember=False)
            rotate_session_security()
            auth_protection.record_auth_attempt(success=True, email=pending_email, route="login_mfa")
            finalize_successful_login(user, route="login_mfa")
            try:
                from services.web_security_auth_enterprise.login_pipeline import enrich_successful_login
                from services.bounded_background import submit_background

                submit_background(
                    enrich_successful_login,
                    name="WsaeEnrichLoginMfa",
                    user=user,
                    route="login_mfa",
                    mfa_passed=True,
                )
            except Exception as wsae_exc:
                logger.debug("wsae enrich mfa: %s", wsae_exc)
            return redirect(url_for('dashboard.dashboard_principal'), code=302)

        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        if not email or not password:
            from services.csrf_service import issue_csrf_token
            return render_template(
                'login.html',
                error="Todos los campos son obligatorios",
                csrf_token=issue_csrf_token(),
            )

        user = User.authenticate(email, password)
        if user:
            try:
                from services.csrf_service import rotate_session_security, issue_csrf_token
                from services.auth_protection_service import auth_protection
                from services.web_security_auth_enterprise.mfa_policy import (
                    audit_mfa_policy_event,
                    check_mfa_login_gate,
                )

                gate = check_mfa_login_gate(user, email)

                if gate["action"] == "verify":
                    session["_wsae_mfa_pending_email"] = email
                    session["_wsae_mfa_pending_uid"] = int(user.id)
                    session.modified = True
                    return render_template(
                        "login.html",
                        error=None,
                        mfa_required=True,
                        email=email,
                        csrf_token=issue_csrf_token(),
                        message="Introduzca el código MFA (Authenticator) o un código de recuperación.",
                    )

                if gate["action"] == "enroll":
                    audit_mfa_policy_event(
                        email,
                        "admin_login_blocked_pending_mfa",
                        detail={"role": getattr(user, "role", None)},
                    )
                    session.permanent = False
                    login_user(user, remember=False)
                    rotate_session_security()
                    session["_wsae_mfa_enrollment_required"] = True
                    session["_wsae_mfa_enrollment_email"] = email
                    session.modified = True
                    auth_protection.record_auth_attempt(success=True, email=email, route="login_mfa_enroll_required")
                    return redirect(url_for("auth.mfa_setup"), code=302)

                from services.login_session_audit_service import finalize_successful_login

                # Sin remember-me: exige autenticación en cada apertura de sesión de navegador
                session.permanent = False
                login_user(user, remember=False)
                rotate_session_security()
                from services.loadtest_runtime import is_loadtest_email

                if not is_loadtest_email(email):
                    auth_protection.record_auth_attempt(success=True, email=email, route="login")
                finalize_successful_login(user, route="login")
                try:
                    from services.web_security_auth_enterprise.login_pipeline import enrich_successful_login
                    from services.loadtest_runtime import is_loadtest_email as _lt
                    from services.bounded_background import submit_background

                    # LOADTEST: no encolar enrich pesado (no es bypass de MFA/RBAC/CSRF)
                    if not _lt(email):
                        submit_background(
                            enrich_successful_login,
                            name="WsaeEnrichLogin",
                            user=user,
                            route="login",
                            mfa_passed=False,
                        )
                except Exception as wsae_exc:
                    logger.debug("wsae enrich: %s", wsae_exc)
                # Perfil sectorial ligero en request; UCE/ASPE/escudos pesados en background
                try:
                    from services.loadtest_runtime import is_loadtest_email

                    if is_loadtest_email(email):
                        session["sector_key"] = "fintech"
                        session["sector_label"] = "Load Test"
                    else:
                        from services.sector_shield_service import resolve_sector_for_user
                        from services.sector_profile_service import get_sector_profile, apply_sector_profile_for_user
                        from services.bounded_background import submit_background

                        sector_key = resolve_sector_for_user(user.email)
                        profile = get_sector_profile(sector_key)
                        session["sector_key"] = sector_key
                        session["sector_label"] = profile.get("label")
                        submit_background(
                            apply_sector_profile_for_user,
                            user.email,
                            name="SectorProfilePostLogin",
                        )
                except Exception as sec_exc:
                    logger.debug("sector profile defer: %s", sec_exc)
                logger.info(f"Login successful: {user.email} sector={session.get('sector_key')}")
                return redirect(url_for('dashboard.dashboard_principal'), code=302)
            except Exception as e:
                logger.error(f"Login error: {e}")
                from services.csrf_service import issue_csrf_token
                return render_template(
                    'login.html',
                    error="Error al procesar el login",
                    csrf_token=issue_csrf_token(),
                )

        logger.warning("Invalid credentials")
        try:
            from services.auth_protection_service import auth_protection
            auth_protection.record_auth_attempt(success=False, email=email, route="login")
        except Exception as log_exc:
            logger.debug("auth_protection record: %s", log_exc)
            try:
                db = SessionLocal()
                ip = request.remote_addr or "unknown"
                registrar_log_seguridad(
                    db,
                    "LOGIN_FAILED",
                    f"email={email} ip={ip}",
                )
                db.commit()
            except Exception as fallback_exc:
                logger.debug("LOGIN_FAILED audit: %s", fallback_exc)
            finally:
                try:
                    db.close()
                except Exception:
                    pass
        from services.csrf_service import issue_csrf_token
        from services.registration_approval_service import registration_status_for_email

        reg_status = registration_status_for_email(email)
        if reg_status == "pending":
            err_msg = "Su solicitud de registro está pendiente de autorización del administrador principal."
        elif reg_status == "approved":
            err_msg = "Su registro fue autorizado. Complete su contraseña usando el enlace enviado a su correo."
        elif reg_status == "rejected":
            err_msg = "Su solicitud de registro fue rechazada. Contacte al administrador."
        else:
            err_msg = "Usuario o contraseña incorrectos"
        return render_template(
            'login.html',
            error=err_msg,
            csrf_token=issue_csrf_token(),
        )

    from services.csrf_service import issue_csrf_token
    return render_template('login.html', error=None, csrf_token=issue_csrf_token())


@auth_bp.route('/mfa-setup', methods=['GET'], endpoint='mfa_setup')
def mfa_setup():
    """Inscripción MFA obligatoria para cuentas administrativas."""
    from services.csrf_service import issue_csrf_token
    from services.web_security_auth_enterprise.mfa_policy import user_requires_mfa
    from services.web_security_auth_enterprise.mfa_totp import is_mfa_enabled, mfa_status

    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    if not session.get("_wsae_mfa_enrollment_required") and not user_requires_mfa(current_user):
        return redirect(url_for('dashboard.dashboard_principal'))
    if is_mfa_enabled(current_user.email):
        from services.web_security_auth_enterprise.mfa_policy import complete_enrollment_session
        complete_enrollment_session(current_user)
        return redirect(url_for('dashboard.dashboard_principal'))
    return render_template(
        "mfa_setup.html",
        csrf_token=issue_csrf_token(),
        mfa=mfa_status(current_user.email),
        email=current_user.email,
    )


@auth_bp.route('/logout', endpoint='logout_seguro')
def logout():
    """Logout route."""
    try:
        if current_user.is_authenticated:
            logger.info(f"Session closed for user: {current_user.email}")
            from services.login_session_audit_service import close_login_session
            close_login_session(
                session_audit_id=session.get("_novus_login_session_id"),
                user_email=current_user.email,
            )
        else:
            logger.warning("Logout attempt without authenticated user")

        logout_user()
        session.clear()
        resp = redirect(url_for('auth.login'))
        # Eliminar cookies de remember antiguas (nombre legacy y nuevo)
        for name in ("remember_token", "novus_remember_disabled", Config.REMEMBER_COOKIE_NAME):
            resp.set_cookie(name, "", expires=0, max_age=0)
        resp.set_cookie("session", "", expires=0, max_age=0)
        return resp
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return redirect(url_for('auth.login'))


@auth_bp.route('/sector-login', methods=['GET'])
@auth_bp.route('/sector_login', methods=['GET'])
def sector_login_page():
    """Sector login uses the same SQLite-backed authentication."""
    return render_template('sector_login.html')


@auth_bp.route('/sector-auth', methods=['POST'])
@auth_bp.route('/sector_auth', methods=['POST'])
def sector_auth():
    """Validate sector access against registered users in SQLite."""
    from flask import jsonify
    from services.auth_protection_service import auth_protection

    gate = auth_protection.check_login_allowed()
    if not gate.get("allowed"):
        msg = gate.get("message", "Origen bloqueado temporalmente")
        if request.is_json:
            return jsonify({"status": "error", "message": msg, "blocked_until": gate.get("blocked_until")}), 429
        return render_template('sector_access_denied.html', email="", sector="", mensaje=msg)

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        email = (payload.get('email') or '').strip().lower()
        password = payload.get('password') or ''
        sector = (payload.get('sector') or '').strip().lower()
    else:
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        sector = (request.form.get('sector') or '').strip().lower()

    user = User.authenticate(email, password)
    if not user:
        auth_protection.record_auth_attempt(success=False, email=email, route="sector_auth")
        if request.is_json:
            return jsonify({"status": "error", "message": "Credenciales incorrectas"}), 401
        return render_template('sector_access_denied.html', email=email, sector=sector, mensaje="Credenciales incorrectas")

    db = SessionLocal()
    try:
        usuario = db.query(Usuario).filter(Usuario.email == email).first()
        user_sector = (usuario.sector or '').lower() if usuario else ''
        if sector and user_sector and sector not in user_sector and user_sector not in sector:
            msg = "Usuario no autorizado para este sector"
            if request.is_json:
                return jsonify({"status": "error", "message": msg}), 403
            return render_template('sector_access_denied.html', email=email, sector=sector, mensaje=msg)
    finally:
        db.close()

    # P0-4: MFA gate BEFORE login_user (align with /login — no admin privileges pre-MFA).
    from services.csrf_service import rotate_session_security, issue_csrf_token
    from services.web_security_auth_enterprise.mfa_policy import (
        audit_mfa_policy_event,
        check_mfa_login_gate,
    )

    gate = check_mfa_login_gate(user, email)
    if gate["action"] == "verify":
        # Pending MFA: do NOT create Flask-Login session yet.
        session.permanent = False
        session["_wsae_mfa_pending_email"] = email
        session["_wsae_mfa_pending_uid"] = int(user.id)
        session.modified = True
        if request.is_json:
            return jsonify({"status": "mfa_required", "message": "Código MFA requerido"}), 403
        return render_template(
            "login.html",
            mfa_required=True,
            email=email,
            csrf_token=issue_csrf_token(),
            message="Introduzca el código MFA (Authenticator).",
        )
    if gate["action"] == "enroll":
        audit_mfa_policy_event(
            email,
            "admin_login_blocked_pending_mfa",
            detail={"role": getattr(user, "role", None), "route": "sector_auth"},
        )
        session.permanent = False
        login_user(user, remember=False)
        rotate_session_security()
        session["_wsae_mfa_enrollment_required"] = True
        session["_wsae_mfa_enrollment_email"] = email
        session.modified = True
        auth_protection.record_auth_attempt(success=True, email=email, route="sector_auth_mfa_enroll")
        if request.is_json:
            return jsonify({"status": "mfa_enrollment_required", "redirect": url_for("auth.mfa_setup")}), 403
        return redirect(url_for("auth.mfa_setup"))

    from services.login_session_audit_service import finalize_successful_login

    session.permanent = False
    login_user(user, remember=False)
    rotate_session_security()
    finalize_successful_login(user, route="sector_auth")
    try:
        from services.sector_shield_service import resolve_sector_for_user
        from services.sector_profile_service import get_sector_profile, apply_sector_profile_for_user
        from services.bounded_background import submit_background

        sector_key = resolve_sector_for_user(user.email)
        profile = get_sector_profile(sector_key)
        session["sector_key"] = sector_key
        session["sector_label"] = profile.get("label")
        submit_background(
            apply_sector_profile_for_user,
            user.email,
            name="SectorProfileSectorAuth",
        )
    except Exception as sec_exc:
        logger.debug("sector profile defer sector_auth: %s", sec_exc)
    try:
        from realtime_engine import realtime_engine
        realtime_engine.register_access_attempt(
            email, sector or (user.sector or ""), True, request.remote_addr or ""
        )
    except Exception as exc:
        logger.debug(f"realtime_engine: {exc}")
    if request.is_json:
        return jsonify({"status": "success", "redirect": url_for('dashboard.dashboard_principal')})
    return redirect(url_for('dashboard.dashboard_principal'))


@auth_bp.route('/registro_empresa', methods=['GET', 'POST'], endpoint='registro_empresa')
def registro_empresa():
    """Company registration persisted in SQLite."""
    from flask import current_app
    import psutil

    if not current_app.config.get('ALLOW_PUBLIC_REGISTRATION', False):
        logger.warning("Intento de acceso a registro público deshabilitado desde %s", request.remote_addr)
        return redirect(url_for('auth.login'))

    config_actual = _build_registration_config()
    from services.csrf_service import issue_csrf_token, rotate_session_security
    csrf_token = issue_csrf_token()

    if request.method == 'POST':
        nit = request.form.get('nit', '').strip()
        nombre = request.form.get('empresa', '').strip()
        email = request.form.get('email_usuario', '').strip().lower()
        sector = request.form.get('sector', '').strip()
        servicio = request.form.get('servicio', '').strip()
        empleados = request.form.get('empleados', '').strip()

        if not nit or not nombre or not email:
            return render_template(
                'registro_empresa.html',
                config=config_actual,
                error="NIT, empresa y correo del administrador son obligatorios",
                csrf_token=csrf_token,
            )

        infra = {
            "plan": request.form.get('plan_seleccionado', 'business'),
            "infra_tipo": request.form.get('infra_tipo', ''),
            "dispositivos_est": request.form.get('dispositivos_est', ''),
        }
        from services.registration_approval_service import create_registration_request

        result = create_registration_request(
            email=email,
            company_name=nombre,
            nit=nit,
            sector=sector or None,
            servicio=servicio or None,
            empleados=empleados or None,
            infra=infra,
            request_ip=request.remote_addr,
        )
        if not result.get("ok"):
            err_map = {
                "email_already_registered": "El email ya está registrado. Inicie sesión.",
                "registration_already_pending": "Ya existe una solicitud pendiente o autorizada para este correo.",
                "registration_data_rejected": "No fue posible completar el registro con los datos proporcionados.",
            }
            return render_template(
                'registro_empresa.html',
                config=config_actual,
                error=err_map.get(result.get("error"), "No se pudo enviar la solicitud"),
                csrf_token=issue_csrf_token(),
            )

        logger.info("Registration request submitted (pending CEO approval): %s NIT=%s", nombre, nit)
        return render_template(
            'registro_pendiente.html',
            email=email,
            company_name=nombre,
        )

    from services.membership_catalog_service import get_catalog_payload, compare_plans
    catalog = get_catalog_payload()
    from utils.sectores_config import SECTORES_NOVUS
    return render_template(
        'registro_empresa.html',
        config=config_actual,
        csrf_token=csrf_token,
        catalog=catalog,
        comparison=compare_plans(),
        sectores=SECTORES_NOVUS,
    )


@auth_bp.route('/completar-registro', methods=['GET', 'POST'], endpoint='completar_registro')
def completar_registro():
    """Establecer contraseña tras autorización del administrador principal."""
    from services.csrf_service import issue_csrf_token, validate_csrf_token
    from services.registration_approval_service import get_request_by_token, complete_registration

    token = (request.args.get('token') or request.form.get('token') or '').strip()
    req = get_request_by_token(token) if token else None

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            return render_template(
                'completar_registro.html',
                error="Solicitud rechazada (CSRF). Recargue e intente de nuevo.",
                csrf_token=issue_csrf_token(),
                token=token,
                email=req.email if req else None,
                company_name=req.company_name if req else None,
            ), 403
        password = request.form.get('password', '').strip()
        password2 = request.form.get('password_confirm', '').strip()
        if password != password2:
            return render_template(
                'completar_registro.html',
                error="Las contraseñas no coinciden",
                csrf_token=issue_csrf_token(),
                token=token,
                email=req.email if req else None,
                company_name=req.company_name if req else None,
            )
        result = complete_registration(token, password)
        if not result.get("ok"):
            err_map = {
                "invalid_token": "Enlace inválido o expirado. Solicite una nueva autorización.",
                "token_expired": "El enlace expiró. Contacte al administrador.",
                "password_too_short": "La contraseña debe tener al menos 10 caracteres.",
                "email_already_registered": "Esta cuenta ya está registrada. Inicie sesión.",
                "registration_data_rejected": "No fue posible completar el registro con los datos proporcionados.",
            }
            return render_template(
                'completar_registro.html',
                error=err_map.get(result.get("error"), "No se pudo completar el registro"),
                csrf_token=issue_csrf_token(),
                token=token,
            )
        return redirect(url_for('auth.login', msg='Registro completado. Inicie sesión y configure MFA.'))

    if not req:
        return render_template(
            'completar_registro.html',
            error="Enlace inválido, expirado o registro ya completado.",
            csrf_token=issue_csrf_token(),
        )
    return render_template(
        'completar_registro.html',
        csrf_token=issue_csrf_token(),
        token=token,
        email=req.email,
        company_name=req.company_name,
    )


@auth_bp.route('/admin/registros-pendientes', methods=['GET', 'POST'], endpoint='admin_registros_pendientes')
def admin_registros_pendientes():
    """Panel del administrador principal — autorizar/rechazar registros."""
    from services.csrf_service import issue_csrf_token, validate_csrf_token
    from services.registration_approval_service import (
        list_all_requests,
        approve_request,
        reject_request,
    )
    from services.rbac_service import get_user_role

    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    if get_user_role(current_user) != 'super_admin':
        return render_template(
            'rbac_access_denied.html',
            message='Acceso denegado',
            detail='Solo administrador principal (super_admin)',
            path=request.path,
        ), 403

    csrf_token = issue_csrf_token()
    message = None
    error = None
    setup_url = None

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            error = "CSRF inválido"
        else:
            action = request.form.get('action')
            req_id = request.form.get('request_id')
            try:
                rid = int(req_id)
            except (TypeError, ValueError):
                rid = 0
            base_url = request.url_root.rstrip('/')
            if action == 'approve' and rid:
                res = approve_request(rid, current_user.email, base_url)
                if res.get('ok'):
                    message = f"Registro autorizado: {res.get('email')}"
                    setup_url = res.get('setup_url')
                else:
                    error = res.get('error', 'No se pudo aprobar')
            elif action == 'reject' and rid:
                res = reject_request(rid, current_user.email, request.form.get('reason', ''))
                message = "Solicitud rechazada" if res.get('ok') else res.get('error', 'Error al rechazar')

    requests_list = list_all_requests()
    return render_template(
        'admin_registros_pendientes.html',
        requests=requests_list,
        csrf_token=csrf_token,
        message=message,
        error=error,
        setup_url=setup_url,
    )


@auth_bp.route('/membresias', methods=['GET'], endpoint='membresias')
def membresias():
    """Catálogo público de planes NOVUS (solo capacidades verificadas)."""
    from flask import current_app
    from services.membership_catalog_service import get_catalog_payload, compare_plans
    from services.csrf_service import issue_csrf_token

    from utils.sectores_config import SECTORES_NOVUS
    catalog = get_catalog_payload()
    return render_template(
        'membresias.html',
        catalog=catalog,
        comparison=compare_plans(),
        csrf_token=issue_csrf_token(),
        registration_enabled=current_app.config.get('ALLOW_PUBLIC_REGISTRATION', False),
        sectores=SECTORES_NOVUS,
    )
