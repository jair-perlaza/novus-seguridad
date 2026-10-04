"""
Flask application initialization
Centralized app factory for NOVUS
"""
from flask import Flask
from flask_login import LoginManager
from core.config import get_config
import logging
import os
from datetime import timedelta


def create_app(config_name='default'):
    """Application factory pattern"""
    # Get the directory where this file is located
    basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    
    app = Flask(__name__,
                template_folder=os.path.join(basedir, 'templates'),
                static_folder=os.path.join(basedir, 'static'))
    
    # Load configuration
    config_obj = get_config(config_name)
    app.config.from_object(config_obj)
    # Política de cookies enterprise: adaptar por entorno sin romper HTTP local.
    # production/beta → Secure=True por defecto; development → Secure=False por defecto.
    # Override explícito vía SESSION_COOKIE_SECURE siempre gana.
    env_name = (config_name or "default").lower()
    # Production/beta must never run with Flask DEBUG (stack traces / interactive debugger).
    if env_name in ("production", "beta"):
        app.config["DEBUG"] = False
        app.config["TESTING"] = False
        app.config["PROPAGATE_EXCEPTIONS"] = False
        if os.environ.get("DEBUG", "").strip().lower() in ("1", "true", "yes", "on"):
            logging.getLogger("novus").warning(
                "DEBUG env ignored under NOVUS_ENV=%s — forcing DEBUG=False", env_name
            )
    if "SESSION_COOKIE_SECURE" in os.environ:
        secure = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
    elif env_name in ("production", "beta"):
        secure = True
    else:
        secure = False
    app.config["SESSION_COOKIE_SECURE"] = secure
    if "REMEMBER_COOKIE_SECURE" in os.environ:
        app.config["REMEMBER_COOKIE_SECURE"] = (
            os.environ.get("REMEMBER_COOKIE_SECURE", "False").lower() == "true"
        )
    else:
        app.config["REMEMBER_COOKIE_SECURE"] = secure
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    if not app.config.get("SESSION_COOKIE_SAMESITE"):
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    if env_name in ("production", "beta") and "PREFERRED_URL_SCHEME" not in os.environ:
        app.config["PREFERRED_URL_SCHEME"] = "https"
    try:
        from services.flask_secret_service import resolve_flask_secret_key

        secret, secret_source = resolve_flask_secret_key()
        app.config["SECRET_KEY"] = secret
        app.config["NOVUS_SECRET_KEY_SOURCE"] = secret_source
    except Exception as exc:
        logging.getLogger("novus").error("SECRET_KEY resolve failed: %s", exc)
    app.config['PERMANENT_SESSION_LIFETIME'] = getattr(
        config_obj, 'PERMANENT_SESSION_LIFETIME', timedelta(hours=8)
    )
    app.config.setdefault(
        'REMEMBER_COOKIE_NAME',
        getattr(config_obj, 'REMEMBER_COOKIE_NAME', 'novus_remember_disabled'),
    )
    app.config.setdefault(
        'REMEMBER_COOKIE_DURATION',
        getattr(config_obj, 'REMEMBER_COOKIE_DURATION', timedelta(seconds=0)),
    )
    app.config.setdefault('PROPAGATE_EXCEPTIONS', False)
    app.config.setdefault('TRAP_HTTP_EXCEPTIONS', True)
    
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = "Debes iniciar sesión para acceder"
    login_manager.login_message_category = "warning"
    login_manager.session_protection = app.config['SESSION_PROTECTION']
    
    # Store login_manager in app config for access by other modules
    app.login_manager = login_manager

    @login_manager.user_loader
    def load_user(user_id):
        if user_id is None or not str(user_id).isdigit():
            return None
        try:
            from flask import g, has_request_context

            if has_request_context():
                cached = getattr(g, "_novus_loaded_user", None)
                if cached is not None and str(getattr(cached, "id", "")) == str(user_id):
                    return cached
        except Exception:
            pass
        try:
            from services.auth_session_cache import get_cached_user, set_cached_user

            proc = get_cached_user(str(user_id))
            if proc is not None:
                try:
                    from flask import g, has_request_context

                    if has_request_context():
                        g._novus_loaded_user = proc
                except Exception:
                    pass
                return proc
        except Exception:
            proc = None

        from models.user import User

        user = User.get_by_id(user_id)
        try:
            from services.auth_session_cache import set_cached_user

            if user is not None:
                set_cached_user(str(user_id), user)
        except Exception:
            pass
        try:
            from flask import g, has_request_context

            if has_request_context() and user is not None:
                g._novus_loaded_user = user
        except Exception:
            pass
        return user
    
    # Setup logging
    setup_logging(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers (centralizado — sin JSON técnico al usuario)
    from core.error_handlers import register_error_handlers as _register_core_errors
    _register_core_errors(app)

    from core.recovery_middleware import register_recovery_middleware
    register_recovery_middleware(app)

    from services.http_request_profiler import register_http_profiler
    register_http_profiler(app)

    from core.security import register_security
    register_security(app)

    @app.context_processor
    def _inject_v1_runtime_helpers():
        from services.v1_runtime_surface import is_v1_nav_route_visible

        return {"is_v1_nav_visible": is_v1_nav_route_visible}

    return app


def setup_logging(app):
    """Configure application logging"""
    log_level = getattr(app.config, 'LOG_LEVEL', 'INFO')
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )
    app.logger.setLevel(getattr(logging, log_level))


def register_blueprints(app):
    """Register all blueprints"""
    # Import blueprints here to avoid circular imports
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.network import network_bp
    from routes.main import main_bp
    from routes.healthz import healthz_bp

    # CLOUD-P1: register early — cheap probe, no scanners
    app.register_blueprint(healthz_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(network_bp)

    # API blueprints before catch-all page routes
    from api.dashboard import dashboard_api_bp
    from api.network import network_api_bp
    from api.system import system_api_bp
    from api.security import security_api_bp
    from api.tenant import tenant_api_bp
    from api.reports import reports_api_bp
    from api.search import search_api_bp
    from api.monitoring import monitoring_api_bp
    from api.network_security_history import network_history_api_bp

    from api.playbooks import playbooks_api_bp

    app.register_blueprint(dashboard_api_bp)
    app.register_blueprint(network_api_bp)
    app.register_blueprint(system_api_bp, url_prefix='/api/system')
    app.register_blueprint(security_api_bp, url_prefix='/api/security')
    try:
        from api.wsae import wsae_api_bp
        app.register_blueprint(wsae_api_bp)
    except Exception as _wsae_reg:
        from utils.logger import logger as _lg
        _lg.warning("WSAE API register: %s", _wsae_reg)
    app.register_blueprint(tenant_api_bp)
    app.register_blueprint(reports_api_bp)
    app.register_blueprint(monitoring_api_bp)
    app.register_blueprint(network_history_api_bp)
    app.register_blueprint(playbooks_api_bp)
    app.register_blueprint(search_api_bp)

    from api.ai import ai_api_bp
    app.register_blueprint(ai_api_bp)

    from api.kernel_enterprise_v2 import enterprise_v2_bp
    app.register_blueprint(enterprise_v2_bp)

    from api.swarm_defense import swarm_defense_api_bp
    app.register_blueprint(swarm_defense_api_bp)
    from api.swarm_mesh import swarm_mesh_api_bp
    app.register_blueprint(swarm_mesh_api_bp)

    from api.zero_day_detection import zdde_api_bp
    app.register_blueprint(zdde_api_bp)
    from api.health_engine import health_api_bp
    app.register_blueprint(health_api_bp)

    from api.tie import tie_api_bp
    app.register_blueprint(tie_api_bp)

    from api.sope import sope_api_bp
    app.register_blueprint(sope_api_bp)

    from api.asm import asm_api_bp
    app.register_blueprint(asm_api_bp)

    from api.viem import viem_api_bp
    app.register_blueprint(viem_api_bp)

    from api.imcm import imcm_api_bp
    app.register_blueprint(imcm_api_bp)

    from api.soc import soc_api_bp
    app.register_blueprint(soc_api_bp)

    from api.sdl import sdl_api_bp
    app.register_blueprint(sdl_api_bp)

    from api.sdace import sdace_api_bp
    app.register_blueprint(sdace_api_bp)

    from services.identity_intelligence import identity_intelligence_api_bp
    app.register_blueprint(identity_intelligence_api_bp)

    from api.iapa import iapa_api_bp
    app.register_blueprint(iapa_api_bp)

    from api.deception import deception_api_bp
    app.register_blueprint(deception_api_bp)

    from api.csv_bas import csv_api_bp
    app.register_blueprint(csv_api_bp)

    from api.gmail import gmail_api_bp
    app.register_blueprint(gmail_api_bp)

    from api.audit import audit_api_bp
    app.register_blueprint(audit_api_bp)

    from api.threat_intel import threat_intel_api_bp
    app.register_blueprint(threat_intel_api_bp)

    from api.ndci import ndci_api_bp
    app.register_blueprint(ndci_api_bp)

    from api.web_shield import web_shield_api_bp
    app.register_blueprint(web_shield_api_bp)

    from api.mail_shield import mail_shield_api_bp
    app.register_blueprint(mail_shield_api_bp)

    from api.endpoint_scan import endpoint_scan_api_bp
    app.register_blueprint(endpoint_scan_api_bp)

    from api.manual_defense import manual_defense_api_bp
    app.register_blueprint(manual_defense_api_bp)

    from api.enterprise_data import enterprise_data_bp
    app.register_blueprint(enterprise_data_bp)

    from api.forensic_evidence import forensic_evidence_bp
    app.register_blueprint(forensic_evidence_bp)

    from api.forensic_pcap import forensic_pcap_bp
    app.register_blueprint(forensic_pcap_bp)

    from api.memberships import memberships_api_bp
    app.register_blueprint(memberships_api_bp)

    from api.compliance import compliance_api_bp
    app.register_blueprint(compliance_api_bp)

    from api.behavior_notifications import behavior_notif_api_bp
    app.register_blueprint(behavior_notif_api_bp)

    from api.engines import engines_api_bp
    app.register_blueprint(engines_api_bp)

    app.register_blueprint(main_bp)
