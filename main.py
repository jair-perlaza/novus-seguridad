"""
NOVUS - Modular Backend Architecture
Refactored for multi-tenant support and scalability
"""
import sys
import os
import socket
import threading
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _bootstrap_remote_proxy_env() -> None:
    """Aplica configuración de túnel ngrok/proxy antes de crear la app Flask."""
    import json
    ra_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "remote_access.json")
    if os.path.isfile(ra_path):
        try:
            with open(ra_path, "r", encoding="utf-8") as fh:
                info = json.load(fh)
            for key, val in (info.get("proxy_required_env") or {}).items():
                os.environ.setdefault(key, str(val))
            pub = info.get("public_url")
            if pub:
                os.environ.setdefault("NOVUS_PUBLIC_URL", pub)
        except Exception:
            pass
    # Desarrollo local HTTP: cookies Secure rompen CSRF/login en http://127.0.0.1:5000
    if os.environ.get("NOVUS_ENV", "development").strip().lower() == "development":
        os.environ["SESSION_COOKIE_SECURE"] = "False"
        os.environ["REMEMBER_COOKIE_SECURE"] = "False"
    # Enterprise perf default: do not auto-expose public tunnel unless explicitly enabled.
    if os.environ.get("NOVUS_AUTO_NGROK", "False").strip().lower() in ("1", "true", "yes", "on"):
        os.environ.setdefault("NOVUS_BEHIND_PROXY", "True")
        os.environ.setdefault("SESSION_COOKIE_SECURE", "True")
        os.environ.setdefault("PREFERRED_URL_SCHEME", "https")


_bootstrap_remote_proxy_env()

from core.app import create_app
from database import inicializar_db, ensure_tables_exist
from services.gmail_analyzer_service import start_background_gmail_sync
from models.user import User
from utils.logger import logger

NOVUS_ENV = os.environ.get('NOVUS_ENV', 'development')
app = create_app(NOVUS_ENV)

try:
    from services import http_abuse_guard as _hab

    _hab._windows.clear()
    _hab._circuit_open_until.clear()
    logger.info("HTTP abuse guard state cleared on startup")
except Exception as _hab_exc:
    logger.debug("http abuse guard reset: %s", _hab_exc)

# Ensure SQLite schema is available before serving requests
try:
    from services.db_at_rest_encryption import ensure_runtime_database

    _db_rest = ensure_runtime_database()
    logger.info("DB at-rest ensure: %s", _db_rest.get("action") or _db_rest)
except Exception as _db_rest_exc:
    logger.debug("DB at-rest ensure: %s", _db_rest_exc)

inicializar_db()
ensure_tables_exist()

def _deferred_db_migrate() -> None:
    try:
        from migrate_database import migrate_database
        migrate_database()
    except Exception as _mig_exc:
        logger.debug("migrate_database: %s", _mig_exc)


threading.Thread(target=_deferred_db_migrate, daemon=True, name="NovusDbMigrate").start()

from services.alert_reconciliation_service import reconcile_stale_security_alerts


def _deferred_startup_reconcile() -> None:
    try:
        result = reconcile_stale_security_alerts()
        logger.info("Reconciliación de alertas (background): %s", result)
    except Exception as exc:
        logger.warning("reconcile_stale_security_alerts: %s", exc)
    try:
        from services.runtime_environment_service import reconcile_runtime_environment_on_startup
        env_result = reconcile_runtime_environment_on_startup()
        logger.info("Huella de entorno de ejecución (background): %s", env_result)
    except Exception as exc:
        logger.warning("runtime_environment reconcile: %s", exc)


threading.Thread(target=_deferred_startup_reconcile, daemon=True, name="NovusStartupReconcile").start()

if NOVUS_ENV in ('production', 'beta') and not app.config.get('SECRET_KEY'):
    logger.warning(
        "SECRET_KEY no configurada — obligatoria para beta/producción remota. "
        "Defina SECRET_KEY en el entorno antes de exponer NOVUS."
    )


def _safe_boot(label: str, starter) -> None:
    try:
        result = starter()
        status = result.get("status") if isinstance(result, dict) else str(result)
        logger.info("%s: %s", label, status)
    except Exception as exc:
        logger.warning("%s boot: %s", label, exc)


def _start_services_staged() -> None:
    """Arranque escalonado por prioridad — P0 inmediato, P1 ligero, P2 pesado diferido.
    CLOUD-P1: NOVUS_RUNTIME=cloud omite auto-start Client-Node (LAN/ARP/YARA/Endpoint).
    """
    t0 = time.time()
    ngrok_enabled = os.environ.get("NOVUS_AUTO_NGROK", "False").strip().lower() in ("1", "true", "yes", "on")
    try:
        from services.cloud_runtime_service import is_cloud_runtime, runtime_info

        _cloud = is_cloud_runtime()
        if _cloud:
            logger.info("CLOUD-P1 runtime=cloud — skip Client-Node LAN/Endpoint auto-start %s", runtime_info())
    except Exception:
        _cloud = False

    try:
        from services.resource_backpressure_service import ensure_monitor_started

        ensure_monitor_started()
    except Exception as exc:
        logger.debug("backpressure monitor: %s", exc)

    # PRIORIDAD 0 — Flask ya activo; contexto de red + snapshots pending
    logger.info("Startup P0: network context + snapshots")
    try:
        from services.gmail_oauth_service import is_oauth_configured

        if is_oauth_configured():
            _safe_boot("Gmail background sync", start_background_gmail_sync)
        else:
            logger.info("Gmail background sync skipped — OAuth no configurado (fuera MVP)")
    except Exception as exc:
        logger.debug("Gmail sync gate: %s", exc)
    time.sleep(1.0)

    if _cloud:
        # Cloud API process: Auth/MFA/RBAC/API only — no ARP/Scapy/YARA/Endpoint loops.
        try:
            from services.security_snapshot_service import schedule_security_warmup

            schedule_security_warmup()
        except Exception as exc:
            logger.debug("security warmup schedule: %s", exc)
        logger.info(
            "Cloud staged boot complete in %.2fs (Client-Node engines not started)",
            time.time() - t0,
        )
        return

    try:
        from services.network_snapshot_service import bootstrap_network_context, bootstrap_initial_snapshots, set_boot_grace_period

        bootstrap_network_context()
        time.sleep(0.5)
        bootstrap_initial_snapshots()
        set_boot_grace_period(90.0)

        def _delayed_discovery_and_ready() -> None:
            time.sleep(90.0)
            try:
                from services.network_scan_coordinator import schedule_network_discovery
                from services.network_snapshot_service import mark_network_boot_ready
                from services.resource_backpressure_service import should_run_background, CAT_NETWORK

                if should_run_background(CAT_NETWORK):
                    schedule_network_discovery(consumer="boot_warmup", force=False)
                mark_network_boot_ready()
            except Exception as exc:
                logger.warning("delayed network discovery: %s", exc)
                try:
                    from services.network_snapshot_service import mark_network_boot_ready

                    mark_network_boot_ready()
                except Exception:
                    pass

        threading.Thread(target=_delayed_discovery_and_ready, daemon=True, name="NovusNetDiscoveryDelay").start()
    except Exception as exc:
        logger.warning("network snapshot bootstrap: %s", exc)

    def _delayed_p1_heavy() -> None:
        delay = float(os.environ.get("NOVUS_P1_HEAVY_DELAY_SEC", "90"))
        time.sleep(delay)
        logger.info("Startup P1b: shields + threat scanner + AI kernel (post-delay %.0fs)", delay)
        _safe_boot("NOVUS Web Shield", lambda: __import__("services.web_shield_engine", fromlist=["start_web_shield_engine"]).start_web_shield_engine())
        _safe_boot("NOVUS Mail Shield", lambda: __import__("services.mail_shield_engine", fromlist=["start_mail_shield_engine"]).start_mail_shield_engine())
        try:
            from services.novus_security_integration import start_background_threat_scanner

            _safe_boot("Background threat scanner", start_background_threat_scanner)
        except Exception as exc:
            logger.warning("Threat scanner boot: %s", exc)
        try:
            from services.ai_kernel import start_ai_kernel

            _safe_boot("AI Kernel", start_ai_kernel)
        except Exception as exc:
            logger.warning("AI Kernel boot: %s", exc)
        try:
            from services.lazy_engine_manager import start_if_needed

            _safe_boot("Endpoint realtime (lazy)", lambda: start_if_needed("endpoint_realtime"))
        except Exception as exc:
            logger.warning("Endpoint realtime boot: %s", exc)

        # CORE BETA detectors — one-shot via existing lazy_engine_manager (idempotent).
        # Not workers-per-request; not GET/login/dashboard. Honors backpressure inside start_if_needed.
        if os.environ.get("NOVUS_CORE_BETA_AUTO_START", "1").strip().lower() not in (
            "0",
            "false",
            "no",
            "off",
        ):
            try:
                from services.lazy_engine_manager import start_if_needed

                logger.info("Startup P1b: CORE BETA engines (endpoint_enterprise, btde, zdde)")
                _safe_boot("Endpoint Enterprise / YARA loop", lambda: start_if_needed("endpoint_enterprise"))
                # If lazy P2 backpressure blocked start, fall back to direct CORE starter once
                try:
                    from services.endpoint_enterprise import get_endpoint_enterprise_status, start_endpoint_enterprise

                    if not (get_endpoint_enterprise_status() or {}).get("active"):
                        _safe_boot("Endpoint Enterprise (direct CORE fallback)", start_endpoint_enterprise)
                except Exception as exc:
                    logger.warning("Endpoint Enterprise fallback: %s", exc)
                _safe_boot("BTDE", lambda: start_if_needed("btde"))
                try:
                    from services.behavioral_threat_detection import get_btde_orchestrator_status, start_btde

                    if not (get_btde_orchestrator_status() or {}).get("active"):
                        _safe_boot("BTDE (direct CORE fallback)", start_btde)
                except Exception as exc:
                    logger.warning("BTDE fallback: %s", exc)
                _safe_boot("ZDDE", lambda: start_if_needed("zdde"))
                try:
                    from services.zero_day_detection import get_zdde_orchestrator_status, start_zdde

                    if not (get_zdde_orchestrator_status() or {}).get("active"):
                        _safe_boot("ZDDE (direct CORE fallback)", start_zdde)
                except Exception as exc:
                    logger.warning("ZDDE fallback: %s", exc)
            except Exception as exc:
                logger.warning("CORE BETA lazy engines boot: %s", exc)
            try:
                from services.swarm_defense import swarm_defense_engine

                _safe_boot("Swarm Defense bus", swarm_defense_engine.start)
            except Exception as exc:
                logger.warning("Swarm Defense boot: %s", exc)

    threading.Thread(target=_delayed_p1_heavy, daemon=True, name="NovusP1HeavyDelay").start()

    time.sleep(1.0)
    try:
        from services.security_snapshot_service import schedule_security_warmup

        schedule_security_warmup()
    except Exception as exc:
        logger.debug("security warmup schedule: %s", exc)
    # Security summary: precalentado en background — HTTP solo lee snapshot/cache
    logger.info("Security snapshot warmup scheduled — HTTP reads snapshot/cache only")

    # PRIORIDAD 2 — Network Monitor + ensure CORE network path; P2b also started in P1b when enabled
    def _priority2_heavy() -> None:
        from services.resource_backpressure_service import should_run_background, CAT_NETWORK

        delay = float(os.environ.get("NOVUS_P2_HEAVY_DELAY_SEC", "60"))
        time.sleep(delay)
        logger.info("Startup P2a: Network Monitor (post boot-grace %.0fs)", delay)
        if should_run_background(CAT_NETWORK):
            try:
                from services.network_scanner import start_background_scanner

                start_background_scanner()
            except Exception as exc:
                logger.warning("Network Monitor boot: %s", exc)
        else:
            logger.warning("Startup P2a deferred — RAM backpressure")
        # Retry CORE endpoint group if P1b was blocked by transient backpressure
        if os.environ.get("NOVUS_CORE_BETA_AUTO_START", "1").strip().lower() not in (
            "0",
            "false",
            "no",
            "off",
        ):
            try:
                from services.lazy_engine_manager import start_if_needed

                _safe_boot("Endpoint realtime (P2 retry)", lambda: start_if_needed("endpoint_realtime"))
                _safe_boot("Endpoint Enterprise (P2 retry)", lambda: start_if_needed("endpoint_enterprise"))
            except Exception as exc:
                logger.warning("CORE BETA P2 retry: %s", exc)

    threading.Thread(target=_priority2_heavy, daemon=True, name="NovusPriority2Heavy").start()
    logger.info("Startup staged complete in %.2fs (P2 continues in background)", time.time() - t0)


# Start background services only in main process (prevent duplicate in debug reloader).
# FLASK_DEBUG="False" is a set env var — must not be treated as truthy (would skip staged boot).
_flask_debug_on = os.environ.get("FLASK_DEBUG", "False").strip().lower() in ("1", "true", "yes", "on")
if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not _flask_debug_on:
    threading.Thread(target=_start_services_staged, daemon=True, name="NovusStagedBoot").start()

if __name__ == '__main__':
    from services.process_singleton import acquire_singleton_or_exit

    acquire_singleton_or_exit(force=os.environ.get("NOVUS_FORCE_SINGLETON", "").lower() in ("1", "true", "yes"))
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    port = int(os.environ.get('PORT', app.config.get('PORT', 5000)))
    host = app.config.get('HOST', '0.0.0.0')
    wsgi_backend = os.environ.get('NOVUS_WSGI', 'waitress').strip().lower()
    logger.info("\n" + "=" * 50)
    logger.info("KERNEL NOVUS DESPLEGADO — nodo: %s", os.environ.get("NODE_ID", socket.gethostname()))
    logger.info("ENTORNO: %s", NOVUS_ENV)
    logger.info("ESPERANDO CONEXIONES EN EL PUERTO %s", port)
    logger.info("WSGI: %s", wsgi_backend)
    logger.info("PROXY INVERSO: %s", app.config.get("BEHIND_PROXY"))
    logger.info("URL PUBLICA: %s", app.config.get("PUBLIC_BASE_URL") or "(dinamica via Host del túnel)")
    logger.info("REGISTRO PUBLICO: %s", app.config.get("ALLOW_PUBLIC_REGISTRATION"))
    logger.info("ARQUITECTURA MODULAR ACTIVA")
    logger.info("MODO DEBUG: %s", debug_mode)
    logger.info("=" * 50 + "\n")
    if debug_mode and wsgi_backend != 'waitress':
        app.run(debug=debug_mode, host=host, port=port, use_reloader=debug_mode, threaded=True)
    else:
        try:
            from services.wsgi_server import serve_flask_app

            serve_flask_app(app, host=host, port=port)
        except ImportError:
            logger.warning("Waitress unavailable — falling back to Flask threaded server")
            app.run(debug=False, host=host, port=port, use_reloader=False, threaded=True)
