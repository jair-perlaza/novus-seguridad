"""
Configuration module for NOVUS
Centralized configuration management for multi-tenant support
"""
import os
import socket
from datetime import datetime, timedelta


class Config:
    """Base configuration class"""
    
    # Flask Configuration — SECRET_KEY se resuelve en create_app (env | archivo envuelto | generado).
    # Sin fallback hardcodeado conocido.
    SECRET_KEY = os.environ.get("SECRET_KEY") or "UNSET-RESOLVE-AT-RUNTIME"
    # Fail-safe: DEBUG off unless explicitly enabled (DevelopmentConfig still sets True).
    DEBUG = os.environ.get("DEBUG", "False").strip().lower() in ("1", "true", "yes", "on")
    
    # Server Configuration
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    # URL pública (túnel Cloudflare, ngrok, etc.) — sin barra final
    PUBLIC_BASE_URL = os.environ.get('NOVUS_PUBLIC_URL', '').rstrip('/')
    
    # Security Configuration
    # Sesión de navegador (no "remember me" de 30 días): al cerrar el navegador o expirar, exige Login.
    SESSION_PROTECTION = "strong"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=int(os.environ.get("NOVUS_SESSION_HOURS", "8")))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Base: respeta env; subclases fijan default enterprise (prod) vs local HTTP (dev).
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    # Remember-me desactivado: cookie con nombre versionado + duración 0 (ignora cookies antiguas)
    REMEMBER_COOKIE_NAME = os.environ.get("NOVUS_REMEMBER_COOKIE_NAME", "novus_remember_disabled")
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = os.environ.get(
        'REMEMBER_COOKIE_SECURE',
        os.environ.get('SESSION_COOKIE_SECURE', 'False'),
    ).lower() == 'true'
    REMEMBER_COOKIE_DURATION = timedelta(seconds=0)
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME', 'http')
    BEHIND_PROXY = os.environ.get('NOVUS_BEHIND_PROXY', 'False').lower() == 'true'
    TRUSTED_PROXY_COUNT = int(os.environ.get('NOVUS_TRUSTED_PROXY_COUNT', '1'))
    ALLOW_PUBLIC_REGISTRATION = os.environ.get('NOVUS_ALLOW_REGISTRATION', 'True').lower() == 'true'
    API_RATE_LIMIT = int(os.environ.get('NOVUS_API_RATE_LIMIT', '120'))
    LOGIN_RATE_LIMIT = int(os.environ.get('NOVUS_LOGIN_RATE_LIMIT', '15'))
    SENSITIVE_API_RATE_LIMIT = int(os.environ.get('NOVUS_SENSITIVE_API_RATE_LIMIT', '30'))
    API_JSON_MAX_BYTES = int(os.environ.get('NOVUS_API_JSON_MAX_BYTES', '1048576'))
    
    # Network Scanning Configuration
    # Network defaults are detected at runtime — never used as fallback scan targets.
    NETWORK_SCAN_INTERVAL = 60  # seconds
    NETWORK_SCAN_TIMEOUT = 5  # seconds
    # Even when force=True, avoid duplicate ARP scans back-to-back.
    NETWORK_FORCE_SCAN_MIN_INTERVAL = int(os.environ.get("NOVUS_FORCE_SCAN_MIN_INTERVAL", "15"))
    # Full port enrichment is expensive; allow quick forced ARP cycles between deep enrichments.
    NETWORK_FORCE_FULL_ENRICH_INTERVAL = int(os.environ.get("NOVUS_FORCE_FULL_ENRICH_INTERVAL", "90"))
    
    # Threat scanning configuration
    THREAT_SCAN_INTERVAL = 60  # seconds

    # Panel/read-path cache TTL (no reduce frecuencia de escaneos en background)
    PANEL_CACHE_TTL = 12  # sector shield, ASPE panel, topology
    PROCESS_CONN_CACHE_TTL = 60  # conteo conexiones (net_connections)
    COUNTERS_CACHE_TTL = 20  # platform counters agregados
    SOC_OVERVIEW_CACHE_TTL = 15  # soc get_overview
    HEALTH_STATUS_CACHE_TTL = 10  # health status snapshot API
    SECURITY_SUMMARY_CACHE_TTL = 12  # security summary API wrapper
    TIE_DASHBOARD_SNAPSHOT_STALE_SEC = int(os.environ.get("NOVUS_TIE_SNAPSHOT_STALE_SEC", "90"))
    SOPE_DASHBOARD_SNAPSHOT_STALE_SEC = int(os.environ.get("NOVUS_SOPE_SNAPSHOT_STALE_SEC", "60"))
    IMCM_DASHBOARD_SNAPSHOT_STALE_SEC = int(os.environ.get("NOVUS_IMCM_SNAPSHOT_STALE_SEC", "45"))
    IMCM_TIMELINE_SNAPSHOT_STALE_SEC = int(os.environ.get("NOVUS_IMCM_TIMELINE_STALE_SEC", "45"))

    # Gmail OAuth 2.0 (official API — never store passwords)
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
    GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', '')
    GMAIL_SYNC_INTERVAL = int(os.environ.get('GMAIL_SYNC_INTERVAL', 120))

    # AI Kernel Configuration
    AI_KERNEL_INTERVAL = 10  # seconds
    CPU_CRITICAL_THRESHOLD = 85
    MEMORY_CRITICAL_THRESHOLD = 90
    
    # Multi-tenant Configuration
    MAX_CONCURRENT_PYMES = 50
    ENABLE_MULTI_TENANT = True
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    
    # Application Metadata
    APP_NAME = "NOVUS"
    VERSION = "2.0.0"
    NODE_ID = os.environ.get('NODE_ID') or socket.gethostname()
    
    @staticmethod
    def get_timestamp():
        """Get current timestamp in standard format"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class DevelopmentConfig(Config):
    """Development — HTTP local: Secure=False salvo override explícito."""
    DEBUG = True
    LOG_LEVEL = "DEBUG"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
    REMEMBER_COOKIE_SECURE = os.environ.get(
        "REMEMBER_COOKIE_SECURE",
        os.environ.get("SESSION_COOKIE_SECURE", "False"),
    ).lower() == "true"
    PREFERRED_URL_SCHEME = os.environ.get("PREFERRED_URL_SCHEME", "http")


class ProductionConfig(Config):
    """Production — cookies Secure por defecto (HTTPS); override con SESSION_COOKIE_SECURE=False."""
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    LOG_LEVEL = "INFO"
    ALLOW_PUBLIC_REGISTRATION = os.environ.get('NOVUS_ALLOW_REGISTRATION', 'False').lower() == 'true'
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "True").lower() == "true"
    REMEMBER_COOKIE_SECURE = os.environ.get(
        "REMEMBER_COOKIE_SECURE",
        os.environ.get("SESSION_COOKIE_SECURE", "True"),
    ).lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    PREFERRED_URL_SCHEME = os.environ.get("PREFERRED_URL_SCHEME", "https")
    BEHIND_PROXY = os.environ.get("NOVUS_BEHIND_PROXY", "True").lower() == "true"


class BetaConfig(ProductionConfig):
    """Beta privada remota — registro público deshabilitado por defecto."""
    ALLOW_PUBLIC_REGISTRATION = os.environ.get('NOVUS_ALLOW_REGISTRATION', 'False').lower() == 'true'


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'beta': BetaConfig,
    'default': DevelopmentConfig
}


def get_config(env='default'):
    """Get configuration based on environment"""
    return config.get(env, config['default'])
