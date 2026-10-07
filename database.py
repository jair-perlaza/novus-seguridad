from sqlalchemy import Column, Integer, String, create_engine, Boolean, Text, Float, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from typing import Optional
import hashlib
import re
from collections import defaultdict
import time

Base = declarative_base()

# --- MODELO DE USUARIOS ---
class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    intentos_fallidos = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    is_temporal = Column(Boolean, default=False)
    trial_expiry = Column(String, nullable=True)
    sector = Column(String, nullable=True)
    nit_pyme = Column(String, nullable=True)
    role = Column(String, default="analyst", index=True)


class RegistrationRequest(Base):
    """Solicitud de registro empresarial — requiere aprobación del administrador principal."""
    __tablename__ = "registration_requests"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    company_name = Column(String)
    nit = Column(String, index=True)
    sector = Column(String, nullable=True)
    servicio = Column(String, nullable=True)
    empleados = Column(String, nullable=True)
    infra_json = Column(Text, nullable=True)
    status = Column(String, default="pending", index=True)  # pending | approved | rejected | completed
    setup_token = Column(String, nullable=True, index=True)
    token_expires_at = Column(String, nullable=True)
    approved_by = Column(String, nullable=True)
    approved_at = Column(String, nullable=True)
    rejected_by = Column(String, nullable=True)
    rejected_at = Column(String, nullable=True)
    rejection_reason = Column(String, nullable=True)
    request_ip = Column(String, nullable=True)
    created_at = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# --- MODELO DE SEGURIDAD (Para Centro de Amenazas / IPS Bloqueadas) ---
class IPBloqueada(Base):
    __tablename__ = "ips_bloqueadas"
    id = Column(Integer, primary_key=True, index=True)
    direccion_ip = Column(String, unique=True)
    razon = Column(String, nullable=True)
    blocked_at = Column(String, nullable=True)
    blocked_until = Column(String, nullable=True)
    failed_attempts = Column(Integer, default=0)
    target_email = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    os_name = Column(String, nullable=True)
    block_reason = Column(String, nullable=True)
    evidence_json = Column(Text, nullable=True)
    recurrence_count = Column(Integer, default=0)
    requires_admin_review = Column(Boolean, default=False)
    status = Column(String, default="active")

# --- NUEVO: MODELO DE VULNERABILIDADES ---
class TenantMonitoringScope(Base):
    """Alcance de monitoreo por empresa — aislamiento multi-tenant."""
    __tablename__ = "tenant_monitoring_scope"
    tenant_id = Column(String, primary_key=True, index=True)
    monitoring_enabled = Column(Boolean, default=True)
    node_id = Column(String, nullable=True)
    monitoring_mode = Column(String, default="none")  # none | platform_node | agent
    configured_at = Column(String, nullable=True)
    updated_at = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


class Vulnerabilidad(Base):
    __tablename__ = "vulnerabilidades"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    titulo = Column(String) # Cambiado de nombre a titulo para consistencia
    descripcion = Column(Text, nullable=True)
    nivel = Column(String, default="medium") # low, medium, high, critical
    severidad = Column(String, default="media") # Crítica, Alta, Media, Baja
    estado = Column(String, default="abierto") # abierto, cerrado, mitigado
    componente = Column(String, nullable=True) # componente afectado
    fecha = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# --- NUEVO: MODELO DE ALERTAS (Para el Historial de Alertas) ---
class Alerta(Base):
    __tablename__ = "alertas"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    titulo = Column(String)
    descripcion = Column(Text)
    nivel = Column(String) # Info, Warning, Critical
    fecha = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    ip_afectada = Column(String, nullable=True) # IP asociada a la alerta
    recomendacion = Column(Text, nullable=True) # Recomendación de seguridad
    motor = Column(String, nullable=True)
    fuente = Column(String, nullable=True)
    confianza = Column(String, nullable=True)
    estado = Column(String, default="activo")
    estado_remediacion = Column(String, nullable=True)
    evidencia_json = Column(Text, nullable=True)
    acciones_json = Column(Text, nullable=True)
    activa = Column(Boolean, default=True)

# --- MODELO DE ACCESO POR SECTOR ---
class SectorAcceso(Base):
    __tablename__ = "sector_acceso"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    sector = Column(String, index=True)
    dispositivo_id = Column(String, index=True)
    dispositivo_fingerprint = Column(String)
    fecha_registro = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"))
    ultimo_acceso = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"))
    is_active = Column(Boolean, default=True)

# --- MODELO DE DISPOSITIVOS CONFIADOS ---
class DispositivoConfiado(Base):
    __tablename__ = "dispositivos_confiados"
    id = Column(Integer, primary_key=True, index=True)
    usuario_email = Column(String, index=True)
    dispositivo_id = Column(String, unique=True, index=True)
    fingerprint = Column(String)
    user_agent = Column(String)
    ip_address = Column(String)
    fecha_registro = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"))
    is_active = Column(Boolean, default=True)

# --- MODELO DE INTENTOS DE ACCESO NO AUTORIZADOS ---
class IntentoAcceso(Base):
    __tablename__ = "intentos_acceso"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String)
    sector_intentado = Column(String)
    dispositivo_id = Column(String)
    ip_address = Column(String)
    user_agent = Column(String)
    fecha = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"))
    razon_bloqueo = Column(String)
    alerta_generada = Column(Boolean, default=False)


class AuthAccessEvent(Base):
    """Auditoría de cada intento de autenticación (éxito o fallo)."""
    __tablename__ = "auth_access_events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"), index=True)
    ip_address = Column(String, index=True)
    email = Column(String, nullable=True, index=True)
    device_fingerprint = Column(String, index=True)
    session_id = Column(String, nullable=True, index=True)
    user_agent = Column(String, nullable=True)
    route = Column(String, default="login")
    success = Column(Boolean, default=False)
    sanction_level = Column(Integer, default=0)
    incident_id = Column(String, nullable=True, index=True)
    evidence_json = Column(Text, nullable=True)


class AuthOriginSanction(Base):
    """Sanciones por origen (IP, dispositivo o sesión) — no bloquea la API global."""
    __tablename__ = "auth_origin_sanctions"
    id = Column(Integer, primary_key=True, index=True)
    origin_type = Column(String, index=True)  # ip | device | session
    origin_key = Column(String, index=True)
    sanction_level = Column(Integer, default=1)
    failed_attempts = Column(Integer, default=0)
    recurrence_count = Column(Integer, default=0)
    blocked_until = Column(String, nullable=True, index=True)
    incident_id = Column(String, nullable=True, index=True)
    status = Column(String, default="active", index=True)  # active | expired | revoked
    reason = Column(String, nullable=True)
    evidence_json = Column(Text, nullable=True)
    created_at = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    updated_at = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


class LoginSessionAudit(Base):
    """Historial de sesiones — auditoría de acceso y verificación post-login."""
    __tablename__ = "login_session_audits"
    id = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    user_id = Column(Integer, nullable=True, index=True)
    user_email = Column(String, index=True)
    login_at = Column(String, index=True)
    logout_at = Column(String, nullable=True, index=True)
    duration_seconds = Column(Integer, nullable=True)
    ip_address = Column(String, index=True)
    session_id = Column(String, index=True)
    os_name = Column(String, nullable=True)
    browser = Column(String, nullable=True)
    device_type = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    login_result = Column(String, default="success", index=True)
    attempt_count = Column(Integer, default=1)
    config_fingerprint = Column(String, nullable=True)
    security_status = Column(String, default="pending", index=True)
    post_login_check_json = Column(Text, nullable=True)
    risks_json = Column(Text, nullable=True)
    actions_json = Column(Text, nullable=True)
    active = Column(Boolean, default=True, index=True)
    auth_access_event_id = Column(Integer, nullable=True)


class MfaTotpCredential(Base):
    """
    CLOUD-P0 — MFA TOTP persistente en DB (compartible multi-instancia).
    Secretos siempre cifrados (Fernet); nunca plaintext.
    """
    __tablename__ = "mfa_totp_credentials"
    email = Column(String, primary_key=True, index=True)
    secret_enc = Column(Text, nullable=True)
    pending_secret_enc = Column(Text, nullable=True)
    enabled = Column(Boolean, default=False, index=True)
    recovery_hashes_json = Column(Text, nullable=True)
    pending_at_utc = Column(String, nullable=True)
    enrolled_at_utc = Column(String, nullable=True)
    updated_at_utc = Column(String, nullable=True)
    disabled_at_utc = Column(String, nullable=True)
    policy_locked = Column(Boolean, default=False)

# --- MODELO DE PLAYBOOKS (Automatización) ---
class Playbook(Base):
    __tablename__ = "playbooks"
    id = Column(String, primary_key=True, index=True)
    nombre = Column(String, nullable=False)
    trigger = Column(String, nullable=False)
    accion = Column(String, nullable=False)
    prioridad = Column(String, default="Medio")
    estado = Column(String, default="Activo")
    reglas_asociadas = Column(Text, nullable=True)
    remediaciones_asociadas = Column(Text, nullable=True)
    automatizaciones_asociadas = Column(Text, nullable=True)
    kernel_respuestas = Column(Text, nullable=True)
    ejecuciones = Column(Integer, default=0)
    fecha_creacion = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    fecha_actualizacion = Column(String, nullable=True)


class PlaybookExecution(Base):
    """Historial auditable de ejecuciones de playbooks."""
    __tablename__ = "playbook_executions"
    id = Column(String, primary_key=True, index=True)
    playbook_id = Column(String, index=True, nullable=False)
    playbook_nombre = Column(String, nullable=False)
    usuario = Column(String, nullable=True)
    estado = Column(String, default="exitoso")
    nivel_exito = Column(String, default="Medio")
    trigger_met = Column(Boolean, default=True)
    duracion_ms = Column(Integer, default=0)
    resultado = Column(Text, nullable=True)
    acciones_json = Column(Text, nullable=True)
    motores_json = Column(Text, nullable=True)
    report_id = Column(String, nullable=True, index=True)
    fecha = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# --- MODELO DE AUDITORÍA ---
class Log(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    evento = Column(String, index=True)
    detalle = Column(String) 
    fecha = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"), index=True)


class MotorTelemetryEvent(Base):
    """Telemetría verificable de motores (Dashboard / monitoreo post-login)."""
    __tablename__ = "motor_telemetry_events"
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, index=True)
    session_id = Column(String, index=True)
    motor_id = Column(String, index=True)
    motor_label = Column(String)
    status = Column(String, index=True)  # running | completed | failed
    started_at = Column(String, nullable=True)
    finished_at = Column(String, nullable=True)
    duration_sec = Column(Float, nullable=True)
    elements_analyzed = Column(Text, nullable=True)
    result = Column(String, nullable=True)
    evidence_json = Column(Text, nullable=True)
    errors_json = Column(Text, nullable=True)
    progress_pct = Column(Integer, nullable=True)
    created_at = Column(String, index=True)


class NetworkDeviceInventory(Base):
    """Inventario persistente de dispositivos — gestionado por Asset Intelligence Engine (AIE)."""
    __tablename__ = "network_device_inventory"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    mac = Column(String, index=True)
    ip = Column(String, index=True)
    hostname = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    device_type = Column(String, nullable=True)
    os_estimate = Column(String, nullable=True)
    first_seen = Column(String)
    last_seen = Column(String)
    times_seen = Column(Integer, default=1)
    is_known = Column(Boolean, default=False)
    risk_level = Column(String, default="observacion")
    history_json = Column(Text, nullable=True)
    last_open_ports_json = Column(Text, nullable=True)
    services_json = Column(Text, nullable=True)
    network_segment = Column(String, nullable=True)
    asset_status = Column(String, default="pendiente_aprobacion")
    trust_score = Column(Integer, default=45)
    learning_json = Column(Text, nullable=True)
    classification_reason = Column(Text, nullable=True)
    admin_action = Column(String, nullable=True)
    admin_action_by = Column(String, nullable=True)
    admin_action_at = Column(String, nullable=True)
    admin_tag = Column(String, nullable=True)
    admin_notes = Column(Text, nullable=True)


class PlatformEvidence(Base):
    """Centro de Evidencias — trazabilidad unificada de acciones y detecciones NOVUS."""
    __tablename__ = "platform_evidences"
    id = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    fecha = Column(String, index=True)
    hora = Column(String, index=True)
    timestamp = Column(String, index=True)
    motor = Column(String, index=True)
    categoria = Column(String, index=True)
    descripcion = Column(Text)
    nivel_riesgo = Column(String, index=True)
    nivel_confianza = Column(String, nullable=True)
    estado = Column(String, index=True, default="registrado")
    accion_ejecutada = Column(String, nullable=True)
    resultado = Column(String, nullable=True)
    source_event_id = Column(String, index=True, nullable=True)
    evidence_json = Column(Text, nullable=True)
    created_at = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


class DeviceConnectionEvent(Base):
    """Historial permanente de conexión/desconexión de dispositivos de red (evidencia ARP/AIE)."""
    __tablename__ = "device_connection_events"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    event_type = Column(String, index=True)  # connect | disconnect | ip_change | hostname_change | behavior_change
    timestamp = Column(String, index=True, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    ip_address = Column(String, index=True, nullable=True)
    mac_address = Column(String, index=True, nullable=True)
    hostname = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    device_type = Column(String, nullable=True)
    asset_status = Column(String, nullable=True)
    trust_score = Column(Integer, nullable=True)
    risk_level = Column(String, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    evidence_json = Column(Text, nullable=True)


class WebShieldEvent(Base):
    """Eventos reales del motor NOVUS Web Shield (URL, descargas, configuración host)."""
    __tablename__ = "web_shield_events"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    event_type = Column(String, index=True)
    severity = Column(String, index=True, default="info")
    action_taken = Column(String, nullable=True)
    domain = Column(String, index=True, nullable=True)
    url = Column(String, nullable=True)
    risk_score = Column(Integer, nullable=True)
    timestamp = Column(String, index=True, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    evidence_json = Column(Text, nullable=True)
    created_at = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


class MailShieldEvent(Base):
    """Eventos verificables NOVUS Mail Shield (correo autorizado vía API oficial)."""
    __tablename__ = "mail_shield_events"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    provider = Column(String, index=True)
    mailbox_user_id = Column(String, index=True, nullable=True)
    message_id = Column(String, index=True, nullable=True)
    event_type = Column(String, index=True)
    severity = Column(String, index=True, default="info")
    action_taken = Column(String, nullable=True)
    subject = Column(String, nullable=True)
    sender = Column(String, index=True, nullable=True)
    risk_score = Column(Integer, nullable=True)
    timestamp = Column(String, index=True, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    evidence_json = Column(Text, nullable=True)
    created_at = Column(String, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


class MailShieldQuarantine(Base):
    """Cuarentena Mail Shield — correos/adjuntos con evidencia."""
    __tablename__ = "mail_shield_quarantine"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    provider = Column(String, index=True)
    message_id = Column(String, index=True, nullable=True)
    item_type = Column(String, index=True)
    reason = Column(String, nullable=True)
    mailbox_user_id = Column(String, nullable=True)
    affected_user = Column(String, nullable=True)
    action_taken = Column(String, nullable=True)
    timestamp = Column(String, index=True, default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    evidence_json = Column(Text, nullable=True)


# --- NOVUS THREAT INTELLIGENCE CENTER — Expedientes de casos ---
class InteligenciaCaso(Base):
    __tablename__ = "inteligencia_casos"
    id = Column(String, primary_key=True, index=True)
    fecha = Column(String, index=True)
    hora = Column(String)
    empresa = Column(String, index=True, nullable=True)
    usuario = Column(String, index=True, nullable=True)
    equipo = Column(String, index=True, nullable=True)
    sistema_operativo = Column(String, nullable=True)
    sector = Column(String, index=True, nullable=True)
    tipo = Column(String, index=True)
    nivel_riesgo = Column(String, index=True)
    estado = Column(String, index=True, default="abierto")
    evidencia_json = Column(Text, nullable=True)
    motores_json = Column(Text, nullable=True)
    hallazgos_json = Column(Text, nullable=True)
    reglas_json = Column(Text, nullable=True)
    acciones_json = Column(Text, nullable=True)
    tiempo_respuesta_sec = Column(String, nullable=True)
    resultado = Column(Text, nullable=True)
    recomendaciones_json = Column(Text, nullable=True)
    lecciones_json = Column(Text, nullable=True)
    correlacion_grupo = Column(String, index=True, nullable=True)
    source_ref = Column(String, index=True, nullable=True)
    keywords = Column(Text, nullable=True)
    created_at = Column(String)
    updated_at = Column(String)


class InteligenciaTimeline(Base):
    __tablename__ = "inteligencia_timeline"
    id = Column(Integer, primary_key=True, index=True)
    caso_id = Column(String, index=True)
    timestamp = Column(String)
    evento = Column(String)
    detalle = Column(Text, nullable=True)
    orden = Column(Integer, default=0)


class InteligenciaPropuesta(Base):
    __tablename__ = "inteligencia_propuestas"
    id = Column(Integer, primary_key=True, index=True)
    caso_id = Column(String, index=True)
    propuesta = Column(Text)
    estado = Column(String, default="pendiente")
    fecha = Column(String)


# --- NOVUS Digital Case Intelligence (NDCI) — expedientes inmutables ---
class NdciCaso(Base):
    __tablename__ = "ndci_casos"
    id = Column(String, primary_key=True, index=True)
    fecha = Column(String, index=True)
    hora = Column(String)
    usuario = Column(String, index=True, nullable=True)
    sector = Column(String, index=True, nullable=True)
    origen = Column(String, index=True)
    source_ref = Column(String, index=True, nullable=True)
    titulo = Column(String)
    nivel_riesgo = Column(String, index=True)
    duracion_sec = Column(String, nullable=True)
    expediente_json = Column(Text)
    pdf_path = Column(String, nullable=True)
    intel_case_id = Column(String, nullable=True)
    keywords = Column(Text, nullable=True)
    created_at = Column(String)


class EndpointScanRecord(Base):
    __tablename__ = "endpoint_scan_records"
    id = Column(String, primary_key=True, index=True)
    scan_id = Column(String, index=True)
    mode = Column(String, index=True)
    profile = Column(String)
    status = Column(String, index=True)
    hostname = Column(String)
    started_at = Column(String, index=True)
    finished_at = Column(String, nullable=True)
    findings_json = Column(Text)
    stats_json = Column(Text)
    report_summary = Column(Text, nullable=True)


class EndpointMonitorEvent(Base):
    __tablename__ = "endpoint_monitor_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String, index=True)
    severity = Column(String, index=True)
    detail_json = Column(Text)
    timestamp = Column(String, index=True)


class EndpointQuarantineRecord(Base):
    __tablename__ = "endpoint_quarantine"
    id = Column(String, primary_key=True, index=True)
    original_path = Column(Text)
    quarantine_path = Column(Text)
    sha256 = Column(String, index=True)
    action = Column(String, index=True)
    status = Column(String, index=True)
    requested_by = Column(String, nullable=True)
    created_at = Column(String, index=True)
    evidence_json = Column(Text)


class ManualDefenseRun(Base):
    __tablename__ = "manual_defense_runs"
    id = Column(String, primary_key=True, index=True)
    user_email = Column(String, index=True)
    hostname = Column(String)
    client_ip = Column(String)
    started_at = Column(String, index=True)
    finished_at = Column(String, nullable=True)
    duration_sec = Column(String, nullable=True)
    mechanisms_json = Column(Text)
    findings_json = Column(Text)
    evidence_json = Column(Text)
    actions_json = Column(Text)
    report_json = Column(Text)
    report_id = Column(String, nullable=True, index=True)


# Configuración del motor NOVUS — CLOUD-P0: DATABASE_URL opcional (PostgreSQL);
# por defecto SQLite local intacto (no migración automática, no destructivo).
import os as _os

def _resolve_database_url() -> str:
    raw = (_os.environ.get("DATABASE_URL") or "").strip()
    if raw:
        # SQLAlchemy 2 + psycopg3: postgresql+psycopg://...
        if raw.startswith("postgres://"):
            raw = "postgresql://" + raw[len("postgres://") :]
        return raw
    return "sqlite:///./novus_vault_v2.db"


DATABASE_URL = _resolve_database_url()
DB_BACKEND = (
    "postgresql"
    if DATABASE_URL.startswith("postgresql")
    else ("sqlite" if DATABASE_URL.startswith("sqlite") else "other")
)

# SQLite: pocas conexiones reales — pool grande aumenta contención de locks bajo Waitress.
# timeout/busy_timeout cortos: fallar/reintentar rápido en vez de colgar workers 60s (causa timeouts HTTP).
_SQLITE_BUSY_MS = int(_os.environ.get("NOVUS_SQLITE_BUSY_TIMEOUT_MS", "5000"))
_SQLITE_CONNECT_TIMEOUT = float(_os.environ.get("NOVUS_SQLITE_CONNECT_TIMEOUT_SEC", "5"))
# Lecturas concurrentes bajo WAL: pool demasiado pequeño (8) hace que Waitress espere checkout → timeouts HTTP
_SQLITE_POOL = int(_os.environ.get("NOVUS_SQLITE_POOL_SIZE", "16"))
_SQLITE_OVERFLOW = int(_os.environ.get("NOVUS_SQLITE_MAX_OVERFLOW", "16"))
_PG_POOL = int(_os.environ.get("NOVUS_PG_POOL_SIZE", "5"))
_PG_OVERFLOW = int(_os.environ.get("NOVUS_PG_MAX_OVERFLOW", "10"))


def _build_engine():
    if DB_BACKEND == "sqlite":
        return create_engine(
            DATABASE_URL,
            connect_args={"check_same_thread": False, "timeout": _SQLITE_CONNECT_TIMEOUT},
            pool_size=max(2, _SQLITE_POOL),
            max_overflow=max(0, _SQLITE_OVERFLOW),
            pool_pre_ping=True,
            pool_recycle=1800,
        )
    # PostgreSQL / otros dialectos SQLAlchemy — sin PRAGMAs SQLite.
    return create_engine(
        DATABASE_URL,
        pool_size=max(1, _PG_POOL),
        max_overflow=max(0, _PG_OVERFLOW),
        pool_pre_ping=True,
        pool_recycle=1800,
    )


engine = _build_engine()


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    if DB_BACKEND != "sqlite":
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute(f"PRAGMA busy_timeout={_SQLITE_BUSY_MS}")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA temp_store=MEMORY")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA mmap_size=268435456")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def database_backend_info() -> dict:
    """Introspección segura (sin credenciales) para ops / CLOUD-P0."""
    url = DATABASE_URL
    safe = url
    if "@" in url:
        # ocultar userinfo
        try:
            scheme, rest = url.split("://", 1)
            if "@" in rest:
                rest = rest.split("@", 1)[1]
                safe = f"{scheme}://***@{rest}"
        except Exception:
            safe = f"{DB_BACKEND}://***"
    return {"backend": DB_BACKEND, "url_safe": safe}


# ==================== CAPA ULTRA SEGURA PARA BASE DE DATOS ====================

class DatabaseSecurityLayer:
    """
    Ultra-secure database layer with:
    - SQL injection protection
    - SHA256 hashing
    - Rate limiting
    - Input validation
    - Query monitoring
    - Access auditing
    """
    
    _instance = None
    _rate_limit_buckets = defaultdict(lambda: {"tokens": 100.0, "last_refill": time.time()})
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
    
    @staticmethod
    def sanitize_and_validate_query(user_input: str, context: str = "GENERAL") -> dict:
        """
        Sanitize and validate user input to prevent SQL injection
        Uses the same logic as security_engine.sanitize_and_validate_query
        """
        sqli_risk = 0.0
        malicious_patterns = []
        
        sqli_signatures = {
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)": "Detección de caracteres de escape/comentarios",
            r"(?i)\b(UNION|SELECT|INSERT|DELETE|DROP|UPDATE|ALTER|CREATE|TRUNCATE)\b": "Inyección de comandos DDL/DML",
            r"(?i)\b(OR|AND)\b\s+(['\"]?\d?['\"]?)\s*=\s*\2": "Tautología detectada (ej. 1=1)",
            r"(?i)SLEEP\(|WAITFOR\s+DELAY|BENCHMARK\(": "Ataque de SQLi basado en tiempo (Blind SQLi)"
        }
        
        for pattern, description in sqli_signatures.items():
            if re.search(pattern, user_input):
                sqli_risk += 0.45
                malicious_patterns.append(description)
        
        if re.search(r"(?i)0x[0-9a-fA-F]+|CHAR\(", user_input):
            sqli_risk += 0.50
            malicious_patterns.append("Uso de codificación sospechosa (Hex/Char)")
        
        if len(user_input) > 100 and context != "COMMENTS":
            sqli_risk += 0.20
            malicious_patterns.append("Longitud de entrada excesiva para el contexto.")
        
        if sqli_risk >= 0.60:
            action = "BLOCK_AND_REPORT"
            status = "ATAQUE DETECTADO: Intento de Inyección SQL"
            clean_input = None
        elif sqli_risk >= 0.30:
            action = "STRIP_SPECIAL_CHARS"
            status = "ADVERTENCIA: Caracteres sospechosos removidos"
            clean_input = re.sub(r"[^a-zA-Z0-9@\.]", "", user_input)
        else:
            return {"status": "SAFE", "data": user_input}
        
        return {
            "status": "INTERCEPTED",
            "log": {
                "time": datetime.now().strftime("%H:%M:%S"),
                "incident": "SQL Injection Attempt",
                "risk_score": f"{sqli_risk*100:.0f}%",
                "detected_patterns": malicious_patterns,
                "action": action
            },
            "cleaned_data": clean_input
        }
    
    @staticmethod
    def hash_sha256(data: str) -> str:
        """Generate SHA256 hash for sensitive data"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def validate_input_length(input_data: str, max_length: int = 100) -> bool:
        """Validate input length to prevent buffer overflow attacks"""
        return len(input_data) <= max_length
    
    @staticmethod
    def validate_email_format(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @classmethod
    def reset_rate_limit_buckets(cls) -> None:
        """Limpia token buckets in-memory — benchmark / diagnóstico."""
        cls._rate_limit_buckets.clear()

    @classmethod
    def check_rate_limit(cls, identifier: str, max_requests: int = 100, window_seconds: int = 60) -> dict:
        """
        Check rate limit for database operations
        Uses token bucket algorithm
        """
        now = time.time()
        bucket = cls._rate_limit_buckets[identifier]
        
        time_passed = now - bucket["last_refill"]
        bucket["tokens"] = min(max_requests, bucket["tokens"] + (time_passed * max_requests / window_seconds))
        bucket["last_refill"] = now
        
        if bucket["tokens"] >= 1.0:
            bucket["tokens"] -= 1.0
            return {"status": "ALLOWED", "remaining_tokens": int(bucket["tokens"])}
        else:
            return {
                "status": "RATE_LIMITED",
                "message": "Too many requests. Please try again later.",
                "retry_after": int(window_seconds / max_requests)
            }
    
    @staticmethod
    def audit_query(query: str, params: dict, user: str = "unknown"):
        """
        Audit database queries for security monitoring
        Logs suspicious query patterns
        """
        suspicious_keywords = ["DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT", "REVOKE"]
        query_upper = query.upper()
        
        for keyword in suspicious_keywords:
            if keyword in query_upper:
                # Log suspicious query
                from database import Log
                db = SessionLocal()
                try:
                    log = Log(
                        evento=f"SUSPICIOUS_QUERY_{keyword}",
                        detalle=f"Query: {query[:200]}... | User: {user} | Params: {str(params)[:100]}",
                        fecha=datetime.now().strftime("%Y-%m-%d %H:%M")
                    )
                    db.add(log)
                    db.commit()
                except:
                    db.rollback()
                finally:
                    db.close()
                break


class BehaviorActivityEvent(Base):
    """Evento real de actividad del cliente — Behavior Baseline Engine (SQL)."""
    __tablename__ = "behavior_activity_events"
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, unique=True, index=True)
    user_email = Column(String, index=True, nullable=False)
    tenant_id = Column(String, index=True, nullable=True)
    event_type = Column(String, index=True, nullable=False)  # login | logout | scan | network_change | ...
    event_date = Column(String, index=True)
    event_time = Column(String, index=True)
    recorded_at = Column(String, index=True)
    equipment = Column(String, nullable=True)
    ip_address = Column(String, nullable=True, index=True)
    network_scope = Column(String, nullable=True, index=True)
    gateway = Column(String, nullable=True)
    dns_json = Column(Text, nullable=True)
    location_approx = Column(String, nullable=True)
    os_name = Column(String, nullable=True)
    os_version = Column(String, nullable=True)
    browser = Column(String, nullable=True)
    session_audit_id = Column(String, index=True, nullable=True)
    session_duration_sec = Column(Integer, nullable=True)
    risk_level = Column(String, nullable=True)
    mechanisms_json = Column(Text, nullable=True)
    devices_json = Column(Text, nullable=True)
    processes_sample_json = Column(Text, nullable=True)
    services_sample_json = Column(Text, nullable=True)
    apps_sample_json = Column(Text, nullable=True)
    alerts_count = Column(Integer, default=0)
    incidents_count = Column(Integer, default=0)
    scans_count = Column(Integer, default=0)
    evidence_json = Column(Text, nullable=True)
    source_motor = Column(String, nullable=True)


class BehaviorBaselineProfile(Base):
    """Línea base aprendida por usuario — solo datos históricos reales."""
    __tablename__ = "behavior_baseline_profiles"
    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, unique=True, index=True, nullable=False)
    tenant_id = Column(String, index=True, nullable=True)
    events_count = Column(Integer, default=0)
    enough_data = Column(Boolean, default=False)
    normality_score = Column(Float, nullable=True)  # 0-100
    anomaly_score = Column(Float, nullable=True)  # 0-100
    profile_json = Column(Text, nullable=True)
    recommendations_json = Column(Text, nullable=True)
    built_at = Column(String, nullable=True)
    updated_at = Column(String, index=True)


class BehaviorAnomaly(Base):
    """Anomalía detectada contra la línea base real del cliente."""
    __tablename__ = "behavior_anomalies"
    id = Column(Integer, primary_key=True, index=True)
    anomaly_id = Column(String, unique=True, index=True)
    user_email = Column(String, index=True, nullable=False)
    tenant_id = Column(String, index=True, nullable=True)
    anomaly_type = Column(String, index=True)
    severity = Column(String, index=True)  # info | warning | high | critical
    title = Column(String)
    description = Column(Text)
    observed_value = Column(String, nullable=True)
    baseline_value = Column(String, nullable=True)
    evidence_json = Column(Text, nullable=True)
    activity_event_id = Column(String, nullable=True, index=True)
    status = Column(String, default="open", index=True)
    detected_at = Column(String, index=True)
    source_motor = Column(String, default="behavior_baseline_engine")


class NovusNotification(Base):
    """Centro de Notificaciones / Eventos Inteligentes — solo eventos reales."""
    __tablename__ = "novus_notifications"
    id = Column(Integer, primary_key=True, index=True)
    notification_id = Column(String, unique=True, index=True)
    user_email = Column(String, index=True, nullable=True)  # None = broadcast plataforma
    tenant_id = Column(String, index=True, nullable=True)
    category = Column(String, index=True)  # seguridad, amenazas, kernel_ia, ...
    priority = Column(String, index=True)  # info | warning | high | critical
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="unread", index=True)  # unread | read | archived
    related_user = Column(String, nullable=True)
    related_equipment = Column(String, nullable=True)
    detail_url = Column(String, nullable=True)
    incident_url = Column(String, nullable=True)
    source_motor = Column(String, index=True, nullable=True)
    source_ref = Column(String, nullable=True, index=True)
    event_date = Column(String, index=True)
    event_time = Column(String, index=True)
    created_at = Column(String, index=True)
    read_at = Column(String, nullable=True)
    archived_at = Column(String, nullable=True)
    payload_json = Column(Text, nullable=True)


# Global database security instance
db_security = DatabaseSecurityLayer()


def inicializar_db():
    """Crea todas las tablas en la base de datos"""
    try:
        Base.metadata.create_all(bind=engine)
        from core.enterprise_databases.bootstrap import (
            initialize_enterprise_databases,
            sync_legacy_clients_snapshot,
        )

        ent = initialize_enterprise_databases()
        sync_legacy_clients_snapshot()
        try:
            from services.forensic_evidence_keys import ensure_forensic_signing_key
            ensure_forensic_signing_key()
        except Exception as fk_exc:
            print(f"Forensic keys init note: {fk_exc}")
        print("Base de datos inicializada correctamente")
        print("Bases empresariales:", ent.get("domains"))
    except Exception as e:
        print(f"Error inicializando base de datos: {e}")

def ensure_tables_exist():
    """Asegura que todas las tablas existan, las crea si faltan"""
    try:
        # Crear todas las tablas (esto agrega columnas faltantes)
        Base.metadata.create_all(bind=engine)
        
        # Verificar tablas críticas sin hacer consultas que fallen
        db = SessionLocal()
        try:
            from sqlalchemy import text
            db.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
            
            print("Base de datos verificada correctamente")
            
        except Exception as e:
            print(f"Error verificando tablas: {e}")
        finally:
            db.close()
            
    except Exception as e:
        print(f"Error asegurando tablas: {e}")
        Base.metadata.create_all(bind=engine)
    try:
        ensure_performance_indexes()
    except Exception as exc:
        print(f"Performance indexes: {exc}")


def ensure_performance_indexes() -> None:
    """Índices idempotentes para consultas multi-tenant y auth bajo carga."""
    from sqlalchemy import text

    statements = [
        "CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email)",
        "CREATE INDEX IF NOT EXISTS idx_usuarios_nit ON usuarios(nit_pyme)",
        # 1 EMPRESA = 1 CUENTA = 1 TENANT — unique among non-empty NIT (NULLs allowed; reversible DROP INDEX).
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_usuarios_nit_pyme_unique ON usuarios(nit_pyme) WHERE nit_pyme IS NOT NULL AND length(trim(nit_pyme)) > 0",
        "CREATE INDEX IF NOT EXISTS idx_tenant_scope_tid ON tenant_monitoring_scope(tenant_id)",
        "CREATE INDEX IF NOT EXISTS idx_platform_evidence_tenant ON platform_evidences(tenant_id)",
        "CREATE INDEX IF NOT EXISTS idx_platform_evidence_fecha ON platform_evidences(fecha)",
        "CREATE INDEX IF NOT EXISTS idx_alertas_tenant ON alertas(tenant_id)",
        "CREATE INDEX IF NOT EXISTS idx_alertas_estado ON alertas(estado)",
        "CREATE INDEX IF NOT EXISTS idx_logs_fecha ON logs(fecha)",
        "CREATE INDEX IF NOT EXISTS idx_novus_notifications_tenant ON novus_notifications(tenant_id)",
        "CREATE INDEX IF NOT EXISTS idx_novus_notifications_user_status_created ON novus_notifications(user_email, status, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_novus_notifications_tenant_user_status ON novus_notifications(tenant_id, user_email, status)",
        "CREATE INDEX IF NOT EXISTS idx_novus_notifications_status ON novus_notifications(status)",
        "CREATE INDEX IF NOT EXISTS idx_login_session_tenant ON login_session_audits(tenant_id)",
        "CREATE INDEX IF NOT EXISTS idx_network_device_tenant ON network_device_inventory(tenant_id)",
    ]
    db = SessionLocal()
    try:
        for stmt in statements:
            db.execute(text(stmt))
        db.commit()
    finally:
        db.close()

def registrar_log_seguridad(db, evento: str, detalle: str, vault=None, fecha: Optional[str] = None):
    """
    Registra un evento de seguridad en la tabla de auditoria.
    Si se proporciona vault, cifra el detalle antes de almacenarlo.
    """
    if vault:
        try:
            detalle = vault.proteger(detalle)
        except Exception:
            # Fallback seguro en caso de falla de cifrado.
            detalle = "[ERROR_CIFRADO_LOG]"
    log = Log(
        evento=evento,
        detalle=detalle,
        fecha=fecha or datetime.now().strftime("%Y-%m-%d %H:%M")
    )
    db.add(log)
    try:
        from services.enterprise_data_service import record_audit_domain

        record_audit_domain(
            action=evento[:120],
            outcome="logged",
            detail={"detalle_preview": (detalle or "")[:500], "encrypted": bool(vault)},
        )
    except Exception:
        pass
    return log