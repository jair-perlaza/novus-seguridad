"""Modelos por dominio — bases independientes."""
from __future__ import annotations

from sqlalchemy import Boolean, Column, Integer, String, Text
from sqlalchemy.orm import declarative_base

ClientsBase = declarative_base()
SecurityEventsBase = declarative_base()
HistoryBase = declarative_base()
KernelBase = declarative_base()
EvidenceBase = declarative_base()
StudyCasesBase = declarative_base()
AuditBase = declarative_base()


# --- 1. CLIENTES ---
class EnterpriseRecord(ClientsBase):
    __tablename__ = "enterprises"
    tenant_id = Column(String, primary_key=True, index=True)
    display_name = Column(String, nullable=True)
    sector = Column(String, nullable=True)
    license_tier = Column(String, nullable=True)
    security_config_json = Column(Text, nullable=True)
    preferences_json = Column(Text, nullable=True)
    created_at = Column(String, index=True)
    updated_at = Column(String, nullable=True)


class ClientUserRecord(ClientsBase):
    __tablename__ = "client_users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    legacy_user_id = Column(Integer, index=True, nullable=True)
    tenant_id = Column(String, index=True)
    email = Column(String, index=True)
    role = Column(String, index=True)
    is_active = Column(Boolean, default=True)
    synced_at = Column(String, nullable=True)


class RegisteredDeviceRecord(ClientsBase):
    __tablename__ = "registered_devices"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String, index=True)
    device_id = Column(String, index=True)
    fingerprint = Column(String, nullable=True)
    user_email = Column(String, index=True, nullable=True)
    metadata_json = Column(Text, nullable=True)
    registered_at = Column(String, index=True)


# --- 2. EVENTOS DE SEGURIDAD ---
class SecurityEventRecord(SecurityEventsBase):
    __tablename__ = "security_events"
    id = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    event_type = Column(String, index=True)
    event_date = Column(String, index=True)
    event_time = Column(String, index=True)
    timestamp = Column(String, index=True)
    user_email = Column(String, index=True, nullable=True)
    equipment = Column(String, nullable=True)
    severity = Column(String, index=True, nullable=True)
    status = Column(String, index=True, default="recorded")
    action_taken = Column(String, nullable=True)
    motor = Column(String, index=True, nullable=True)
    evidence_json = Column(Text, nullable=True)
    legacy_ref = Column(String, index=True, nullable=True)


# --- 3. HISTÓRICO ---
class NetworkProfileRecord(HistoryBase):
    __tablename__ = "network_profiles"
    scope_id = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    lookup_key = Column(String, index=True)
    identification_json = Column(Text, nullable=True)
    first_analysis_at = Column(String, index=True)
    last_analysis_at = Column(String, index=True)
    state_json = Column(Text, nullable=True)


class HistoryAnalysisSession(HistoryBase):
    __tablename__ = "analysis_sessions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scope_id = Column(String, index=True)
    session_audit_id = Column(String, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    user_email = Column(String, index=True, nullable=True)
    equipment_json = Column(Text, nullable=True)
    started_at = Column(String, index=True)
    finished_at = Column(String, nullable=True)
    duration_sec = Column(String, nullable=True)
    motors_json = Column(Text, nullable=True)
    status = Column(String, index=True)


class HistorySnapshot(HistoryBase):
    __tablename__ = "history_snapshots"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scope_id = Column(String, index=True, nullable=True)
    tenant_id = Column(String, index=True, nullable=True)
    snapshot_type = Column(String, index=True)
    timestamp = Column(String, index=True)
    payload_json = Column(Text, nullable=True)


# --- 4. KERNEL IA ---
class KernelPatternRecord(KernelBase):
    __tablename__ = "kernel_patterns"
    id = Column(Integer, primary_key=True, autoincrement=True)
    pattern_key = Column(String, index=True)
    scope_id = Column(String, index=True, nullable=True)
    description = Column(Text)
    source = Column(String, nullable=True)
    confidence = Column(String, nullable=True)
    derived_from_event_count = Column(Integer, default=0)
    created_at = Column(String, index=True)
    payload_json = Column(Text, nullable=True)


class KernelTrendRecord(KernelBase):
    __tablename__ = "kernel_trends"
    id = Column(Integer, primary_key=True, autoincrement=True)
    trend_key = Column(String, index=True)
    summary = Column(Text)
    sufficient_data = Column(Boolean, default=False)
    created_at = Column(String, index=True)
    payload_json = Column(Text, nullable=True)


class KernelRecommendationRecord(KernelBase):
    __tablename__ = "kernel_recommendations"
    id = Column(Integer, primary_key=True, autoincrement=True)
    recommendation_key = Column(String, index=True)
    summary = Column(Text)
    risk_model = Column(String, nullable=True)
    created_at = Column(String, index=True)
    payload_json = Column(Text, nullable=True)


# --- 5. EVIDENCIAS ---
class EvidenceRecord(EvidenceBase):
    __tablename__ = "evidence_records"
    id = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    related_event_id = Column(String, index=True, nullable=True)
    evidence_type = Column(String, index=True)
    file_path = Column(String, nullable=True)
    content_hash = Column(String, index=True, nullable=True)
    timestamp = Column(String, index=True)
    motor = Column(String, nullable=True)
    metadata_json = Column(Text, nullable=True)
    legacy_evidence_id = Column(String, index=True, nullable=True)


# --- 6. CASOS DE ESTUDIO (anonimizados, propiedad NOVUS) ---
class AnonymizedStudyCase(StudyCasesBase):
    __tablename__ = "anonymized_study_cases"
    id = Column(String, primary_key=True, index=True)
    sector = Column(String, index=True, nullable=True)
    attack_type = Column(String, index=True, nullable=True)
    techniques_json = Column(Text, nullable=True)
    vulnerabilities_json = Column(Text, nullable=True)
    response_time_sec = Column(String, nullable=True)
    mechanisms_json = Column(Text, nullable=True)
    outcome = Column(Text, nullable=True)
    lessons_json = Column(Text, nullable=True)
    recommendations_json = Column(Text, nullable=True)
    source_internal_ref = Column(String, index=True, nullable=True)
    created_at = Column(String, index=True)


# --- 7. AUDITORÍA ---
class AuditLogRecord(AuditBase):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String, index=True, nullable=True)
    user_email = Column(String, index=True, nullable=True)
    event_date = Column(String, index=True)
    event_time = Column(String, index=True)
    timestamp = Column(String, index=True)
    equipment = Column(String, nullable=True)
    ip_address = Column(String, index=True, nullable=True)
    action = Column(String, index=True)
    outcome = Column(String, nullable=True)
    detail_json = Column(Text, nullable=True)


class SupportAccessTokenRecord(AuditBase):
    __tablename__ = "support_access_tokens"
    token = Column(String, primary_key=True, index=True)
    tenant_id = Column(String, index=True)
    authorized_by_email = Column(String, index=True)
    purpose = Column(String, nullable=True)
    created_at = Column(String, index=True)
    expires_at = Column(String, index=True)
    used_at = Column(String, nullable=True)
    used_by_email = Column(String, nullable=True)
    status = Column(String, index=True, default="active")
