"""Motores SQLAlchemy — una base SQLite por dominio."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.enterprise_databases.paths import (
    DB_AUDIT,
    DB_CLIENTS,
    DB_EVIDENCE,
    DB_HISTORY,
    DB_KERNEL,
    DB_SECURITY_EVENTS,
    DB_STUDY_CASES,
    ensure_data_dir,
)

_CONNECT = {"check_same_thread": False, "timeout": 30}


def _engine(path: str):
    ensure_data_dir()
    return create_engine(
        f"sqlite:///{path.replace(chr(92), '/')}",
        connect_args=_CONNECT,
    )


clients_engine = _engine(DB_CLIENTS)
security_events_engine = _engine(DB_SECURITY_EVENTS)
history_engine = _engine(DB_HISTORY)
kernel_engine = _engine(DB_KERNEL)
evidence_engine = _engine(DB_EVIDENCE)
study_cases_engine = _engine(DB_STUDY_CASES)
audit_engine = _engine(DB_AUDIT)

ClientsSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=clients_engine)
SecurityEventsSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=security_events_engine)
HistorySessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=history_engine)
KernelSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=kernel_engine)
EvidenceSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=evidence_engine)
StudyCasesSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=study_cases_engine)
AuditSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=audit_engine)

ALL_ENGINES = {
    "clients": clients_engine,
    "security_events": security_events_engine,
    "history": history_engine,
    "kernel": kernel_engine,
    "evidence": evidence_engine,
    "study_cases": study_cases_engine,
    "audit": audit_engine,
}
