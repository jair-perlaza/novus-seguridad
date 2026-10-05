"""Inicialización de esquemas empresariales."""
from __future__ import annotations

from typing import Any, Dict

from utils.logger import logger

from core.enterprise_databases.engines import ALL_ENGINES
from core.enterprise_databases.schema import (
    AuditBase,
    ClientsBase,
    EvidenceBase,
    HistoryBase,
    KernelBase,
    SecurityEventsBase,
    StudyCasesBase,
)

_BASE_BY_DOMAIN = {
    "clients": ClientsBase,
    "security_events": SecurityEventsBase,
    "history": HistoryBase,
    "kernel": KernelBase,
    "evidence": EvidenceBase,
    "study_cases": StudyCasesBase,
    "audit": AuditBase,
}


def initialize_enterprise_databases() -> Dict[str, Any]:
    stats: Dict[str, Any] = {"domains": {}, "errors": []}
    for domain, eng in ALL_ENGINES.items():
        base = _BASE_BY_DOMAIN[domain]
        try:
            base.metadata.create_all(bind=eng)
            stats["domains"][domain] = "ok"
        except Exception as exc:
            logger.error("enterprise DB init %s: %s", domain, exc)
            stats["domains"][domain] = "error"
            stats["errors"].append(f"{domain}:{exc}")
    return stats


def sync_legacy_clients_snapshot() -> Dict[str, int]:
    """Copia usuarios/empresas reales desde el monolito legacy (solo lectura, sin inventar filas)."""
    from datetime import datetime

    from database import SessionLocal, Usuario

    from core.enterprise_databases.engines import ClientsSessionLocal
    from core.enterprise_databases.schema import ClientUserRecord, EnterpriseRecord

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {"enterprises": 0, "users": 0}
    legacy = SessionLocal()
    domain = ClientsSessionLocal()
    try:
        users = legacy.query(Usuario).all()
        tenants_seen = set()
        for u in users:
            tid = (u.nit_pyme or "").strip() or f"tenant-user-{u.id}"
            if tid not in tenants_seen:
                tenants_seen.add(tid)
                ent = domain.query(EnterpriseRecord).filter(EnterpriseRecord.tenant_id == tid).first()
                if not ent:
                    domain.add(EnterpriseRecord(
                        tenant_id=tid,
                        display_name=None,
                        sector=getattr(u, "sector", None),
                        created_at=now,
                        updated_at=now,
                    ))
                    counts["enterprises"] += 1
            existing = domain.query(ClientUserRecord).filter(
                ClientUserRecord.legacy_user_id == u.id
            ).first()
            if not existing:
                domain.add(ClientUserRecord(
                    legacy_user_id=u.id,
                    tenant_id=tid,
                    email=(u.email or "").lower(),
                    role=getattr(u, "role", None) or "analyst",
                    is_active=bool(u.is_active),
                    synced_at=now,
                ))
                counts["users"] += 1
        domain.commit()
    except Exception as exc:
        domain.rollback()
        logger.error("sync_legacy_clients: %s", exc)
    finally:
        legacy.close()
        domain.close()
    return counts
