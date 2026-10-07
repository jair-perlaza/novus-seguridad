"""
Alcance multi-tenant de NOVUS — resolución de empresa y monitoreo por tenant.

Cada usuario autenticado pertenece a una empresa (nit_pyme / company_id).
Solo los tenants con monitoreo habilitado pueden leer telemetría del nodo asignado.
"""
from __future__ import annotations

import os
import socket
import threading
from datetime import datetime
from typing import Any, Dict, Optional

from utils.logger import logger

_provision_locks_guard = threading.Lock()
_provision_locks: Dict[str, threading.Lock] = {}

MONITORING_NOT_CONFIGURED_MSG = (
    "El monitoreo de red aún no está configurado para esta empresa."
)

def get_platform_tenant_id() -> str:
    """
    Tenant del nodo plataforma — solo vía NOVUS_PLATFORM_TENANT_ID o lab explícito.
    Sin fallback QA en runtime normal (evita contaminación).
    """
    explicit = os.environ.get("NOVUS_PLATFORM_TENANT_ID", "").strip()
    if explicit:
        return explicit
    try:
        from services.production_runtime_guard import (
            is_lab_runtime_allowed,
            lab_platform_tenant_id,
        )

        if is_lab_runtime_allowed():
            return lab_platform_tenant_id()
    except Exception:
        pass
    return ""


def _platform_admin_emails() -> frozenset:
    raw = os.environ.get("NOVUS_PLATFORM_ADMIN_EMAILS", "").strip()
    if raw:
        return frozenset(e.strip().lower() for e in raw.split(",") if e.strip())
    try:
        from services.production_runtime_guard import (
            is_lab_runtime_allowed,
            lab_platform_admin_emails,
        )

        if is_lab_runtime_allowed():
            return lab_platform_admin_emails()
    except Exception:
        pass
    return frozenset()


def resolve_tenant_id(user) -> Optional[str]:
    """
    Resolución amplia (scope/monitoring). Preferir nit_pyme / company_id.
    Fallback email-domain SOLO si no hay nit — NO usar en APIs canónicas
    (usar require_canonical_tenant_id que nunca usa email-domain).
    """
    if user is None:
        return None
    tenant_id = getattr(user, "company_id", None) or getattr(user, "nit_pyme", None)
    if tenant_id and str(tenant_id).strip():
        return str(tenant_id).strip()
    email = getattr(user, "email", None)
    if email and "@" in email:
        return email.split("@", 1)[1].lower()
    return None


def _default_node_id() -> str:
    from core.config import Config
    return Config.NODE_ID or socket.gethostname()


def get_tenant_scope_record(tenant_id: str):
    from database import SessionLocal, TenantMonitoringScope

    if not tenant_id:
        return None
    try:
        from services.auth_session_cache import get_cached_tenant_scope, set_cached_tenant_scope

        proc_cached = get_cached_tenant_scope(tenant_id)
        if proc_cached is not None:
            return proc_cached
    except Exception:
        pass
    try:
        from flask import g, has_request_context

        if has_request_context():
            cache = getattr(g, "_tenant_scope_cache", None)
            if cache is None:
                g._tenant_scope_cache = {}
                cache = g._tenant_scope_cache
            if tenant_id in cache:
                return cache[tenant_id]
    except Exception:
        cache = None
    db = SessionLocal()
    try:
        record = db.query(TenantMonitoringScope).filter(
            TenantMonitoringScope.tenant_id == tenant_id
        ).first()
    finally:
        db.close()
    try:
        from flask import g, has_request_context

        if has_request_context():
            if cache is None:
                g._tenant_scope_cache = {}
                cache = g._tenant_scope_cache
            cache[tenant_id] = record
    except Exception:
        pass
    try:
        from services.auth_session_cache import set_cached_tenant_scope

        set_cached_tenant_scope(tenant_id, record)
    except Exception:
        pass
    return record


def is_monitoring_enabled(tenant_id: Optional[str]) -> bool:
    if not tenant_id:
        return False
    record = get_tenant_scope_record(tenant_id)
    return bool(record and record.monitoring_enabled)


def get_tenant_context(user) -> Dict[str, Any]:
    ensure_tenant_scope_for_user(user)
    tenant_id = resolve_tenant_id(user)
    record = get_tenant_scope_record(tenant_id) if tenant_id else None
    platform_tid = get_platform_tenant_id()
    monitoring_enabled = bool(record and record.monitoring_enabled)
    mode = (record.monitoring_mode if record else "none") or "none"
    if mode == "disabled_manual":
        monitoring_enabled = False
    return {
        "tenant_id": tenant_id,
        "monitoring_enabled": monitoring_enabled,
        "monitoring_mode": mode,
        "node_id": (record.node_id if record else None),
        "platform_tenant_id": platform_tid,
        "is_platform_tenant": tenant_id == platform_tid if tenant_id else False,
        "message": None if monitoring_enabled else MONITORING_NOT_CONFIGURED_MSG,
    }


def tenant_may_read_platform_telemetry(ctx: Dict[str, Any]) -> bool:
    """True si el tenant puede leer telemetría LIVE del nodo local."""
    if not ctx.get("monitoring_enabled"):
        return False
    mode = (ctx.get("monitoring_mode") or "none").strip()
    if mode == "disabled_manual":
        return False
    local_node = _default_node_id()
    node_id = ctx.get("node_id")
    if mode == "platform_node":
        return not node_id or str(node_id) == str(local_node)
    platform_tid = ctx.get("platform_tenant_id") or get_platform_tenant_id()
    if ctx.get("tenant_id") == platform_tid:
        return True
    if mode == "agent" and node_id:
        return True
    return False


def provision_tenant_network_monitoring(
    tenant_id: str,
    *,
    enabled: bool = True,
    manual: bool = False,
) -> Optional[Any]:
    """
    Provisiona monitoreo de red base para una empresa registrada.
    manual=True + enabled=False → desactivación explícita del administrador.
    """
    from database import SessionLocal, TenantMonitoringScope

    if not tenant_id or not str(tenant_id).strip():
        return None
    tenant_id = str(tenant_id).strip()
    node_id = _default_node_id()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db = SessionLocal()
    try:
        row = db.query(TenantMonitoringScope).filter(
            TenantMonitoringScope.tenant_id == tenant_id
        ).first()
        if not row:
            row = TenantMonitoringScope(
                tenant_id=tenant_id,
                monitoring_enabled=enabled,
                node_id=node_id if enabled else None,
                monitoring_mode="disabled_manual" if (manual and not enabled) else ("platform_node" if enabled else "none"),
                configured_at=now if enabled else None,
                updated_at=now,
            )
            db.add(row)
        else:
            row.monitoring_enabled = enabled
            row.updated_at = now
            if enabled:
                row.node_id = node_id
                row.monitoring_mode = "platform_node"
                if not row.configured_at:
                    row.configured_at = now
            elif manual:
                row.monitoring_mode = "disabled_manual"
                row.node_id = None
        db.commit()
        db.refresh(row)
        try:
            from flask import g, has_request_context

            if has_request_context():
                cache = getattr(g, "_tenant_scope_cache", None)
                if isinstance(cache, dict):
                    cache[tenant_id] = row
        except Exception:
            pass
        return row
    except Exception as exc:
        db.rollback()
        logger.error("provision_tenant_network_monitoring: %s", exc, exc_info=True)
        return None
    finally:
        db.close()


def ensure_tenant_scope_for_user(user) -> Optional[Any]:
    """Lazy-provision: tenant registrado sin fila → monitoreo activo automático."""
    tenant_id = resolve_tenant_id(user)
    if not tenant_id:
        return None
    record = get_tenant_scope_record(tenant_id)
    if record:
        if record.monitoring_mode == "disabled_manual":
            return record
        if not record.monitoring_enabled or record.monitoring_mode in (None, "", "none"):
            pass  # caer a provision serializado
        else:
            return record

    # Serializar provision por tenant — evita 600 escrituras SQLite concurrentes en el primer wave
    with _provision_locks_guard:
        lock = _provision_locks.get(tenant_id)
        if lock is None:
            lock = threading.Lock()
            _provision_locks[tenant_id] = lock
    with lock:
        record = get_tenant_scope_record(tenant_id)
        if record:
            if record.monitoring_mode == "disabled_manual":
                return record
            if record.monitoring_enabled and record.monitoring_mode not in (None, "", "none"):
                return record
        return provision_tenant_network_monitoring(tenant_id, enabled=True, manual=False)


def seed_loadtest_tenant_scopes(manifest_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Pre-provisiona TenantMonitoringScope para tenants LOADTEST.
    Debe ejecutarse ANTES del bench 600 — evita stampede de writes en el primer GET.
    """
    from pathlib import Path
    import json

    from database import SessionLocal, TenantMonitoringScope

    root = Path(__file__).resolve().parents[1]
    path = Path(manifest_path) if manifest_path else root / "data" / "production_closure" / "loadtest_users_manifest.json"
    if not path.is_file():
        return {"ok": False, "reason": "manifest_missing"}
    users = json.loads(path.read_text(encoding="utf-8")).get("users") or []
    node_id = _default_node_id()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    created = 0
    updated = 0
    db = SessionLocal()
    try:
        for u in users:
            tid = str(u.get("tenant_id") or u.get("company_id") or "").strip()
            if not tid:
                email = str(u.get("email") or "")
                if "@" in email:
                    tid = email.split("@", 1)[1].lower()
            if not tid:
                continue
            row = db.query(TenantMonitoringScope).filter(TenantMonitoringScope.tenant_id == tid).first()
            if not row:
                db.add(
                    TenantMonitoringScope(
                        tenant_id=tid,
                        monitoring_enabled=True,
                        node_id=node_id,
                        monitoring_mode="platform_node",
                        configured_at=now,
                        updated_at=now,
                    )
                )
                created += 1
            else:
                changed = False
                if not row.monitoring_enabled:
                    row.monitoring_enabled = True
                    changed = True
                if row.monitoring_mode in (None, "", "none"):
                    row.monitoring_mode = "platform_node"
                    changed = True
                if not row.node_id:
                    row.node_id = node_id
                    changed = True
                if changed:
                    row.updated_at = now
                    updated += 1
            if (created + updated) % 100 == 0:
                db.commit()
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("seed_loadtest_tenant_scopes: %s", exc, exc_info=True)
        return {"ok": False, "error": str(exc)[:200]}
    finally:
        db.close()
    return {"ok": True, "created": created, "updated": updated, "users": len(users)}


def ensure_tenant_monitoring_seeded() -> Dict[str, Any]:
    """
    Garantiza filas en tenant_monitoring_scope:
    - Tenant plataforma: monitoreo activo en nodo local.
    - Empresas registradas: monitoreo activo por defecto (platform_node).
    - Solo permanece deshabilitado si monitoring_mode == disabled_manual.
    """
    from database import SessionLocal, TenantMonitoringScope, Usuario

    platform_tid = get_platform_tenant_id()
    node_id = _default_node_id()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stats = {"platform_tenant": platform_tid or None, "created": 0, "updated": 0, "enabled": 0}

    db = SessionLocal()
    try:
        if platform_tid:
            platform_row = db.query(TenantMonitoringScope).filter(
                TenantMonitoringScope.tenant_id == platform_tid
            ).first()
            if not platform_row:
                db.add(TenantMonitoringScope(
                    tenant_id=platform_tid,
                    monitoring_enabled=True,
                    node_id=node_id,
                    monitoring_mode="platform_node",
                    configured_at=now,
                    updated_at=now,
                ))
                stats["created"] += 1
            else:
                changed = False
                if not platform_row.monitoring_enabled:
                    platform_row.monitoring_enabled = True
                    changed = True
                if not platform_row.node_id:
                    platform_row.node_id = node_id
                    changed = True
                if platform_row.monitoring_mode in (None, "", "none"):
                    platform_row.monitoring_mode = "platform_node"
                    changed = True
                if changed:
                    platform_row.updated_at = now
                    stats["updated"] += 1

        users = db.query(Usuario).filter(Usuario.is_active == True).all()
        for user in users:
            email = (user.email or "").strip().lower()
            if email in _platform_admin_emails() and platform_tid:
                if user.nit_pyme != platform_tid:
                    user.nit_pyme = platform_tid
                    stats["updated"] += 1

            tid = (user.nit_pyme or "").strip()
            if not tid:
                continue
            row = db.query(TenantMonitoringScope).filter(
                TenantMonitoringScope.tenant_id == tid
            ).first()
            if not row:
                db.add(TenantMonitoringScope(
                    tenant_id=tid,
                    monitoring_enabled=True,
                    node_id=node_id,
                    monitoring_mode="platform_node",
                    configured_at=now,
                    updated_at=now,
                ))
                stats["created"] += 1
                stats["enabled"] += 1
                continue
            if row.monitoring_mode == "disabled_manual":
                continue
            changed = False
            if not row.monitoring_enabled:
                row.monitoring_enabled = True
                changed = True
            if row.monitoring_mode in (None, "", "none"):
                row.monitoring_mode = "platform_node"
                changed = True
            if not row.node_id:
                row.node_id = node_id
                changed = True
            if not row.configured_at and row.monitoring_enabled:
                row.configured_at = now
                changed = True
            if changed:
                row.updated_at = now
                stats["updated"] += 1
                stats["enabled"] += 1

        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("ensure_tenant_monitoring_seeded: %s", exc, exc_info=True)
        stats["error"] = str(exc)
    finally:
        db.close()

    return stats


def backfill_tenant_ids_on_legacy_rows() -> int:
    """Asigna tenant_id de plataforma a filas históricas sin empresa."""
    from database import (
        SessionLocal,
        Alerta,
        Vulnerabilidad,
        NetworkDeviceInventory,
        PlatformEvidence,
        DeviceConnectionEvent,
    )

    platform_tid = get_platform_tenant_id()
    if not platform_tid:
        return 0
    updated = 0
    db = SessionLocal()
    try:
        for model in (
            Alerta,
            Vulnerabilidad,
            NetworkDeviceInventory,
            PlatformEvidence,
            DeviceConnectionEvent,
        ):
            if not hasattr(model, "tenant_id"):
                continue
            rows = db.query(model).filter(
                (model.tenant_id.is_(None)) | (model.tenant_id == "")
            ).all()
            for row in rows:
                row.tenant_id = platform_tid
                updated += 1
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("backfill_tenant_ids: %s", exc, exc_info=True)
    finally:
        db.close()
    return updated
