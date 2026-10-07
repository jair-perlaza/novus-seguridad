"""
Aislamiento multi-tenant en capa de datos/servicio.
SECURITY > DATA ISOLATION > CORRECTNESS
"""
from __future__ import annotations

import re
from typing import Any, Optional

from services.tenant_scope_service import resolve_tenant_id


class TenantAccessDenied(Exception):
    """Acceso a recurso de otro tenant o sin tenant_id verificable."""


def resolve_user_tenant_id(user: Any) -> Optional[str]:
    if user is None:
        return None
    return resolve_tenant_id(user)


def require_user_tenant_id(user: Any) -> str:
    tid = resolve_user_tenant_id(user)
    if not tid or not str(tid).strip():
        raise TenantAccessDenied("tenant_not_configured")
    return str(tid).strip()


def require_canonical_tenant_id(user: Any) -> str:
    """
    Tenant canónico para búsquedas/API tenant-scoped.
    Solo company_id / nit_pyme — nunca email-domain / IP / MAC / hostname.
    """
    if user is None:
        raise TenantAccessDenied("tenant_not_configured")
    tid = getattr(user, "company_id", None) or getattr(user, "nit_pyme", None)
    if tid and str(tid).strip():
        return str(tid).strip()
    raise TenantAccessDenied("tenant_not_configured")


def sanitize_tenant_id_for_path(tenant_id: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", str(tenant_id or "unknown"))[:120]
    return safe or "unknown"


def tenant_ids_match(resource_tenant_id: Optional[str], request_tenant_id: Optional[str]) -> bool:
    if not request_tenant_id or not str(request_tenant_id).strip():
        return False
    if not resource_tenant_id or not str(resource_tenant_id).strip():
        return False
    return str(resource_tenant_id).strip() == str(request_tenant_id).strip()


def assert_tenant_access(
    resource_tenant_id: Optional[str],
    request_tenant_id: Optional[str],
    *,
    resource_kind: str = "resource",
) -> None:
    if not tenant_ids_match(resource_tenant_id, request_tenant_id):
        raise TenantAccessDenied(f"{resource_kind}_tenant_mismatch")


def sql_tenant_filter(query, model, tenant_id: Optional[str]):
    """Filtro obligatorio: solo filas con tenant_id exacto (excluye NULL)."""
    from sqlalchemy import false

    if not tenant_id:
        return query.filter(false())
    return query.filter(model.tenant_id == tenant_id)
