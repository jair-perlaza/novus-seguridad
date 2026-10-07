"""Control de acceso empresarial — aislamiento por tenant y roles NOVUS."""
from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple

from services.rbac_service import (
    ROLE_COMPANY_ADMIN,
    ROLE_NOVUS_CREATOR,
    ROLE_SUPER_ADMIN,
    get_user_role,
    normalize_role,
)
from services.tenant_scope_service import resolve_tenant_id

ROLE_NOVUS_SUPPORT = "novus_support"


def is_novus_creator(user) -> bool:
    if user is None:
        return False
    role = normalize_role(getattr(user, "role", None))
    if role == ROLE_NOVUS_CREATOR:
        return True
    email = (getattr(user, "email", None) or "").strip().lower()
    creators = os.environ.get("NOVUS_CREATOR_EMAIL", "").strip().lower()
    if creators:
        allowed = {e.strip() for e in creators.split(",") if e.strip()}
        if email in allowed:
            return True
    return role == ROLE_SUPER_ADMIN and os.environ.get("NOVUS_CREATOR_ALSO_SUPER", "").lower() in ("1", "true", "yes")


def is_novus_support(user) -> bool:
    return normalize_role(getattr(user, "role", None)) == ROLE_NOVUS_SUPPORT


def user_may_access_tenant(user, tenant_id: Optional[str], *, support_token_tenant: Optional[str] = None) -> Tuple[bool, str]:
    if not tenant_id:
        return False, "tenant_required"
    if is_novus_creator(user):
        return True, ""
    user_tid = resolve_tenant_id(user)
    if user_tid == tenant_id:
        return True, ""
    role = get_user_role(user)
    if role == ROLE_COMPANY_ADMIN and user_tid == tenant_id:
        return True, ""
    if is_novus_support(user) and support_token_tenant == tenant_id:
        return True, "support_token"
    return False, "tenant_isolation"


def filter_query_by_tenant(query, model, user, tenant_column: str = "tenant_id"):
    tid = resolve_tenant_id(user)
    if is_novus_creator(user):
        return query
    col = getattr(model, tenant_column, None)
    if col is None or not tid:
        return query.filter(model.id == -1)
    return query.filter(col == tid)


def assert_tenant_access(user, tenant_id: Optional[str]) -> Tuple[bool, str]:
    ok, reason = user_may_access_tenant(user, tenant_id)
    if ok:
        return True, ""
    from services.enterprise_data_service import record_audit_domain

    record_audit_domain(
        action="tenant_access_denied",
        user_email=getattr(user, "email", None),
        tenant_id=tenant_id,
        outcome="denied",
        detail={"reason": reason},
    )
    return False, reason
