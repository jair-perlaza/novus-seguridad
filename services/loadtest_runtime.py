"""
Identidad aislada LOADTEST — usuarios/tenants de benchmark, nunca mezclados con producción.
"""
from __future__ import annotations

import os
import re
from typing import Optional

_LOADTEST_EMAIL_RE = re.compile(r"^loadtest-user-\d{4}@loadtest\.novus\.local$", re.I)
_LOADTEST_TENANT_RE = re.compile(r"^LOADTEST-T\d{4}$", re.I)


def is_loadtest_email(email: Optional[str]) -> bool:
    if not email:
        return False
    e = str(email).strip().lower()
    if _LOADTEST_EMAIL_RE.match(e):
        return True
    if e.startswith("loadtest-") and "@loadtest." in e:
        return True
    return False


def is_loadtest_tenant(tenant_id: Optional[str]) -> bool:
    if not tenant_id:
        return False
    tid = str(tenant_id).strip()
    if _LOADTEST_TENANT_RE.match(tid):
        return True
    return tid.upper().startswith("LOADTEST-")


def loadtest_enabled() -> bool:
    return os.environ.get("NOVUS_LOADTEST_MODE", "").strip().lower() in ("1", "true", "yes", "on")


def loadtest_password() -> str:
    return os.environ.get("NOVUS_LOADTEST_PASSWORD", "LoadTest#NOVUS2026!")


def apply_loadtest_client_headers(session, email: str) -> None:
    """Identifica tráfico de benchmark — sin falsificar IP ni eludir protecciones."""
    session.headers["User-Agent"] = "NOVUS-LoadTest-MultiUser/1.0"
