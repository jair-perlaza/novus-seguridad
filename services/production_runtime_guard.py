"""
Frontera PRODUCTION vs TEST/LAB — evita que fixtures y datos QA contaminen runtime.
Los tests pueden usar fixtures; el runtime de producción no debe leerlos por defecto.
"""
from __future__ import annotations

import os
from typing import Optional

_LAB_PLATFORM_TENANT_ID = "QA-NOVUS-2026"
_LAB_PLATFORM_ADMIN_EMAIL = "novus.qa.jul2026@example.com"


def novus_env() -> str:
    return os.environ.get("NOVUS_ENV", "development").strip().lower()


def is_production_runtime() -> bool:
    return novus_env() in ("production", "beta", "prod")


def is_lab_runtime_allowed() -> bool:
    """True solo si el operador habilita explícitamente datos/lab en runtime no-prod."""
    if is_production_runtime():
        return False
    return os.environ.get("NOVUS_ALLOW_LAB_RUNTIME", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def lab_platform_tenant_id() -> str:
    return _LAB_PLATFORM_TENANT_ID


def lab_platform_admin_emails() -> frozenset:
    return frozenset({_LAB_PLATFORM_ADMIN_EMAIL})


def legacy_imcm_merge_enabled() -> bool:
    if is_production_runtime():
        return False
    if not is_lab_runtime_allowed():
        return False
    return os.environ.get("NOVUS_IMCM_LEGACY_MERGE", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def legacy_soc_merge_enabled() -> bool:
    return legacy_imcm_merge_enabled()


def enterprise_warmup_enabled() -> bool:
    if is_production_runtime():
        return False
    return os.environ.get("NOVUS_ENTERPRISE_WARMUP", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def qa_seed_scripts_enabled() -> bool:
    if is_production_runtime():
        return False
    return os.environ.get("NOVUS_ALLOW_QA_SEED", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def is_qa_lab_tenant(tenant_id: Optional[str]) -> bool:
    """True si el tenant es plataforma QA/LAB — no debe mezclarse con clientes reales."""
    if not tenant_id:
        return False
    tid = str(tenant_id).strip()
    return tid == _LAB_PLATFORM_TENANT_ID or tid.upper().startswith("QA-")


def lab_data_visible_to_tenant(viewer_tenant_id: Optional[str], data_tenant_id: Optional[str]) -> bool:
    """
    Frontera LAB/QA → producción: datos QA solo visibles al tenant QA o con lab runtime explícito.
    """
    if not is_qa_lab_tenant(data_tenant_id):
        return True
    if is_lab_runtime_allowed():
        return True
    if viewer_tenant_id and str(viewer_tenant_id).strip() == str(data_tenant_id).strip():
        return True
    return False
