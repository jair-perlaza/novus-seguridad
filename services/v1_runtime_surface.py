"""
Superficie cliente NOVUS V1 — qué módulos y datos pueden aparecer en runtime real.
Separación PRODUCTION vs LAB/QA sin inventar telemetría.
"""
from __future__ import annotations

import json
import re
from functools import wraps
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, TypeVar

from services.production_runtime_guard import (
    is_lab_runtime_allowed,
    is_production_runtime,
    lab_platform_tenant_id,
)

# Módulos RBAC / nav que no deben mostrarse al cliente hasta tener backend real verificado.
V1_HIDDEN_CLIENT_MODULES: frozenset = frozenset({
    "mail_shield",
    "platform_health",
    "casos_estudio",
    "centro_casos_estudio_novus",
})

# Claves nav enterprise (sin RBAC) — ocultas en runtime cliente V1.
V1_HIDDEN_NAV_KEYS: frozenset = frozenset({
    "threat_intel",
    "playbook_center",
    "asm_center",
    "viem_center",
    "imcm_center",
    "soc_center",
    "sdl_center",
    "sdace_center",
    "identity_intelligence",
    "iapa_center",
    "deception_center",
    "csv_bas_center",
    "btde_obs",
    "zdde_obs",
    "swarm_obs",
    "mesh_obs",
    "adaptive_profile_obs",
    "wsae_obs",
    "cryptovault_obs",
    "siem",
})

QA_TENANT_MARKERS = frozenset({"QA-NOVUS-2026", "901.567.123-4"})
QA_EMAIL_MARKERS = frozenset({"novus.qa.jul2026@example.com", "@example.com"})
QA_CONTENT_MARKERS = (
    "QA-NOVUS-2026",
    "TEST-PORT-9999",
    "DB-VULN",
    "SEC-TEST",
    "simulated",
    "placeholder",
    "demo fixture",
    "203.0.113.",
    "192.0.2.",
    "198.51.100.",
    "EICAR-STANDARD",
    # CSV/BAS validation noise — never treat as LIVE operational incidents.
    "csv_bas_validation",
    "csv_bas",
    "SYNTHETIC_TEST_ONLY",
    "TEST_FIXTURE",
)
_NAV_CATALOG_TYPES = frozenset({"Módulo", "Widget", "Shield", "Formulario"})


def is_v1_client_module_visible(module_key: str) -> bool:
    if module_key in V1_HIDDEN_CLIENT_MODULES:
        return False
    if is_production_runtime() or not is_lab_runtime_allowed():
        if module_key in V1_HIDDEN_CLIENT_MODULES:
            return False
    return True


def is_v1_nav_route_visible(nav_key: str) -> bool:
    if nav_key in V1_HIDDEN_NAV_KEYS:
        return is_lab_runtime_allowed() and not is_production_runtime()
    return True


def apply_v1_module_access_map(access: Dict[str, bool]) -> Dict[str, bool]:
    if is_lab_runtime_allowed() and not is_production_runtime():
        return access
    out = dict(access)
    for mod in V1_HIDDEN_CLIENT_MODULES:
        out[mod] = False
    return out


def is_lab_tenant_id(tenant_id: Optional[str]) -> bool:
    tid = str(tenant_id or "").strip()
    if not tid:
        return False
    if tid in QA_TENANT_MARKERS:
        return True
    if tid.startswith("CLIENT-") and tid.endswith("-TEST"):
        return True
    return False


def is_lab_email(email: Optional[str]) -> bool:
    em = str(email or "").strip().lower()
    if not em:
        return False
    if em in {e.lower() for e in QA_EMAIL_MARKERS}:
        return True
    if em.endswith("@example.com") or em.endswith("@novus-client.test"):
        return not is_lab_runtime_allowed()
    return False


def text_contains_lab_marker(text: Optional[str]) -> bool:
    if not text:
        return False
    low = str(text).lower()
    for marker in QA_CONTENT_MARKERS:
        if marker.lower() in low:
            return True
    return False


def blob_contains_lab_marker(obj: Any) -> bool:
    try:
        return text_contains_lab_marker(json.dumps(obj, ensure_ascii=False, default=str))
    except Exception:
        return text_contains_lab_marker(str(obj))


def filter_lab_search_results(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if is_lab_runtime_allowed() and not is_production_runtime():
        return list(items)
    out: List[Dict[str, Any]] = []
    for item in items:
        blob = " ".join(
            str(item.get(k) or "")
            for k in ("id", "name", "description", "location", "type", "url")
        )
        if text_contains_lab_marker(blob):
            continue
        tagged = dict(item)
        if tagged.get("type") in _NAV_CATALOG_TYPES:
            tagged["data_origin"] = "navigation_catalog"
            tagged["data_freshness"] = "STATIC"
        else:
            tagged.setdefault("data_freshness", "LIVE")
        out.append(tagged)
    return out


def ndci_simulations_enabled() -> bool:
    return is_lab_runtime_allowed() and not is_production_runtime()


def module_unavailable_message(module_label: str) -> str:
    return (
        f"{module_label} no está disponible todavía en esta versión. "
        "NOVUS no muestra datos simulados ni de laboratorio en producción."
    )


def swarm_simulate_ingest_allowed() -> bool:
    return is_lab_runtime_allowed() and not is_production_runtime()


NAV_KEY_LABELS: Dict[str, str] = {
    "threat_intel": "Threat Intelligence",
    "playbook_center": "Playbook Center",
    "asm_center": "Asset Intelligence",
    "viem_center": "Vulnerability Intelligence",
    "imcm_center": "Incident Management",
    "soc_center": "Security Operations",
    "sdl_center": "Security Data Lake",
    "sdace_center": "Data Analytics",
    "identity_intelligence": "Identity Intelligence",
    "iapa_center": "Attack Path",
    "deception_center": "Deception",
    "csv_bas_center": "Security Validation",
    "btde_obs": "BTDE",
    "zdde_obs": "ZDDE",
    "swarm_obs": "Swarm Defense",
    "mesh_obs": "Swarm Mesh",
    "adaptive_profile_obs": "Adaptive Profile",
    "wsae_obs": "WSAE",
    "cryptovault_obs": "CryptoVault",
    "siem": "SIEM",
}

F = TypeVar("F", bound=Callable[..., Any])


def v1_nav_route_guard(nav_key: str, *, label: Optional[str] = None) -> Callable[[F], F]:
    """Oculta rutas enterprise/lab en runtime cliente V1 (respuesta honesta, no datos simulados)."""
    module_label = label or NAV_KEY_LABELS.get(nav_key, nav_key)

    def decorator(view_func: F) -> F:
        @wraps(view_func)
        def wrapped(*args: Any, **kwargs: Any):
            if is_v1_nav_route_visible(nav_key):
                return view_func(*args, **kwargs)
            from flask import render_template
            from flask_login import current_user
            from utils.user_helpers import get_current_user_data

            return (
                render_template(
                    "v1_module_unavailable.html",
                    user=get_current_user_data(),
                    active_module=nav_key,
                    title=f"{module_label} no disponible",
                    message=module_unavailable_message(module_label),
                ),
                200,
            )

        return wrapped  # type: ignore[return-value]

    return decorator


def filter_lab_runtime_rows(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Excluye filas con marcadores QA/LAB/LOADTEST del runtime cliente."""
    if is_lab_runtime_allowed() and not is_production_runtime():
        return list(rows)
    out: List[Dict[str, Any]] = []
    for row in rows:
        if blob_contains_lab_marker(row):
            continue
        try:
            from services.loadtest_runtime import is_loadtest_email, is_loadtest_tenant

            email = row.get("user_email") or row.get("email")
            tid = row.get("tenant_id") or row.get("nit_pyme")
            if is_loadtest_email(email) or is_loadtest_tenant(tid):
                continue
        except Exception:
            pass
        out.append(row)
    return out


def client_runtime_active() -> bool:
    """True cuando el runtime debe ocultar lab/simulaciones (prod o dev sin NOVUS_ALLOW_LAB_RUNTIME)."""
    return is_production_runtime() or not is_lab_runtime_allowed()
