"""Política transversal de procedencia — ningún dato operativo sin trazabilidad verificable."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, Union

# Orígenes canónicos (API / motores)
OPERATIONAL_ORIGINS = frozenset(
    {
        "live",
        "cached",
        "calculated",
        "stale",
        "not_available",
        "not_implemented",
        "not_verifiable",
        "no_data",
    }
)

# Estados explícitos para UI cuando no hay dato operativo verificable
DISPLAY_STATES = frozenset(
    {
        "NO_DATA",
        "NOT_AVAILABLE",
        "NOT_IMPLEMENTED",
        "STALE",
        "NOT_VERIFIABLE",
    }
)

NO_DATA_LABEL = "Sin datos disponibles"
SIN_ANALISIS_LABEL = "Sin análisis disponible"
EMPTY_VULNS_LABEL = "No se detectaron vulnerabilidades en el último análisis."
EMPTY_THREATS_LABEL = "No se detectaron amenazas en el último análisis."


def analysis_display(
    *,
    count: Optional[int],
    last_scan: Optional[str],
    empty_label: str = EMPTY_VULNS_LABEL,
) -> Dict[str, Any]:
    """Distingue NOT_AVAILABLE (sin escaneo) de EMPTY (escaneo válido, cero hallazgos)."""
    if not last_scan:
        return {
            "value": None,
            "display": SIN_ANALISIS_LABEL,
            "data_origin": "not_available",
            "analysis_state": "NOT_AVAILABLE",
        }
    if count is None:
        return {
            "value": None,
            "display": NO_DATA_LABEL,
            "data_origin": "not_verifiable",
            "analysis_state": "NOT_VERIFIABLE",
        }
    if count == 0:
        return {
            "value": 0,
            "display": empty_label,
            "data_origin": "live",
            "analysis_state": "EMPTY",
        }
    return {
        "value": count,
        "display": count,
        "data_origin": "live",
        "analysis_state": "LIVE",
    }


def attach_operational_provenance(
    payload: Dict[str, Any],
    *,
    data_origin: str,
    source: str,
    tenant_id: Optional[str] = None,
    observed_at: Optional[str] = None,
    source_engine: Optional[str] = None,
    freshness: Optional[str] = None,
    evidence: Optional[Any] = None,
) -> Dict[str, Any]:
    """Bloque estándar de procedencia en respuestas API operativas."""
    prov = provenance_meta(
        data_origin=data_origin,
        source=source,
        tenant_id=tenant_id,
        observed_at=observed_at,
        source_engine=source_engine,
        freshness=freshness,
    )
    if evidence is not None:
        prov["evidence"] = evidence
    out = dict(payload)
    out["provenance"] = prov
    return out


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_origin(data_origin: Optional[str]) -> str:
    origin = (data_origin or "not_available").lower().strip()
    if origin in OPERATIONAL_ORIGINS:
        return origin
    aliases = {
        "unavailable": "not_available",
        "unknown": "not_verifiable",
        "pending": "not_available",
        "not_configured": "not_implemented",
    }
    return aliases.get(origin, "not_available")


def provenance_meta(
    *,
    data_origin: str,
    source: str,
    tenant_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    observed_at: Optional[str] = None,
    source_engine: Optional[str] = None,
    freshness: Optional[str] = None,
    evidence_id: Optional[str] = None,
    confidence: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Construye bloque estándar de procedencia (no inventa mediciones)."""
    origin = normalize_origin(data_origin)
    block: Dict[str, Any] = {
        "data_origin": origin,
        "source": source,
        "timestamp": timestamp or _utc_now(),
    }
    if observed_at:
        block["observed_at"] = observed_at
    if tenant_id is not None:
        block["tenant_id"] = tenant_id
    if source_engine:
        block["source_engine"] = source_engine
    if freshness:
        block["freshness"] = freshness
    if evidence_id:
        block["evidence_id"] = evidence_id
    if confidence:
        block["confidence"] = confidence
    if extra:
        block.update(extra)
    return block


def attach_provenance(payload: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    out = dict(payload)
    out["provenance"] = provenance_meta(**kwargs)
    return out


def operational_field(
    value: Any,
    *,
    data_origin: str,
    source: str,
    source_engine: Optional[str] = None,
    tenant_id: Optional[str] = None,
    observed_at: Optional[str] = None,
    freshness: Optional[str] = None,
    evidence_id: Optional[str] = None,
    display_state: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Envuelve un valor operativo con procedencia obligatoria.
    Si value es None y no hay display_state, devuelve NOT_AVAILABLE.
    """
    origin = normalize_origin(data_origin)
    state = display_state
    if value is None and state is None:
        if origin in ("stale",):
            state = "STALE"
        elif origin in ("not_implemented",):
            state = "NOT_IMPLEMENTED"
        elif origin in ("not_verifiable",):
            state = "NOT_VERIFIABLE"
        else:
            state = "NO_DATA"
    out: Dict[str, Any] = {
        "value": value,
        "display_state": state,
        "provenance": provenance_meta(
            data_origin=origin,
            source=source,
            tenant_id=tenant_id,
            observed_at=observed_at,
            source_engine=source_engine,
            freshness=freshness,
            evidence_id=evidence_id,
        ),
    }
    return out


def resolve_operational_display(field: Union[Dict[str, Any], Any]) -> Any:
    """Valor listo para UI: número/texto real o etiqueta explícita de ausencia."""
    if not isinstance(field, dict):
        return field
    val = field.get("value")
    if val is not None:
        return val
    state = field.get("display_state")
    if state in DISPLAY_STATES:
        return NO_DATA_LABEL if state == "NO_DATA" else state.replace("_", " ").title()
    return NO_DATA_LABEL


def is_operational_value_verifiable(field: Union[Dict[str, Any], Any]) -> bool:
    if not isinstance(field, dict):
        return field is not None
    prov = field.get("provenance") or {}
    origin = normalize_origin(prov.get("data_origin"))
    if origin in ("not_available", "not_implemented", "not_verifiable", "no_data"):
        return False
    if field.get("value") is None:
        return False
    if origin == "stale" and prov.get("freshness") == "stale":
        return False
    return bool(prov.get("source"))


def validate_security_notification(
    *,
    source_motor: Optional[str],
    source_ref: Optional[str],
    payload: Optional[dict],
) -> Tuple[bool, Optional[str]]:
    """
    Notificación security exige motor, referencia y evidencia verificable.
    Bloquea heurísticas de sesión/escaneo/módulo sin detección real.
    """
    if not (source_motor and str(source_motor).strip()):
        return False, "missing_source_motor"
    if source_ref is None or str(source_ref).strip() == "":
        return False, "missing_source_ref"
    pl = dict(payload or {})
    has_evidence = bool(
        pl.get("evidence_id")
        or pl.get("evidence")
        or pl.get("anomaly_id")
        or pl.get("detection_id")
        or pl.get("finding_id")
        or pl.get("incident_id")
        or pl.get("event_id")
        or pl.get("verifiable") is True
    )
    if not has_evidence:
        return False, "missing_evidence"
    blocked_reasons = pl.get("blocked_reason") or pl.get("non_security")
    if blocked_reasons:
        return False, "non_security_event"
    return True, None
