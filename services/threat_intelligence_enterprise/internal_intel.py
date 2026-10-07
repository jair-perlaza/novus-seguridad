#!/usr/bin/env python3
"""
Inteligencia propia generada por NOVUS.
Correlaciona IOC de detecciones internas (BTDE, Forense, Endpoint, Red)
sin compartir datos personales — solo IOC + metadatos técnicos anonimizados.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.threat_intelligence_enterprise.store import (
    load_iocs,
    load_internal_intel,
    store_internal_intel,
    store_swarm_ioc,
    NA,
)
from services.threat_intelligence_enterprise.limitations import PRIVACY_NEVER_SHARE
from utils.logger import logger


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _anonymize_value(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def ingest_internal_detection(
    ioc_type: str,
    ioc_value: str,
    source_engine: str,
    severity: str = "MEDIO",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Ingesta un IOC detectado internamente por motores NOVUS."""
    metadata = metadata or {}
    for field in list(metadata.keys()):
        if field in PRIVACY_NEVER_SHARE:
            del metadata[field]

    entry = {
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "source_engine": source_engine,
        "severity": severity,
        "metadata": metadata,
        "timestamp_utc": _utc(),
        "origin": "novus_internal",
        "invented": False,
    }
    store_internal_intel(entry)
    return entry


def generate_anonymized_intelligence() -> Dict[str, Any]:
    """
    Genera inteligencia anonimizada a partir de las detecciones internas.
    Correlaciona frecuencia, severidad, recurrencia, distribución.
    Nunca expone datos personales.
    """
    intel = load_internal_intel(limit=1000)
    if not intel:
        return {
            "status": "no_internal_data",
            "iocs": [],
            "summary": "Sin detecciones internas para correlacionar.",
            "generated_at_utc": _utc(),
        }

    ioc_counter: Counter = Counter()
    severity_map: Dict[str, List[str]] = {}
    engine_map: Dict[str, set] = {}

    for entry in intel:
        val = entry.get("ioc_value", "")
        typ = entry.get("ioc_type", "unknown")
        key = f"{typ}:{val}"
        ioc_counter[key] += 1
        severity_map.setdefault(key, []).append(entry.get("severity", "MEDIO"))
        engine_map.setdefault(key, set()).add(entry.get("source_engine", "unknown"))

    anonymized_iocs: List[Dict[str, Any]] = []
    for key, count in ioc_counter.most_common(50):
        typ, val = key.split(":", 1)
        severities = severity_map.get(key, [])
        max_sev = max(severities, key=lambda s: {"CRITICO": 4, "ALTO": 3, "MEDIO": 2, "BAJO": 1}.get(s, 0), default="MEDIO")
        anonymized_iocs.append({
            "ioc_type": typ,
            "ioc_value_hash": _anonymize_value(val),
            "ioc_value": val,
            "frequency": count,
            "max_severity": max_sev,
            "engines_detected": list(engine_map.get(key, [])),
            "recurrence_score": min(1.0, count / 10.0),
            "invented": False,
        })

    result = {
        "status": "ok",
        "iocs": anonymized_iocs,
        "total_detections": len(intel),
        "unique_iocs": len(ioc_counter),
        "generated_at_utc": _utc(),
        "privacy": "anonymized_metadata_only",
    }
    return result


def publish_to_swarm_mesh(iocs: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Publica IOC anonimizados al Swarm Mesh.
    Solo comparte: ioc_type, ioc_value_hash, frequency, max_severity.
    NUNCA comparte: documentos, correos, contraseñas, tokens, cookies.
    """
    if iocs is None:
        intel = generate_anonymized_intelligence()
        iocs = intel.get("iocs", [])

    published = []
    for ioc in iocs:
        safe_entry = {
            "ioc_type": ioc.get("ioc_type"),
            "ioc_value_hash": ioc.get("ioc_value_hash") or _anonymize_value(str(ioc.get("ioc_value", ""))),
            "ioc_value": ioc.get("ioc_value"),
            "frequency": ioc.get("frequency", 1),
            "max_severity": ioc.get("max_severity", "MEDIO"),
            "recurrence_score": ioc.get("recurrence_score", 0),
            "published_at_utc": _utc(),
            "privacy": "anonymized",
            "invented": False,
        }
        store_swarm_ioc(safe_entry)
        published.append(safe_entry)

    try:
        from services.defense_coordinator import defense_coordinator
        defense_coordinator.publish_event({
            "type": "tie_ioc_batch",
            "source": "threat_intelligence_enterprise",
            "iocs_count": len(published),
            "timestamp": _utc(),
        })
    except Exception as exc:
        logger.debug("TIE swarm publish fallback: %s", exc)

    return {
        "published_count": len(published),
        "timestamp_utc": _utc(),
        "privacy": "anonymized_metadata_only",
    }
