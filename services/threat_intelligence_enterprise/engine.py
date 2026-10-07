#!/usr/bin/env python3
"""
Motor principal del Threat Intelligence Enterprise.
Orquesta: feeds externos, inteligencia propia, enriquecimiento, Swarm, CryptoVault.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.threat_intelligence_enterprise.connectors import fetch_all_feeds, enrich_indicator, ALL_CONNECTORS
from services.threat_intelligence_enterprise.internal_intel import (
    generate_anonymized_intelligence,
    publish_to_swarm_mesh,
    ingest_internal_detection,
)
from services.threat_intelligence_enterprise.enrichment import enrich_for_kernel
from services.threat_intelligence_enterprise.store import (
    load_iocs,
    load_feed_log,
    load_internal_intel,
    load_enrichments,
    load_swarm_outbox,
    save_snapshot,
    NA,
)
from utils.logger import logger


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_full_cycle(
    fetch_feeds: bool = True,
    generate_internal: bool = True,
    publish_swarm: bool = True,
    limit_per_feed: int = 15,
) -> Dict[str, Any]:
    """Ejecuta un ciclo completo del TIE."""
    t0 = time.perf_counter()
    result: Dict[str, Any] = {"cycle_started_utc": _utc()}

    # 1. Fetch external feeds
    if fetch_feeds:
        try:
            feeds = fetch_all_feeds(limit_per_feed=limit_per_feed)
            result["external_feeds"] = feeds
        except Exception as exc:
            logger.error("TIE fetch feeds: %s", exc)
            result["external_feeds"] = {"status": NA, "reason": str(exc)[:300]}
    else:
        result["external_feeds"] = {"status": "skipped"}

    # 2. Generate internal intelligence
    if generate_internal:
        try:
            internal = generate_anonymized_intelligence()
            result["internal_intelligence"] = {
                "status": internal.get("status"),
                "unique_iocs": internal.get("unique_iocs", 0),
                "total_detections": internal.get("total_detections", 0),
            }
        except Exception as exc:
            logger.error("TIE internal intel: %s", exc)
            result["internal_intelligence"] = {"status": NA, "reason": str(exc)[:300]}
    else:
        result["internal_intelligence"] = {"status": "skipped"}

    # 3. Publish to Swarm Mesh
    if publish_swarm:
        try:
            swarm_result = publish_to_swarm_mesh()
            result["swarm_publish"] = swarm_result
        except Exception as exc:
            logger.error("TIE swarm publish: %s", exc)
            result["swarm_publish"] = {"status": NA, "reason": str(exc)[:300]}
    else:
        result["swarm_publish"] = {"status": "skipped"}

    # 4. Summary
    iocs = load_iocs(limit=500)
    result["summary"] = {
        "total_iocs_stored": len(iocs),
        "connectors_available": ALL_CONNECTORS,
        "cycle_duration_ms": round((time.perf_counter() - t0) * 1000, 2),
    }
    result["cycle_finished_utc"] = _utc()
    result["invented"] = False
    save_snapshot(result)
    return result


def get_dashboard() -> Dict[str, Any]:
    """Dashboard del Threat Intelligence Center."""
    iocs = load_iocs(limit=500)
    feeds = load_feed_log(limit=50)
    internal = load_internal_intel(limit=200)
    enrichments = load_enrichments(limit=100)
    swarm = load_swarm_outbox(limit=50)

    type_counts: Dict[str, int] = {}
    source_counts: Dict[str, int] = {}
    country_counts: Dict[str, int] = {}
    threat_counts: Dict[str, int] = {}
    malware_families: Dict[str, int] = {}

    for ioc in iocs:
        typ = ioc.get("type", "unknown")
        type_counts[typ] = type_counts.get(typ, 0) + 1
        src = ioc.get("source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1
        c = ioc.get("country")
        if c:
            country_counts[c] = country_counts.get(c, 0) + 1
        tt = ioc.get("threat_type")
        if tt:
            threat_counts[tt] = threat_counts.get(tt, 0) + 1
        mf = ioc.get("malware_family")
        if mf and mf != NA:
            malware_families[mf] = malware_families.get(mf, 0) + 1

    top_iocs = sorted(iocs, key=lambda x: float(x.get("confidence") or 0), reverse=True)[:20]

    return {
        "total_iocs": len(iocs),
        "iocs_by_type": type_counts,
        "iocs_by_source": source_counts,
        "iocs_by_country": dict(sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
        "threat_types": dict(sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:15]),
        "malware_families": dict(sorted(malware_families.items(), key=lambda x: x[1], reverse=True)[:15]),
        "top_iocs": top_iocs,
        "feed_history": feeds[-20:],
        "internal_detections": len(internal),
        "enrichments_performed": len(enrichments),
        "swarm_published": len(swarm),
        "connectors": ALL_CONNECTORS,
        "generated_at_utc": _utc(),
        "invented": False,
    }


def search_iocs(
    ioc_type: Optional[str] = None,
    value: Optional[str] = None,
    source: Optional[str] = None,
    threat_type: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Busca IOC en el store local."""
    iocs = load_iocs(limit=1000)
    results = []
    for ioc in iocs:
        if ioc_type and ioc.get("type") != ioc_type:
            continue
        if value and value.lower() not in str(ioc.get("value", "")).lower():
            continue
        if source and ioc.get("source") != source:
            continue
        if threat_type and threat_type.lower() not in str(ioc.get("threat_type", "")).lower():
            continue
        results.append(ioc)
        if len(results) >= limit:
            break
    return results


def stats() -> Dict[str, Any]:
    iocs = load_iocs(limit=1000)
    feeds = load_feed_log(limit=50)
    return {
        "total_iocs": len(iocs),
        "total_feeds_fetched": len(feeds),
        "connectors": ALL_CONNECTORS,
        "last_feed": feeds[-1] if feeds else None,
        "internal_detections": len(load_internal_intel(limit=500)),
        "enrichments": len(load_enrichments(limit=500)),
        "swarm_published": len(load_swarm_outbox(limit=500)),
        "generated_at_utc": _utc(),
    }
