#!/usr/bin/env python3
"""
Propagación automática de amenazas a peers confiados (colonia).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from utils.logger import logger


def build_intel_payload_from_correlation(
    *,
    correlation: Dict[str, Any],
    origin_event: Optional[Dict[str, Any]] = None,
    indicators: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    inds = dict(indicators or {})
    # Normalizar desde extract_indicators / correlation
    if not inds and origin_event:
        try:
            from services.swarm_defense.indicators import extract_indicators

            inds = extract_indicators(origin_event) or {}
        except Exception:
            inds = {}
    # Mapear a estructura mesh
    mapped = {
        "ips": list(inds.get("ips") or inds.get("ip") or []),
        "domains": list(inds.get("domains") or inds.get("domain") or []),
        "urls": list(inds.get("urls") or inds.get("url") or []),
        "hashes": list(inds.get("hashes") or inds.get("hash") or []),
        "iocs": list(inds.get("iocs") or []),
        "ioas": list(inds.get("ioas") or []),
        "behaviors": list(inds.get("behaviors") or inds.get("behavior") or []),
    }
    # Si correlation trae keys
    for k in ("ips", "domains", "hashes", "urls"):
        extra = correlation.get(k) if isinstance(correlation, dict) else None
        if isinstance(extra, list):
            mapped[k] = list({*mapped[k], *[str(x) for x in extra if x]})

    # P0-2: conservar tenant canónico en el payload Mesh (no email-domain).
    from services.swarm_defense.mesh.intel_store import resolve_ioc_tenant_id

    tid = resolve_ioc_tenant_id(origin_event) or resolve_ioc_tenant_id(correlation)

    return {
        "indicators": mapped,
        "tenant_id": tid,
        "origin": {
            "source_event_id": (origin_event or {}).get("event_id")
            or (origin_event or {}).get("id")
            or (correlation or {}).get("event_id"),
            "correlation_id": (correlation or {}).get("correlation_id") or (correlation or {}).get("id"),
            "confidence": (correlation or {}).get("confidence"),
            "classification": (correlation or {}).get("classification") or (correlation or {}).get("category"),
            "tenant_id": tid,
        },
        "evidence_ref": (correlation or {}).get("evidence_ref"),
        "swarm_decision": {
            "priority": (correlation or {}).get("priority"),
            "auto_actions": (correlation or {}).get("auto_actions"),
        },
        "invented": False,
        "synthetic": False,
    }


def propagate_to_peers(
    *,
    correlation: Dict[str, Any],
    origin_event: Optional[Dict[str, Any]] = None,
    indicators: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Firma+cifra y empuja intel a cada peer confiado con canal."""
    from services.swarm_defense.mesh import (
        anti_abuse,
        channel_keys,
        envelope,
        intel_store,
        node_identity,
        trust_registry,
        transport,
    )
    from services.swarm_defense.mesh import forensic_mesh

    payload = build_intel_payload_from_correlation(
        correlation=correlation or {},
        origin_event=origin_event,
        indicators=indicators,
    )
    v = anti_abuse.validate_intel_payload(payload)
    if not v.get("ok"):
        return {"ok": False, "skipped": True, "reason": v.get("reason"), "sent": 0}

    private, sender_id, _pub = node_identity.load_signing_keypair()
    peers = trust_registry.list_peers()
    results: List[Dict[str, Any]] = []
    sent = 0
    for peer in peers:
        pid = peer["peer_id"]
        if pid == sender_id:
            continue
        if not channel_keys.has_channel(pid):
            results.append({"peer_id": pid, "ok": False, "error": "no_channel_key"})
            continue
        try:
            key = channel_keys.load_channel_key(pid)
            env = envelope.seal_envelope(
                payload=payload,
                peer_id=pid,
                sender_node_id=sender_id,
                private_key=private,
                channel_key=key,
                msg_type="threat_intel",
            )
            push = transport.push_envelope(base_url=peer["base_url"], envelope=env)
            forensic_mesh.seal_mesh_transfer(
                direction="outbound",
                peer_id=pid,
                msg_id=(env.get("meta") or {}).get("msg_id"),
                ok=bool(push.get("ok")),
                detail={"latency_ms": push.get("latency_ms"), "status": push.get("status")},
            )
            intel_store.record_outbound(
                {
                    "peer_id": pid,
                    "msg_id": (env.get("meta") or {}).get("msg_id"),
                    "push": {"ok": push.get("ok"), "status": push.get("status"), "latency_ms": push.get("latency_ms")},
                    "indicator_count": v.get("indicator_count"),
                }
            )
            if push.get("ok"):
                sent += 1
            results.append({"peer_id": pid, **push})
        except Exception as exc:
            logger.debug("mesh propagate peer=%s: %s", pid, exc)
            results.append({"peer_id": pid, "ok": False, "error": str(exc)[:160]})

    # APE: no observe_async aquí (ARP); el aprendizaje ocurre en nodo emisor vía propagator
    return {"ok": sent > 0 or not peers, "sent": sent, "peers_targeted": len(peers), "results": results}
