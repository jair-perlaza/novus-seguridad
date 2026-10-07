#!/usr/bin/env python3
"""Estado del Swarm Mesh para dashboard / API (solo datos reales)."""
from __future__ import annotations

from typing import Any, Dict, List


def mesh_status() -> Dict[str, Any]:
    from services.swarm_defense.mesh import channel_keys, intel_store, node_identity, trust_registry

    identity = node_identity.identity_status()
    trust = trust_registry.trust_status()
    intel = intel_store.stats()
    peers = trust.get("peers") or []
    channels_ready = 0
    peer_rows: List[Dict[str, Any]] = []
    for p in peers:
        pid = p.get("peer_id")
        has_ch = channel_keys.has_channel(pid) if pid else False
        if has_ch:
            channels_ready += 1
        peer_rows.append(
            {
                "peer_id": pid,
                "label": p.get("label"),
                "base_url": p.get("base_url"),
                "fingerprint": p.get("fingerprint"),
                "reputation": p.get("reputation"),
                "messages_accepted": p.get("messages_accepted"),
                "messages_rejected": p.get("messages_rejected"),
                "channel_ready": has_ch,
                "revoked": bool(p.get("revoked")),
            }
        )

    enabled = bool(identity.get("ok")) and True  # mesh code present
    healthy = bool(identity.get("ok")) and (trust.get("trusted_peers", 0) == 0 or channels_ready > 0)

    return {
        "ok": True,
        "implemented": True,
        "enabled": enabled,
        "mode": "http_peer_mesh",
        "centralized_broker": False,
        "node": {
            "node_id": identity.get("node_id"),
            "fingerprint": identity.get("fingerprint"),
            "algorithm": identity.get("algorithm"),
            "crypto_ok": bool(identity.get("ok")),
        },
        "peers_connected": channels_ready,  # ready channel = operable peer
        "trusted_peers": trust.get("trusted_peers"),
        "revoked_peers": trust.get("revoked_peers"),
        "channels_ready": channels_ready,
        "sync": {
            "outbound_events": intel.get("outbound_events"),
            "inbound_events": intel.get("inbound_events"),
            "ioc_counts": intel.get("ioc_counts"),
        },
        "crypto": {
            "node_identity": "Ed25519",
            "envelope": "AES-256-GCM",
            "transport": "HTTP(S) peer push — TLS 1.3 when peer serves HTTPS",
            "anti_replay": True,
            "anti_poisoning": True,
            "trust_list": True,
            "revocation": True,
        },
        "health": "ok" if healthy else "degraded",
        "peers": peer_rows,
        "recent_inbound": intel_store.recent("inbound", 10),
        "recent_outbound": intel_store.recent("outbound", 10),
        "limitations": [
            "Mesh peer-to-peer HTTP; requiere peers confiados + clave de canal.",
            "TLS 1.3 depende del listener HTTPS del peer (lab local puede ser HTTP).",
            "No hay broker central: cada nodo empuja a sus peers.",
        ],
    }
