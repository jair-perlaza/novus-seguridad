#!/usr/bin/env python3
"""Swarm Mesh Enterprise — colmena distribuida multi-nodo (peer-to-peer)."""
from __future__ import annotations

from services.swarm_defense.mesh import (
    anti_abuse,
    channel_keys,
    envelope,
    forensic_mesh,
    ingest,
    intel_store,
    node_identity,
    propagator,
    status,
    transport,
    trust_registry,
)

__all__ = [
    "anti_abuse",
    "channel_keys",
    "envelope",
    "forensic_mesh",
    "ingest",
    "intel_store",
    "node_identity",
    "propagator",
    "status",
    "transport",
    "trust_registry",
    "mesh_status",
    "ingest_envelope",
    "propagate_to_peers",
    "ensure_local_node",
]


def mesh_status():
    return status.mesh_status()


def ingest_envelope(envelope_dict):
    return ingest.ingest_envelope(envelope_dict)


def propagate_to_peers(**kwargs):
    return propagator.propagate_to_peers(**kwargs)


def ensure_local_node():
    return node_identity.ensure_node_identity()
