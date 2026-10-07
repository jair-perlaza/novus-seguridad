"""
CLOUD-P1 — runtime role separation (Cloud vs Client Node).

Does not remove engines. When NOVUS_RUNTIME=cloud, Client-Node-only starters
(LAN/ARP/YARA/Endpoint/BTDE/ZDDE network scan) must not auto-start.
Default remains client_node / full local beta behavior.
"""
from __future__ import annotations

import os
from typing import FrozenSet

# Engines that require local host / LAN / filesystem sensors — Client Node only.
CLIENT_NODE_ONLY_ENGINES: FrozenSet[str] = frozenset(
    {
        "endpoint_realtime",
        "endpoint_enterprise",
        "network_endpoint_enterprise",
        "btde",
        "zdde",
        "forensic_pcap",
        "endpoint",  # group alias
    }
)


def resolve_runtime_role() -> str:
    """
    Returns: cloud | client_node

    NOVUS_RUNTIME=cloud → Cloud Run-oriented process (no LAN scanners at boot).
    NOVUS_RUNTIME=client_node | empty | other → full local / node behavior.
    """
    raw = (os.environ.get("NOVUS_RUNTIME") or "").strip().lower()
    if raw in ("cloud", "cloud_run", "api"):
        return "cloud"
    return "client_node"


def is_cloud_runtime() -> bool:
    return resolve_runtime_role() == "cloud"


def client_node_engines_enabled() -> bool:
    return not is_cloud_runtime()


def may_start_engine(name: str) -> bool:
    """False when cloud runtime and engine is Client-Node-only."""
    if not is_cloud_runtime():
        return True
    key = (name or "").strip().lower()
    return key not in CLIENT_NODE_ONLY_ENGINES


def may_run_network_discovery() -> bool:
    """ARP/Scapy discovery must not run on Cloud runtime."""
    if is_cloud_runtime():
        return False
    skip = (os.environ.get("NOVUS_SKIP_NETWORK_DISCOVERY") or "").strip().lower()
    if skip in ("1", "true", "yes", "on"):
        return False
    return True


def runtime_info() -> dict:
    return {
        "runtime": resolve_runtime_role(),
        "client_node_engines_enabled": client_node_engines_enabled(),
        "network_discovery_allowed": may_run_network_discovery(),
        "env_novus_runtime": (os.environ.get("NOVUS_RUNTIME") or "").strip() or None,
    }
