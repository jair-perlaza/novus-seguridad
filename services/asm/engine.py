#!/usr/bin/env python3
"""
Motor principal ASM — Asset Intelligence & Attack Surface Management.
Coordina discovery, calcula exposicion, criticidad, shadow IT, dependencias.
"""
from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.asm.limitations import NA
from services.asm.discovery import (
    discover_local_host,
    discover_network_nodes,
    discover_installed_software,
    discover_services,
    discover_certificates,
    discover_open_ports_local,
    discover_processes_summary,
)
from services.asm.store import (
    save_inventory, load_inventory, record_history, record_shadow_it,
    load_history, load_shadow_it,
)
from utils.logger import logger

_previous_inventory: Optional[Dict[str, Any]] = None


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _compute_exposure(asset: Dict, ports: List, certs: List, software: List) -> Dict[str, Any]:
    score = 0.0
    factors = []
    open_count = len([p for p in ports if isinstance(p, dict) and p.get("port")])
    if open_count > 20:
        score += 0.3; factors.append(f"{open_count} puertos abiertos")
    elif open_count > 5:
        score += 0.15; factors.append(f"{open_count} puertos abiertos")
    expired_certs = [c for c in certs if isinstance(c, dict) and c.get("expired")]
    if expired_certs:
        score += 0.2; factors.append(f"{len(expired_certs)} certificados vencidos")
    insecure_ports = [p for p in ports if isinstance(p, dict) and p.get("port") in (21, 23, 69, 161, 445, 3389)]
    if insecure_ports:
        score += 0.2; factors.append(f"{len(insecure_ports)} servicios inseguros")
    if not factors:
        factors.append("Exposicion minima")
    return {
        "exposure_score": round(min(1.0, score), 4),
        "factors": factors,
        "open_ports_count": open_count,
        "expired_certificates": len(expired_certs),
        "insecure_services": len(insecure_ports),
    }


def _compute_criticality(asset: Dict, exposure: Dict) -> Dict[str, Any]:
    base = 0.5
    classification = asset.get("classification", "cliente")
    if classification == "servidor": base = 0.8
    elif classification == "infraestructura": base = 0.9
    elif classification in ("iot_camera", "iot"): base = 0.6
    exp_score = exposure.get("exposure_score", 0)
    criticality = round(min(1.0, base * 0.6 + exp_score * 0.4), 4)
    if criticality >= 0.75: level = "CRITICO"
    elif criticality >= 0.5: level = "ALTO"
    elif criticality >= 0.25: level = "MEDIO"
    else: level = "BAJO"
    return {
        "criticality_score": criticality,
        "level": level,
        "classification": classification,
        "impact": "alto" if classification in ("servidor", "infraestructura") else "medio",
    }


def _detect_shadow_it(
    current_nodes: List[Dict],
    previous_nodes: List[Dict],
    current_software: List[Dict],
    previous_software: List[Dict],
) -> List[Dict[str, Any]]:
    prev_macs = {(n.get("mac") or "").lower() for n in previous_nodes if n.get("mac")}
    prev_sw = {s.get("name", "") for s in previous_software if s.get("name")}
    findings = []
    for node in current_nodes:
        mac = (node.get("mac") or "").lower()
        if mac and mac not in prev_macs and mac != NA.lower():
            finding = {
                "type": "new_device",
                "asset_id": node.get("asset_id"),
                "hostname": node.get("hostname"),
                "ip": node.get("ip"),
                "mac": node.get("mac"),
                "vendor": node.get("vendor"),
                "detail": "Dispositivo nuevo detectado en la red.",
                "detected_at_utc": _utc(),
                "invented": False,
            }
            findings.append(finding)
            record_shadow_it(finding)
    for sw in current_software:
        name = sw.get("name", "")
        if name and name not in prev_sw and name != NA:
            finding = {
                "type": "new_software",
                "name": name,
                "version": sw.get("version"),
                "publisher": sw.get("publisher"),
                "detail": "Software nuevo detectado.",
                "detected_at_utc": _utc(),
                "invented": False,
            }
            findings.append(finding)
            record_shadow_it(finding)
    return findings


def _build_dependency_map(host: Dict, nodes: List, ports: List) -> List[Dict[str, Any]]:
    deps = []
    gateway = host.get("gateway")
    if gateway and gateway != NA:
        deps.append({"from": host.get("asset_id"), "to": f"gateway-{gateway}", "type": "network", "via": "default_gateway"})
    for dns in host.get("dns_servers", []):
        if dns != NA:
            deps.append({"from": host.get("asset_id"), "to": f"dns-{dns}", "type": "dns"})
    db_ports = [p for p in ports if isinstance(p, dict) and p.get("port") in (3306, 5432, 1433, 27017, 6379)]
    for p in db_ports:
        deps.append({"from": host.get("asset_id"), "to": f"db-port-{p['port']}", "type": "database", "port": p["port"]})
    web_ports = [p for p in ports if isinstance(p, dict) and p.get("port") in (80, 443, 8080, 8443)]
    for p in web_ports:
        deps.append({"from": host.get("asset_id"), "to": f"web-port-{p['port']}", "type": "web_service", "port": p["port"]})
    return deps


def run_full_scan() -> Dict[str, Any]:
    """Ejecuta scan completo: host, red, software, servicios, certificados, puertos."""
    global _previous_inventory
    t0 = time.perf_counter()
    prev = load_inventory() or {}
    _previous_inventory = prev

    host = discover_local_host()
    nodes = discover_network_nodes()
    software = discover_installed_software()
    services = discover_services()
    certs = discover_certificates()
    ports = discover_open_ports_local()
    processes = discover_processes_summary()

    exposure = _compute_exposure(host, ports, certs, software)
    criticality = _compute_criticality(host, exposure)
    dependencies = _build_dependency_map(host, nodes, ports)

    prev_nodes = prev.get("network_nodes") or []
    prev_software = prev.get("software") or []
    shadow_it = _detect_shadow_it(nodes, prev_nodes, software, prev_software)

    inventory = {
        "local_host": host,
        "network_nodes": nodes,
        "software": software,
        "services": services,
        "certificates": certs,
        "open_ports": ports,
        "processes": processes,
        "exposure": exposure,
        "criticality": criticality,
        "dependencies": dependencies,
        "shadow_it_findings": shadow_it,
        "summary": {
            "total_assets": 1 + len(nodes),
            "network_devices": len(nodes),
            "software_count": len([s for s in software if s.get("name") and s["name"] != NA]),
            "services_count": len([s for s in services if s.get("name") and s["name"] != NA]),
            "certificates_count": len([c for c in certs if c.get("subject") and c["subject"] != NA]),
            "open_ports_count": len([p for p in ports if isinstance(p, dict) and p.get("port") and p["port"] != NA]),
            "shadow_it_count": len(shadow_it),
            "exposure_score": exposure.get("exposure_score", 0),
            "criticality_level": criticality.get("level"),
        },
        "scan_duration_ms": round((time.perf_counter() - t0) * 1000, 2),
        "scanned_at_utc": _utc(),
        "invented": False,
    }

    save_inventory(inventory)
    record_history({
        "event": "full_scan",
        "assets_discovered": inventory["summary"]["total_assets"],
        "shadow_it": len(shadow_it),
        "duration_ms": inventory["scan_duration_ms"],
    })
    return inventory


def get_dashboard() -> Dict[str, Any]:
    inv = load_inventory()
    if not inv:
        return {"status": "no_scan_yet", "note": "Ejecute un scan primero."}
    return {
        "local_host": inv.get("local_host", {}),
        "network_nodes_count": len(inv.get("network_nodes") or []),
        "network_nodes": inv.get("network_nodes", [])[:30],
        "software_count": inv.get("summary", {}).get("software_count", 0),
        "software_sample": inv.get("software", [])[:20],
        "services_count": inv.get("summary", {}).get("services_count", 0),
        "certificates": inv.get("certificates", []),
        "open_ports": inv.get("open_ports", [])[:30],
        "exposure": inv.get("exposure", {}),
        "criticality": inv.get("criticality", {}),
        "dependencies": inv.get("dependencies", []),
        "shadow_it": inv.get("shadow_it_findings", []),
        "summary": inv.get("summary", {}),
        "scanned_at_utc": inv.get("scanned_at_utc"),
        "history": load_history(20),
        "invented": False,
    }


def stats() -> Dict[str, Any]:
    inv = load_inventory()
    if not inv:
        return {"status": "no_scan", "total_assets": 0}
    return {
        "total_assets": inv.get("summary", {}).get("total_assets", 0),
        "network_devices": inv.get("summary", {}).get("network_devices", 0),
        "software": inv.get("summary", {}).get("software_count", 0),
        "services": inv.get("summary", {}).get("services_count", 0),
        "certificates": inv.get("summary", {}).get("certificates_count", 0),
        "open_ports": inv.get("summary", {}).get("open_ports_count", 0),
        "shadow_it": inv.get("summary", {}).get("shadow_it_count", 0),
        "exposure_score": inv.get("summary", {}).get("exposure_score", 0),
        "criticality": inv.get("summary", {}).get("criticality_level"),
        "scanned_at_utc": inv.get("scanned_at_utc"),
    }
