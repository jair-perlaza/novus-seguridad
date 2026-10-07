#!/usr/bin/env python3
"""
VIEM Scanner — detecta vulnerabilidades reales correlacionando ASM + puertos + software.
NO inventa CVE. Consulta bases publicas cuando hay conexion.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil

from services.viem.limitations import NA
from services.viem.store import record_vuln, record_history
from utils.logger import logger


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _has_internet():
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3).close()
        return True
    except OSError:
        return False


def _vuln_id(software: str, version: str, port: Optional[int] = None) -> str:
    seed = f"{software}:{version}:{port or ''}"
    return f"VIEM-{hashlib.sha256(seed.encode()).hexdigest()[:10].upper()}"


# Known insecure service/version patterns (factual, not invented)
KNOWN_INSECURE_SERVICES = {
    21: {"service": "FTP", "risk": "ALTO", "reason": "FTP transmite credenciales en texto plano."},
    23: {"service": "Telnet", "risk": "CRITICO", "reason": "Telnet sin cifrado; toda comunicacion es visible."},
    69: {"service": "TFTP", "risk": "ALTO", "reason": "TFTP sin autenticacion ni cifrado."},
    161: {"service": "SNMP", "risk": "MEDIO", "reason": "SNMP v1/v2c usa community strings en texto plano."},
    445: {"service": "SMB", "risk": "ALTO", "reason": "SMB expuesto puede permitir movimiento lateral."},
    3389: {"service": "RDP", "risk": "ALTO", "reason": "RDP expuesto es vector comun de ataque."},
    5900: {"service": "VNC", "risk": "ALTO", "reason": "VNC sin cifrado por defecto."},
    1433: {"service": "MSSQL", "risk": "MEDIO", "reason": "Base de datos expuesta directamente."},
    3306: {"service": "MySQL", "risk": "MEDIO", "reason": "Base de datos expuesta directamente."},
    5432: {"service": "PostgreSQL", "risk": "MEDIO", "reason": "Base de datos expuesta directamente."},
    27017: {"service": "MongoDB", "risk": "ALTO", "reason": "MongoDB sin auth por defecto."},
    6379: {"service": "Redis", "risk": "ALTO", "reason": "Redis sin auth por defecto."},
    9200: {"service": "Elasticsearch", "risk": "ALTO", "reason": "Elasticsearch sin auth por defecto."},
    8080: {"service": "HTTP-alt", "risk": "BAJO", "reason": "HTTP sin cifrado en puerto alternativo."},
}


def scan_local_vulnerabilities() -> List[Dict[str, Any]]:
    """Escanea el host local buscando vulnerabilidades reales."""
    vulns: List[Dict[str, Any]] = []

    # 1. Open ports with insecure services
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr:
                port = conn.laddr.port
                if port in KNOWN_INSECURE_SERVICES:
                    info = KNOWN_INSECURE_SERVICES[port]
                    vuln = {
                        "vuln_id": _vuln_id(info["service"], "exposed", port),
                        "type": "insecure_service",
                        "title": f"{info['service']} expuesto en puerto {port}",
                        "description": info["reason"],
                        "risk_level": info["risk"],
                        "port": port,
                        "service": info["service"],
                        "host": socket.gethostname(),
                        "ip": conn.laddr.ip,
                        "pid": conn.pid,
                        "status": "open",
                        "first_seen_utc": _utc(),
                        "last_seen_utc": _utc(),
                        "remediation_status": "pending",
                        "remediation_proposal": f"Considerar deshabilitar o restringir acceso a {info['service']} en puerto {port}.",
                        "invented": False,
                    }
                    vulns.append(vuln)
                    record_vuln(vuln)
    except (psutil.AccessDenied, PermissionError):
        pass

    # 2. OS-level checks
    if platform.system() == "Windows":
        # Check Windows version for EOL
        ver = platform.version()
        release = platform.release()
        eol_versions = {"7", "8", "8.1", "XP", "Vista"}
        if release in eol_versions:
            vuln = {
                "vuln_id": _vuln_id("Windows", release),
                "type": "eol_os",
                "title": f"Sistema operativo obsoleto: Windows {release}",
                "description": f"Windows {release} ya no recibe actualizaciones de seguridad.",
                "risk_level": "CRITICO",
                "host": socket.gethostname(),
                "software": f"Windows {release}",
                "version": ver,
                "status": "open",
                "first_seen_utc": _utc(),
                "last_seen_utc": _utc(),
                "remediation_status": "pending",
                "remediation_proposal": "Actualizar a una version soportada de Windows.",
                "invented": False,
            }
            vulns.append(vuln)
            record_vuln(vuln)

    # 3. Check for well-known vulnerable software patterns from ASM
    try:
        from services.asm import discover_installed_software
        software = discover_installed_software()
        for sw in software:
            name = (sw.get("name") or "").lower()
            version = sw.get("version") or ""
            # Only flag actually known-vulnerable patterns, don't invent
            if "adobe flash" in name:
                vuln = {
                    "vuln_id": _vuln_id("Adobe Flash", version),
                    "type": "eol_software",
                    "title": f"Software obsoleto: Adobe Flash Player {version}",
                    "description": "Adobe Flash Player descontinuado y con multiples CVE conocidos.",
                    "risk_level": "CRITICO",
                    "software": sw.get("name"),
                    "version": version,
                    "host": socket.gethostname(),
                    "status": "open",
                    "remediation_proposal": "Desinstalar Adobe Flash Player.",
                    "invented": False,
                }
                vulns.append(vuln)
                record_vuln(vuln)
            elif "java" in name and "runtime" in name:
                # Old Java versions have many CVEs
                major = re.search(r"(\d+)[\._]", version)
                if major and int(major.group(1)) < 11:
                    vuln = {
                        "vuln_id": _vuln_id("Java", version),
                        "type": "outdated_software",
                        "title": f"Java Runtime obsoleto: {version}",
                        "description": "Versiones de Java < 11 tienen multiples CVE conocidos.",
                        "risk_level": "ALTO",
                        "software": sw.get("name"),
                        "version": version,
                        "host": socket.gethostname(),
                        "status": "open",
                        "remediation_proposal": "Actualizar a Java 17+ LTS.",
                        "invented": False,
                    }
                    vulns.append(vuln)
                    record_vuln(vuln)
    except Exception as exc:
        logger.debug("VIEM software scan: %s", exc)

    # 4. Correlate with ASM exposure
    try:
        from services.asm.store import load_inventory
        inv = load_inventory()
        if inv:
            exp = inv.get("exposure", {})
            for vuln in vulns:
                vuln["asm_exposure_score"] = exp.get("exposure_score", 0)
                vuln["asm_criticality"] = inv.get("criticality", {}).get("level")
                vuln["asm_asset_id"] = inv.get("local_host", {}).get("asset_id")
    except Exception:
        pass

    return vulns


def enrich_with_tie(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enriquece vulnerabilidades con Threat Intelligence (solo datos reales)."""
    for vuln in vulns:
        service = vuln.get("service") or vuln.get("software") or ""
        try:
            from services.threat_intelligence_enterprise.store import load_iocs
            iocs = load_iocs(limit=200)
            related = [i for i in iocs if service.lower() in str(i.get("threat_type") or "").lower()]
            vuln["tie_related_iocs"] = len(related)
            vuln["tie_enriched"] = len(related) > 0
        except Exception:
            vuln["tie_related_iocs"] = 0
            vuln["tie_enriched"] = False
    return vulns


def compute_risk_scores(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Calcula risk scores explicables para cada vulnerabilidad."""
    risk_map = {"CRITICO": 1.0, "ALTO": 0.75, "MEDIO": 0.5, "BAJO": 0.25}
    for vuln in vulns:
        base_risk = risk_map.get(vuln.get("risk_level", "MEDIO"), 0.5)
        exposure = float(vuln.get("asm_exposure_score") or 0)
        tie_factor = 0.1 if vuln.get("tie_enriched") else 0

        risk_score = round(min(1.0, base_risk * 0.5 + exposure * 0.3 + tie_factor + 0.1), 4)
        vuln["risk_score"] = risk_score
        vuln["exposure_score"] = exposure
        vuln["exploit_likelihood"] = "known" if vuln.get("type") in ("eol_software", "eol_os") else "potential"
        vuln["remediation_priority"] = (
            "INMEDIATA" if risk_score >= 0.7 else
            "ALTA" if risk_score >= 0.5 else
            "MEDIA" if risk_score >= 0.3 else "BAJA"
        )
        vuln["risk_factors"] = {
            "base_risk": base_risk,
            "asm_exposure": exposure,
            "tie_enrichment": tie_factor,
        }
    return vulns
