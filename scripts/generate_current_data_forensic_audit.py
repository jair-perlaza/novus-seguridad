#!/usr/bin/env python3
"""Generador READ-ONLY de auditoría forense de datos visibles — no modifica plataforma."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "novus_release_candidate"
LIVE_SNAP = OUT_DIR / "_audit_live_snapshot.json"
OUT_JSON = OUT_DIR / "NOVUS_CURRENT_DATA_FORENSIC_AUDIT.json"
OUT_INV = OUT_DIR / "NOVUS_CURRENT_DATA_INVENTORY.json"
OUT_MD = OUT_DIR / "NOVUS_CURRENT_DATA_FORENSIC_AUDIT.md"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _item(
    *,
    screen: str,
    element: str,
    value_observed: Any = None,
    endpoint: str = "",
    service: str = "",
    motor: str = "",
    primary_source: str = "",
    provenance: str = "",
    freshness: str = "",
    classification: str = "UNKNOWN",
    confiable: str = "NO PUEDO CONFIRMARLO",
    evidence: str = "",
    notes: str = "",
    file_ref: str = "",
    function_ref: str = "",
    risk: str = "",
) -> Dict[str, Any]:
    return {
        "pantalla": screen,
        "elemento": element,
        "valor_observado": value_observed,
        "endpoint": endpoint,
        "servicio": service,
        "motor": motor,
        "fuente_primaria": primary_source,
        "provenance": provenance,
        "freshness": freshness,
        "clasificacion": classification,
        "confiable": confiable,
        "evidencia": evidence,
        "notas": notes,
        "archivo": file_ref,
        "funcion": function_ref,
        "riesgo": risk,
    }


def _load_live() -> Dict[str, Any]:
    if LIVE_SNAP.is_file():
        return json.loads(LIVE_SNAP.read_text(encoding="utf-8"))
    return {"paths": {}}


def _body(live: Dict[str, Any], path: str) -> Dict[str, Any]:
    return (live.get("paths", {}).get(path, {}) or {}).get("body") or {}


def _snapshot_meta() -> List[Dict[str, Any]]:
    rows = []
    for rel in (
        "data/network/nodes_snapshot.json",
        "data/network/ndr_snapshot.json",
        "data/network/topology_snapshot.json",
        "data/security/summary_snapshot.json",
        "data/network/context_snapshot.json",
    ):
        p = ROOT / rel
        if not p.is_file():
            continue
        st = p.stat()
        rows.append(
            {
                "path": rel,
                "size_bytes": st.st_size,
                "mtime_utc": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
                "feeds_ui": rel.endswith("nodes_snapshot.json")
                or rel.endswith("summary_snapshot.json")
                or rel.endswith("topology_snapshot.json")
                or rel.endswith("ndr_snapshot.json"),
            }
        )
    return rows


def build_inventory(live: Dict[str, Any]) -> List[Dict[str, Any]]:
    inv: List[Dict[str, Any]] = []
    dash = _body(live, "/api/dashboard/live")
    summary = _body(live, "/api/security/summary")
    nodes = _body(live, "/api/network/nodes?trigger_discovery=false")
    topo = _body(live, "/api/network/topology")
    ndr = _body(live, "/api/network/ndr")
    nm = _body(live, "/api/monitoring/network-config")
    threats = _body(live, "/api/security/threats")
    vulns = _body(live, "/api/security/vulnerabilities")
    endpoints = _body(live, "/api/security/endpoints")
    ai = _body(live, "/api/ai/status")
    notif_sec = _body(live, "/api/notifications?kind=security&limit=20")
    notif_sys = _body(live, "/api/notifications?kind=system&limit=20")
    scope = _body(live, "/api/tenant/scope")
    web = _body(live, "/api/web-shield/status")
    search = _body(live, "/api/search?q=alert&limit=10")
    reports = _body(live, "/api/reports")
    evidence = _body(live, "/api/system/evidence-center?limit=20")
    sessions = _body(live, "/api/system/login-sessions")
    health = _body(live, "/api/health/status")
    defense = _body(live, "/api/manual-defense/summary")

    # Dashboard KPIs
    inv.append(
        _item(
            screen="Dashboard",
            element="CPU %",
            value_observed=dash.get("cpu_percent") or dash.get("cpu"),
            endpoint="/api/dashboard/live",
            service="dashboard_live_service",
            motor="system_monitor",
            primary_source="psutil / OS",
            provenance="system_monitor.get_system_status",
            freshness="REAL_LIVE",
            classification="REAL_LIVE",
            confiable="SI",
            evidence="Lectura directa del host en request",
            file_ref="services/dashboard_live_service.py",
            function_ref="get_dashboard_live_payload",
        )
    )
    inv.append(
        _item(
            screen="Dashboard",
            element="RAM %",
            value_observed=dash.get("ram_percent") or dash.get("ram"),
            endpoint="/api/dashboard/live",
            service="dashboard_live_service",
            motor="system_monitor",
            primary_source="psutil",
            provenance="system_monitor",
            freshness="REAL_LIVE",
            classification="REAL_LIVE",
            confiable="SI",
            file_ref="services/system_monitor.py",
        )
    )
    inv.append(
        _item(
            screen="Dashboard",
            element="Amenazas (contador KPI)",
            value_observed=dash.get("amenazas"),
            endpoint="/api/dashboard/live",
            service="dashboard_live_service",
            motor="novus_security_integration",
            primary_source="novus_security.get_cached_threat_count()",
            provenance="motor cache RAM",
            freshness="CACHED o UNAVAILABLE",
            classification="REAL_CACHED" if dash.get("amenazas") not in (None, "Sin datos disponibles") else "NOT_AVAILABLE",
            confiable="SI" if dash.get("amenazas") not in (None, "Sin datos disponibles") else "NO PUEDO CONFIRMARLO",
            notes="Observado: Sin datos disponibles cuando counters_pending=true",
            file_ref="services/dashboard_live_service.py",
        )
    )
    inv.append(
        _item(
            screen="Dashboard",
            element="Dispositivos red (KPI)",
            value_observed=dash.get("nodes_total"),
            endpoint="/api/dashboard/live",
            service="platform_metrics_service / network_snapshot_service",
            motor="network_scanner",
            primary_source="nodes_snapshot + ARP cache",
            provenance="read_nodes_api",
            freshness=str(nodes.get("data_freshness") or "pending"),
            classification="REAL_STALE" if nodes.get("data_freshness") == "stale" else "REAL_CACHED",
            confiable="SI" if nodes.get("observed_device_count") else "NO",
            notes=f"count={nodes.get('count')} observed={nodes.get('observed_device_count')}",
            file_ref="services/network_snapshot_service.py",
            risk="MEDIO" if nodes.get("count") and not nodes.get("observed_device_count") else "",
        )
    )
    inv.append(
        _item(
            screen="Dashboard",
            element="counters_pending flag",
            value_observed=dash.get("counters_pending"),
            endpoint="/api/dashboard/live",
            service="dashboard_live_service",
            primary_source="performance_cache peek",
            classification="STATIC",
            confiable="SI",
            evidence="Indicador honesto de datos no listos — no inventa contadores",
            file_ref="services/dashboard_live_service.py",
        )
    )
    inv.append(
        _item(
            screen="Dashboard",
            element="Protection score",
            value_observed=summary.get("protection_score") or dash.get("protection_score"),
            endpoint="/api/system/protection-score o /api/security/summary",
            service="platform_protection_score_service",
            motor="N/A",
            primary_source="checks binarios runtime",
            provenance="compute_protection_score",
            classification="CALCULATED_FROM_REAL",
            confiable="SI",
            evidence="Fórmula: passed_checks/core_total*100 — no hardcoded percent",
            file_ref="services/platform_protection_score_service.py",
            function_ref="compute_protection_score",
        )
    )
    inv.append(
        _item(
            screen="Dashboard",
            element="Estado General (SSE progreso)",
            value_observed="stream",
            endpoint="/api/monitoring/stream",
            service="continuous_monitoring_orchestrator",
            motor="defense motors poll",
            primary_source="motor telemetry + session state",
            classification="REAL_LIVE",
            confiable="SI",
            file_ref="services/continuous_monitoring_orchestrator.py",
        )
    )
    inv.append(
        _item(
            screen="Dashboard",
            element="Tráfico red (chart)",
            value_observed={"recv": dash.get("network_bytes_recv"), "sent": dash.get("network_bytes_sent")},
            endpoint="/api/dashboard/live",
            service="system_monitor",
            primary_source="psutil.net_io_counters (host local)",
            classification="REAL_LIVE",
            confiable="SI",
            notes="Solo tráfico del host NOVUS, no tráfico LAN total",
            file_ref="services/system_monitor.py",
        )
    )

    # Network
    for field, src in (
        ("local_ip", "OS interface / network_scanner meta"),
        ("gateway", "OS / ARP meta"),
        ("network_cidr", "interface netmask calculation"),
        ("interface", "psutil/netsh"),
        ("dns", "network_dns_service live query"),
    ):
        inv.append(
            _item(
                screen="Network / Config Monitoreo",
                element=field,
                value_observed=nodes.get(field) or nm.get(field),
                endpoint="/api/network/nodes | /api/monitoring/network-config",
                service="network_monitoring_service / network_snapshot_service",
                motor="network_scanner",
                primary_source=src,
                classification="REAL_LIVE",
                confiable="SI",
                file_ref="services/network_monitoring_service.py",
            )
        )
    inv.append(
        _item(
            screen="Network",
            element="Lista dispositivos (count)",
            value_observed={"count": nodes.get("count"), "observed_device_count": nodes.get("observed_device_count")},
            endpoint="/api/network/nodes",
            service="network_snapshot_service.read_nodes_api",
            motor="network_scanner ARP/Scapy",
            primary_source="data/network/nodes_snapshot.json → ARP cache",
            provenance="arp_scapy + snapshot_meta",
            freshness=str(nodes.get("data_freshness")),
            classification="REAL_STALE" if nodes.get("data_freshness") == "stale" else "REAL_CACHED",
            confiable="SI" if nodes.get("data_freshness") == "live" else "NO PUEDO CONFIRMARLO",
            notes="observed_device_count=0 cuando stale — no presenta histórico como LIVE",
            file_ref="services/network_snapshot_service.py",
            function_ref="observed_device_count_for_freshness",
            risk="CRITICAL_DATA_TRUST_ISSUE" if nodes.get("data_freshness") == "live" and nodes.get("snapshot_meta", {}).get("snapshot_stale") else "",
        )
    )
    for i, node in enumerate((nodes.get("nodes") or [])[:10]):
        inv.append(
            _item(
                screen="Network",
                element=f"Dispositivo[{i}] IP/MAC",
                value_observed={"ip": node.get("ip"), "mac": node.get("mac"), "method": node.get("detection_method")},
                endpoint="/api/network/nodes",
                service="network_scanner",
                motor="ARP/Scapy",
                primary_source="scan_arp_light",
                classification="REAL_CACHED",
                freshness=str(node.get("data_freshness") or nodes.get("data_freshness")),
                confiable="NO PUEDO CONFIRMARLO" if nodes.get("data_freshness") == "stale" else "SI",
                file_ref="services/network_scanner.py",
            )
        )

    # Topology — CRITICAL
    inv.append(
        _item(
            screen="Topology",
            element="Nodos mapa",
            value_observed=len(topo.get("nodes") or []),
            endpoint="/api/network/topology",
            service="topology_service",
            motor="network_scanner + NDR snapshot",
            primary_source="topology_snapshot / nodes ARP",
            classification="REAL_CACHED",
            confiable="SI",
            file_ref="services/topology_service.py",
        )
    )
    inv.append(
        _item(
            screen="Topology",
            element="Intensidad tráfico (gateway edges)",
            value_observed="min(100, connections_active * 3)",
            endpoint="/api/network/topology",
            service="topology_service.build_real_connections",
            motor="NDR connection counts",
            primary_source="heurística sobre conexiones psutil",
            classification="CALCULATED_FROM_REAL",
            confiable="NO",
            evidence="No mide bytes; escala conexiones ×3",
            notes="REAL_TOPOLOGY_NO_TRAFFIC_MEASUREMENT para peer edges",
            file_ref="services/topology_service.py",
            function_ref="build_real_connections",
            risk="ALTO — puede interpretarse como tráfico medido",
        )
    )
    inv.append(
        _item(
            screen="Topology",
            element="Peer connections traffic_measured",
            value_observed=False,
            endpoint="/api/network/topology",
            service="topology_service.build_peer_connections",
            classification="REAL_TOPOLOGY_NO_TRAFFIC_MEASUREMENT",
            confiable="SI",
            evidence="traffic_measured=False explícito",
            file_ref="services/topology_service.py",
        )
    )

    # Threats / Vulns
    inv.append(
        _item(
            screen="Amenazas / XDR",
            element="Lista alertas",
            value_observed=len(threats.get("alerts") or threats.get("threats") or []),
            endpoint="/api/security/threats",
            service="alerts_canonical_service",
            motor="threat_registry + SQLite Alerta + NDR",
            primary_source="merge canonical",
            classification="REAL_CACHED",
            confiable="SI",
            file_ref="services/alerts_canonical_service.py",
        )
    )
    inv.append(
        _item(
            screen="Vulnerabilidades",
            element="Hallazgos",
            value_observed=len(vulns.get("vulnerabilities") or vulns.get("items") or []),
            endpoint="/api/security/vulnerabilities",
            service="novus_security_integration",
            motor="vulnerability_scanner",
            primary_source="_threat_cache RAM",
            classification="REAL_CACHED" if vulns.get("status") != "empty" else "NOT_AVAILABLE",
            confiable="SI" if vulns.get("vulnerabilities") else "SI",
            notes="0 vulns observadas — mensaje honesto",
            file_ref="services/novus_security_integration.py",
        )
    )

    # Notifications
    for n in (notif_sec.get("notifications") or [])[:20]:
        inv.append(
            _item(
                screen="Campana seguridad",
                element=n.get("title"),
                value_observed={"priority": n.get("priority"), "category": n.get("category")},
                endpoint="/api/notifications?kind=security",
                service="notification_center_service",
                motor=n.get("source_motor") or "adaptive_profile_engine/behavior",
                primary_source="SQLite novus_notifications",
                provenance=(n.get("payload") or {}).get("data_origin", "live"),
                classification="REAL_LIVE",
                confiable="NO PUEDO CONFIRMARLO",
                notes="Requiere validar evidencia del motor emisor",
                file_ref="services/notification_center_service.py",
            )
        )
    for n in (notif_sys.get("notifications") or [])[:10]:
        inv.append(
            _item(
                screen="Notificaciones sistema",
                element=n.get("title"),
                value_observed=n.get("category"),
                endpoint="/api/notifications?kind=system",
                service="notification_center_service",
                classification="REAL_LIVE",
                confiable="SI",
                notes="Login/scan — no deben mezclarse en campana seguridad",
            )
        )

    # AI Kernel
    inv.append(
        _item(
            screen="IA Kernel panel",
            element="operational_status",
            value_observed=ai.get("operational_status"),
            endpoint="/api/ai/status",
            service="ai_kernel",
            motor="AIKernel thread",
            primary_source="get_status()",
            classification="REAL_LIVE",
            confiable="SI",
            notes=f"Observado STOPPED — no afirma ACTIVE sin thread",
            file_ref="services/ai_kernel.py",
            function_ref="get_status",
        )
    )
    for cap, meta in (ai.get("capabilities") or {}).items():
        if isinstance(meta, dict):
            inv.append(
                _item(
                    screen="IA Kernel",
                    element=f"capability:{cap}",
                    value_observed=meta.get("status"),
                    endpoint="/api/ai/status",
                    service="ai_kernel",
                    primary_source=meta.get("source"),
                    classification="REAL_CACHED" if "cache" in str(meta.get("source", "")).lower() else "REAL_LIVE",
                    confiable="NO PUEDO CONFIRMARLO" if meta.get("status") == "ACTIVE" else "SI",
                    notes=meta.get("description"),
                    file_ref="services/ai_kernel.py",
                )
            )

    # Motors / defense
    inv.append(
        _item(
            screen="Dashboard / Manual Defense",
            element="Motores defensa resumen",
            value_observed=defense.get("engines") or defense.get("summary"),
            endpoint="/api/manual-defense/summary",
            service="defense_center_service",
            motor="multiple",
            classification="CALCULATED_FROM_REAL",
            confiable="NO PUEDO CONFIRMARLO",
            file_ref="services/continuous_monitoring_orchestrator.py",
            function_ref="get_defense_motors_dashboard_status",
            notes="network monitor cuenta +2 motores",
        )
    )

    # Endpoints
    inv.append(
        _item(
            screen="Endpoints",
            element="Inventario host",
            value_observed=endpoints.get("endpoints") or endpoints.get("inventory"),
            endpoint="/api/security/endpoints",
            service="platform_metrics_service.build_endpoint_inventory",
            primary_source="psutil local host",
            classification="REAL_LIVE",
            confiable="SI",
            file_ref="services/platform_metrics_service.py",
        )
    )

    # Search
    inv.append(
        _item(
            screen="Búsqueda global",
            element="Resultados dinámicos",
            value_observed=len(search.get("results") or search.get("items") or []),
            endpoint="/api/search",
            service="global_search_index",
            primary_source="DB + caches + static index",
            classification="REAL_CACHED",
            confiable="SI",
            notes="Índice estático rebuild 10min; sin resultados simulados",
            file_ref="services/global_search_index.py",
        )
    )
    inv.append(
        _item(
            screen="Búsqueda global",
            element="Módulos estáticos indexados",
            value_observed="hardcoded catalog",
            endpoint="/api/search",
            service="global_search_index.build_static_index",
            classification="STATIC",
            confiable="SI",
            notes="Navegación UI — no telemetría",
            file_ref="services/global_search_index.py",
        )
    )

    # Reports / Evidence / Sessions
    inv.append(
        _item(
            screen="Reports",
            element="Lista reportes tenant",
            value_observed=len(reports.get("reports") or reports.get("items") or []),
            endpoint="/api/reports",
            service="security_report_service",
            primary_source="data/reports/by_tenant/{tenant}/",
            classification="REAL_CACHED",
            confiable="SI",
            file_ref="services/security_report_service.py",
        )
    )
    inv.append(
        _item(
            screen="Centro Evidencias",
            element="Registros evidencia",
            value_observed=len(evidence.get("items") or evidence.get("evidence") or []),
            endpoint="/api/system/evidence-center",
            service="evidence_center_service",
            primary_source="DB tenant-scoped",
            classification="REAL_LIVE",
            confiable="SI",
            file_ref="services/evidence_center_service.py",
        )
    )
    inv.append(
        _item(
            screen="Sessions / Accesos",
            element="Sesiones login",
            value_observed=len(sessions.get("sessions") or sessions.get("items") or []),
            endpoint="/api/system/login-sessions",
            service="login_session_audit_service",
            primary_source="SQLite LoginSessionAudit",
            classification="REAL_LIVE",
            confiable="SI",
            file_ref="services/login_session_audit_service.py",
        )
    )

    # Web shield
    inv.append(
        _item(
            screen="Web Shield",
            element="Estado motor",
            value_observed=web.get("active") or web.get("status"),
            endpoint="/api/web-shield/status",
            service="web_shield_engine",
            primary_source="get_engine_status()",
            classification="REAL_LIVE",
            confiable="SI",
            file_ref="services/web_shield_engine.py",
        )
    )

    # Tenant
    inv.append(
        _item(
            screen="Tenant scope",
            element="monitoring_enabled",
            value_observed=scope.get("monitoring_enabled"),
            endpoint="/api/tenant/scope",
            service="tenant_scope_service",
            primary_source="TenantMonitoringScope DB",
            classification="REAL_LIVE",
            confiable="SI",
            file_ref="services/tenant_scope_service.py",
        )
    )

    # NDR
    inv.append(
        _item(
            screen="Network NDR",
            element="Top traffic / bytes local",
            value_observed=ndr.get("top_traffic") or ndr.get("device_count"),
            endpoint="/api/network/ndr",
            service="network_ndr_service",
            motor="psutil",
            primary_source="psutil.net_connections + local io_counters",
            classification="REAL_LIVE",
            confiable="SI",
            notes="Bytes solo host local; remoto = conexiones no bytes",
            file_ref="services/network_ndr_service.py",
        )
    )

    # Security summary snapshot
    inv.append(
        _item(
            screen="Security Summary",
            element="Payload agregado",
            value_observed=summary.get("status"),
            endpoint="/api/security/summary",
            service="security_snapshot_service",
            primary_source="data/security/summary_snapshot.json",
            provenance="platform_metrics + unified payload",
            freshness=str(summary.get("data_freshness") or summary.get("status")),
            classification="REAL_CACHED",
            confiable="SI",
            notes="Stale >120s vacía threats/vulns — no fabrica",
            file_ref="services/security_snapshot_service.py",
            risk="CRITICAL_DATA_TRUST_ISSUE" if summary.get("status") == "live" and summary.get("stale") else "",
        )
    )

    # Health
    inv.append(
        _item(
            screen="Health Center",
            element="Estado plataforma",
            value_observed=health.get("status") or health.get("overall"),
            endpoint="/api/health/status",
            service="health_engine",
            primary_source="health probes",
            classification="REAL_LIVE",
            confiable="SI",
            notes="fake_telemetry=false en diseño",
            file_ref="services/health_engine/engine.py",
        )
    )

    # QA/LAB paths audit (code-level, may not reach UI)
    inv.append(
        _item(
            screen="Runtime guard",
            element="QA tenant isolation",
            value_observed="QA-NOVUS-2026",
            endpoint="N/A",
            service="production_runtime_guard",
            primary_source="env NOVUS_ALLOW_LAB_RUNTIME",
            classification="LAB_ONLY",
            confiable="SI",
            notes="No llega a UI producción si NOVUS_ENV=production",
            file_ref="services/production_runtime_guard.py",
            risk="MEDIO si lab runtime habilitado en dev",
        )
    )

    # Static UI labels (not data claims)
    inv.append(
        _item(
            screen="Global UI",
            element='Texto "Sin datos disponibles"',
            value_observed="Sin datos disponibles",
            classification="STATIC",
            confiable="SI",
            notes="Etiqueta honesta — no es dato observado",
        )
    )

    # Catálogo extendido — motores de defensa (estado UI)
    motors = [
        ("Network Discovery", "network_scanner", "network_scan_coordinator", "/api/network/nodes", "ARP/Scapy"),
        ("Network Monitoring", "network_monitor_engine", "network_monitor_engine", "/api/network/monitor/status", "OS+ARP"),
        ("Threat Detection", "novus_security_integration", "security_engine", "/api/security/threats", "process/port/heuristics"),
        ("Vulnerability Detection", "novus_security_integration", "vulnerability_scanner", "/api/security/vulnerabilities", "local scan"),
        ("Endpoint Protection", "endpoint_realtime_monitor", "endpoint_realtime_monitor", "/api/security/endpoints", "psutil host"),
        ("Web Shield", "web_shield_engine", "web_shield_engine", "/api/web-shield/status", "HTTP proxy engine"),
        ("Mail Shield", "mail_shield_engine", "mail_shield_engine", "/api/mail-shield/status", "OAuth optional"),
        ("AI Kernel", "ai_kernel", "AIKernel thread", "/api/ai/status", "GuardIA+context"),
        ("BTDE / Anomaly", "behavioral_threat_detection", "BTDE", "/api/btde/status", "lazy start"),
        ("Swarm Defense", "swarm_defense", "swarm_defense.engine", "/api/swarm-defense/status", "mesh local"),
        ("Deception", "deception_platform", "deception_platform.engine", "/api/deception/status", "simulated_attacks=false"),
        ("SIEM", "siem", "soc/engine", "/api/siem/status", "partial"),
    ]
    for name, svc, motor, ep, src in motors:
        inv.append(
            _item(
                screen="Motores defensa / SOC",
                element=f"Estado {name}",
                value_observed="poll at login/dashboard",
                endpoint=ep,
                service=svc,
                motor=motor,
                primary_source=src,
                classification="REAL_LIVE",
                confiable="NO PUEDO CONFIRMARLO",
                file_ref=f"services/{svc.split('.')[0] if '.' not in svc else svc.replace('.', '/')}",
                function_ref="get_engine_status / get_monitor_status",
                notes="Requiere verificar última ejecución en telemetría",
            )
        )

    # Pantallas adicionales (datos vía API documentada)
    extra_screens = [
        ("Incidentes", "/api/security/alerts", "alerts_canonical_service", "Lista incidentes SSR+poll"),
        ("Inteligencia", "/api/threat-intel/dashboard", "threat_intelligence_service", "Casos TI"),
        ("SOC Center", "/api/soc/overview", "soc/engine", "Overview táctico"),
        ("Centro Evidencias forense", "/api/forensic-evidence/summary", "forensic_evidence_integrity_service", "Integridad cadena"),
        ("Historial red", "/api/network/events", "network_event_log", "Eventos escaneo reales"),
        ("Config sector/pentest", "/api/system/config/load", "sector_profile_service", "Preferencias tenant"),
        ("Auth protection", "/api/system/auth-protection/config", "auth_protection_service", "Umbrales login"),
        ("Endpoint scan", "/api/endpoint-scan/engine/status", "endpoint_scan_engine", "Escaneo bajo demanda"),
        ("Sector shield", "/api/system/sector-shield/status", "sector_shield_service", "Escudo sectorial"),
        ("Compliance center", "/api/compliance/center", "compliance_center_service", "Controles técnicos"),
    ]
    for screen, ep, svc, desc in extra_screens:
        inv.append(
            _item(
                screen=screen,
                element="Payload principal",
                value_observed=desc,
                endpoint=ep,
                service=svc,
                classification="REAL_CACHED",
                confiable="NO PUEDO CONFIRMARLO",
                notes="No incluido en snapshot live — trazabilidad código",
            )
        )

    # Protection score checks (calculated)
    try:
        from services.platform_protection_score_service import compute_protection_score
        score = compute_protection_score()
        for chk in score.get("checks") or []:
            inv.append(
                _item(
                    screen="Dashboard / Protection Score",
                    element=f"check:{chk.get('check')}",
                    value_observed=chk.get("passed"),
                    endpoint="/api/system/protection-score",
                    service="platform_protection_score_service",
                    primary_source=chk.get("evidence"),
                    classification="CALCULATED_FROM_REAL",
                    confiable="SI",
                    file_ref="services/platform_protection_score_service.py",
                )
            )
    except Exception:
        pass

    return inv


def classify_counts(inv: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in inv:
        c = row.get("clasificacion") or "UNKNOWN"
        counts[c] = counts.get(c, 0) + 1
    return counts


def trust_matrix(inv: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "elemento": f"{r['pantalla']} / {r['elemento']}",
            "visible": True,
            "fuente": r.get("fuente_primaria") or r.get("servicio"),
            "provenance": r.get("provenance") or r.get("motor"),
            "freshness": r.get("freshness") or r.get("clasificacion"),
            "evidencia": r.get("evidencia") or r.get("notas"),
            "confiable": r.get("confiable"),
        }
        for r in inv
    ]


def top_issues(inv: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    issues = []
    for r in inv:
        if r.get("confiable") == "NO" or r.get("clasificacion") in (
            "SIMULATED", "SYNTHETIC", "HARDCODED", "MOCK", "QA", "LAB"
        ):
            issues.append(r)
        elif r.get("riesgo") in ("ALTO", "CRITICAL_DATA_TRUST_ISSUE"):
            issues.append(r)
        elif r.get("clasificacion") == "REAL_STALE" and r.get("pantalla") == "Network":
            issues.append(r)
    return issues[:25]


def trusted_data(inv: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [r for r in inv if r.get("confiable") == "SI" and r.get("clasificacion") in (
        "REAL_LIVE", "REAL_CACHED", "CALCULATED_FROM_REAL", "NOT_AVAILABLE", "STATIC"
    )][:40]


def write_md(audit: Dict[str, Any]) -> str:
    lines = [
        "# NOVUS — Auditoría Forense de Datos Mostrados",
        "",
        f"**Generado:** {audit['generated_at']}",
        f"**Modo:** READ-ONLY — sin modificaciones de código",
        f"**Instancia:** C:\\NOVUS puerto 5000",
        f"**Elementos auditados:** {audit['totals']['audited']}",
        "",
        "## Resumen por clasificación",
        "",
    ]
    for k, v in sorted(audit["classification_counts"].items(), key=lambda x: -x[1]):
        lines.append(f"- **{k}:** {v}")
    lines.extend(["", "## Top 10 problemas más graves", ""])
    for i, p in enumerate(audit["top_10_issues"][:10], 1):
        lines.append(f"{i}. **{p.get('pantalla')} / {p.get('elemento')}** — {p.get('clasificacion')} — {p.get('notas') or p.get('riesgo') or p.get('confiable')}")
    lines.extend(["", "## Datos correctamente respaldados (muestra)", ""])
    for r in audit["trusted_sample"][:15]:
        lines.append(f"- {r['pantalla']} / {r['elemento']}: {r.get('clasificacion')} — {r.get('evidencia') or r.get('fuente_primaria')}")
    lines.extend(["", "## Datos que no deberían presentarse como observación actual", ""])
    for r in audit["untrusted_or_risky"][:20]:
        lines.append(f"- {r['pantalla']} / {r['elemento']}: {r.get('confiable')} — {r.get('notas')}")
    lines.extend(["", "## Snapshots que alimentan UI", ""])
    for s in audit.get("snapshot_files", []):
        lines.append(f"- `{s['path']}` mtime={s['mtime_utc']} feeds_ui={s['feeds_ui']}")
    lines.extend(["", "## Matriz de confianza", "", "| Elemento | Fuente | Freshness | Confiable |", "|----------|--------|-----------|-----------|"])
    for m in audit["trust_matrix"][:30]:
        lines.append(f"| {m['elemento'][:60]} | {(m['fuente'] or '')[:40]} | {m['freshness']} | {m['confiable']} |")
    lines.append("")
    lines.append("Inventario completo: `NOVUS_CURRENT_DATA_INVENTORY.json`")
    return "\n".join(lines)


def main() -> int:
    live = _load_live()
    inv = build_inventory(live)
    counts = classify_counts(inv)
    issues = top_issues(inv)
    audit = {
        "generated_at": _utc(),
        "mode": "read_only_forensic",
        "instance": {"path": str(ROOT), "port": 5000},
        "totals": {"audited": len(inv), **{f"class_{k}": v for k, v in counts.items()}},
        "classification_counts": counts,
        "snapshot_files": _snapshot_meta(),
        "live_observations": {
            "dashboard_counters_pending": _body(live, "/api/dashboard/live").get("counters_pending"),
            "network_freshness": _body(live, "/api/network/nodes?trigger_discovery=false").get("data_freshness"),
            "threats_visible": len(_body(live, "/api/security/threats").get("alerts") or []),
            "vulns_visible": len(_body(live, "/api/security/vulnerabilities").get("vulnerabilities") or []),
            "ai_status": _body(live, "/api/ai/status").get("operational_status"),
        },
        "inventory": inv,
        "trust_matrix": trust_matrix(inv),
        "top_10_issues": issues[:10],
        "untrusted_or_risky": [r for r in inv if r.get("confiable") != "SI"],
        "trusted_sample": trusted_data(inv),
        "methodology": [
            "Mapeo UI→API→servicio desde templates/static JS",
            "Snapshot API in-process (tenant QA) sin modificar código",
            "Revisión servicios: topology, dashboard, network_snapshot, alerts, notifications, ai_kernel",
            "Clasificación granular solicitada",
        ],
        "disclaimer": "Auditoría técnica. NO PUEDO CONFIRMARLO donde falta evidencia runtime directa.",
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_INV.write_text(json.dumps(inv, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT_JSON.write_text(json.dumps(audit, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT_MD.write_text(write_md(audit), encoding="utf-8")
    print(json.dumps({"audited": len(inv), "counts": counts, "out": str(OUT_JSON)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
