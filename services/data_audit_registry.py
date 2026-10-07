"""
Registro de trazabilidad de datos — Auditoría de Datos Reales NOVUS.
Cada componente visible mapea a su fuente verificable.
"""
from datetime import datetime
import os
import socket

REGISTRY_VERSION = "1.0.0"


def _entry(component, source_type, source_detail, file_path, function_name,
           status, notes=""):
    return {
        "component": component,
        "source_type": source_type,
        "source_detail": source_detail,
        "file": file_path,
        "function": function_name,
        "service": source_detail.split("::")[0] if "::" in source_detail else source_detail,
        "api": source_detail if source_detail.startswith("/api") else None,
        "database": "SQLite" if "database" in source_type or "SQLite" in source_detail else None,
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "notes": notes,
    }


def build_audit_registry():
    """Construye inventario completo de componentes y fuentes."""
    entries = [
        # Dashboard
        _entry("Dashboard KPI CPU", "psutil", "system_monitor::get_system_status", "services/system_monitor.py", "get_system_status", "REAL"),
        _entry("Dashboard KPI RAM", "psutil", "system_monitor::get_system_status", "services/system_monitor.py", "get_system_status", "REAL"),
        _entry("Dashboard KPI Disco", "psutil", "system_monitor::get_system_status", "services/system_monitor.py", "get_system_status", "REAL"),
        _entry("Dashboard KPI Tráfico", "psutil", "system_monitor::get_network_stats", "services/system_monitor.py", "get_network_stats", "REAL"),
        _entry("Dashboard KPI Nodos", "Scapy ARP", "network_scanner::scan_network", "services/network_scanner.py", "scan_network", "REAL"),
        _entry("Dashboard KPI Amenazas", "motor seguridad", "novus_security_integration::get_cached_threat_count", "services/novus_security_integration.py", "get_cached_threat_count", "REAL"),
        _entry("Dashboard KPI Conexiones", "psutil", "connections_metrics_service::analyze_host_connections", "services/connections_metrics_service.py", "get_summary_for_dashboard", "REAL", "Sockets IPv4/IPv6; no solo ESTABLISHED"),
        _entry("Dashboard desglose conexiones", "API", "/api/dashboard/connections-detail", "api/dashboard.py", "dashboard_connections_detail", "REAL"),
        _entry("Aislamiento entorno", "runtime", "runtime_environment_service::reconcile_runtime_environment_on_startup", "services/runtime_environment_service.py", "reconcile_runtime_environment_on_startup", "REAL", "Invalida caché si cambia red/nodo"),
        _entry("Guardia telemetría SSR", "tenant", "monitoring_telemetry_guard::assert_telemetry_access", "services/monitoring_telemetry_guard.py", "assert_telemetry_access", "REAL"),
        _entry("Web Shield motor", "host", "web_shield_engine::start_web_shield_engine", "services/web_shield_engine.py", "start_web_shield_engine", "REAL"),
        _entry("Web Shield API", "API", "/api/web-shield/status", "api/web_shield.py", "web_shield_status", "REAL"),
        _entry("Mail Shield motor", "OAuth/API", "mail_shield_engine::start_mail_shield_engine", "services/mail_shield_engine.py", "start_mail_shield_engine", "REAL"),
        _entry("Mail Shield API", "API", "/api/mail-shield/status", "api/mail_shield.py", "mail_shield_status", "REAL"),
        _entry("Dashboard dispositivos", "Scapy ARP", "/api/network/nodes", "api/network.py", "get_network_nodes", "REAL"),

        # Network
        _entry("Network Radar", "Scapy ARP", "network_scanner::get_cached_nodes", "services/network_scanner.py", "get_cached_nodes", "REAL"),
        _entry("Network Gateway/CIDR", "psutil+route", "network_scanner::get_network_meta", "services/network_scanner.py", "get_network_meta", "REAL"),
        _entry("Network Event Log", "log interno", "network_event_log::get_recent", "services/network_event_log.py", "get_recent", "REAL"),
        _entry("Network Estado dispositivo", "ARP respuesta", "network_scanner::_parse_arp_results", "services/network_scanner.py", "scan_network", "REAL", "Estado: Detectado (ARP), no Online asumido"),

        # XDR
        _entry("XDR Eventos", "motor amenazas", "novus_security_integration::detect_threats_realtime", "services/novus_security_integration.py", "detect_threats_realtime", "REAL"),
        _entry("XDR Procesos sospechosos", "advanced_detector", "advanced_detector_service::scan_running_processes", "services/advanced_detector_service.py", "scan_running_processes", "REAL"),
        _entry("XDR Puertos abiertos", "socket scan", "advanced_detector_service::scan_open_ports", "services/advanced_detector_service.py", "scan_open_ports", "REAL"),

        # Vulnerabilidades
        _entry("Vulnerabilidades hallazgos", "motor vulns", "novus_security_integration::scan_vulnerabilities", "services/novus_security_integration.py", "scan_vulnerabilities", "REAL"),
        _entry("Vulnerabilidades puertos", "socket scan", "vulnerability_scanner::scan_open_ports", "vulnerability_scanner.py", "scan_open_ports", "REAL"),
        _entry("Vulnerabilidades CVE paquetes", "pip list", "vulnerability_scanner::check_package_vulnerabilities", "vulnerability_scanner.py", "check_package_vulnerabilities", "PENDIENTE", "Requiere OSV/NVD API — sin CVE estáticos"),

        # Incidentes
        _entry("Incidentes", "SQLite", "database::Alerta", "database.py", "SessionLocal", "REAL"),
        _entry("Incidentes threat_registry", "motor seguridad", "security_engine::threat_registry", "security_engine.py", "threat_registry", "REAL"),

        # Reportes
        _entry("Reportes historial", "filesystem+SQLite", "security_report_service::list_reports", "services/security_report_service.py", "list_reports", "REAL"),
        _entry("Reportes PDF", "fpdf2", "report_pdf_service::generate_pdf", "services/report_pdf_service.py", "generate_pdf", "REAL"),

        # Endpoints
        _entry("Endpoints locales", "psutil", "/api/system/endpoints/live", "api/system.py", "get_live_endpoints", "REAL"),
        _entry("Endpoints remotos ARP", "Scapy ARP", "network_scanner", "services/network_scanner.py", "scan_network", "REAL", "Solo IP/MAC; CPU/RAM remota: SIN FUENTE"),

        # Kernel IA
        _entry("Kernel IA Deep Scan", "motor integral", "deep_scan_engine::start_scan", "services/deep_scan_engine.py", "start_scan", "REAL", "Sin caché; escaneo en hilo dedicado"),
        _entry("Kernel IA clasificación", "heurística NL", "ai_orchestrator::classify_intent", "services/ai_orchestrator.py", "classify_intent", "REAL", "Clasifica intención; datos de respuesta son de motores reales"),

        # Gmail
        _entry("Gmail análisis", "Gmail API OAuth", "gmail_analyzer_service::sync_new_messages", "services/gmail_analyzer_service.py", "sync_new_messages", "PENDIENTE", "Requiere GOOGLE_CLIENT_ID/SECRET"),
        _entry("Gmail edad dominio", "WHOIS", "N/A", "services/gmail_analyzer_service.py", "analyze_message", "SIN FUENTE", "No se inventa domain_age_days"),

        # Automatización
        _entry("Automatización reglas", "motor en vivo", "novus_security_integration::detect_threats_realtime", "services/novus_security_integration.py", "detect_threats_realtime", "REAL"),
        _entry("Automatización ejecuciones/mes", "N/A", "N/A", "routes/main.py", "automatizacion", "SIN FUENTE", "Muestra Sin datos disponibles"),

        # Configuración
        _entry("Configuración sector", "SQLite Usuario", "models/user.py", "models/user.py", "User.sector", "REAL"),
        _entry("Configuración stats", "psutil", "routes/main.py", "routes/main.py", "ruta_configuracion", "REAL"),

        # Búsqueda global
        _entry("Búsqueda global índice", "catálogo estático+DB", "global_search_index", "services/global_search_index.py", "search", "REAL", "Navegación + datos dinámicos DB"),

        # Sin fuente implementada
        _entry("Firewall SO nativo", "OS firewall", "N/A", "N/A", "N/A", "NO IMPLEMENTADO", "Solo puertos locales vía socket scan"),
        _entry("Licenciamiento", "N/A", "N/A", "routes/auth.py", "login", "NO IMPLEMENTADO"),
        _entry("Geolocalización nodo", "N/A", "N/A", "templates/xdr.html", "N/A", "ELIMINADO", "Reemplazado por NODE_ID real"),
        _entry("VirusTotal reputación", "API externa", "VIRUSTOTAL_API_KEY", "services/advanced_detector_service.py", "scan_file_reputation", "PENDIENTE"),
    ]
    return entries


def get_audit_summary():
    entries = build_audit_registry()
    counts = {"REAL": 0, "SIN FUENTE": 0, "SIMULADO": 0, "PENDIENTE": 0, "NO IMPLEMENTADO": 0, "ELIMINADO": 0}
    for e in entries:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    return {
        "version": REGISTRY_VERSION,
        "generated_at": datetime.now().isoformat(),
        "node_id": os.environ.get("NODE_ID") or socket.gethostname(),
        "total_components": len(entries),
        "counts": counts,
        "entries": entries,
    }
