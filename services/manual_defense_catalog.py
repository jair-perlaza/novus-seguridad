"""
Catálogo verificable del Centro de Defensa Manual — solo mecanismos con motor real o estado explícito.
"""
from __future__ import annotations

import platform
from typing import Any, Dict, List, Optional

IS_WINDOWS = platform.system().lower() == "windows"

CATEGORIES = [
    ("equipo", "Protección del equipo"),
    ("red", "Protección de red"),
    ("web", "Protección web"),
    ("correo", "Protección de correo"),
    ("endpoint", "Protección de endpoints"),
    ("sectorial", "Protección sectorial"),
    ("cloud", "Protección Cloud"),
]

# Documentación estructurada para Kernel IA (hechos sobre motores reales, sin prometer lo inexistente).
KERNEL_DOCS: Dict[str, Dict[str, Any]] = {}


def _doc(
    mid: str,
    *,
    what: str,
    threats: str,
    techniques: str,
    limitations: str,
    needs: str,
    evidence: str,
    actions: str,
) -> None:
    KERNEL_DOCS[mid] = {
        "what": what,
        "threats_detected": threats,
        "techniques": techniques,
        "limitations": limitations,
        "information_needed": needs,
        "evidence_generated": evidence,
        "actions_taken": actions,
    }


_doc(
    "host_scan_full",
    what="Escaneo integral del host local donde corre NOVUS mediante deep_scan_engine (perfil full).",
    threats="Malware, persistencia, puertos expuestos, procesos anómalos, autorun sospechoso.",
    techniques="Fases reales: procesos, memoria, servicios, registro (Windows), archivos usuario, ARP, Advanced Detector.",
    limitations="Un solo host (nodo NOVUS). Escaneos largos; CPU/disco elevados durante la ejecución.",
    needs="Permisos del usuario del servicio NOVUS sobre el sistema de archivos y WMI/registro en Windows.",
    evidence="Informe SOC con hallazgos, rutas, hashes parciales, severidad y fases ejecutadas.",
    actions="Registro en endpoint_scan_records; hallazgos visibles en UI; sin bloqueo automático salvo cuarentena manual.",
)
_doc(
    "host_scan_folder",
    what="Escaneo de carpetas locales indicadas (perfil custom/custom_roots).",
    threats="Ejecutables sospechosos, DLL, scripts ofuscados en la ruta indicada.",
    techniques="Recorrido acotado de disco, entropía, reputación de archivo cuando aplica.",
    limitations="Requiere ruta absoluta existente en el host. Profundidad y conteo de archivos limitados (MAX_FILES_PER_SCAN).",
    needs="Parámetro path o paths (lista).",
    evidence="Lista de archivos analizados y hallazgos por ruta.",
    actions="Informe de escaneo; cuarentena solo si el operador la solicita aparte.",
)
_doc(
    "host_scan_file",
    what="Análisis de un archivo local: entropía y reputación (advanced_detector).",
    threats="Ransomware/ofuscación (entropía alta), indicadores maliciosos conocidos.",
    techniques="Lectura del archivo en disco, Shannon entropy, scan_file_reputation.",
    limitations="El archivo debe existir en el host NOVUS y ser legible.",
    needs="Parámetro path absoluto al archivo.",
    evidence="Entropía, veredicto, detalle de reputación.",
    actions="Resultado consultable; no mueve el archivo automáticamente.",
)
_doc(
    "host_scan_processes",
    what="Inventario de procesos activos con heurísticas Advanced Detector.",
    threats="Mineros, shells, procesos sin imagen en disco, líneas de comando sospechosas.",
    techniques="psutil + reglas MALWARE_CMD_PATTERNS y heurísticas del detector.",
    limitations="No sustituye EDR kernel-mode; procesos muy efímeros pueden no capturarse.",
    needs="Ninguno.",
    evidence="Lista de procesos marcados con motivo y PID.",
    actions="Telemetría XDR/incidentes si el motor publica eventos.",
)
_doc(
    "host_scan_memory",
    what="Perfil memory del deep_scan: working set y correlación con procesos.",
    threats="Procesos con consumo anómalo, indicadores en memoria indirecta vía procesos.",
    techniques="psutil memory_info, fases memory_scan y processes.",
    limitations="No hay volcado completo de RAM ni análisis forense de kernel.",
    needs="Ninguno.",
    evidence="Métricas de memoria y hallazgos ligados a procesos.",
    actions="Informe parcial deep_scan.",
)
_doc(
    "host_scan_services",
    what="Enumeración de servicios Windows y drivers (deep_scan perfil services).",
    threats="Servicios no firmados, persistencia vía servicios.",
    techniques="WMI/sc query en Windows; en otros SO marca PENDIENTE.",
    limitations="Detalle completo solo en Windows.",
    needs="Ninguno.",
    evidence="Listado de servicios y hallazgos asociados.",
    actions="Informe deep_scan.",
)
_doc(
    "host_scan_installed",
    what="Programas instalados, extensiones de navegador e inicio (perfil installed).",
    threats="Software no deseado, extensiones riesgosas.",
    techniques="Registro/uninstall keys Windows, rutas estándar de extensiones.",
    limitations="Cobertura parcial fuera de Windows.",
    needs="Ninguno.",
    evidence="Inventario programas/extensiones detectados.",
    actions="Informe deep_scan.",
)
_doc(
    "host_scan_scheduled",
    what="Tareas programadas y persistencia (perfil scheduled).",
    threats="Tareas maliciosas, scripts en Task Scheduler.",
    techniques="schtasks / PowerShell en Windows.",
    limitations="Windows-centric.",
    needs="Ninguno.",
    evidence="Tareas listadas y hallazgos.",
    actions="Informe deep_scan.",
)
_doc(
    "host_scan_startup",
    what="Elementos de inicio automático (fase startup + registro Run).",
    threats="Persistencia al boot, autorun malicioso.",
    techniques="Registro, carpetas Startup, deep_scan startup phase.",
    limitations="Algunas entradas requieren elevación para ver todas.",
    needs="Ninguno.",
    evidence="Entradas de inicio detectadas.",
    actions="Informe deep_scan.",
)
_doc(
    "host_scan_registry",
    what="Escaneo de claves Run/RunOnce y autorun (perfil registry).",
    threats="Persistencia vía registro.",
    techniques="Lectura registro Windows autorun.",
    limitations="Solo Windows; requiere permisos de lectura en HKLM/HKCU.",
    needs="Ninguno.",
    evidence="Claves y valores listados.",
    actions="Informe deep_scan.",
)
_doc(
    "host_malware_known",
    what="Búsqueda de malware conocido vía perfil malware + Advanced Detector + VT si API configurada.",
    threats="Binarios maliciosos, scripts, indicadores conocidos.",
    techniques="Firmas heurísticas, hash VT opcional.",
    limitations="Sin API VirusTotal la reputación cloud puede ser limitada.",
    needs="Opcional: clave VirusTotal en configuración.",
    evidence="Hallazgos con hash y motivo.",
    actions="Informe; cuarentena manual.",
)
_doc(
    "host_ransomware",
    what="Heurística de ransomware: entropía en ejecutables y patrones en perfil malware.",
    threats="Cifrado masivo, extensiones anómalas, procesos sospechosos.",
    techniques="Entropía ≥7.2, patrones en deep_scan y procesos.",
    limitations="No monitoriza en tiempo real el filesystem salvo monitor endpoint aparte.",
    needs="Ninguno.",
    evidence="Archivos/procesos con indicadores de alto riesgo.",
    actions="Alertas en informe.",
)
_doc(
    "host_rootkit",
    what="Perfil rootkit: procesos ocultos, drivers, servicios, DLL.",
    threats="Procesos sin binario en disco, drivers sospechosos.",
    techniques="Comparación proceso vs ruta ejecutable, fases rootkit.",
    limitations="Sin driver kernel propio; no garantiza detección de rootkits avanzados.",
    needs="Ninguno.",
    evidence="Hallazgos de anomalías de procesos/drivers.",
    actions="Informe deep_scan.",
)
_doc(
    "host_miners",
    what="Detección de mineros en procesos y líneas de comando.",
    threats="xmrig, minerd, consumo CPU anómalo.",
    techniques="Patrones MALWARE_CMD_PATTERNS y scan_running_processes.",
    limitations="Mineros con nombres ofuscados pueden eludir strings conocidos.",
    needs="Ninguno.",
    evidence="Procesos coincidentes con patrón.",
    actions="Listado en hallazgos.",
)
_doc(
    "host_dll_injection",
    what="Fase dll_scan del deep_scan: DLL/ejecutables en rutas sensibles.",
    threats="DLL side-loading, módulos sin firma.",
    techniques="Entropía y rutas en perfil processes/malware.",
    limitations="No inspecciona memoria de procesos ajenos a nivel API Windows avanzada.",
    needs="Ninguno.",
    evidence="DLL/EXE marcados con motivo.",
    actions="Informe.",
)
_doc(
    "host_hidden_processes",
    what="Regla: proceso sin ejecutable resoluble en disco.",
    threats="Procesos ocultos o injectados.",
    techniques="psutil exe path vs nombre de proceso.",
    limitations="Falsos positivos en procesos protegidos del SO.",
    needs="Ninguno.",
    evidence="PID y motivo 'sin ejecutable en disco'.",
    actions="Hallazgo en informe.",
)
_doc(
    "host_privilege_escalation",
    what="Revisión de procesos con privilegios elevados y cuentas admin (fase users/threats).",
    threats="Procesos SYSTEM anómalos, cuentas administrativas activas.",
    techniques="psutil + users phase deep_scan.",
    limitations="No audita tokens UAC en tiempo real.",
    needs="Ninguno.",
    evidence="Usuarios admin y procesos privilegiados listados.",
    actions="Informe.",
)

# --- Red ---
_doc(
    "net_scan_full",
    what="Escaneo ARP/network del segmento local (network_scanner).",
    threats="Dispositivos no autorizados, superficie de red.",
    techniques="ARP scan real en la interfaz local.",
    limitations="Solo segmento L2/L3 alcanzable; sin inventario inventado.",
    needs="Interfaz de red activa.",
    evidence="Lista de nodos MAC/IP reales.",
    actions="Actualiza caché de topología/NDR.",
)
_doc(
    "net_device_discovery",
    what="Igual que escaneo de red — descubrimiento de dispositivos presentes.",
    threats="Hosts desconocidos en LAN.",
    techniques="network_scanner.scan_network.",
    limitations="Dispositivos fuera de ARP no aparecen.",
    needs="Ninguno.",
    evidence="Nodos detectados.",
    actions="Refresh inventario.",
)
_doc(
    "net_new_devices",
    what="Eventos recientes de conexión (device_connection_monitor).",
    threats="Conexiones nuevas no aprobadas.",
    techniques="Comparación ARP entre ciclos.",
    limitations="Requiere ciclos previos del monitor.",
    needs="Monitor de red activo (main.py).",
    evidence="Eventos connect del historial.",
    actions="Registro en device_connection_events.",
)
_doc(
    "net_disconnected_devices",
    what="Dispositivos que dejaron de aparecer en ARP recientemente.",
    threats="Desconexiones anómalas o evasión.",
    techniques="device_connection_monitor disconnect events.",
    limitations="Depende de escaneos periódicos.",
    needs="Historial de monitor.",
    evidence="Eventos disconnect.",
    actions="Historial dispositivos.",
)
_doc(
    "net_reconnections",
    what="Reaparición de MAC/IP tras desconexión.",
    threats="Reconexión de host sospechoso.",
    techniques="Historial device_connection_monitor.",
    limitations="Sin timestamps sub-segundo.",
    needs="Ninguno.",
    evidence="Eventos reconnect/reappear.",
    actions="Listado verificable.",
)
_doc(
    "net_unknown_devices",
    what="Dispositivos sin inventario aprobado (NDR unknown_devices).",
    threats="Activos no autorizados.",
    techniques="build_ndr_payload + inventario AIE.",
    limitations="Inventario vacío marca muchos como desconocidos hasta aprobación.",
    needs="Inventario configurado para comparar.",
    evidence="Lista unknown_devices del NDR.",
    actions="Alertas NDR.",
)
_doc(
    "net_mitm",
    what="MITM Shield: verify_tunnel_integrity con metadatos de conexión local.",
    threats="Proxy malicioso, túnel alterado.",
    techniques="security_engine.verify_tunnel_integrity + proxy/DNS local (web_shield_host_audit).",
    limitations="No captura paquetes en tránsito; analiza configuración y metadatos.",
    needs="Ninguno.",
    evidence="Resultado MITM + snapshot proxy/DNS.",
    actions="Informe de verificación.",
)
_doc(
    "net_arp_spoofing",
    what="Alertas NDR por conflicto ARP / IP duplicada.",
    threats="ARP spoofing, envenenamiento ARP.",
    techniques="network_ndr_service alertas reales.",
    limitations="Sin sensor inline; inferencia por telemetría ARP.",
    needs="Escaneos ARP recientes.",
    evidence="Alertas con título y evidencia NDR.",
    actions="Visibilidad en NDR.",
)
_doc(
    "net_dns_spoofing",
    what="Comparación DNS configurado vs hosts file y proxy (web_shield_host_audit).",
    threats="DNS alterado localmente, hosts hijacked.",
    techniques="netsh DNS, lectura hosts.",
    limitations="No inspecciona respuestas DNS en vuelo (sin PCAP).",
    needs="Windows para netsh DNS detallado.",
    evidence="Servidores DNS y entradas hosts.",
    actions="Informe audit.",
)
_doc(
    "net_rogue_dhcp",
    what="Alertas NDR relacionadas con cambios DHCP/IP inesperados.",
    threats="Servidor DHCP rogue.",
    techniques="Alertas 'Cambio de IP' / patrones NDR.",
    limitations="dhcp_analyzer dedicado no implementado (soc_report_builder).",
    needs="Telemetría NDR.",
    evidence="Alertas filtradas DHCP/IP.",
    actions="Recomendaciones en informe.",
)
_doc(
    "net_open_ports",
    what="Puertos abiertos locales y opcionalmente en nodos (advanced_detector + deep_scan ports).",
    threats="Servicios expuestos RDP/Telnet/etc.",
    techniques="psutil connections, scan_open_ports.",
    limitations="Escaneo remoto limitado a nodos ya descubiertos.",
    needs="Ninguno.",
    evidence="Lista puertos y procesos.",
    actions="Hallazgos en informe.",
)
_doc(
    "net_traffic_analysis",
    what="Métricas de tráfico psutil y top talkers NDR cuando existen.",
    threats="Exfiltración, volumen anómalo.",
    techniques="psutil net_io_counters, NDR top_traffic.",
    limitations="Sin DPI completo.",
    needs="Ninguno.",
    evidence="Contadores bytes/paquetes y ranking NDR.",
    actions="Telemetría dashboard.",
)
_doc(
    "net_forensic_pcap",
    what="Inicia captura PCAP de tráfico real en el host NOVUS (Scapy + Npcap en Windows).",
    threats="Incidentes de red que requieren evidencia de paquetes (MITM, ARP, exfiltración, etc.).",
    techniques="sniff en interfaz seleccionada; metadatos continuos en metadata_ring.jsonl.",
    limitations="Requiere permisos elevados; no decodifica TLS; ventana pre-evento limitada al ring de metadatos.",
    needs="Npcap (Windows) o CAP_NET_RAW (Linux); interfaz de red activa.",
    evidence="Archivo .pcap con hash SHA-256 y sello forense Ed25519.",
    actions="Asociar capture_id a caso o incidente; exportar con manifiesto forense.",
)
_doc(
    "net_gateway_analysis",
    what="Gateway por defecto y estabilidad (monitor + psutil).",
    threats="Gateway malicioso, cambios de ruta.",
    techniques="network_monitor_engine gateway tracking.",
    limitations="Un gateway por defecto por ciclo.",
    needs="Red configurada.",
    evidence="IP gateway actual e historial de cambios del monitor.",
    actions="Eventos si gateway cambia.",
)
_doc(
    "net_dns_analysis",
    what="Servidores DNS del sistema (netsh / web_shield_host_audit).",
    threats="DNS hijacking local.",
    techniques="Lectura configuración DNS OS.",
    limitations="Plataforma Windows preferente.",
    needs="Ninguno.",
    evidence="Lista DNS servers.",
    actions="Informe.",
)
_doc(
    "net_stability",
    what="Estabilidad de red: ciclos estables, errores y latencia del network monitor.",
    threats="Red inestable, pérdida de visibilidad ARP.",
    techniques="get_monitor_status + métricas internas.",
    limitations="Métricas desde arranque del proceso NOVUS.",
    needs="Monitor activo.",
    evidence="stable_cycles, error_count, avg detection times.",
    actions="Estado monitor.",
)

# --- Web ---
_doc(
    "web_analyze_url",
    what="Web Shield analyze_and_policy_url.",
    threats="URLs maliciosas, phishing, descargas riesgosas.",
    techniques="Motor web_shield_engine + políticas.",
    limitations="Requiere URL válida http(s).",
    needs="Parámetro url.",
    evidence="Veredicto, categoría, detalle política.",
    actions="Eventos web_shield si aplica.",
)
_doc(
    "web_analyze_site",
    what="Análisis de sitio vía misma URL (contenido/política Web Shield).",
    threats="Sitios comprometidos, redirecciones.",
    techniques="analyze_and_policy_url profundo.",
    limitations="No renderiza browser completo sin extensión.",
    needs="url base del sitio.",
    evidence="Resultado analyze-url.",
    actions="Registro eventos.",
)
_doc(
    "web_domain_reputation",
    what="Reputación de dominio extraída del análisis Web Shield.",
    threats="Dominios recién registrados maliciosos.",
    techniques="Parsing dominio + reglas Web Shield.",
    limitations="Sin feed externo unless configured.",
    needs="url o domain.",
    evidence="Score/etiquetas del motor.",
    actions="Informe.",
)
_doc(
    "web_ssl_tls",
    what="Validación certificado TLS al analizar URL https.",
    threats="Certificados expirados, autofirmados, mismatch.",
    techniques="Handshake/inspección en web_shield_engine.",
    limitations="Solo si URL es https alcanzable desde el host.",
    needs="url https.",
    evidence="Detalle certificado en respuesta motor.",
    actions="Hallazgo en resultado.",
)
_doc(
    "web_downloaded_files",
    what="Escaneo de archivo subido o ruta local (mismo motor que protección equipo archivo).",
    threats="Malware en descargas.",
    techniques="advanced_detector scan_file_reputation.",
    limitations="No accede a carpeta Downloads del usuario sin path.",
    needs="path local o upload vía /api/system/scan/file.",
    evidence="Entropía y reputación.",
    actions="Veredicto PERMITIDO/BLOQUEADO heurístico.",
)
_doc(
    "web_suspicious_links",
    what="Análisis de enlace con Web Shield.",
    threats="Enlaces acortados, dominios typosquatting.",
    techniques="analyze_and_policy_url.",
    limitations="Requiere URL del enlace.",
    needs="url.",
    evidence="Política y razones.",
    actions="Evento web shield.",
)
_doc(
    "web_phishing",
    what="Phishing Shield inspect_email_integrity o Web Shield según contexto URL.",
    threats="Suplantación, credenciales.",
    techniques="security_engine + web_shield.",
    limitations="Correo requiere integración; URL requiere parámetro.",
    needs="url o metadatos email si integración mail.",
    evidence="Status phishing del motor.",
    actions="Informe.",
)
_doc(
    "web_malicious_sites",
    what="Clasificación malicioso vía Web Shield.",
    threats="Hosts C2, malware distribution.",
    techniques="Políticas y listas Web Shield.",
    limitations="Cobertura según config web_shield.",
    needs="url.",
    evidence="Veredicto motor.",
    actions="Bloqueo policy si configurado.",
)
_doc(
    "web_fraud_pages",
    what="Detección de fraude en página vía heurísticas Web Shield.",
    threats="Páginas fraudulentas de pago.",
    techniques="analyze_and_policy_url.",
    limitations="Sin OCR de capturas.",
    needs="url.",
    evidence="Resultado análisis.",
    actions="Recomendaciones.",
)
_doc(
    "web_credential_theft",
    what="Indicadores de robo de credenciales en URL (Web Shield + host audit).",
    threats="Formularios falsos, proxy local.",
    techniques="URL heuristics + proxy/hosts audit.",
    limitations="Sin extensión browser el formulario remoto no se ve.",
    needs="url opcional.",
    evidence="Proxy/hosts + analyze-url.",
    actions="Informe combinado.",
)

# --- Correo (integración) ---
for _mid, _what in [
    ("mail_scan_mailbox", "Sincronización buzón vía OAuth (Google/Microsoft) — mail_shield_engine.sync_now."),
    ("mail_phishing", "Detección phishing en mensajes reales sincronizados."),
    ("mail_bec", "BEC Shield sobre metadatos de mensajes reales."),
    ("mail_malware", "Adjuntos analizados por Mail Shield."),
    ("mail_spam", "Clasificación spam del motor Mail Shield."),
    ("mail_spoofed_domains", "Dominios falsificados en From/Reply-To."),
    ("mail_headers", "Análisis de encabezados SMTP reales."),
    ("mail_rules", "Reglas automáticas del buzón vía API proveedor."),
    ("mail_attachments", "Hash y reputación de adjuntos descargados vía API."),
    ("mail_links", "Enlaces extraídos de correos sincronizados."),
]:
    _doc(
        _mid,
        what=_what,
        threats="Phishing, BEC, malware, spam según mensajes reales.",
        techniques="Microsoft Graph / Gmail API oficiales cuando OAuth conectado.",
        limitations="Sin OAuth configurado la función no ejecuta — mensaje explícito al operador.",
        needs="Administrador debe conectar Google Workspace o Microsoft 365.",
        evidence="Eventos mail_shield y resultados sync.",
        actions="Cuarentena mail si política activa.",
    )

# --- Endpoint ---
_doc(
    "endpoint_scan_full",
    what="Escaneo endpoint_shield modo full (deep_scan).",
    threats="Compromiso del endpoint host NOVUS.",
    techniques="endpoint_scan_engine + deep_scan.",
    limitations="Un endpoint: el host del servidor.",
    needs="Ninguno.",
    evidence="Informe endpoint scan.",
    actions="Persistencia EndpointScanRecord.",
)
_doc(
    "endpoint_firewall",
    what="Estado firewall Windows (netsh advfirewall) fase deep_scan.",
    threats="Firewall deshabilitado.",
    techniques="netsh en Windows.",
    limitations="No Linux/mac firewall unificado.",
    needs="Ninguno.",
    evidence="Perfiles y estado.",
    actions="Hallazgo informe.",
)
_doc(
    "endpoint_antivirus",
    what="Estado Microsoft Defender (fase defender_status).",
    threats="AV desactualizado o apagado.",
    techniques="WMI/Defender status en Windows.",
    limitations="Solo Defender integrado Windows.",
    needs="Ninguno.",
    evidence="Estado defender en informe.",
    actions="Recomendación.",
)
_doc(
    "endpoint_encryption",
    what="BitLocker/disco cifrado cuando WMI lo reporta (fase disks).",
    threats="Datos en reposo sin cifrar.",
    techniques="Consulta disco deep_scan.",
    limitations="Puede no detectar cifrado de terceros.",
    needs="Ninguno.",
    evidence="Estado volumen.",
    actions="Informe.",
)
_doc(
    "endpoint_integrity",
    what="Salud sistema advanced_detector.scan_system_health.",
    threats="Degradación, servicios críticos off.",
    techniques="scan_system_health.",
    limitations="Host local únicamente.",
    needs="Ninguno.",
    evidence="JSON salud sistema.",
    actions="Métricas platform.",
)
_doc(
    "endpoint_policies",
    what="Políticas locales visibles: firewall, UAC indirecto, defender.",
    threats="Endurecimiento débil.",
    techniques="Agregación fases security del deep_scan quick.",
    limitations="No GPO centralizado sin agente AD.",
    needs="Ninguno.",
    evidence="Resumen políticas locales.",
    actions="Informe.",
)
_doc(
    "endpoint_status",
    what="Estado consolidado endpoint_scan engine_status + salud.",
    threats="N/A — telemetría.",
    techniques="endpoint_scan_engine.engine_status + system health.",
    limitations="Host NOVUS únicamente.",
    needs="Ninguno.",
    evidence="JSON estado.",
    actions="Ninguna automática.",
)

# --- Sectorial ---
for sk, label in [
    ("sector_fintech", "Fintech — BEC, ATO, Phishing, API Shield."),
    ("sector_logistica", "Logística — IoT Guard, MITM, network scanner."),
    ("sector_mobile", "Aplicaciones móviles — UI Shield, runtime (motores security_engine)."),
    ("sector_salud", "Salud — escudo sectorial build_sector_protection + vuln/threat scan."),
    ("sector_gobierno", "Gobierno — escudo sectorial + cumplimiento local."),
    ("sector_cloud", "Cloud — NOVUS CLOUD SHIELD planificado (sin CSPM operativo)."),
]:
    _doc(
        sk,
        what=f"Protección sectorial {label}",
        threats="Amenazas del sector según motores NOVUS activos.",
        techniques="sector_shield_service / security_engine / ASPE cuando aplica.",
        limitations="Cloud: arquitectura reservada. Salud/Gobierno: motores genéricos sectoriales.",
        needs="Sector configurado en perfil usuario excepto ejecución explícita por sector.",
        evidence="Pasos scan_sector o build_sector_protection.",
        actions="ASPE evaluate_incident si hay hallazgos.",
    )


_doc(
    "cloud_env_detect",
    what="Detección UCE de variables/proyectos cloud en el entorno del host NOVUS.",
    threats="Exposición involuntaria de credenciales cloud en entorno local.",
    techniques="Lectura de variables de entorno AWS/Azure/GCP (sin llamadas API cloud).",
    limitations="No sustituye CSPM; solo señales locales en el nodo.",
    needs="Ninguno.",
    evidence="Lista de proveedores detectados y variables (sin valores secretos).",
    actions="Informe UCE; no modifica cloud.",
)


MECHANISMS: List[Dict[str, Any]] = [
    {"id": "host_scan_full", "category": "equipo", "title": "Escanear computador completo", "full_protection": True,
     "exec": "deep_scan", "profile": "full", "params": []},
    {"id": "host_scan_folder", "category": "equipo", "title": "Escanear carpeta específica", "full_protection": False,
     "exec": "deep_scan", "profile": "custom", "params": ["paths"]},
    {"id": "host_scan_file", "category": "equipo", "title": "Escanear archivo", "full_protection": False,
     "exec": "file_path", "params": ["path"]},
    {"id": "host_scan_processes", "category": "equipo", "title": "Escanear procesos activos", "full_protection": True,
     "exec": "processes", "params": []},
    {"id": "host_scan_memory", "category": "equipo", "title": "Escanear memoria", "full_protection": True,
     "exec": "deep_scan", "profile": "memory", "params": []},
    {"id": "host_scan_services", "category": "equipo", "title": "Escanear servicios", "full_protection": False,
     "exec": "deep_scan", "profile": "services", "params": []},
    {"id": "host_scan_installed", "category": "equipo", "title": "Escanear programas instalados", "full_protection": False,
     "exec": "deep_scan", "profile": "installed", "params": []},
    {"id": "host_scan_scheduled", "category": "equipo", "title": "Escanear tareas programadas", "full_protection": False,
     "exec": "deep_scan", "profile": "scheduled", "params": []},
    {"id": "host_scan_startup", "category": "equipo", "title": "Escanear inicio automático", "full_protection": False,
     "exec": "deep_scan", "profile": "services", "params": []},
    {"id": "host_scan_registry", "category": "equipo", "title": "Escanear registro Windows", "full_protection": True,
     "exec": "deep_scan", "profile": "registry", "params": [], "requires_windows": True},
    {"id": "host_malware_known", "category": "equipo", "title": "Buscar malware conocido", "full_protection": False,
     "exec": "deep_scan", "profile": "malware", "params": []},
    {"id": "host_ransomware", "category": "equipo", "title": "Buscar ransomware", "full_protection": False,
     "exec": "deep_scan", "profile": "malware", "filter": "ransomware", "params": []},
    {"id": "host_rootkit", "category": "equipo", "title": "Buscar rootkits", "full_protection": False,
     "exec": "deep_scan", "profile": "rootkit", "params": []},
    {"id": "host_miners", "category": "equipo", "title": "Buscar mineros", "full_protection": False,
     "exec": "miners", "params": []},
    {"id": "host_dll_injection", "category": "equipo", "title": "Buscar DLL Injection", "full_protection": False,
     "exec": "deep_scan", "profile": "malware", "filter": "dll", "params": []},
    {"id": "host_hidden_processes", "category": "equipo", "title": "Buscar procesos ocultos", "full_protection": False,
     "exec": "deep_scan", "profile": "rootkit", "filter": "hidden_process", "params": []},
    {"id": "host_privilege_escalation", "category": "equipo", "title": "Buscar elevación de privilegios", "full_protection": False,
     "exec": "deep_scan", "profile": "processes", "filter": "privilege", "params": []},
    {"id": "net_scan_full", "category": "red", "title": "Escaneo completo de red", "full_protection": True, "exec": "network_scan", "params": []},
    {"id": "net_device_discovery", "category": "red", "title": "Descubrimiento de dispositivos", "full_protection": False, "exec": "network_scan", "params": []},
    {"id": "net_new_devices", "category": "red", "title": "Detectar dispositivos nuevos", "full_protection": False, "exec": "net_events", "params": [], "event_filter": "connect"},
    {"id": "net_disconnected_devices", "category": "red", "title": "Detectar desconectados", "full_protection": False, "exec": "net_events", "params": [], "event_filter": "disconnect"},
    {"id": "net_reconnections", "category": "red", "title": "Detectar reconexiones", "full_protection": False, "exec": "net_events", "params": [], "event_filter": "reconnect"},
    {"id": "net_unknown_devices", "category": "red", "title": "Dispositivos desconocidos (inventario)", "full_protection": False, "exec": "ndr_unknown", "params": []},
    {"id": "net_mitm", "category": "red", "title": "Buscar MITM", "full_protection": False, "exec": "mitm", "params": []},
    {"id": "net_arp_spoofing", "category": "red", "title": "Buscar ARP Spoofing", "full_protection": False, "exec": "ndr_alerts", "params": [], "alert_filter": "arp"},
    {"id": "net_dns_spoofing", "category": "red", "title": "Buscar DNS Spoofing", "full_protection": False, "exec": "dns_audit", "params": []},
    {"id": "net_rogue_dhcp", "category": "red", "title": "Buscar Rogue DHCP", "full_protection": False, "exec": "ndr_alerts", "params": [], "alert_filter": "dhcp"},
    {"id": "net_open_ports", "category": "red", "title": "Buscar puertos abiertos", "full_protection": False, "exec": "open_ports", "params": []},
    {"id": "net_traffic_analysis", "category": "red", "title": "Analizar tráfico", "full_protection": False, "exec": "traffic", "params": []},
    {"id": "net_forensic_pcap", "category": "red", "title": "Captura forense PCAP (manual)", "full_protection": False,
     "exec": "forensic_pcap", "params": []},
    {"id": "net_gateway_analysis", "category": "red", "title": "Analizar gateway", "full_protection": False, "exec": "gateway", "params": []},
    {"id": "net_dns_analysis", "category": "red", "title": "Analizar DNS", "full_protection": False, "exec": "dns_audit", "params": []},
    {"id": "net_stability", "category": "red", "title": "Estabilidad de red", "full_protection": False, "exec": "net_stability", "params": []},
    {"id": "web_analyze_url", "category": "web", "title": "Analizar URL", "full_protection": False, "exec": "web_url", "params": ["url"]},
    {"id": "web_analyze_site", "category": "web", "title": "Analizar sitio web", "full_protection": False, "exec": "web_url", "params": ["url"]},
    {"id": "web_domain_reputation", "category": "web", "title": "Reputación del dominio", "full_protection": False, "exec": "web_url", "params": ["url"]},
    {"id": "web_ssl_tls", "category": "web", "title": "Certificados SSL/TLS", "full_protection": False, "exec": "web_url", "params": ["url"]},
    {"id": "web_downloaded_files", "category": "web", "title": "Archivos descargados", "full_protection": False, "exec": "file_path", "params": ["path"]},
    {"id": "web_suspicious_links", "category": "web", "title": "Enlaces sospechosos", "full_protection": False, "exec": "web_url", "params": ["url"]},
    {"id": "web_phishing", "category": "web", "title": "Detectar phishing (web)", "full_protection": False, "exec": "web_url", "params": ["url"]},
    {"id": "web_malicious_sites", "category": "web", "title": "Sitios maliciosos", "full_protection": False, "exec": "web_url", "params": ["url"]},
    {"id": "web_fraud_pages", "category": "web", "title": "Páginas fraudulentas", "full_protection": False, "exec": "web_url", "params": ["url"]},
    {"id": "web_credential_theft", "category": "web", "title": "Robo de credenciales", "full_protection": False, "exec": "web_credential", "params": ["url"]},
    {"id": "mail_scan_mailbox", "category": "correo", "title": "Escanear buzón", "full_protection": True, "exec": "mail", "mail_action": "sync", "params": []},
    {"id": "mail_phishing", "category": "correo", "title": "Phishing correo", "full_protection": False, "exec": "mail", "mail_action": "events_phishing", "params": []},
    {"id": "mail_bec", "category": "correo", "title": "Detectar BEC", "full_protection": False, "exec": "mail", "mail_action": "bec", "params": []},
    {"id": "mail_malware", "category": "correo", "title": "Malware en correo", "full_protection": False, "exec": "mail", "mail_action": "events_malware", "params": []},
    {"id": "mail_spam", "category": "correo", "title": "Detectar spam", "full_protection": False, "exec": "mail", "mail_action": "events_spam", "params": []},
    {"id": "mail_spoofed_domains", "category": "correo", "title": "Dominios falsificados", "full_protection": False, "exec": "mail", "mail_action": "events_spoof", "params": []},
    {"id": "mail_headers", "category": "correo", "title": "Analizar encabezados", "full_protection": False, "exec": "mail", "mail_action": "headers", "params": []},
    {"id": "mail_rules", "category": "correo", "title": "Reglas automáticas", "full_protection": False, "exec": "mail", "mail_action": "rules", "params": []},
    {"id": "mail_attachments", "category": "correo", "title": "Analizar adjuntos", "full_protection": False, "exec": "mail", "mail_action": "attachments", "params": []},
    {"id": "mail_links", "category": "correo", "title": "Analizar enlaces", "full_protection": False, "exec": "mail", "mail_action": "links", "params": []},
    {"id": "endpoint_scan_full", "category": "endpoint", "title": "Escaneo completo endpoint", "full_protection": True, "exec": "deep_scan", "profile": "full", "params": []},
    {"id": "endpoint_firewall", "category": "endpoint", "title": "Verificación firewall", "full_protection": False, "exec": "deep_scan", "profile": "connections", "params": []},
    {"id": "endpoint_antivirus", "category": "endpoint", "title": "Verificación antivirus", "full_protection": False, "exec": "deep_scan", "profile": "quick", "filter": "defender", "params": []},
    {"id": "endpoint_encryption", "category": "endpoint", "title": "Verificación cifrado", "full_protection": False, "exec": "deep_scan", "profile": "quick", "filter": "disks", "params": []},
    {"id": "endpoint_integrity", "category": "endpoint", "title": "Integridad del sistema", "full_protection": False, "exec": "system_health", "params": []},
    {"id": "endpoint_policies", "category": "endpoint", "title": "Políticas de seguridad", "full_protection": False, "exec": "deep_scan", "profile": "quick", "params": []},
    {"id": "endpoint_status", "category": "endpoint", "title": "Estado del endpoint", "full_protection": True, "exec": "endpoint_status", "params": []},
    {"id": "sector_fintech", "category": "sectorial", "title": "Fintech", "full_protection": False, "exec": "sector", "sector_key": "fintech", "params": []},
    {"id": "sector_logistica", "category": "sectorial", "title": "Logística", "full_protection": False, "exec": "sector", "sector_key": "logistica", "params": []},
    {"id": "sector_mobile", "category": "sectorial", "title": "Aplicaciones móviles", "full_protection": False, "exec": "sector", "sector_key": "aplicaciones_moviles", "params": []},
    {"id": "sector_salud", "category": "sectorial", "title": "Salud", "full_protection": False, "exec": "sector", "sector_key": "salud", "params": []},
    {"id": "sector_gobierno", "category": "sectorial", "title": "Gobierno", "full_protection": False, "exec": "sector", "sector_key": "gobierno", "params": []},
    {"id": "sector_cloud", "category": "cloud", "title": "NOVUS Cloud Shield (CSPM)", "full_protection": False, "exec": "sector", "sector_key": "cloud", "params": [], "planned": True},
    {"id": "cloud_env_detect", "category": "cloud", "title": "Detectar señales cloud en el host (UCE)", "full_protection": False, "exec": "cloud_uce", "params": []},
]

MAIL_INTEGRATION_MSG = (
    "Función disponible cuando el administrador conecte el proveedor de correo "
    "(Google Workspace o Microsoft 365 vía OAuth oficial)."
)
CLOUD_PLANNED_MSG = (
    "NOVUS CLOUD SHIELD está en arquitectura reservada — no hay CSPM/API cloud operativa en este nodo."
)


def get_mechanism(mechanism_id: str) -> Optional[Dict[str, Any]]:
    for m in MECHANISMS:
        if m["id"] == mechanism_id:
            return m
    return None


def get_kernel_doc(mechanism_id: str) -> Optional[Dict[str, Any]]:
    return KERNEL_DOCS.get(mechanism_id)


def _mail_available(user_id) -> bool:
    try:
        from services.mail_shield_service import get_integration_status
        st = get_integration_status(user_id)
        return bool(st.get("any_connected"))
    except Exception:
        return False


def check_availability(mechanism: Dict[str, Any], user_id=None) -> Dict[str, Any]:
    mid = mechanism["id"]
    if mechanism.get("planned"):
        return {"available": False, "reason": CLOUD_PLANNED_MSG, "manual": False, "automatic": False}
    if mechanism.get("requires_windows") and not IS_WINDOWS:
        return {
            "available": False,
            "reason": "Requiere Windows en el host donde corre NOVUS.",
            "manual": True,
            "automatic": False,
        }
    if mechanism["category"] == "correo":
        if not _mail_available(user_id):
            return {
                "available": False,
                "reason": MAIL_INTEGRATION_MSG,
                "manual": True,
                "automatic": False,
            }
        return {"available": True, "reason": None, "manual": True, "automatic": True}
    if mid == "host_scan_memory":
        return {
            "available": True,
            "reason": "Análisis indirecto vía procesos/working set — no volcado completo de RAM.",
            "manual": True,
            "automatic": True,
        }
    if mid in ("net_dns_spoofing", "net_rogue_dhcp"):
        return {
            "available": True,
            "reason": "Detección limitada sin sensor de paquetes inline; usa telemetría ARP/DNS local.",
            "manual": True,
            "automatic": True,
        }
    if mid == "net_forensic_pcap":
        try:
            from services.forensic_pcap_capture_service import capture_capability

            cap = capture_capability()
            if not cap.get("scapy_available"):
                return {
                    "available": False,
                    "reason": cap.get("error") or "Scapy no instalado — PCAP no disponible.",
                    "manual": True,
                    "automatic": False,
                }
            if not cap.get("npcap_or_capture_ready"):
                return {
                    "available": True,
                    "reason": "Scapy presente pero sin interfaz capturable — ejecute como administrador e instale Npcap.",
                    "manual": True,
                    "automatic": True,
                }
        except Exception as exc:
            return {"available": False, "reason": str(exc)[:120], "manual": True, "automatic": False}
    return {"available": True, "reason": None, "manual": True, "automatic": True}


def build_catalog(user_id=None) -> List[Dict[str, Any]]:
    out = []
    for m in MECHANISMS:
        avail = check_availability(m, user_id)
        out.append({
            **m,
            "availability": avail,
            "kernel": KERNEL_DOCS.get(m["id"]),
        })
    return out


def full_protection_sequence(user_id=None) -> List[str]:
    return compatible_for_full_defense(user_id)


def compatible_for_full_defense(user_id=None) -> List[str]:
    """Mecanismos ejecutables en secuencia sin parámetros ni integración pendiente."""
    out: List[str] = []
    for m in MECHANISMS:
        if m.get("params"):
            continue
        if m.get("planned"):
            continue
        av = check_availability(m, user_id)
        if not av.get("available"):
            continue
        out.append(m["id"])
    return out


def audit_capabilities(user_id=None) -> Dict[str, Any]:
    catalog = build_catalog(user_id)
    implemented = []
    working = []
    needs_perms = []
    needs_integration = []
    automatic = []
    manual = []
    limitations = []
    for item in catalog:
        implemented.append(item["id"])
        av = item["availability"]
        if av.get("available"):
            working.append(item["id"])
        else:
            if item["category"] == "correo":
                needs_integration.append(item["id"])
            elif item.get("requires_windows") and not IS_WINDOWS:
                needs_perms.append(item["id"])
            elif item.get("planned"):
                limitations.append({"id": item["id"], "note": CLOUD_PLANNED_MSG})
        if av.get("automatic"):
            automatic.append(item["id"])
        if av.get("manual"):
            manual.append(item["id"])
        if av.get("reason") and av.get("available"):
            limitations.append({"id": item["id"], "note": av["reason"]})
    return {
        "implemented_mechanisms": implemented,
        "working": working,
        "needs_additional_permissions": needs_perms,
        "needs_future_integrations": needs_integration,
        "runs_automatically_in_background": list(set(automatic)),
        "manual_executable": list(set(manual)),
        "limitations": limitations,
        "host_os": platform.system(),
        "total": len(implemented),
    }
