"""
Catálogo de controles del NOVUS Compliance Center.
Solo controles con verificación técnica posible o marcados explícitamente como PENDIENTE/manual.
No afirma certificaciones ni cumplimiento legal completo.
"""
from __future__ import annotations

from typing import Any, Dict, List

# Estados canónicos del panel (nunca "Cumple totalmente")
STATUS_VERIFIED = "VERIFICADO"
STATUS_NOT_VERIFIED = "NO_VERIFICADO"
STATUS_NA = "NO_APLICA"
STATUS_PENDING = "PENDIENTE"

SECTORS: List[Dict[str, Any]] = [
    {"id": "fintech", "label": "Fintech", "modules": ["data_protection", "fintech", "cloud", "platform"]},
    {"id": "logistica", "label": "Logística", "modules": ["data_protection", "logistics", "platform"]},
    {"id": "movil", "label": "Aplicaciones móviles", "modules": ["data_protection", "mobile", "cloud", "platform"]},
    {"id": "ecommerce", "label": "Comercio electrónico", "modules": ["data_protection", "fintech", "cloud", "platform"]},
    {"id": "tecnologia", "label": "Empresas de tecnología", "modules": ["data_protection", "cloud", "platform"]},
    {"id": "salud", "label": "Salud", "modules": ["data_protection", "platform"]},
    {"id": "educacion", "label": "Educación", "modules": ["data_protection", "platform"]},
    {"id": "manufactura", "label": "Manufactura", "modules": ["data_protection", "logistics", "platform"]},
    {"id": "otros", "label": "Otros sectores empresariales", "modules": ["data_protection", "platform"]},
]

# Mapeo técnico → marcos de referencia (solo orientación; NOVUS no certifica)
FRAMEWORK_MAP: List[Dict[str, Any]] = [
    {
        "id": "iso27001_tech",
        "label": "ISO/IEC 27001 (controles técnicos orientativos)",
        "note": "NOVUS verifica controles técnicos locales; no sustituye certificación ISO.",
        "control_prefixes": ["dp_", "plat_"],
    },
    {
        "id": "nist_csf_tech",
        "label": "NIST CSF (Identify/Protect/Detect — parcial)",
        "note": "Mapeo a capacidades de detección y protección del nodo NOVUS.",
        "control_prefixes": ["plat_", "fin_", "log_"],
    },
    {
        "id": "pci_dss_tech",
        "label": "PCI DSS (controles técnicos parciales — Fintech)",
        "note": "Solo controles observables en el host NOVUS. Validación QSA externa requerida.",
        "control_prefixes": ["fin_", "dp_"],
        "sectors": ["fintech", "ecommerce"],
    },
    {
        "id": "gdpr_tech",
        "label": "GDPR / Ley 1581 (controles técnicos de protección de datos)",
        "note": "Cifrado, accesos, auditoría y evidencias en plataforma. Cumplimiento legal completo requiere revisión jurídica.",
        "control_prefixes": ["dp_"],
    },
]

# control_id → checker key en compliance_center_service
CONTROLS: List[Dict[str, Any]] = [
    # —— Protección de Datos ——
    {
        "id": "dp_encryption",
        "module": "data_protection",
        "title": "Cifrado (CryptoVault AES)",
        "description": "Verifica salud del CryptoVault y disponibilidad AES en el nodo NOVUS.",
        "risk_reduced": "Exposición de secretos y datos sensibles en reposo/transito interno.",
        "checker": "cryptovault",
        "novus_actions": ["Consultar platform-health / cryptovault", "Rotación AES programada al arranque"],
        "manual_needed": "Validar cifrado de bases de datos externas y almacenamiento cloud del cliente.",
    },
    {
        "id": "dp_access_mgmt",
        "module": "data_protection",
        "title": "Gestión de accesos y sesiones",
        "description": "Protección de autenticación, rate limit y sesiones de login auditadas.",
        "risk_reduced": "Accesos no autorizados y fuerza bruta.",
        "checker": "auth_protection",
        "novus_actions": ["Revisar Centro de Bloqueos", "Historial de accesos"],
        "manual_needed": "Políticas de identidad corporativa (AD/SSO) fuera de NOVUS.",
    },
    {
        "id": "dp_mfa",
        "module": "data_protection",
        "title": "MFA (autenticación multifactor)",
        "description": "Comprueba si existe implementación MFA operativa en NOVUS.",
        "risk_reduced": "Compromiso de credenciales únicas.",
        "checker": "mfa_absent",
        "novus_actions": [],
        "manual_needed": "MFA no implementado en NOVUS. Validar MFA en IdP corporativo.",
    },
    {
        "id": "dp_rbac",
        "module": "data_protection",
        "title": "RBAC (control de acceso por roles)",
        "description": "Verifica mapa de módulos MODULE_ACCESS y rol del usuario actual.",
        "risk_reduced": "Escalada de privilegios en la consola NOVUS.",
        "checker": "rbac",
        "novus_actions": ["Ajustar rol de usuario en BD", "Revisar denegaciones RBAC en evidencias"],
        "manual_needed": "Revisión periódica de roles de operadores.",
    },
    {
        "id": "dp_user_mgmt",
        "module": "data_protection",
        "title": "Gestión de usuarios",
        "description": "Usuarios activos registrados en SQLite (conteo verificable).",
        "risk_reduced": "Cuentas huérfanas o privilegios excesivos.",
        "checker": "user_mgmt",
        "novus_actions": ["Revisar tabla Usuario", "Desactivar cuentas inactivas"],
        "manual_needed": "Proceso HR de alta/baja de personal.",
    },
    {
        "id": "dp_audit_logs",
        "module": "data_protection",
        "title": "Registros de auditoría de login",
        "description": "Sesiones de login persistidas (login_session_audits).",
        "risk_reduced": "Falta de trazabilidad de acceso.",
        "checker": "login_sessions",
        "novus_actions": ["Abrir Historial Accesos", "GET /api/system/login-sessions"],
        "manual_needed": "Retención legal y exportación a SIEM externo.",
    },
    {
        "id": "dp_evidence",
        "module": "data_protection",
        "title": "Evidencias de seguridad",
        "description": "Centro de evidencias y/o defense registry con eventos reales.",
        "risk_reduced": "Imposibilidad de demostrar hallazgos ante auditoría.",
        "checker": "evidence_center",
        "novus_actions": ["Centro de Evidencias", "Defense Registry"],
        "manual_needed": None,
    },
    {
        "id": "dp_integrity",
        "module": "data_protection",
        "title": "Integridad de datos / evidencias forenses",
        "description": "Ledger forense SHA-256 + Ed25519 (verificador).",
        "risk_reduced": "Alteración no detectada de evidencias.",
        "checker": "forensic_integrity",
        "novus_actions": ["Verificador de Evidencias", "verify-all"],
        "manual_needed": "Custodia física / HSM externo si se requiere.",
    },
    {
        "id": "dp_backup",
        "module": "data_protection",
        "title": "Copias de seguridad",
        "description": "Backup de clave AES CryptoVault (no backup completo de plataforma).",
        "risk_reduced": "Pérdida de capacidad de descifrado tras rotación.",
        "checker": "aes_key_backup",
        "novus_actions": ["Revisar data/cryptovault_backups"],
        "manual_needed": "Backup de SQLite, configs y datos del cliente fuera de NOVUS.",
    },
    {
        "id": "dp_recovery",
        "module": "data_protection",
        "title": "Recuperación ante fallos",
        "description": "Middleware de recuperación UX; no es DR completo.",
        "risk_reduced": "Exposición de errores técnicos al usuario final.",
        "checker": "recovery_middleware",
        "novus_actions": ["Revisar recovery_middleware"],
        "manual_needed": "Plan DR/BCP empresarial y restore de BD.",
    },
    {
        "id": "dp_retention",
        "module": "data_protection",
        "title": "Conservación de registros",
        "description": "Historial de seguridad de red y ledgers append-only en disco.",
        "risk_reduced": "Pérdida de historial operativo.",
        "checker": "network_history_retention",
        "novus_actions": ["Historial seguridad red", "forensic ledger"],
        "manual_needed": "Política de retención legal por jurisdicción.",
    },
    {
        "id": "dp_secure_delete",
        "module": "data_protection",
        "title": "Eliminación segura",
        "description": "Comprueba si existe shred/wipe operativo en plataforma.",
        "risk_reduced": "Recuperación de datos residuales.",
        "checker": "secure_delete_absent",
        "novus_actions": [],
        "manual_needed": "Procedimientos OS de borrado seguro / destrucción de medios.",
    },
    # —— Fintech ——
    {
        "id": "fin_api_security",
        "module": "fintech",
        "title": "Seguridad de APIs (auth + rate limit)",
        "description": "APIs protegidas por sesión y rate limiting en core/security.",
        "risk_reduced": "Abuso de APIs y acceso anónimo.",
        "checker": "api_hardening",
        "novus_actions": ["Revisar core/security.py", "API rate limits"],
        "manual_needed": "WAF / API gateway corporativo.",
    },
    {
        "id": "fin_oauth",
        "module": "fintech",
        "title": "OAuth (Gmail / Microsoft 365)",
        "description": "Estado de configuración OAuth Mail Shield (sin inventar tokens).",
        "risk_reduced": "Credenciales de correo en texto plano.",
        "checker": "oauth_mail",
        "novus_actions": ["Configurar GOOGLE_/AZURE_ env", "Mail Shield integrations"],
        "manual_needed": "Consentimiento de buzones y revisión de scopes OAuth.",
    },
    {
        "id": "fin_jwt_sessions",
        "module": "fintech",
        "title": "Gestión de sesiones Flask",
        "description": "Sesiones Flask-Login con protección strong (no JWT de negocio propio).",
        "risk_reduced": "Secuestro de sesión de consola.",
        "checker": "session_protection",
        "novus_actions": ["SESSION_PROTECTION=strong", "cookies secure en HTTPS"],
        "manual_needed": "Si el cliente usa JWT propios, auditar fuera de NOVUS.",
    },
    {
        "id": "fin_credentials",
        "module": "fintech",
        "title": "Protección de credenciales",
        "description": "Contraseñas con hash Werkzeug; vault para secretos de motores.",
        "risk_reduced": "Filtración de contraseñas en claro.",
        "checker": "credential_hashing",
        "novus_actions": ["No almacenar passwords en claro"],
        "manual_needed": "Secret managers externos (Vault corporativo).",
    },
    {
        "id": "fin_tx_logs",
        "module": "fintech",
        "title": "Registro de transacciones financieras",
        "description": "NOVUS no es un core bancario; control marcado según evidencia disponible.",
        "risk_reduced": "Fraude transaccional no monitoreado.",
        "checker": "tx_logs_pending",
        "novus_actions": [],
        "manual_needed": "Integrar logs de transacciones del core Fintech del cliente.",
    },
    {
        "id": "fin_monitoring",
        "module": "fintech",
        "title": "Monitoreo y sector Fintech (ASPE/Sector Shield)",
        "description": "Panel ASPE / sector shield activo para sector fintech si aplica.",
        "risk_reduced": "Ausencia de controles sectoriales.",
        "checker": "sector_fintech",
        "novus_actions": ["ASPE status", "Sector Shield scan"],
        "manual_needed": None,
    },
    {
        "id": "fin_incidents",
        "module": "fintech",
        "title": "Gestión de incidentes",
        "description": "Alertas canónicas y módulo de incidentes con evidencia.",
        "risk_reduced": "Incidentes sin seguimiento.",
        "checker": "alerts_incidents",
        "novus_actions": ["/incidentes", "/api/security/alerts"],
        "manual_needed": "Playbooks IR humanos y comunicación regulatoria.",
    },
    # —— Logística ——
    {
        "id": "log_segmentation",
        "module": "logistics",
        "title": "Visibilidad / segmentación de red (ARP)",
        "description": "Dispositivos ARP y NDR del nodo; no es segmentación VLAN completa.",
        "risk_reduced": "Dispositivos desconocidos en LAN.",
        "checker": "ndr_network",
        "novus_actions": ["Network/NDR", "Topology"],
        "manual_needed": "Firewall/VLAN del sitio del cliente.",
    },
    {
        "id": "log_devices",
        "module": "logistics",
        "title": "Gestión de dispositivos",
        "description": "Inventario de activos / device connection monitor.",
        "risk_reduced": "Activos no inventariados.",
        "checker": "device_inventory",
        "novus_actions": ["Inventario activos", "Historial dispositivos"],
        "manual_needed": "CMDB empresarial.",
    },
    {
        "id": "log_integrity",
        "module": "logistics",
        "title": "Integridad y evidencias de red",
        "description": "Historial de seguridad de red + defense events.",
        "risk_reduced": "Pérdida de trazabilidad de eventos de red.",
        "checker": "network_history",
        "novus_actions": ["Historial seguridad red"],
        "manual_needed": None,
    },
    {
        "id": "log_servers",
        "module": "logistics",
        "title": "Estado de servidores / host NOVUS",
        "description": "Platform health y telemetría del proceso NOVUS.",
        "risk_reduced": "Degradación no detectada del nodo de monitoreo.",
        "checker": "platform_health",
        "novus_actions": ["Platform Health"],
        "manual_needed": "Monitoreo de servidores fuera del nodo NOVUS.",
    },
    {
        "id": "log_comms",
        "module": "logistics",
        "title": "Comunicaciones / Web Shield host audit",
        "description": "Auditoría DNS/hosts/proxy local vía Web Shield.",
        "risk_reduced": "Manipulación DNS/proxy local.",
        "checker": "web_shield_host",
        "novus_actions": ["Web Shield host-audit"],
        "manual_needed": "TLS inspection corporativa / SD-WAN.",
    },
    # —— Móvil ——
    {
        "id": "mob_apis",
        "module": "mobile",
        "title": "APIs backend (protección NOVUS)",
        "description": "APIs de la plataforma autenticadas; no audita app móvil del cliente.",
        "risk_reduced": "API backend NOVUS expuesta sin auth.",
        "checker": "api_hardening",
        "novus_actions": [],
        "manual_needed": "Pentest de APIs móviles del producto del cliente.",
    },
    {
        "id": "mob_tokens",
        "module": "mobile",
        "title": "Tokens OAuth Mail (proxy de buenas prácticas)",
        "description": "Tokens Mail Shield cifrados con CryptoVault cuando OAuth está activo.",
        "risk_reduced": "Tokens en texto plano en disco.",
        "checker": "oauth_token_vault",
        "novus_actions": ["mail_shield_token_vault"],
        "manual_needed": "Almacenamiento de tokens de apps móviles del cliente.",
    },
    {
        "id": "mob_tls",
        "module": "mobile",
        "title": "Comunicación cifrada (TLS / proxy)",
        "description": "Estado TLS reportado por CryptoVault / configuración HTTPS.",
        "risk_reduced": "Tráfico en claro hacia la consola.",
        "checker": "tls_status",
        "novus_actions": ["Usar túnel HTTPS / SESSION_COOKIE_SECURE"],
        "manual_needed": "Certificate pinning en apps móviles del cliente.",
    },
    {
        "id": "mob_aspe",
        "module": "mobile",
        "title": "Protección sector móvil (ASPE/UI Shield)",
        "description": "ASPE para sector aplicaciones móviles cuando el perfil lo activa.",
        "risk_reduced": "Falta de baseline sectorial.",
        "checker": "sector_mobile",
        "novus_actions": ["ASPE / sector movil"],
        "manual_needed": "Mobile Shield dedicado está planificado, no operativo completo.",
    },
    {
        "id": "mob_vulns",
        "module": "mobile",
        "title": "Gestión de vulnerabilidades (host)",
        "description": "Hallazgos del motor de vulnerabilidades del nodo NOVUS.",
        "risk_reduced": "Vulnerabilidades sin inventario.",
        "checker": "vulnerabilities",
        "novus_actions": ["/vulnerabilidades"],
        "manual_needed": "SAST/DAST de apps móviles del cliente.",
    },
    # —— Cloud ——
    {
        "id": "cloud_uce",
        "module": "cloud",
        "title": "Detección de infraestructura (UCE)",
        "description": "Universal Compatibility Engine — detección local, no CSPM cloud completo.",
        "risk_reduced": "Desconocimiento de componentes locales/cloud-edge.",
        "checker": "uce",
        "novus_actions": ["/api/system/uce/detect"],
        "manual_needed": "CSPM (AWS/Azure/GCP) — Cloud Shield planificado.",
    },
    {
        "id": "cloud_access",
        "module": "cloud",
        "title": "Accesos a consolas cloud del cliente",
        "description": "Fuera del alcance técnico de NOVUS en el host local.",
        "risk_reduced": "IAM cloud mal configurado.",
        "checker": "always_pending",
        "novus_actions": [],
        "manual_needed": "Revisión IAM en proveedor cloud del cliente.",
    },
    {
        "id": "cloud_audit",
        "module": "cloud",
        "title": "Auditoría integral NOVUS",
        "description": "Auditoría integral de fuentes y motores de la plataforma.",
        "risk_reduced": "Desalineación de fuentes de telemetría.",
        "checker": "integral_audit",
        "novus_actions": ["/api/audit/integral/summary"],
        "manual_needed": None,
    },
    # —— Plataforma NOVUS (Auditar NOVUS / transversal) ——
    {
        "id": "plat_kernel",
        "module": "platform",
        "title": "Kernel IA operativo",
        "description": "AI Kernel en ejecución con estado consultable.",
        "risk_reduced": "Asistente operativo indisponible.",
        "checker": "ai_kernel",
        "novus_actions": ["/api/ai/status"],
        "manual_needed": None,
    },
    {
        "id": "plat_defense",
        "module": "platform",
        "title": "Centro de Defensa / defense stack",
        "description": "Defense registry y catálogo de mecanismos manuales.",
        "risk_reduced": "Motores de defensa sin telemetría.",
        "checker": "defense_registry",
        "novus_actions": ["Centro de Defensa", "defense-registry"],
        "manual_needed": None,
    },
    {
        "id": "plat_xdr",
        "module": "platform",
        "title": "XDR (motor de amenazas host)",
        "description": "Threat cache / security motor integrado.",
        "risk_reduced": "Amenazas host sin visibilidad.",
        "checker": "xdr_threats",
        "novus_actions": ["/xdr", "/api/security/threats"],
        "manual_needed": None,
    },
    {
        "id": "plat_ndr",
        "module": "platform",
        "title": "NDR (radar de red)",
        "description": "Payload NDR construido desde ARP/psutil reales.",
        "risk_reduced": "Red local sin monitoreo.",
        "checker": "ndr_network",
        "novus_actions": ["/network", "/api/network/ndr"],
        "manual_needed": None,
    },
    {
        "id": "plat_web_shield",
        "module": "platform",
        "title": "Web Shield",
        "description": "Motor Web Shield activo.",
        "risk_reduced": "Navegación/descargas sin control en el nodo.",
        "checker": "web_shield",
        "novus_actions": ["/web-shield"],
        "manual_needed": None,
    },
    {
        "id": "plat_mail_shield",
        "module": "platform",
        "title": "Mail Shield",
        "description": "Motor Mail Shield; ingesta condicionada a OAuth.",
        "risk_reduced": "Correo sin análisis si OAuth ausente.",
        "checker": "mail_shield",
        "novus_actions": ["/mail-shield"],
        "manual_needed": "Configurar OAuth para buzones reales.",
    },
    {
        "id": "plat_db",
        "module": "platform",
        "title": "Base de datos operativa",
        "description": "SQLite inicializada y tablas esenciales presentes.",
        "risk_reduced": "Pérdida de persistencia de usuarios/alertas.",
        "checker": "database",
        "novus_actions": ["ensure_tables_exist"],
        "manual_needed": "Backup externo de SQLite.",
    },
]


def get_sector(sector_id: str) -> Dict[str, Any]:
    sid = (sector_id or "otros").lower().strip()
    for s in SECTORS:
        if s["id"] == sid:
            return s
    return SECTORS[-1]


def controls_for_modules(module_ids: List[str]) -> List[Dict[str, Any]]:
    mods = set(module_ids or [])
    return [c for c in CONTROLS if c["module"] in mods]


def frameworks_for_sector(sector_id: str) -> List[Dict[str, Any]]:
    out = []
    for fw in FRAMEWORK_MAP:
        sectors = fw.get("sectors")
        if sectors and sector_id not in sectors:
            continue
        out.append(fw)
    return out
