"""
Global search index for NOVUS — static platform catalog + live runtime data.
Fuzzy matching; no simulated results.
"""
import os
import socket
from datetime import timedelta

from utils.sectores_config import SECTORES_NOVUS
from utils.logger import logger

# Cache static index at import time; refreshed on demand
_STATIC_INDEX = None
_INDEX_BUILT_AT = None
_INDEX_TTL = timedelta(minutes=10)


def _item(item_id, name, item_type, url, description, icon, keywords=None, location=None):
    keywords = keywords or []
    search_text = " ".join([name, item_type, description, location or url, " ".join(keywords)]).lower()
    return {
        "id": item_id,
        "name": name,
        "type": item_type,
        "location": location or url,
        "url": url,
        "description": description,
        "icon": icon,
        "keywords": keywords,
        "search_text": search_text,
    }


def build_static_index():
    """Index routes, menus, forms, widgets and visible modules."""
    items = []

    modules = [
        ("mod-dashboard", "Dashboard", "Módulo", "/", "Panel principal SOC con KPIs y dispositivos en tiempo real", "fa-th-large", ["dashboard", "inicio", "home", "soc"]),
        ("mod-network", "Network", "Módulo", "/network", "Monitor de red, radar ARP y escaneo de nodos", "fa-network-wired", ["network", "red", "radar", "arp", "scanner", "net"]),
        ("mod-amenazas", "Amenazas / XDR", "Módulo", "/amenazas", "Centro de amenazas y respuesta extendida XDR", "fa-biohazard", ["xdr", "amenazas", "threats", "threat detector"]),
        ("mod-vulnerabilidades", "Vulnerabilidades", "Módulo", "/vulnerabilidades", "Escáner de vulnerabilidades y remediación", "fa-bug", ["vuln", "vulnerability", "vulnerabilidades", "pentesting", "cve"]),
        ("mod-endpoints", "Endpoints", "Módulo", "/endpoints", "Inventario y estado de endpoints del sistema", "fa-laptop-code", ["endpoint", "endpoints", "host", "equipo"]),
        ("mod-reportes", "Reportes", "Módulo", "/reportes", "Historial de informes de seguridad y exportación PDF", "fa-file-alt", ["reportes", "reports", "informe", "pdf"]),
        ("mod-automatizacion", "Automatización", "Módulo", "/automatizacion", "Playbooks y defensa activa automatizada", "fa-robot", ["automation", "automatizacion", "playbook"]),
        ("mod-configuracion", "Configuración", "Módulo", "/configuracion", "Ajustes de sector, pentesting y alertas", "fa-cog", ["config", "configuracion", "settings", "permisos"]),
        ("mod-topology", "Topology", "Módulo", "/topology", "Mapa topológico de red interactivo", "fa-project-diagram", ["topology", "topologia", "mapa", "network map"]),
        ("mod-layout", "Layout Operativo", "Módulo", "/layout_novus", "Shell operativo con widgets en vivo", "fa-columns", ["layout", "operativo", "shell"]),
        ("mod-incidentes", "Incidentes", "Módulo", "/incidentes", "Centro de incidentes y mitigación", "fa-exclamation-triangle", ["incidentes", "incidents", "alertas", "mitigar"]),
        ("mod-centro-defensa", "Centro de Defensa", "Módulo", "/centro-defensa", "Mecanismos de escaneo y defensa manual verificable", "fa-shield-virus", ["defensa", "manual", "escaneo", "mdr"]),
        ("mod-centro-evidencias", "Centro de Evidencias", "Módulo", "/centro-evidencias", "Evidencias verificables de motores NOVUS", "fa-fingerprint", ["evidencia", "evidence"]),
        ("mod-centro-bloqueos", "Centro de Bloqueos", "Módulo", "/centro-bloqueos", "Origenes bloqueados y políticas activas", "fa-ban", ["bloqueo", "block"]),
        ("mod-inventario", "Inventario de Activos", "Módulo", "/inventario-activos", "Activos de red autorizados y pendientes", "fa-server", ["activos", "inventario", "assets"]),
        ("mod-historial-red", "Historial de Seguridad Red", "Módulo", "/historial-seguridad-red", "Eventos NDR y red archivados", "fa-history", ["historial", "ndr", "red"]),
        ("mod-inteligencia", "Centro de Inteligencia", "Módulo", "/inteligencia", "NOVUS Threat Intelligence Center — casos y base de conocimiento", "fa-brain", ["inteligencia", "threat intelligence", "casos", "tic", "conocimiento"]),
        ("mod-siem", "SIEM / Logs", "Módulo", "/siem", "Consola SIEM y flujo de logs de auditoría", "fa-database", ["siem", "logs", "eventos", "auditoria"]),
        ("mod-identidades", "Identidades", "Módulo", "/sector-login", "Acceso sectorial y verificación de identidad", "fa-fingerprint", ["identidades", "identity", "sector", "roles"]),
        ("mod-sector-selector", "Selector de Sector", "Módulo", "/sector_selector", "Selección de sector económico", "fa-building", ["sector", "fintech", "logistica"]),
    ]
    for m in modules:
        items.append(_item(*m))

    security_layers = [
        ("shield-ato", "Anti Account Takeover", "Shield", "/amenazas", "Capa ATO — análisis de riesgo de acceso", "fa-user-shield", ["ato", "account", "takeover", "shield"]),
        ("shield-phishing", "Anti Phishing", "Shield", "/amenazas", "Inspección de correos y suplantación", "fa-envelope-open-text", ["phishing", "correo", "email"]),
        ("shield-ransom", "Anti Ransomware", "Shield", "/amenazas", "Monitor de ransomware y cifrado", "fa-lock", ["ransom", "ransomware"]),
        ("shield-mitm", "Anti MITM", "Shield", "/amenazas", "Verificación de intermediarios en red", "fa-exchange-alt", ["mitm", "man in the middle"]),
        ("shield-sqli", "Anti SQL Injection", "Shield", "/amenazas", "Sanitización y detección SQLi", "fa-code", ["sqli", "sql injection"]),
        ("shield-iot", "IoT Shield", "Shield", "/amenazas", "Validación de dispositivos IoT", "fa-microchip", ["iot", "dispositivo"]),
        ("shield-bec", "Anti BEC", "Shield", "/amenazas", "Fraude de correo empresarial", "fa-briefcase", ["bec", "fraude"]),
        ("shield-virus", "Virus Scanner", "Shield", "/amenazas", "Escáner antivirus integrado", "fa-shield-virus", ["virus", "malware", "scanner"]),
        ("shield-threat", "Threat Detector", "Shield", "/amenazas", "Motor de detección de amenazas en tiempo real", "fa-radiation", ["threat", "detector", "amenaza"]),
    ]
    for s in security_layers:
        items.append(_item(*s))

    widgets = [
        ("widget-radar", "Radar de Red", "Widget", "/network", "Visualización radar de nodos activos", "fa-broadcast-tower", ["radar", "novusradar"]),
        ("widget-traffic", "Gráfico de Tráfico", "Widget", "/", "Gráfico de tráfico de red en dashboard", "fa-chart-area", ["grafico", "traffic", "trafico"]),
        ("widget-kpi-riesgo", "KPI Nivel de Riesgo", "Widget", "/", "Indicador de riesgo del sistema", "fa-tachometer-alt", ["riesgo", "kpi", "risk"]),
        ("widget-ai-kernel", "AI Kernel", "Widget", "/", "Asistente IA y comandos del kernel", "fa-brain", ["ai", "kernel", "asistente"]),
    ]
    for w in widgets:
        items.append(_item(*w))

    for sector in SECTORES_NOVUS:
        sid = sector["id"]
        items.append(_item(
            f"cfg-sector-{sid}",
            f"Sector {sector['nombre']}",
            "Configuración",
            f"/configuracion#sector-{sid}",
            f"Configurar sector {sector['nombre']}: {sector['enfoque']}",
            "fa-industry",
            [sid, sector["nombre"].lower(), "sector", "fintech" if sid == "fintech" else sid, "logistics" if sid == "logistica" else sid, "mobile" if sid == "movil" else sid],
            "Configuración > Sectores",
        ))

    config_forms = [
        ("cfg-pentest-pasivo", "Pentesting Pasivo", "Formulario", "/configuracion#pentest-config", "Modo de escaneo pasivo sin estrés", "fa-feather", ["pasivo", "pentest"]),
        ("cfg-pentest-estandar", "Pentesting Estándar", "Formulario", "/configuracion#pentest-config", "Modo recomendado de pentesting", "fa-balance-scale", ["estandar", "pentest"]),
        ("cfg-pentest-agresivo", "Pentesting Agresivo", "Formulario", "/configuracion#pentest-config", "Modo de estrés y escaneo agresivo", "fa-fire", ["agresivo", "pentest", "estres"]),
        ("cfg-alert-whatsapp", "Alertas WhatsApp", "Formulario", "/configuracion#alert-whatsapp", "Canal de alertas para gerencia vía WhatsApp", "fab fa-whatsapp", ["whatsapp", "alerta"]),
        ("cfg-alert-email", "Reporte Diario Email", "Formulario", "/configuracion#alert-email", "Envío de reporte diario por correo", "fa-envelope", ["email", "reporte", "correo"]),
        ("cfg-guardar", "Guardar Configuración", "Formulario", "/configuracion#guardar", "Persistir ajustes tácticos de NOVUS", "fa-save", ["guardar", "save", "config"]),
    ]
    for c in config_forms:
        items.append(_item(*c))

    api_modules = [
        ("api-processes", "Procesos del Sistema", "API", "/endpoints", "Listado de procesos en ejecución", "fa-microchip", ["procesos", "process", "pid"]),
        ("api-ports", "Puertos Abiertos", "API", "/vulnerabilidades", "Escaneo de puertos expuestos", "fa-door-open", ["puertos", "ports", "servicios"]),
        ("api-threat-registry", "Registro de Amenazas", "API", "/amenazas", "Threat registry en tiempo real", "fa-list", ["registry", "amenazas"]),
        ("api-virus-scanner", "Virus Scanner API", "API", "/amenazas", "Endpoint del escáner antivirus", "fa-shield-virus", ["virus scanner"]),
    ]
    for a in api_modules:
        items.append(_item(*a))

    gateway_pages = [
        "dashboard", "sector_dashboard", "sector_selector",
    ]
    for page in gateway_pages:
        items.append(_item(
            f"page-{page}",
            page.replace("_", " ").title(),
            "Página",
            f"/{page}",
            f"Vista {page} de NOVUS",
            "fa-file",
            [page.replace("_", " ")],
        ))

    return items


def get_static_index():
    global _STATIC_INDEX, _INDEX_BUILT_AT
    from datetime import datetime
    now = datetime.now()
    if _STATIC_INDEX is None or _INDEX_BUILT_AT is None or (now - _INDEX_BUILT_AT) > _INDEX_TTL:
        _STATIC_INDEX = build_static_index()
        _INDEX_BUILT_AT = now
        logger.info(f"Global search static index built: {len(_STATIC_INDEX)} items")
    return _STATIC_INDEX


def _fuzzy_score(query, item):
    q = query.lower().strip()
    if not q:
        return 0
    name = item.get("name", "").lower()
    text = item.get("search_text", "").lower()
    keywords = " ".join(item.get("keywords", [])).lower()

    if name == q:
        return 100
    if name.startswith(q):
        return 95
    if q in name:
        return 90
    if any(k.startswith(q) or q in k for k in keywords.split()):
        return 85
    if q in text:
        return 75

    tokens = [t for t in q.split() if t]
    if tokens and all(t in text for t in tokens):
        return 65

    # Subsequence fuzzy: "net" matches "network"
    for word in text.split():
        if word.startswith(q) and len(q) >= 2:
            return 60
        idx = 0
        for ch in q:
            idx = word.find(ch, idx)
            if idx == -1:
                break
            idx += 1
        else:
            if len(q) >= 3:
                return 50

    return 0


def search_static(query, limit=20):
    scored = []
    for item in get_static_index():
        score = _fuzzy_score(query, item)
        if score > 0:
            entry = dict(item)
            entry["score"] = score
            scored.append(entry)
    scored.sort(key=lambda x: (-x["score"], x["name"]))
    return scored[:limit]


def search_dynamic(query, limit=30, *, tenant_id=None):
    """Search live data — tenant_id obligatorio desde contexto autenticado."""
    q = query.lower().strip()
    tid = str(tenant_id or "").strip()
    if not q or not tid:
        return []

    from services.tenant_scope_service import get_platform_tenant_id

    platform_tid = get_platform_tenant_id()
    host_telemetry_ok = tid == platform_tid

    results = []
    hostname = socket.gethostname()

    try:
        from services.security_report_service import list_reports
        for rep in list_reports(limit=50, tenant_id=tenant_id):
            blob = f"{rep.get('id','')} {rep.get('tipo','')} {rep.get('severidad','')} {rep.get('equipo_afectado','')}".lower()
            if q in blob or _fuzzy_score(q, {"name": rep.get("tipo", ""), "search_text": blob, "keywords": [rep.get("id", "")]}) >= 50:
                results.append(_item(
                    f"rep-{rep['id']}",
                    rep.get("tipo", "Informe"),
                    "Reporte",
                    f"/reportes?report={rep['id']}",
                    rep.get("resumen", rep.get("id", ""))[:120] or f"Informe {rep.get('severidad', '')}",
                    "fa-file-pdf",
                    [rep.get("id", "")],
                    f"Reportes > {rep.get('id', '')}",
                ))
    except Exception as exc:
        logger.error(f"Search reports error: {exc}")

    try:
        from services.novus_security_integration import novus_security

        if host_telemetry_ok:
            from services.http_shell_service import get_cached_vulnerabilities_snapshot

            vulns = get_cached_vulnerabilities_snapshot()[:30]
            for vuln in vulns:
                blob = f"{vuln.get('id','')} {vuln.get('nombre','')} {vuln.get('ip','')} {vuln.get('descripcion','')}".lower()
                if q in blob or _fuzzy_score(q, {"name": vuln.get("nombre", ""), "search_text": blob, "keywords": []}) >= 50:
                    results.append(_item(
                        f"vuln-{vuln.get('id')}",
                        vuln.get("nombre", "Vulnerabilidad"),
                        "Vulnerabilidad",
                        f"/vulnerabilidades?finding={vuln.get('id')}",
                        vuln.get("descripcion", "")[:120],
                        "fa-bug",
                        [vuln.get("id", ""), vuln.get("ip", "")],
                        "Vulnerabilidades",
                    ))
    except Exception as exc:
        logger.error(f"Search vulns error: {exc}")

    try:
        from database import SessionLocal, Alerta
        from services.novus_security_integration import novus_security
        from utils.host_data import get_local_ip, format_ip_or_unavailable

        incidents = []
        db = SessionLocal()
        try:
            from services.tenant_isolation_service import sql_tenant_filter
            from sqlalchemy import and_

            alert_q = (
                sql_tenant_filter(db.query(Alerta), Alerta, tid)
                .filter(and_(Alerta.tenant_id.isnot(None), Alerta.tenant_id != ""))
                .order_by(Alerta.id.desc())
                .limit(20)
            )
            for alerta in alert_q.all():
                incidents.append({
                    "id": f"INC-{alerta.id:04d}",
                    "ip": alerta.ip_afectada or format_ip_or_unavailable(get_local_ip()),
                    "tipo": alerta.titulo or "Alerta de seguridad",
                    "descripcion": alerta.descripcion or "",
                })
        finally:
            db.close()

        if host_telemetry_ok:
            for index, threat in enumerate(reversed(novus_security.security_engine.threat_registry[-15:]), start=1):
                incidents.append({
                    "id": f"RT-{index:04d}",
                    "ip": format_ip_or_unavailable(get_local_ip()),
                    "tipo": threat.get("threat_type", "Amenaza en tiempo real"),
                    "descripcion": str(threat.get("details", threat.get("source", ""))),
                })

        for inc in incidents:
            blob = f"{inc.get('id','')} {inc.get('tipo','')} {inc.get('ip','')} {inc.get('descripcion','')}".lower()
            if q in blob or _fuzzy_score(q, {"name": inc.get("tipo", ""), "search_text": blob, "keywords": []}) >= 50:
                results.append(_item(
                    f"inc-{inc.get('id')}",
                    f"Incidente {inc.get('id')}",
                    "Incidente",
                    f"/incidentes?incident={inc.get('id')}",
                    inc.get("descripcion", inc.get("tipo", ""))[:120],
                    "fa-exclamation-circle",
                    [inc.get("id", ""), inc.get("ip", "")],
                    "Incidentes",
                ))
    except Exception as exc:
        logger.error(f"Search incidents error: {exc}")

    try:
        import psutil

        if host_telemetry_ok:
            for proc in list(psutil.process_iter(["pid", "name", "username"]))[:80]:
                try:
                    info = proc.info
                    name = info.get("name") or ""
                    if q in name.lower() or (len(q) >= 3 and name.lower().startswith(q)):
                        results.append(_item(
                            f"proc-{info.get('pid')}",
                            f"Proceso {name}",
                            "Proceso",
                            f"/endpoints?process={info.get('pid')}",
                            f"PID {info.get('pid')} — usuario {info.get('username') or 'N/D'}",
                            "fa-cogs",
                            [str(info.get("pid")), name.lower()],
                            "Sistema > Procesos",
                        ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                if len(results) > limit:
                    break
    except Exception as exc:
        logger.error(f"Search processes error: {exc}")

    try:
        from services.network_scanner import network_scanner

        if host_telemetry_ok:
            for node in (network_scanner.get_cached_nodes() or [])[:30]:
                blob = f"{node.get('ip','')} {node.get('mac','')} {node.get('name','')}".lower()
                if q in blob or _fuzzy_score(q, {"name": node.get("name", node.get("ip", "")), "search_text": blob, "keywords": []}) >= 50:
                    results.append(_item(
                        f"node-{node.get('ip')}",
                        node.get("name") or node.get("ip", "Dispositivo"),
                        "Dispositivo",
                        f"/network?ip={node.get('ip')}",
                        f"IP {node.get('ip')} MAC {node.get('mac', 'N/D')}",
                        "fa-server",
                        [node.get("ip", ""), node.get("mac", "")],
                        "Network",
                    ))
    except Exception as exc:
        logger.error(f"Search nodes error: {exc}")

    try:
        from database import SessionLocal, Log

        if host_telemetry_ok:
            db = SessionLocal()
            try:
                for reg in db.query(Log).order_by(Log.id.desc()).limit(40).all():
                    blob = f"{reg.evento} {reg.detalle}".lower()
                    if q in blob:
                        results.append(_item(
                            f"log-{reg.id}",
                            reg.evento or "Evento",
                            "Log",
                            f"/siem?log={reg.id}",
                            (reg.detalle or "")[:120],
                            "fa-scroll",
                            [reg.evento or ""],
                            "SIEM / Logs",
                        ))
            finally:
                db.close()
    except Exception as exc:
        logger.error(f"Search logs error: {exc}")

    try:
        from database import SessionLocal, Usuario

        db = SessionLocal()
        try:
            for user in db.query(Usuario).filter(Usuario.nit_pyme == tid).limit(20).all():
                blob = f"{user.email} {user.sector or ''}".lower()
                if q in blob:
                    results.append(_item(
                        f"user-{user.id}",
                        user.email,
                        "Usuario",
                        "/configuracion",
                        f"Sector {user.sector or 'N/D'}",
                        "fa-user",
                        [user.email, user.sector or ""],
                        "Configuración > Usuarios",
                    ))
        finally:
            db.close()
    except Exception as exc:
        logger.error(f"Search users error: {exc}")

    try:
        import os, json
        playbooks_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "playbooks")
        if os.path.isdir(playbooks_dir):
            for filename in os.listdir(playbooks_dir):
                if not filename.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(playbooks_dir, filename), "r", encoding="utf-8") as handle:
                        pb = json.load(handle)
                    blob = f"{pb.get('nombre','')} {pb.get('id','')}".lower()
                    if q in blob:
                        results.append(_item(
                            f"pb-{pb.get('id', filename)}",
                            pb.get("nombre", "Playbook"),
                            "Playbook",
                            "/automatizacion",
                            f"Estado: {pb.get('estado', 'N/D')}",
                            "fa-book",
                            [pb.get("id", "")],
                            "Automatización",
                        ))
                except Exception:
                    continue
    except Exception as exc:
        logger.error(f"Search playbooks error: {exc}")

    try:
        from services.playbook_service import list_playbooks
        for pb in list_playbooks(active_only=False)[:40]:
            blob = f"{pb.get('id','')} {pb.get('nombre','')} {pb.get('descripcion','')}".lower()
            if q in blob or _fuzzy_score(q, {"name": pb.get("nombre", ""), "search_text": blob, "keywords": []}) >= 50:
                results.append(_item(
                    f"pbsvc-{pb.get('id')}",
                    pb.get("nombre", "Playbook"),
                    "Regla",
                    "/automatizacion",
                    (pb.get("accion") or pb.get("trigger") or pb.get("estado") or "")[:120],
                    "fa-robot",
                    [str(pb.get("id", ""))],
                    "Automatización > Playbooks",
                ))
    except Exception as exc:
        logger.error(f"Search playbook service error: {exc}")

    try:
        from services.manual_defense_catalog import MECHANISMS
        for mech in MECHANISMS:
            blob = f"{mech.get('id','')} {mech.get('title','')} {mech.get('category','')}".lower()
            if q in blob or _fuzzy_score(q, {"name": mech.get("title", ""), "search_text": blob, "keywords": []}) >= 50:
                results.append(_item(
                    f"md-{mech.get('id')}",
                    mech.get("title", "Mecanismo"),
                    "Mecanismo de defensa",
                    f"/centro-defensa?mechanism={mech.get('id')}",
                    f"Categoría: {mech.get('category', 'equipo')}",
                    "fa-shield-virus",
                    [mech.get("id", ""), mech.get("category", "")],
                    "Centro de Defensa",
                ))
    except Exception as exc:
        logger.error(f"Search manual defense error: {exc}")

    try:
        from services.manual_defense_service import list_history

        if host_telemetry_ok:
            for job in list_history(25):
                mechs = job.get("mechanisms") or []
                mech_label = mechs[0] if mechs else "defensa"
                blob = f"{mech_label} {job.get('status','')} {job.get('id','')} {job.get('hostname','')}".lower()
                if q in blob:
                    results.append(_item(
                        f"scan-{job.get('id')}",
                        f"Escaneo {mech_label}",
                        "Escaneo",
                        "/centro-defensa",
                        f"Host {job.get('hostname', '—')} · {job.get('started_at', '')}"[:120],
                        "fa-search",
                        [str(job.get("id", ""))],
                        "Centro de Defensa > Historial",
                    ))
    except Exception as exc:
        logger.error(f"Search defense history error: {exc}")

    try:
        from services.threat_intelligence_service import threat_intelligence

        # P0-3: list_cases sin tenant → solo plataforma (HOST), no TENANT_GLOBAL.
        if host_telemetry_ok:
            for case in threat_intelligence.list_cases(limit=30):
                blob = f"{case.get('id','')} {case.get('tipo','')} {case.get('resultado','')} {case.get('equipo','')}".lower()
                title = case.get("tipo") or case.get("id", "Caso")
                if q in blob or _fuzzy_score(q, {"name": title, "search_text": blob, "keywords": []}) >= 50:
                    results.append(_item(
                        f"ioc-{case.get('id')}",
                        f"IOC {case.get('id')}",
                        "IOC",
                        f"/inteligencia?case={case.get('id')}",
                        (case.get("resultado") or case.get("tipo") or "")[:120],
                        "fa-crosshairs",
                        [str(case.get("id", ""))],
                        "Threat Intelligence",
                    ))
    except Exception as exc:
        logger.error(f"Search threat intel error: {exc}")

    try:
        from services.ndci_service import ndci_service

        # P0-3: NDCI cases sin filtro tenant → solo plataforma.
        if host_telemetry_ok:
            for case in ndci_service.list_cases(20):
                blob = f"{case.get('id','')} {case.get('titulo','')} {case.get('sector','')}".lower()
                if q in blob or _fuzzy_score(q, {"name": case.get("titulo", ""), "search_text": blob, "keywords": []}) >= 50:
                    results.append(_item(
                        f"ndci-{case.get('id')}",
                        case.get("titulo", "Caso NDCI"),
                        "Caso de inteligencia",
                        f"/casos-estudio?case={case.get('id')}",
                        (case.get("sector") or case.get("origen") or "")[:120],
                        "fa-folder-open",
                        [str(case.get("id", ""))],
                        "Casos de estudio",
                    ))
    except Exception as exc:
        logger.error(f"Search NDCI error: {exc}")

    try:
        from services.evidence_center_service import list_evidence
        for ev in list_evidence(limit=25, tenant_id=tenant_id):
            blob = f"{ev.get('id','')} {ev.get('descripcion','')} {ev.get('motor','')}".lower()
            if q in blob:
                results.append(_item(
                    f"ev-{ev.get('id')}",
                    ev.get("descripcion", "Evidencia")[:80],
                    "Evidencia",
                    "/centro-evidencias",
                    (ev.get("motor") or ev.get("categoria") or "")[:120],
                    "fa-fingerprint",
                    [str(ev.get("id", ""))],
                    "Centro de Evidencias",
                ))
    except Exception as exc:
        logger.error(f"Search evidence center error: {exc}")

    try:
        from services.imcm.engine import search_incidents

        for inc in search_incidents(keyword=q, limit=15, tenant_id=tid):
            blob = f"{inc.get('id','')} {inc.get('title','')} {inc.get('threat_type','')}".lower()
            if q in blob or _fuzzy_score(q, {"name": inc.get("title", ""), "search_text": blob, "keywords": []}) >= 50:
                results.append(_item(
                    f"imcm-{inc.get('id')}",
                    inc.get("title", "Incidente IMCM"),
                    "Incidente",
                    f"/imcm?incident={inc.get('id')}",
                    (inc.get("threat_type") or inc.get("source_engine") or "")[:120],
                    "fa-folder-open",
                    [str(inc.get("id", ""))],
                    "IMCM",
                ))
    except Exception as exc:
        logger.error(f"Search IMCM error: {exc}")

    try:
        from database import SessionLocal, Alerta
        from services.tenant_isolation_service import sql_tenant_filter
        from sqlalchemy import and_

        db = SessionLocal()
        try:
            # P0-3: filtro tenant ANTES de materializar; legacy NULL/'' excluidos por igualdad exacta.
            alert_q = (
                sql_tenant_filter(db.query(Alerta), Alerta, tid)
                .filter(and_(Alerta.tenant_id.isnot(None), Alerta.tenant_id != ""))
                .order_by(Alerta.id.desc())
                .limit(25)
            )
            for alerta in alert_q.all():
                blob = f"{alerta.titulo} {alerta.descripcion} {alerta.ip_afectada}".lower()
                if q in blob:
                    results.append(_item(
                        f"alert-{alerta.id}",
                        alerta.titulo or "Alerta",
                        "Alerta",
                        f"/incidentes?alert={alerta.id}",
                        (alerta.descripcion or "")[:120],
                        "fa-bell",
                        [str(alerta.id)],
                        "Alertas",
                    ))
        finally:
            db.close()
    except Exception as exc:
        logger.error(f"Search alerts error: {exc}")

    return results[:limit]


def global_search(query, limit=25, *, tenant_id=None):
    """Merge static index and dynamic results with deduplication."""
    if not query or not str(query).strip():
        return []
    tid = str(tenant_id or "").strip()
    if not tid:
        return []

    static = search_static(query, limit=limit)
    dynamic = search_dynamic(query, limit=limit, tenant_id=tid)

    seen = set()
    merged = []
    for item in static + dynamic:
        key = item.get("id") or item.get("url")
        if key in seen:
            continue
        seen.add(key)
        merged.append({k: v for k, v in item.items() if k != "search_text"})
        if len(merged) >= limit:
            break

    return merged


def get_index_stats(*, tenant_id: str | None = None):
    tid = str(tenant_id or "").strip()
    try:
        from services.security_report_service import list_reports
        reports_n = len(list_reports(limit=500, tenant_id=tid)) if tid else 0
    except Exception:
        reports_n = 0
    return {
        "static_items": len(get_static_index()),
        "categories": sorted(set(i["type"] for i in get_static_index())),
        "reports_indexed_estimate": reports_n,
        "tenant_scoped": bool(tid),
    }


def get_dynamic_index_counts(*, tenant_id: str | None = None) -> dict:
    """Conteos de fuentes dinámicas. Alertas/usuarios: solo con tenant canónico."""
    counts = {}
    tid = str(tenant_id or "").strip()
    try:
        from services.security_report_service import list_reports
        counts["reports"] = len(list_reports(limit=500, tenant_id=tid)) if tid else 0
    except Exception:
        counts["reports"] = 0
    try:
        from services.manual_defense_catalog import MECHANISMS
        counts["defense_mechanisms"] = len(MECHANISMS)
    except Exception:
        counts["defense_mechanisms"] = 0
    try:
        from services.playbook_service import list_playbooks
        counts["playbooks"] = len(list_playbooks(active_only=False))
    except Exception:
        counts["playbooks"] = 0
    try:
        from services.network_scanner import network_scanner
        from services.tenant_scope_service import get_platform_tenant_id

        if tid and tid == get_platform_tenant_id():
            counts["network_nodes"] = len(network_scanner.get_cached_nodes() or [])
        else:
            counts["network_nodes"] = 0
    except Exception:
        counts["network_nodes"] = 0
    try:
        from database import SessionLocal, Log, Alerta, Usuario
        from services.tenant_isolation_service import sql_tenant_filter
        from services.tenant_scope_service import get_platform_tenant_id

        db = SessionLocal()
        try:
            if tid and tid == get_platform_tenant_id():
                counts["logs"] = db.query(Log).count()
            else:
                counts["logs"] = 0
            if tid:
                counts["alerts"] = sql_tenant_filter(db.query(Alerta), Alerta, tid).count()
                counts["users"] = db.query(Usuario).filter(Usuario.nit_pyme == tid).count()
            else:
                counts["alerts"] = 0
                counts["users"] = 0
        finally:
            db.close()
    except Exception:
        counts["logs"] = counts.get("logs", 0)
        counts["alerts"] = counts.get("alerts", 0)
        counts["users"] = counts.get("users", 0)
    return counts
