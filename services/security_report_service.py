"""
Professional security report builder and persistence for NOVUS.
All content is derived from real runtime findings — never invented.
"""
import json
import os
import socket
from datetime import datetime
from typing import Optional

from utils.host_data import get_local_ip, format_ip_or_unavailable
from utils.logger import logger

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "reports")
INDEX_FILE = os.path.join(REPORTS_DIR, "index.json")
TENANT_REPORTS_DIR = os.path.join(REPORTS_DIR, "by_tenant")
UNSCOPED_INDEX_FILE = os.path.join(REPORTS_DIR, "unscoped", "index.json")
_LEGACY_MIGRATED_FLAG = os.path.join(REPORTS_DIR, ".tenant_index_migrated")

SEVERITY_ORDER = {"Crítico": 4, "Alto": 3, "Medio": 2, "Bajo": 1, "Informativo": 0}
NO_DATA = "Sin datos disponibles"


def _ensure_dirs():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(TENANT_REPORTS_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(UNSCOPED_INDEX_FILE), exist_ok=True)
    if not os.path.exists(INDEX_FILE):
        with open(INDEX_FILE, "w", encoding="utf-8") as handle:
            json.dump([], handle)


def _sanitize_tenant_id(tenant_id: str) -> str:
    from services.tenant_isolation_service import sanitize_tenant_id_for_path
    return sanitize_tenant_id_for_path(tenant_id)


def _tenant_index_path(tenant_id: str) -> str:
    return os.path.join(TENANT_REPORTS_DIR, _sanitize_tenant_id(tenant_id), "index.json")


def _load_tenant_index(tenant_id: str):
    _ensure_dirs()
    path = _tenant_index_path(tenant_id)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return []


def _save_tenant_index(tenant_id: str, entries):
    _ensure_dirs()
    path = _tenant_index_path(tenant_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(entries, handle, indent=2, ensure_ascii=False)


def _load_unscoped_index():
    _ensure_dirs()
    if not os.path.exists(UNSCOPED_INDEX_FILE):
        return []
    try:
        with open(UNSCOPED_INDEX_FILE, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return []


def _save_unscoped_index(entries):
    _ensure_dirs()
    with open(UNSCOPED_INDEX_FILE, "w", encoding="utf-8") as handle:
        json.dump(entries, handle, indent=2, ensure_ascii=False)


def _migrate_legacy_index_once():
    """Migra index.json global a índices por tenant sin borrar reportes."""
    if os.path.exists(_LEGACY_MIGRATED_FLAG):
        return
    _ensure_dirs()
    legacy = _load_index()
    if not legacy:
        with open(_LEGACY_MIGRATED_FLAG, "w", encoding="utf-8") as fh:
            fh.write("ok\n")
        return
    from services.tenant_scope_service import get_platform_tenant_id

    platform_tid = get_platform_tenant_id()
    unscoped = []
    by_tenant: dict = {}
    for entry in legacy:
        rid = entry.get("id")
        report = get_report(rid) if rid else None
        tid = None
        if report:
            tid = report.get("tenant_id") or report.get("tenant_marker")
        if tid and str(tid).strip():
            by_tenant.setdefault(str(tid).strip(), []).append(entry)
        elif report and platform_tid:
            # Reportes históricos del nodo monitorizado — solo platform tenant verificable
            report["tenant_id"] = platform_tid
            report["migration_note"] = "MIGRATION_REQUIRED→platform_tenant"
            save_report(report, tenant_id=platform_tid, skip_legacy_index=True)
            by_tenant.setdefault(platform_tid, []).append({**entry, "tenant_id": platform_tid})
        else:
            entry["scope_status"] = "UNSCOPED"
            unscoped.append(entry)
    for tid, entries in by_tenant.items():
        existing = _load_tenant_index(tid)
        seen = {e.get("id") for e in existing}
        merged = existing + [e for e in entries if e.get("id") not in seen]
        _save_tenant_index(tid, merged[:500])
    if unscoped:
        _save_unscoped_index(unscoped)
    with open(_LEGACY_MIGRATED_FLAG, "w", encoding="utf-8") as fh:
        fh.write("ok\n")
    logger.info(
        "Reports index migrated: tenants=%s unscoped=%s",
        len(by_tenant),
        len(unscoped),
    )


def _load_index():
    _ensure_dirs()
    try:
        with open(INDEX_FILE, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return []


def _save_index(entries):
    _ensure_dirs()
    with open(INDEX_FILE, "w", encoding="utf-8") as handle:
        json.dump(entries, handle, indent=2, ensure_ascii=False)


def _report_path(report_id):
    return os.path.join(REPORTS_DIR, f"{report_id}.json")


def _normalize_severity(raw):
    value = str(raw or "").lower()
    if "crit" in value or "crít" in value:
        return "Crítico"
    if "high" in value or "alto" in value or "alta" in value:
        return "Alto"
    if "med" in value:
        return "Medio"
    if "low" in value or "bajo" in value or "baja" in value:
        return "Bajo"
    if "info" in value or "detect" in value or "hallazgo" in value:
        return "Informativo"
    return "Medio"


def _port_risk(port):
    try:
        port = int(port)
    except (TypeError, ValueError):
        return "Medio"
    if port in (23, 445, 3389, 5900, 21):
        return "Alto"
    if port in (135, 139, 53, 80, 443):
        return "Medio"
    return "Informativo"


def _build_recommendations(finding):
    """Build evidence-based recommendations only."""
    recs = []
    source = finding.get("fuente") or finding.get("source") or ""
    fid = finding.get("id") or finding.get("finding_id") or ""

    if "PROC" in fid or source == "scan_running_processes":
        pid = finding.get("pid") or fid.replace("FIND-PROC-", "").replace("PROC-", "")
        name = finding.get("nombre") or finding.get("name") or "proceso detectado"
        path = finding.get("descripcion") or finding.get("command_line") or finding.get("path") or ""
        recs.append(f"Terminar el proceso sospechoso PID {pid} ({name}) tras validar que no es operación legítima.")
        if path:
            recs.append(f"Revisar la ruta de ejecución: {path}")
        recs.append("Ejecutar análisis adicional del binario y del usuario que lo inició.")
        recs.append("Si se confirma actividad maliciosa, aislar el equipo de la red y rotar credenciales.")

    elif "PORT" in fid or source == "scan_open_ports":
        port = finding.get("port")
        if not port and "PORT-" in fid:
            port = fid.split("PORT-")[-1]
        service = finding.get("descripcion") or finding.get("service") or f"puerto {port}"
        ip = finding.get("ip") or format_ip_or_unavailable(get_local_ip())
        recs.append(f"Evaluar si el puerto {port} ({service}) debe permanecer accesible en {ip}.")
        recs.append(f"Si no es necesario, detener el servicio asociado o bloquear el puerto {port} en el firewall del sistema.")
        recs.append("Restringir el acceso al puerto solo a redes o hosts autorizados.")
        if str(port) in ("445", "3389", "23"):
            recs.append("Aplicar hardening: deshabilitar servicios legacy o exponerlos únicamente vía VPN.")

    elif finding.get("tipo") == "incidente" or finding.get("type") == "incident":
        recs.append("Revisar los logs del sistema en el intervalo del incidente.")
        recs.append("Validar integridad del host afectado y aplicar parches pendientes.")
        recs.append("Documentar acciones de contención y escalamiento según política interna.")

    else:
        recs.append("Investigar el hallazgo con la evidencia adjunta en este informe.")
        recs.append("Confirmar si el comportamiento observado es esperado en este equipo.")

    return recs


def _build_technical_sections(finding, related=None):
    try:
        from services.vulnerability_analyst_service import enrich_finding
        enriched = enrich_finding(dict(finding))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hostname = socket.gethostname()
        return {
            "fecha_deteccion": enriched.get("fecha") + " " + enriched.get("hora", "") if enriched.get("fecha") else now,
            "severidad": enriched.get("impacto_nivel") or _normalize_severity(enriched.get("riesgo")),
            "tipo_vulnerabilidad": enriched.get("nombre") or "Hallazgo de seguridad",
            "descripcion_tecnica": enriched.get("descripcion_tecnica") or NO_DATA,
            "descripcion_sencilla": enriched.get("descripcion_sencilla") or "",
            "que_ocurrio": enriched.get("descripcion_sencilla") or enriched.get("descripcion_tecnica"),
            "origen": enriched.get("causa_probable") or NO_DATA,
            "causa_probable": enriched.get("causa_probable") or NO_DATA,
            "impacto_potencial": enriched.get("impacto_potencial") or NO_DATA,
            "proceso_servicio_dispositivo": enriched.get("recurso_afectado") or hostname,
            "evidencias": [str(enriched.get("evidencia"))] if enriched.get("evidencia") else [NO_DATA],
            "recursos_afectados": [enriched.get("recurso_afectado") or hostname],
            "riesgo_sistema": enriched.get("impacto_nivel") or "Medio",
            "consecuencias": enriched.get("impacto_potencial") or NO_DATA,
            "relacionados": [r.get("id") for r in (related or []) if r.get("id")],
            "linea_tiempo": enriched.get("historial", {}).get("eventos") or [
                {"hora": now, "evento": "Detección automática por NOVUS"},
            ],
            "estado": enriched.get("estado") or "Activo",
            "acciones_automaticas": enriched.get("acciones_novus") or [],
            "recomendaciones": enriched.get("acciones_cliente") or _build_recommendations(finding),
            "recomendaciones_opcionales": enriched.get("acciones_opcionales") or [],
            "pasos_correccion": enriched.get("acciones_cliente") or [],
            "referencias": [enriched.get("referencia_tecnica")] if enriched.get("referencia_tecnica") != NO_DATA else [],
            "nivel_confianza": enriched.get("confianza") or "MEDIA",
            "motor": enriched.get("motor") or NO_DATA,
            "fuente_evidencia": enriched.get("fuente_evidencia") or NO_DATA,
            "tiempo_correccion": enriched.get("tiempo_correccion") or NO_DATA,
            "dificultad": enriched.get("dificultad") or NO_DATA,
            "historial": enriched.get("historial") or {},
            "observaciones": f"Motor: {enriched.get('motor')}. Fuente: {enriched.get('fuente_evidencia')}.",
        }
    except Exception:
        pass

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = socket.gethostname()
    fid = finding.get("id") or finding.get("finding_id") or "Sin ID"
    severity = _normalize_severity(finding.get("riesgo") or finding.get("severity") or finding.get("gravedad"))
    tipo = finding.get("tipo_vulnerabilidad") or finding.get("tipo") or finding.get("type") or "Hallazgo de seguridad"
    ip = finding.get("ip") or format_ip_or_unavailable(get_local_ip())

    if "PORT" in fid:
        tipo = "Puerto expuesto"
        port = fid.split("PORT-")[-1]
        severity = _port_risk(port)
    elif "PROC" in fid:
        tipo = "Proceso sospechoso"
        severity = "Alto"

    descripcion = finding.get("descripcion") or finding.get("description") or finding.get("nombre") or "Sin descripción adicional"
    evidencias = []
    for key in ("command_line", "path", "port", "service", "nombre", "name", "descripcion"):
        if finding.get(key):
            evidencias.append(f"{key}: {finding[key]}")

    causa = "Sin datos suficientes para determinar la causa raíz exacta."
    if "PROC" in fid:
        causa = "Patrón malicioso confirmado en la línea de comandos o nombre del proceso en ejecución."
    elif "PORT" in fid:
        causa = f"Servicio escuchando conexiones en el puerto detectado en {ip}."
    elif finding.get("fuente") == "database":
        causa = "Registro persistido previamente en la base de datos de vulnerabilidades de NOVUS."

    consecuencias = {
        "Crítico": "Compromiso potencial del sistema, exfiltración de datos o interrupción del servicio.",
        "Alto": "Escalada de privilegios, movimiento lateral o acceso no autorizado.",
        "Medio": "Superficie de ataque ampliada o exposición innecesaria de servicios.",
        "Bajo": "Información de reconocimiento o exposición limitada.",
        "Informativo": "Hallazgo a revisar; impacto directo no confirmado.",
    }.get(severity, "Impacto por evaluar según contexto operativo.")

    return {
        "fecha_deteccion": finding.get("detected_at") or now,
        "severidad": severity,
        "tipo_vulnerabilidad": tipo,
        "descripcion_tecnica": descripcion,
        "que_ocurrio": descripcion,
        "origen": causa,
        "proceso_servicio_dispositivo": finding.get("nombre") or finding.get("name") or hostname,
        "evidencias": evidencias or ["Sin evidencia adicional capturada en el momento del escaneo."],
        "recursos_afectados": [ip, hostname],
        "riesgo_sistema": severity,
        "consecuencias": consecuencias,
        "relacionados": [r.get("id") for r in (related or []) if r.get("id")],
        "linea_tiempo": [
            {"hora": finding.get("detected_at") or now, "evento": "Detección automática por NOVUS"},
            {"hora": now, "evento": "Informe técnico generado"},
        ],
        "estado": finding.get("estado") or "Activo",
        "acciones_automaticas": [],
        "recomendaciones": _build_recommendations(finding),
        "pasos_correccion": _build_recommendations(finding),
        "referencias": finding.get("referencias") or ["CVE/CWE: No disponible — hallazgo detectado por telemetría local, sin correlación CVE automática."],
        "nivel_confianza": finding.get("confianza") or ("Alta" if finding.get("fuente") in ("scan_running_processes", "scan_open_ports") else "Media"),
        "observaciones": finding.get("observaciones") or "Análisis basado exclusivamente en evidencia recolectada en el equipo donde se ejecuta NOVUS.",
    }


def build_report_from_finding(finding, related=None):
    """Build a full professional report dict from a real finding."""
    now = datetime.now()
    report_id = f"SEC-{now.strftime('%Y%m%d%H%M%S')}-{finding.get('id', 'GEN').replace(' ', '')[:20]}"
    technical = _build_technical_sections(finding, related=related)
    hostname = socket.gethostname()

    report = {
        "id": report_id,
        "finding_id": finding.get("id") or finding.get("finding_id"),
        "tipo": finding.get("tipo") or technical["tipo_vulnerabilidad"],
        "fecha": technical["fecha_deteccion"],
        "severidad": technical["severidad"],
        "estado": technical["estado"],
        "equipo_afectado": hostname,
        "tiempo_resolucion": None,
        "resumen_ejecutivo": (
            f"Se detectó {technical['tipo_vulnerabilidad']} con severidad {technical['severidad']} "
            f"en {hostname} ({format_ip_or_unavailable(get_local_ip())}). {technical['que_ocurrio']}"
        ),
        "technical": technical,
        "conclusiones": (
            f"El hallazgo permanece en estado '{technical['estado']}'. "
            f"Nivel de confianza: {technical['nivel_confianza']}. "
            "Se recomienda aplicar las acciones indicadas en este informe."
        ),
        "remediation_log": [],
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
    }
    return report


def save_report(report, *, tenant_id: Optional[str] = None, skip_legacy_index: bool = False):
    _ensure_dirs()
    tid = tenant_id or report.get("tenant_id")
    if not tid:
        from services.tenant_scope_service import get_platform_tenant_id
        tid = get_platform_tenant_id()
    report["tenant_id"] = tid

    path = _report_path(report["id"])
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    summary = {
        "id": report["id"],
        "finding_id": report.get("finding_id"),
        "tipo": report.get("tipo"),
        "fecha": report.get("fecha"),
        "severidad": report.get("severidad"),
        "estado": report.get("estado"),
        "equipo_afectado": report.get("equipo_afectado"),
        "tiempo_resolucion": report.get("tiempo_resolucion"),
        "resumen": report.get("resumen_ejecutivo", "")[:200],
        "tenant_id": tid,
    }
    index = _load_tenant_index(tid)
    index = [e for e in index if e.get("id") != summary.get("id")]
    if summary.get("finding_id"):
        index = [e for e in index if e.get("finding_id") != summary.get("finding_id")]
    index.insert(0, summary)
    _save_tenant_index(tid, index[:500])

    if not skip_legacy_index:
        legacy = _load_index()
        legacy = [e for e in legacy if e.get("id") != summary.get("id")]
        legacy.insert(0, summary)
        _save_index(legacy[:500])
    logger.info(f"Security report saved: {report['id']} tenant={tid}")
    return report


def get_report(report_id, *, tenant_id: Optional[str] = None):
    from services.tenant_isolation_service import tenant_ids_match

    path = _report_path(report_id)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        report = json.load(handle)
    if tenant_id is not None and not tenant_ids_match(report.get("tenant_id"), tenant_id):
        return None
    return report


def _report_is_stale_or_test(entry: dict) -> bool:
    """Excluye artefactos de prueba o hallazgos DB sin verificación en vivo."""
    rid = str(entry.get("id") or "")
    fid = str(entry.get("finding_id") or "")
    motor = str(entry.get("motor") or entry.get("fuente") or "")
    if "TEST" in rid.upper() or "TEST" in fid.upper():
        return True
    if motor.lower() == "test":
        return True
    if "DB-VULN" in fid.upper():
        return True
    if entry.get("estado") == "Archivado-SinEvidencia":
        return True
    return False


def list_reports(limit=100, *, tenant_id: Optional[str] = None):
    if not tenant_id:
        return []
    _migrate_legacy_index_once()
    entries = [e for e in _load_tenant_index(tenant_id) if not _report_is_stale_or_test(e)]
    return entries[:limit]


def get_report_by_finding(finding_id, *, tenant_id: Optional[str] = None):
    if not tenant_id:
        return None
    _migrate_legacy_index_once()
    for entry in _load_tenant_index(tenant_id):
        if entry.get("finding_id") == finding_id:
            return get_report(entry["id"], tenant_id=tenant_id)
    return None


def update_report_status(report_id, estado, remediation_log=None, tiempo_resolucion=None, verification=None, *, tenant_id: Optional[str] = None):
    report = get_report(report_id, tenant_id=tenant_id)
    if not report:
        return None
    report["estado"] = estado
    report["technical"]["estado"] = estado
    if verification:
        report["verification"] = verification
        report["technical"]["verificacion"] = {
            "motor": verification.get("motor"),
            "detalle": verification.get("detail"),
            "resuelto": verification.get("resolved"),
            "hora": verification.get("verified_at"),
        }
    if remediation_log:
        report["remediation_log"] = remediation_log
        report["technical"]["acciones_automaticas"] = [
            step.get("label") or step.get("detail") for step in remediation_log if step.get("status") == "done"
        ]
        report["technical"]["linea_tiempo"].append({
            "hora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "evento": f"Remediación: {estado}",
        })
    if tiempo_resolucion:
        report["tiempo_resolucion"] = tiempo_resolucion
    save_report(report, tenant_id=report.get("tenant_id"))
    return report


def ensure_report_for_finding(finding_id, finding=None, *, tenant_id: Optional[str] = None):
    """Return existing report or create one from finding data."""
    report = get_report_by_finding(finding_id, tenant_id=tenant_id)
    if report:
        return report
    if finding:
        built = build_report_from_finding(finding)
        return save_report(built, tenant_id=tenant_id)
    return None


def auto_generate_for_findings(findings, *, tenant_id: Optional[str] = None):
    """Create reports for new findings not already indexed."""
    if not tenant_id:
        from services.tenant_scope_service import get_platform_tenant_id
        tenant_id = get_platform_tenant_id()
    created = []
    _migrate_legacy_index_once()
    existing_ids = {e.get("finding_id") for e in _load_tenant_index(tenant_id)}
    grouped = {}
    for item in findings:
        key = item.get("ip") or "local"
        grouped.setdefault(key, []).append(item)

    for finding in findings:
        fid = finding.get("id")
        if not fid or fid in existing_ids:
            continue
        related = [f for f in grouped.get(finding.get("ip") or "local", []) if f.get("id") != fid]
        finding = dict(finding)
        finding.setdefault("detected_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        report = save_report(build_report_from_finding(finding, related=related), tenant_id=tenant_id)
        try:
            from services.email_delivery_service import deliver_report_to_ceo

            deliver_report_to_ceo(report, category="finding_report")
        except Exception as exc:
            logger.debug("CEO finding report: %s", exc)
        created.append(report)
        existing_ids.add(fid)
    return created
