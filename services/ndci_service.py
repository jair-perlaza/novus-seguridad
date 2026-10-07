"""
NOVUS Digital Case Intelligence (NDCI) — expedientes técnicos inmutables.

Convierte análisis reales (Deep Scan, operaciones Kernel, SOC) en casos de estudio
completos. Nunca inventa datos; ausencia de evidencia se documenta explícitamente.
"""
from __future__ import annotations

import json
import os
import platform
import re
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from database import NdciCaso, SessionLocal, Usuario
from utils.logger import logger

NDCI_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ndci")
CASES_DIR = os.path.join(NDCI_DIR, "cases")
KNOWLEDGE_FILE = os.path.join(NDCI_DIR, "knowledge.jsonl")
INDEX_FILE = os.path.join(NDCI_DIR, "index.json")

THREAT_CATEGORIES = (
    "malware", "ransomware", "fuerza_bruta", "credential_stuffing",
    "movimiento_lateral", "exfiltracion", "ataques_api", "accesos_no_autorizados",
    "trafico_sospechoso", "comportamiento_anomalo",
)

NO_EVIDENCE_MSG = "No se detectó evidencia de este tipo de amenaza durante el análisis."

MANUAL_ANALYSIS_TYPES = {
    "infraestructura_completa": "Infraestructura completa",
    "estado_red": "Estado actual de la red",
    "auditoria_completa": "Auditoría completa",
    "dispositivo": "Dispositivo específico",
    "vulnerabilidad": "Vulnerabilidad específica",
    "incidente": "Incidente específico",
    "comparacion": "Comparación con otro caso",
    "personalizado": "Análisis personalizado",
}


def _ensure_dirs():
    os.makedirs(CASES_DIR, exist_ok=True)


def _json_dump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str)


def _json_load(raw: Optional[str], default=None):
    if default is None:
        default = {}
    if not raw:
        return default
    try:
        if isinstance(raw, str) and raw.startswith(NDCI_ENC_PREFIX):
            return json.loads(_decrypt_ndci_blob(raw))
        return json.loads(raw)
    except Exception:
        return default


NDCI_ENC_PREFIX = "NOVUSENC:v1:"


def _get_cryptovault():
    from crypto_vault import CryptoVault
    return CryptoVault()


def _encrypt_ndci_blob(plain_text: str) -> str:
    token = _get_cryptovault().proteger(plain_text)
    return NDCI_ENC_PREFIX + token


def _decrypt_ndci_blob(enc_text: str) -> str:
    payload = enc_text[len(NDCI_ENC_PREFIX):] if enc_text.startswith(NDCI_ENC_PREFIX) else enc_text
    return _get_cryptovault().desproteger(payload)


def _store_expediente(expediente: dict) -> str:
    """Persiste expediente cifrado con AES-256-GCM (CryptoVault)."""
    return _encrypt_ndci_blob(_json_dump(expediente))


def _load_expediente(raw: Optional[str]) -> dict:
    if not raw:
        return {}
    if isinstance(raw, str) and raw.startswith(NDCI_ENC_PREFIX):
        try:
            return json.loads(_decrypt_ndci_blob(raw))
        except Exception as exc:
            logger.error("NDCI decrypt expediente: %s", exc)
            return {}
    return _json_load(raw, {})


def _write_case_file(case_id: str, expediente: dict) -> None:
    case_path = os.path.join(CASES_DIR, f"{case_id}.json")
    with open(case_path, "w", encoding="utf-8") as fh:
        fh.write(_store_expediente(expediente))


def _read_case_file(case_id: str) -> Optional[dict]:
    path = os.path.join(CASES_DIR, f"{case_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return _load_expediente(fh.read())


def _next_ndci_id(db) -> str:
    year = datetime.now().year
    prefix = f"NOVUS-CS-{year}-"
    rows = db.query(NdciCaso.id).filter(NdciCaso.id.like(f"{prefix}%")).all()
    seq = len(rows) + 1
    return f"{prefix}{seq:06d}"


def _user_context(user_email: Optional[str] = None) -> dict:
    ctx = {
        "usuario": user_email or "sistema",
        "equipo": socket.gethostname(),
        "sistema_operativo": f"{platform.system()} {platform.release()}".strip(),
        "sector": None,
        "empresa": None,
    }
    if not user_email:
        return ctx
    db = SessionLocal()
    try:
        u = db.query(Usuario).filter(Usuario.email == user_email.strip().lower()).first()
        if u:
            ctx["sector"] = u.sector
            ctx["empresa"] = u.nit_pyme or u.email.split("@")[-1]
    finally:
        db.close()
    return ctx


def _novus_version() -> str:
    try:
        from core.config import Config
        return getattr(Config, "VERSION", "2.0.0")
    except Exception:
        return "2.0.0"


def _kernel_version() -> str:
    return "Kernel IA NOVUS Fase 1 — SOC/XDR Orchestrator"


def _collect_infrastructure() -> dict:
    inv: dict = {
        "total_dispositivos": 0,
        "computadores": 0,
        "portatiles": 0,
        "servidores": 0,
        "celulares": 0,
        "tablets": 0,
        "impresoras": 0,
        "iot": 0,
        "desconocidos": 0,
        "sistemas_operativos": [],
        "gateways": [],
        "routers": [],
        "switches": [],
        "access_points": [],
        "vlans": [],
        "segmentos_red": [],
        "nota_ausencia": None,
    }
    try:
        from services.platform_metrics_service import build_endpoint_inventory
        endpoints = build_endpoint_inventory()
        inv["total_dispositivos"] = len(endpoints)
        os_set = set()
        for ep in endpoints:
            tipo = (ep.get("tipo") or ep.get("device_type") or "").lower()
            name = (ep.get("nombre") or ep.get("name") or "").lower()
            if "print" in name or "impres" in name:
                inv["impresoras"] += 1
            elif "iot" in tipo or "iot" in name:
                inv["iot"] += 1
            elif "server" in tipo or "servidor" in name:
                inv["servidores"] += 1
            elif "mobile" in tipo or "phone" in name:
                inv["celulares"] += 1
            elif "tablet" in tipo:
                inv["tablets"] += 1
            elif "laptop" in tipo or "portátil" in name or "notebook" in name:
                inv["portatiles"] += 1
            elif ep.get("ip") or ep.get("mac"):
                inv["computadores"] += 1
            else:
                inv["desconocidos"] += 1
            so = ep.get("sistema_operativo") or ep.get("os")
            if so and so not in os_set:
                os_set.add(so)
        inv["sistemas_operativos"] = sorted(os_set) or [platform.system()]
    except Exception as exc:
        inv["nota_ausencia"] = f"Inventario de endpoints no disponible: {exc}"
    try:
        from utils.network_helpers import get_default_gateway
        gw = get_default_gateway()
        if gw:
            inv["gateways"].append(gw)
            inv["routers"].append(gw)
    except Exception:
        pass
    try:
        from services.network_scanner import network_scanner
        meta = network_scanner.get_network_meta() or {}
        if meta.get("network_range"):
            inv["segmentos_red"].append(meta["network_range"])
    except Exception:
        pass
    if inv["total_dispositivos"] == 0:
        inv["nota_ausencia"] = (
            inv.get("nota_ausencia")
            or "No hay dispositivos en inventario; el escáner ARP en background alimentará este dato."
        )
    return inv


def _collect_network_state() -> dict:
    state: dict = {
        "topologia": [],
        "arquitectura": None,
        "salud_general": None,
        "rendimiento": {},
        "latencia_ms": None,
        "velocidad_estimada_mbps": None,
        "consumo_ancho_banda": {},
        "dispositivo_mayor_trafico": None,
        "dispositivo_menor_trafico": None,
        "dispositivos_inactivos": [],
        "dispositivos_nuevos": [],
        "cambios_detectados": [],
    }
    try:
        from services.topology_service import build_topology_payload
        topo = build_topology_payload(force_refresh=False)
        ndr = {"nodes": topo.get("nodes"), "meta": topo.get("meta"), "alerts": topo.get("alerts"),
               "top_traffic": topo.get("top_traffic"), "executive_summary": topo.get("executive_summary")}
        nodes = topo.get("nodes") or []
        meta = topo.get("meta") or {}
        twin = topo.get("digital_twin") or {}
        state["topologia"] = {
            "nodos": len(nodes),
            "conexiones": len(topo.get("connections") or []),
            "categorias": topo.get("categories") or [],
            "digital_twin": twin,
        }
        state["arquitectura"] = meta.get("network_range")
        state["salud_general"] = twin.get("network_health") or (topo.get("executive_summary") or {}).get("network_health")
        alerts = topo.get("alerts") or []
        if alerts:
            state["cambios_detectados"] = [
                f"{a.get('title')}: {a.get('evidence')}" for a in alerts[:10]
            ]
        traffic = []
        for n in nodes:
            t = n.get("traffic") or {}
            sent, recv = t.get("bytes_sent"), t.get("bytes_recv")
            if isinstance(sent, int) or isinstance(recv, int):
                traffic.append({"ip": n.get("ip"), "bytes_total": (sent or 0) + (recv or 0)})
            conn = t.get("connections_active")
            if isinstance(conn, int) and conn > 0:
                traffic.append({"ip": n.get("ip"), "connections": conn, "bytes_total": conn})
        if traffic:
            traffic.sort(key=lambda x: x.get("bytes_total") or x.get("connections") or 0, reverse=True)
            state["dispositivo_mayor_trafico"] = traffic[0]
            state["dispositivo_menor_trafico"] = traffic[-1]
        local = [n for n in nodes if n.get("ip") == meta.get("local_ip")]
        if local:
            t = local[0].get("traffic") or {}
            state["consumo_ancho_banda"] = {
                "bytes_sent": t.get("bytes_sent"),
                "bytes_recv": t.get("bytes_recv"),
                "bandwidth_mbps": t.get("bandwidth_mbps"),
            }
            state["velocidad_estimada_mbps"] = t.get("bandwidth_mbps")
        state["dispositivos_nuevos"] = [n.get("ip") for n in nodes if n.get("is_new")]
        state["dispositivos_inactivos"] = [
            n.get("ip") for n in nodes if not n.get("ip")
        ][:20]
    except Exception as exc:
        state["nota_ausencia"] = f"Telemetría de topología no disponible: {exc}"
    return state


def _collect_security() -> dict:
    sec: dict = {
        "vulnerabilidades": [],
        "puertos_abiertos": [],
        "servicios_expuestos": [],
        "configuraciones_inseguras": [],
        "credenciales_debiles": [],
        "riesgos": [],
        "nota_credenciales": (
            "NOVUS no evalúa contraseñas de usuario sin integración explícita de auditoría de credenciales."
        ),
    }
    try:
        from services.novus_security_integration import novus_security
        from services.vulnerability_analyst_service import enrich_findings
        vulns = enrich_findings(novus_security.scan_vulnerabilities())
        sec["vulnerabilidades"] = [
            {
                "id": v.get("id"),
                "nombre": v.get("nombre"),
                "impacto": v.get("impacto_nivel"),
                "confianza": v.get("confianza_porcentaje"),
                "evidencia": v.get("fuente_evidencia") or v.get("evidencia"),
                "riesgo": v.get("impacto_potencial"),
            }
            for v in vulns[:30]
        ]
        threats = novus_security.detect_threats_realtime()
        for p in threats.get("open_ports") or []:
            sec["puertos_abiertos"].append(p if isinstance(p, dict) else {"port": p})
        for sp in threats.get("suspicious_processes") or []:
            sec["riesgos"].append({
                "tipo": "proceso_sospechoso",
                "nombre": sp.get("name"),
                "pid": sp.get("pid"),
                "evidencia": sp.get("description") or sp.get("command_line"),
            })
    except Exception as exc:
        sec["error"] = str(exc)
    return sec


def _classify_threats(findings: List[dict], collected: dict) -> dict:
    result = {cat: [] for cat in THREAT_CATEGORIES}
    result["_sin_evidencia"] = {}

    keywords_map = {
        "malware": ("malware", "virus", "trojan", "worm"),
        "ransomware": ("ransom", "encrypt", "cifrado"),
        "fuerza_bruta": ("brute", "fuerza bruta", "login fail"),
        "credential_stuffing": ("credential", "stuffing", "ato"),
        "movimiento_lateral": ("lateral", "pivot", "smb"),
        "exfiltracion": ("exfil", "upload", "transfer"),
        "ataques_api": ("api abuse", "api shield", "sqli"),
        "accesos_no_autorizados": ("unauthorized", "acceso no", "intrusion"),
        "trafico_sospechoso": ("suspicious connection", "tráfico", "traffic"),
        "comportamiento_anomalo": ("anomal", "anomaly", "unusual"),
    }

    all_text_items = []
    for f in findings:
        blob = " ".join(str(f.get(k, "")) for k in ("title", "name", "reason", "description", "threat_type", "tipo"))
        all_text_items.append((blob.lower(), f))

    sec = collected.get("security") or {}
    for sp in sec.get("suspicious_processes") or []:
        all_text_items.append((str(sp).lower(), sp))

    for cat, kws in keywords_map.items():
        matched = []
        for text, item in all_text_items:
            if any(k in text for k in kws):
                matched.append(item)
        if matched:
            result[cat] = matched[:10]
        else:
            result["_sin_evidencia"][cat] = NO_EVIDENCE_MSG

    return result


def _collect_adaptive_defense(user_email: Optional[str]) -> dict:
    try:
        from services.adaptive_defense_engine import adaptive_defense
        panel = adaptive_defense.get_adaptive_defense_panel(user_email)
        return {
            "estado": panel.get("estado_actual"),
            "contenciones": panel.get("contenciones_activas", 0),
            "acciones": panel.get("acciones_recientes") or panel.get("historial") or [],
            "detalle": panel,
        }
    except Exception as exc:
        return {"estado": "No disponible", "error": str(exc), "acciones": []}


def _build_timeline(
    started_at: datetime,
    finished_at: datetime,
    deep_report: Optional[dict],
    adaptive: dict,
    extra_events: Optional[List[dict]] = None,
) -> List[dict]:
    timeline = [
        {
            "timestamp": started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "evento": "Inicio del análisis",
            "detalle": deep_report.get("query") if deep_report else "Operación Kernel IA / SOC",
        }
    ]
    if deep_report:
        for f in deep_report.get("findings") or []:
            timeline.append({
                "timestamp": finished_at.strftime("%Y-%m-%d %H:%M:%S"),
                "evento": f"Detección: {f.get('title', f.get('name', 'Hallazgo'))}",
                "detalle": f.get("reason") or f.get("description") or "",
            })
    for act in adaptive.get("acciones") or []:
        if isinstance(act, dict):
            timeline.append({
                "timestamp": act.get("fecha") or act.get("timestamp") or finished_at.strftime("%Y-%m-%d %H:%M:%S"),
                "evento": f"Adaptive Defense: {act.get('accion') or act.get('evento', 'Acción')}",
                "detalle": act.get("detalle") or act.get("detail") or "",
            })
    for ev in extra_events or []:
        timeline.append(ev)
    timeline.append({
        "timestamp": finished_at.strftime("%Y-%m-%d %H:%M:%S"),
        "evento": "Finalización",
        "detalle": "Expediente NDCI generado con telemetría verificada.",
    })
    return timeline


def _prioritize_recommendations(findings: List[dict], vulns: List[dict]) -> dict:
    recs = {"criticas": [], "altas": [], "medias": [], "bajas": []}
    for f in findings:
        risk = str(f.get("risk") or f.get("riesgo") or "").upper()
        text = f.get("recommendation") or f.get("reason") or f.get("title") or ""
        if not text:
            continue
        entry = {"motivo": text, "hallazgo_id": f.get("id")}
        if "CRIT" in risk:
            recs["criticas"].append(entry)
        elif "HIGH" in risk or "ALTO" in risk:
            recs["altas"].append(entry)
        elif "LOW" in risk or "BAJO" in risk:
            recs["bajas"].append(entry)
        else:
            recs["medias"].append(entry)
    for v in vulns[:10]:
        nivel = str(v.get("impacto") or v.get("impacto_nivel") or "").upper()
        for act in v.get("acciones_cliente") or v.get("acciones_novus") or []:
            entry = {"motivo": act, "vulnerabilidad_id": v.get("id")}
            if "CRIT" in nivel:
                recs["criticas"].append(entry)
            elif "ALTO" in nivel or "HIGH" in nivel:
                recs["altas"].append(entry)
            else:
                recs["medias"].append(entry)
    return recs


def _build_executive_summary(exp: dict) -> str:
    """Síntesis operativa solo desde datos del expediente — sin generación ficticia."""
    iden = exp.get("identificacion") or {}
    sec = exp.get("seguridad") or {}
    threats = exp.get("amenazas") or {}
    metrics = exp.get("metricas") or {}
    ade = exp.get("adaptive_defense") or {}
    lines = [
        f"Análisis NDCI {iden.get('id')} completado en {iden.get('duracion')} para el sector {iden.get('sector') or 'N/D'}.",
        f"NOVUS analizó {metrics.get('dispositivos', 0)} dispositivo(s), "
        f"{metrics.get('vulnerabilidades', 0)} vulnerabilidad(es) y "
        f"{metrics.get('eventos', 0)} evento(s) registrados.",
    ]
    vuln_n = len(sec.get("vulnerabilidades") or [])
    if vuln_n:
        lines.append(f"Se documentaron {vuln_n} vulnerabilidad(es) con evidencia de motores reales.")
    else:
        lines.append("No se registraron vulnerabilidades activas en el ciclo analizado.")
    detected_threats = sum(len(threats.get(c) or []) for c in THREAT_CATEGORIES if c in threats)
    if detected_threats:
        lines.append(f"Evidencia de amenazas categorizadas: {detected_threats} indicador(es).")
    else:
        lines.append("No se categorizó evidencia de amenazas avanzadas en este ciclo.")
    if ade.get("contenciones"):
        lines.append(f"Adaptive Defense ejecutó {ade.get('contenciones')} contención(es).")
    lines.append(f"Nivel de riesgo general: {exp.get('nivel_riesgo')}. Estado final: {exp.get('estado_final')}.")
    return " ".join(lines)


def _build_kernel_analysis(exp: dict) -> dict:
    findings = []
    for sec in ("seguridad", "amenazas", "infraestructura", "red"):
        block = exp.get(sec) or {}
        if isinstance(block, dict):
            for k, v in block.items():
                if v and k not in ("nota_ausencia", "nota_credenciales", "_sin_evidencia", "error"):
                    findings.append(f"{sec}.{k}")
    return {
        "conclusiones_tecnicas": [
            f"Expediente basado en fuentes: {', '.join(exp.get('fuentes') or [])}.",
            _build_executive_summary(exp),
        ],
        "lecciones_aprendidas": exp.get("resumen_ejecutivo", ""),
        "observaciones": exp.get("metricas", {}),
        "recomendaciones": exp.get("recomendaciones", {}),
        "prioridades": [
            r.get("motivo") for r in (exp.get("recomendaciones") or {}).get("criticas", [])[:3]
        ],
    }


def build_expedient(
    user_email: Optional[str],
    origen: str,
    source_ref: Optional[str],
    deep_scan_report: Optional[dict] = None,
    collected: Optional[dict] = None,
    message: Optional[str] = None,
    elapsed_sec: Optional[float] = None,
    engines: Optional[List[str]] = None,
    started_at: Optional[datetime] = None,
    finished_at: Optional[datetime] = None,
) -> dict:
    """Construye expediente NDCI completo desde telemetría real."""
    _ensure_dirs()
    ctx = _user_context(user_email)
    started = started_at or datetime.now()
    finished = finished_at or datetime.now()
    elapsed = elapsed_sec if elapsed_sec is not None else (finished - started).total_seconds()
    collected = dict(collected or {})

    if deep_scan_report:
        collected.setdefault("deep_scan", deep_scan_report)
        collected.setdefault("findings", deep_scan_report.get("findings") or [])

    findings = list(collected.get("findings") or [])
    if deep_scan_report and not findings:
        findings = deep_scan_report.get("findings") or []

    infra = _collect_infrastructure()
    red = _collect_network_state()
    sec = _collect_security()
    threats = _classify_threats(findings, collected)
    adaptive = _collect_adaptive_defense(user_email)

    try:
        from services.platform_metrics_service import get_platform_counters
        counters = get_platform_counters()
    except Exception:
        counters = {}

    try:
        from services.system_monitor import system_monitor
        sys_m = system_monitor.get_system_status()
    except Exception:
        sys_m = {}

    risk = (deep_scan_report or {}).get("risk_level") or collected.get("risk_level") or "MEDIO"
    if sec.get("vulnerabilidades"):
        top = sec["vulnerabilidades"][0].get("impacto", "")
        if "CRIT" in str(top).upper():
            risk = "CRITICO"
        elif "ALTO" in str(top).upper() and risk not in ("CRITICO",):
            risk = "ALTO"

    stats = (deep_scan_report or {}).get("stats") or {}
    timeline = _build_timeline(started, finished, deep_scan_report, adaptive)
    recommendations = _prioritize_recommendations(findings, sec.get("vulnerabilidades") or [])

    expediente = {
        "identificacion": {
            "id": None,
            "fecha": finished.strftime("%Y-%m-%d"),
            "hora": finished.strftime("%H:%M:%S"),
            "duracion": f"{round(elapsed, 1)}s",
            "duracion_sec": round(elapsed, 2),
            "usuario": ctx.get("usuario"),
            "sector": ctx.get("sector"),
            "empresa": ctx.get("empresa"),
            "equipo": ctx.get("equipo"),
            "sistema_operativo": ctx.get("sistema_operativo"),
            "novus_version": _novus_version(),
            "kernel_version": _kernel_version(),
            "origen": origen,
            "source_ref": source_ref,
            "consulta": message or (deep_scan_report or {}).get("query"),
        },
        "resumen_ejecutivo": "",
        "infraestructura": infra,
        "red": red,
        "seguridad": sec,
        "amenazas": threats,
        "timeline": timeline,
        "adaptive_defense": adaptive,
        "kernel_ia": {},
        "recomendaciones": recommendations,
        "metricas": {
            "cpu_pct": sys_m.get("cpu"),
            "ram_pct": sys_m.get("ram"),
            "tiempo_analisis_sec": round(elapsed, 2),
            "modulos_ejecutados": len(engines or []),
            "eventos": len(timeline),
            "dispositivos": infra.get("total_dispositivos") or counters.get("endpoints_total"),
            "vulnerabilidades": len(sec.get("vulnerabilidades") or []),
            "incidentes": counters.get("incidents_total") or 0,
            "acciones_automaticas": len(adaptive.get("acciones") or []),
            "deep_scan_stats": stats,
        },
        "evidencias": {
            "hallazgos": findings[:50],
            "logs": collected.get("audit_logs") or [],
            "hashes": [h for f in findings for h in ([f.get("hash")] if f.get("hash") else [])],
            "indicadores": engines or [],
        },
        "fuentes": list(dict.fromkeys([
            "platform_metrics_service",
            "network_ndr_service",
            "novus_security_integration",
            "vulnerability_analyst_service",
            "adaptive_defense_engine",
            *(["deep_scan_engine"] if deep_scan_report else []),
        ])),
        "nivel_riesgo": risk,
        "estado_final": "Documentado" if findings or sec.get("vulnerabilidades") else "Sin hallazgos críticos",
        "motores": engines or (deep_scan_report or {}).get("engines_used") or [],
    }
    expediente["resumen_ejecutivo"] = _build_executive_summary(expediente)
    expediente["kernel_ia"] = _build_kernel_analysis(expediente)
    manual_meta = collected.get("manual_meta") or {}
    if manual_meta:
        expediente["identificacion"].update(manual_meta)
    if collected.get("device_focus"):
        expediente["foco_dispositivo"] = collected["device_focus"]
    if collected.get("vulnerability_focus"):
        expediente["foco_vulnerabilidad"] = collected["vulnerability_focus"]
    if collected.get("incident_focus"):
        expediente["foco_incidente"] = collected["incident_focus"]
    if collected.get("compare_with"):
        expediente["comparacion_referencia"] = collected["compare_with"]
    return expediente


def finalize_expedient(expediente: dict, case_id: str) -> dict:
    """Enriquece expediente con secciones profesionales (topología, predicción, cumplimiento…)."""
    from services.ndci_expedient_sections import enrich_expedient_sections
    return enrich_expedient_sections(expediente, case_id)


def _persist_knowledge(case_id: str, expediente: dict):
    """Alimenta base de conocimiento técnica del Kernel (evidencia, no conversaciones)."""
    _ensure_dirs()
    record = {
        "case_id": case_id,
        "fecha": expediente.get("identificacion", {}).get("fecha"),
        "sector": expediente.get("identificacion", {}).get("sector"),
        "nivel_riesgo": expediente.get("nivel_riesgo"),
        "vulnerabilidades": len((expediente.get("seguridad") or {}).get("vulnerabilidades") or []),
        "lecciones": expediente.get("kernel_ia", {}).get("conclusiones_tecnicas"),
        "recomendaciones_criticas": (expediente.get("recomendaciones") or {}).get("criticas"),
        "source_ref": expediente.get("identificacion", {}).get("source_ref"),
    }
    with open(KNOWLEDGE_FILE, "a", encoding="utf-8") as fh:
        plain = json.dumps(record, ensure_ascii=False, default=str)
        fh.write(_encrypt_ndci_blob(plain) + "\n")


class NdciService:
    """Gestión de casos de estudio NDCI — almacenamiento inmutable."""

    def _manual_title(
        self,
        analysis_type: str,
        device_ip: Optional[str] = None,
        vulnerability_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        compare_case_id: Optional[str] = None,
    ) -> str:
        label = MANUAL_ANALYSIS_TYPES.get(analysis_type, analysis_type)
        fecha = datetime.now().strftime("%Y-%m-%d")
        if analysis_type == "dispositivo" and device_ip:
            return f"Caso manual — Dispositivo {device_ip} — {fecha}"
        if analysis_type == "vulnerabilidad" and vulnerability_id:
            return f"Caso manual — Vulnerabilidad {vulnerability_id} — {fecha}"
        if analysis_type == "incidente" and incident_id:
            return f"Caso manual — Incidente {incident_id} — {fecha}"
        if analysis_type == "comparacion" and compare_case_id:
            return f"Caso manual — Comparación vs {compare_case_id} — {fecha}"
        return f"Caso manual — {label} — {fecha}"

    def _prepare_manual_analysis(
        self,
        analysis_type: str,
        user_email: Optional[str] = None,
        device_ip: Optional[str] = None,
        vulnerability_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        compare_case_id: Optional[str] = None,
        custom_message: Optional[str] = None,
    ) -> Tuple[dict, List[str], str]:
        """Recopila telemetría real según el tipo de análisis manual."""
        collected: dict = {
            "manual_meta": {
                "modalidad": "manual",
                "tipo_analisis": analysis_type,
                "tipo_analisis_label": MANUAL_ANALYSIS_TYPES.get(analysis_type, analysis_type),
            },
        }
        engines: List[str] = ["platform_metrics_service"]
        message = custom_message or MANUAL_ANALYSIS_TYPES.get(analysis_type, "Análisis manual NDCI")

        force_network = analysis_type in (
            "estado_red", "auditoria_completa", "dispositivo",
            "infraestructura_completa", "comparacion", "personalizado",
        )

        if force_network:
            try:
                from services.network_ndr_service import build_ndr_payload
                ndr = build_ndr_payload(force_refresh=True)
                collected["ndr_snapshot"] = ndr
                collected["findings"] = list(collected.get("findings") or [])
                for alert in (ndr.get("alerts") or [])[:20]:
                    collected["findings"].append({
                        "title": alert.get("title"),
                        "description": alert.get("evidence"),
                        "ip": alert.get("ip"),
                        "motor": alert.get("motor"),
                    })
                engines.extend(["network_ndr_service", "topology_service", "network_scanner"])
            except Exception as exc:
                collected["ndr_error"] = str(exc)

        if analysis_type in ("infraestructura_completa", "auditoria_completa", "personalizado"):
            engines.append("platform_metrics_service")

        if analysis_type == "auditoria_completa":
            try:
                from services.novus_security_integration import novus_security
                from services.vulnerability_analyst_service import enrich_findings
                vulns = enrich_findings(novus_security.scan_vulnerabilities())
                collected["security"] = {"vulnerabilities": vulns}
                collected["findings"] = list(collected.get("findings") or []) + [
                    {"title": v.get("nombre"), "description": v.get("evidencia"), "id": v.get("id")}
                    for v in vulns[:15]
                ]
                engines.append("novus_security_integration")
            except Exception as exc:
                collected["security_error"] = str(exc)
            try:
                from services.threat_intelligence_service import threat_intelligence
                collected["incidents_snapshot"] = threat_intelligence.list_cases(limit=20)
                engines.append("threat_intelligence_service")
            except Exception:
                pass

        if analysis_type == "dispositivo":
            if not device_ip:
                raise ValueError("Se requiere la IP del dispositivo para este tipo de análisis.")
            try:
                from services.network_ndr_service import investigate_device, get_device_detail
                inv = investigate_device(device_ip)
                if inv.get("status") == "success":
                    collected["device_focus"] = inv
                    collected["findings"] = list(collected.get("findings") or [])
                    for alert in (inv.get("device") or {}).get("alerts") or []:
                        collected["findings"].append(alert)
                    engines.append("advanced_detector.scan_open_ports")
                else:
                    detail = get_device_detail(device_ip)
                    if detail.get("status") != "success":
                        raise ValueError(detail.get("message") or f"Dispositivo {device_ip} no encontrado.")
                    collected["device_focus"] = detail
                message = f"Análisis manual del dispositivo {device_ip}"
            except ValueError:
                raise
            except Exception as exc:
                raise ValueError(f"No se pudo analizar el dispositivo {device_ip}: {exc}") from exc

        if analysis_type == "vulnerabilidad":
            if not vulnerability_id:
                raise ValueError("Se requiere el ID de la vulnerabilidad.")
            try:
                from services.novus_security_integration import novus_security
                from services.vulnerability_analyst_service import enrich_findings
                vulns = enrich_findings(novus_security.scan_vulnerabilities())
                selected = next((v for v in vulns if str(v.get("id")) == str(vulnerability_id)), None)
                if not selected:
                    raise ValueError(f"Vulnerabilidad {vulnerability_id} no encontrada en el último escaneo.")
                collected["vulnerability_focus"] = selected
                collected["findings"] = [selected]
                collected["security"] = {"vulnerabilities": [selected]}
                engines.append("vulnerability_analyst_service")
                message = f"Análisis manual de vulnerabilidad {vulnerability_id}: {selected.get('nombre')}"
            except ValueError:
                raise
            except Exception as exc:
                raise ValueError(f"Error al analizar vulnerabilidad: {exc}") from exc

        if analysis_type == "incidente":
            if not incident_id:
                raise ValueError("Se requiere el ID del incidente.")
            try:
                from services.threat_intelligence_service import threat_intelligence
                incidents = threat_intelligence.list_cases(limit=50) or []
                selected = next(
                    (c for c in incidents if str(c.get("id")) == str(incident_id)),
                    None,
                )
                if not selected:
                    raise ValueError(f"Incidente {incident_id} no encontrado.")
                collected["incident_focus"] = selected
                collected["findings"] = [{
                    "title": selected.get("titulo") or selected.get("nombre"),
                    "description": selected.get("descripcion") or selected.get("resumen"),
                    "id": selected.get("id"),
                }]
                engines.append("threat_intelligence_service")
                message = f"Análisis manual del incidente {incident_id}"
            except ValueError:
                raise
            except Exception as exc:
                raise ValueError(f"Error al analizar incidente: {exc}") from exc

        if analysis_type == "comparacion":
            if not compare_case_id:
                raise ValueError("Se requiere el ID del caso de referencia para comparar.")
            ref = self.get_case(compare_case_id)
            if not ref:
                raise ValueError(f"Caso de referencia {compare_case_id} no encontrado.")
            collected["compare_with"] = {
                "id": ref.get("id"),
                "titulo": ref.get("titulo"),
                "fecha": ref.get("fecha"),
                "nivel_riesgo": ref.get("nivel_riesgo"),
                "expediente_resumen": (ref.get("expediente") or {}).get("resumen_ejecutivo"),
            }
            message = f"Análisis manual comparativo con caso {compare_case_id}"

        if analysis_type == "personalizado" and custom_message:
            message = custom_message.strip()

        collected["manual_meta"]["parametros"] = {
            k: v for k, v in {
                "device_ip": device_ip,
                "vulnerability_id": vulnerability_id,
                "incident_id": incident_id,
                "compare_case_id": compare_case_id,
            }.items() if v
        }
        return collected, list(dict.fromkeys(engines)), message

    def _attach_manual_comparison(self, new_case_id: str, reference_case_id: str) -> None:
        """Persiste comparación explícita entre caso nuevo y caso de referencia."""
        comparison = self.compare_cases(reference_case_id, new_case_id)
        db = SessionLocal()
        try:
            row = db.query(NdciCaso).filter(NdciCaso.id == new_case_id).first()
            if not row:
                return
            exp = _json_load(row.expediente_json, {})
            exp["comparacion_manual"] = comparison
            exp["comparacion_historica"] = {
                "caso_anterior": reference_case_id,
                "fecha_anterior": comparison.get("caso_a"),
                "riesgo_anterior": comparison.get("riesgo_a"),
                "riesgo_actual": comparison.get("riesgo_b"),
                "vulns_anterior": comparison.get("vulns_a"),
                "vulns_actual": comparison.get("vulns_b"),
                "dispositivos_anterior": comparison.get("dispositivos_a"),
                "dispositivos_actual": comparison.get("dispositivos_b"),
                "diferencia_riesgo": comparison.get("diferencia_riesgo"),
                "nota": f"Comparación manual solicitada contra {reference_case_id}",
            }
            row.expediente_json = _store_expediente(exp)
            row.keywords = (row.keywords or "") + f" comparacion {reference_case_id}"
            db.commit()
            _write_case_file(new_case_id, exp)
        except Exception as exc:
            db.rollback()
            logger.warning("NDCI manual comparison attach: %s", exc)
        finally:
            db.close()

    def create_manual_case(
        self,
        analysis_type: str,
        user_email: Optional[str] = None,
        device_ip: Optional[str] = None,
        vulnerability_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        compare_case_id: Optional[str] = None,
        custom_message: Optional[str] = None,
    ) -> dict:
        """Genera un caso de estudio manual con el mismo expediente profesional que los automáticos."""
        if analysis_type not in MANUAL_ANALYSIS_TYPES:
            raise ValueError(f"Tipo de análisis no válido: {analysis_type}")

        started = datetime.now()
        collected, engines, message = self._prepare_manual_analysis(
            analysis_type=analysis_type,
            user_email=user_email,
            device_ip=device_ip,
            vulnerability_id=vulnerability_id,
            incident_id=incident_id,
            compare_case_id=compare_case_id,
            custom_message=custom_message,
        )
        elapsed = (datetime.now() - started).total_seconds()

        case = self.create_case(
            user_email=user_email,
            origen="manual",
            source_ref=f"MANUAL-{analysis_type.upper()}",
            collected=collected,
            message=message,
            elapsed_sec=elapsed,
            engines=engines,
            titulo=self._manual_title(
                analysis_type, device_ip, vulnerability_id, incident_id, compare_case_id
            ),
        )

        if analysis_type == "comparacion" and compare_case_id and case:
            self._attach_manual_comparison(case["id"], compare_case_id)
            case = self.get_case(case["id"])

        return case

    def get_manual_options(self) -> dict:
        """Opciones reales para el asistente de creación manual."""
        options: dict = {
            "analysis_types": [
                {"id": k, "label": v} for k, v in MANUAL_ANALYSIS_TYPES.items()
            ],
            "devices": [],
            "vulnerabilities": [],
            "incidents": [],
            "cases": self.list_cases(limit=30),
        }
        try:
            from services.topology_service import build_topology_payload
            topo = build_topology_payload(force_refresh=False)
            options["devices"] = [
                {
                    "ip": n.get("ip"),
                    "label": f"{n.get('ip')} — {n.get('device_type') or 'Dispositivo'} ({n.get('risk_label') or n.get('risk_level')})",
                    "mac": n.get("mac"),
                }
                for n in (topo.get("nodes") or []) if n.get("ip")
            ]
        except Exception as exc:
            options["devices_error"] = str(exc)
        try:
            from services.novus_security_integration import novus_security
            from services.vulnerability_analyst_service import enrich_findings
            vulns = enrich_findings(novus_security.scan_vulnerabilities())
            options["vulnerabilities"] = [
                {
                    "id": v.get("id"),
                    "label": f"[{v.get('id')}] {v.get('nombre')} — {v.get('impacto_nivel')}",
                }
                for v in vulns[:40]
            ]
        except Exception as exc:
            options["vulnerabilities_error"] = str(exc)
        try:
            from services.threat_intelligence_service import threat_intelligence
            options["incidents"] = [
                {
                    "id": c.get("id"),
                    "label": f"[{c.get('id')}] {c.get('titulo') or c.get('nombre') or 'Incidente'}",
                }
                for c in (threat_intelligence.list_cases(limit=30) or [])
            ]
        except Exception as exc:
            options["incidents_error"] = str(exc)
        return options

    def create_case(
        self,
        user_email: Optional[str] = None,
        origen: str = "kernel_op",
        source_ref: Optional[str] = None,
        deep_scan_report: Optional[dict] = None,
        collected: Optional[dict] = None,
        message: Optional[str] = None,
        elapsed_sec: Optional[float] = None,
        engines: Optional[List[str]] = None,
        titulo: Optional[str] = None,
    ) -> dict:
        expediente = build_expedient(
            user_email=user_email,
            origen=origen,
            source_ref=source_ref,
            deep_scan_report=deep_scan_report,
            collected=collected,
            message=message,
            elapsed_sec=elapsed_sec,
            engines=engines,
        )
        db = SessionLocal()
        try:
            case_id = _next_ndci_id(db)
            expediente["identificacion"]["id"] = case_id
            expediente = finalize_expedient(expediente, case_id)
            iden = expediente["identificacion"]
            keywords = " ".join(filter(None, [
                case_id, origen, source_ref, iden.get("sector"), iden.get("usuario"),
                expediente.get("nivel_riesgo"), titulo or "",
            ]))

            row = NdciCaso(
                id=case_id,
                fecha=iden["fecha"],
                hora=iden["hora"],
                usuario=iden.get("usuario"),
                sector=iden.get("sector"),
                origen=origen,
                source_ref=source_ref,
                titulo=titulo or f"Caso de estudio {origen} — {iden['fecha']}",
                nivel_riesgo=expediente.get("nivel_riesgo", "MEDIO"),
                duracion_sec=str(iden.get("duracion_sec", "")),
                expediente_json=_store_expediente(expediente),
                keywords=keywords,
                created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
            db.add(row)
            db.commit()

            _write_case_file(case_id, expediente)

            try:
                from services.ndci_pdf import generate_ndci_pdf
                pdf_path = generate_ndci_pdf(expediente)
                row.pdf_path = pdf_path
                db.commit()
            except Exception as pdf_exc:
                logger.warning("NDCI PDF: %s", pdf_exc)

            _persist_knowledge(case_id, expediente)
            try:
                from services.kernel_memory import log_operation
                log_operation({
                    "type": "ndci_case_created",
                    "case_id": case_id,
                    "origen": origen,
                    "risk": expediente.get("nivel_riesgo"),
                })
            except Exception:
                pass

            return self.get_case(case_id)
        except Exception as exc:
            db.rollback()
            logger.error("NDCI create_case: %s", exc, exc_info=True)
            raise
        finally:
            db.close()

    def create_from_scan(
        self,
        scan_id: Optional[str] = None,
        operation_id: Optional[str] = None,
        user_email: Optional[str] = None,
        message: Optional[str] = None,
    ) -> dict:
        deep_report = None
        elapsed = None
        engines = None
        collected: dict = {}
        if scan_id:
            from services.deep_scan_engine import deep_scan_engine
            deep_report = deep_scan_engine.get_report(scan_id)
            st = deep_scan_engine.get_status(scan_id) or {}
            elapsed = st.get("elapsed_sec")
            engines = deep_report.get("engines_used") if deep_report else None
            collected["findings"] = (deep_report or {}).get("findings") or []
            collected["deep_scan"] = deep_report
        if operation_id:
            from services.kernel_coordinator import kernel_coordinator
            result = kernel_coordinator.get_result(operation_id) or {}
            collected.update(result.get("data_snapshot") or {})
            engines = engines or result.get("engines_executed")
            elapsed = elapsed or result.get("elapsed_sec")
        return self.create_case(
            user_email=user_email,
            origen="deep_scan" if scan_id else "kernel_op",
            source_ref=scan_id or operation_id,
            deep_scan_report=deep_report,
            collected=collected,
            message=message,
            elapsed_sec=elapsed,
            engines=engines,
            titulo=f"Deep Scan — {scan_id}" if scan_id else f"Operación Kernel — {operation_id}",
        )

    def get_case(self, case_id: str) -> Optional[dict]:
        db = SessionLocal()
        try:
            row = db.query(NdciCaso).filter(NdciCaso.id == case_id).first()
            if not row:
                return _read_case_file(case_id)
            exp = _load_expediente(row.expediente_json)
            return {
                "id": row.id,
                "fecha": row.fecha,
                "hora": row.hora,
                "usuario": row.usuario,
                "sector": row.sector,
                "origen": row.origen,
                "source_ref": row.source_ref,
                "titulo": row.titulo,
                "nivel_riesgo": row.nivel_riesgo,
                "duracion_sec": row.duracion_sec,
                "pdf_path": row.pdf_path,
                "created_at": row.created_at,
                "expediente": exp,
            }
        finally:
            db.close()

    def list_cases(
        self,
        limit: int = 50,
        sector: Optional[str] = None,
        q: Optional[str] = None,
    ) -> List[dict]:
        db = SessionLocal()
        try:
            query = db.query(NdciCaso).order_by(NdciCaso.created_at.desc())
            if sector:
                query = query.filter(NdciCaso.sector.contains(sector))
            if q:
                query = query.filter(NdciCaso.keywords.contains(q))
            rows = query.limit(limit).all()
            return [
                {
                    "id": r.id,
                    "fecha": r.fecha,
                    "hora": r.hora,
                    "titulo": r.titulo,
                    "sector": r.sector,
                    "origen": r.origen,
                    "nivel_riesgo": r.nivel_riesgo,
                    "duracion_sec": r.duracion_sec,
                    "pdf_path": r.pdf_path,
                    "created_at": r.created_at,
                }
                for r in rows
            ]
        finally:
            db.close()

    def compare_cases(self, id_a: str, id_b: str) -> dict:
        a = self.get_case(id_a)
        b = self.get_case(id_b)
        if not a or not b:
            return {"error": "Uno o ambos casos no existen"}
        ea = a.get("expediente") or a
        eb = b.get("expediente") or b
        return {
            "caso_a": id_a,
            "caso_b": id_b,
            "riesgo_a": ea.get("nivel_riesgo"),
            "riesgo_b": eb.get("nivel_riesgo"),
            "vulns_a": len((ea.get("seguridad") or {}).get("vulnerabilidades") or []),
            "vulns_b": len((eb.get("seguridad") or {}).get("vulnerabilidades") or []),
            "dispositivos_a": (ea.get("metricas") or {}).get("dispositivos"),
            "dispositivos_b": (eb.get("metricas") or {}).get("dispositivos"),
            "diferencia_riesgo": f"{ea.get('nivel_riesgo')} vs {eb.get('nivel_riesgo')}",
        }

    def answer_kernel_query(self, question: str) -> Optional[str]:
        q = (question or "").lower()
        if not any(k in q for k in ("caso", "ndci", "novus-cs", "estudio", "expediente", "remediación", "remediacion", "aprendimos", "parecido")):
            return None
        m = re.search(r"novus-cs-\d{4}-\d{6}|(\d{4,6})", q, re.I)
        if m:
            cid = m.group(0)
            if not cid.upper().startswith("NOVUS"):
                year = datetime.now().year
                cid = f"NOVUS-CS-{year}-{int(cid):06d}"
            case = self.get_case(cid.upper())
            if case:
                exp = case.get("expediente") or case
                return (
                    f"Expediente {cid} ({case.get('fecha')}):\n"
                    f"Riesgo: {exp.get('nivel_riesgo')}\n"
                    f"{exp.get('resumen_ejecutivo', '')}\n"
                    f"PDF: {case.get('pdf_path') or 'generar desde Casos de Estudio'}"
                )
        if "compar" in q and re.search(r"\d+", q):
            nums = re.findall(r"\d{4,6}", q)
            if len(nums) >= 2:
                year = datetime.now().year
                cmp = self.compare_cases(
                    f"NOVUS-CS-{year}-{int(nums[0]):06d}",
                    f"NOVUS-CS-{year}-{int(nums[1]):06d}",
                )
                return json.dumps(cmp, ensure_ascii=False, indent=2)
        cases = self.list_cases(limit=5)
        if not cases:
            return "No hay casos de estudio NDCI almacenados aún. Complete un Deep Scan y pulse «Crear Caso de Estudio»."
        lines = ["Casos de estudio NDCI recientes:"]
        for c in cases:
            lines.append(f"• {c['id']} — {c['titulo']} ({c['nivel_riesgo']}) — {c['fecha']}")
        return "\n".join(lines)


ndci_service = NdciService()
