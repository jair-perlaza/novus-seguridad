"""
Centro de Inteligencia NOVUS — síntesis operacional.
Convierte datos reales de motores existentes en decisiones accionables.
No inventa datos. No duplica módulos: agrega y relaciona.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from database import Log, PlaybookExecution, SessionLocal
from utils.logger import logger

LEARNING_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "playbook_learning", "records.jsonl"
)

from services.telemetry_resolver import explain, endpoints_monitored, is_absent

NO_DATA = "Sin datos disponibles"  # legado — preferir explain() en nuevas rutas


def _parse_ts(raw: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%H:%M:%S"):
        try:
            return datetime.strptime(raw.strip(), fmt)
        except Exception:
            continue
    return datetime.now()


def _risk_score(level: str) -> int:
    v = (level or "").upper()
    if "CRIT" in v:
        return 4
    if "ALTO" in v or "HIGH" in v:
        return 3
    if "MED" in v:
        return 2
    if "BAJO" in v or "LOW" in v:
        return 1
    return 2


def collect_operational_data(user_email: Optional[str] = None) -> Dict[str, Any]:
    """Agrega fuentes reales existentes — una sola lectura para el panel."""
    from services.performance_cache import get_or_compute
    return get_or_compute(
        f"intel_ops:{user_email or '_'}",
        8.0,
        lambda: _collect_operational_data_uncached(user_email),
    )


def _collect_operational_data_uncached(user_email: Optional[str] = None) -> Dict[str, Any]:
    data: Dict[str, Any] = {"sources": [], "user_email": user_email}

    try:
        from services.platform_metrics_service import get_unified_security_payload, get_platform_counters
        data["security"] = get_unified_security_payload()
        data["counters"] = get_platform_counters()
        data["sources"].append("platform_metrics_service")
    except Exception as exc:
        logger.debug("intel collect security: %s", exc)
        data["security"] = {}
        data["counters"] = {}

    try:
        from services.threat_intelligence_service import threat_intelligence
        data["cases"] = threat_intelligence.list_cases(limit=100)
        data["stats"] = threat_intelligence.stats()
        data["sources"].append("threat_intelligence_service")
    except Exception as exc:
        data["cases"] = []
        data["stats"] = {}

    try:
        from services.playbook_service import list_executions
        data["playbook_executions"] = list_executions(limit=50)
        data["sources"].append("playbook_service")
    except Exception as exc:
        data["playbook_executions"] = []

    try:
        from services.network_event_log import network_event_log
        data["network_events"] = network_event_log.get_recent(40)
        data["sources"].append("network_event_log")
    except Exception as exc:
        data["network_events"] = []

    db = SessionLocal()
    try:
        data["audit_logs"] = [
            {"evento": r.evento, "detalle": r.detalle, "fecha": r.fecha}
            for r in db.query(Log).order_by(Log.id.desc()).limit(40).all()
        ]
        data["sources"].append("database.Log")
    except Exception as exc:
        data["audit_logs"] = []
    finally:
        db.close()

    if os.path.exists(LEARNING_FILE):
        try:
            records = []
            with open(LEARNING_FILE, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
            data["playbook_learning"] = records[-20:]
            data["sources"].append("playbook_learning")
        except Exception:
            data["playbook_learning"] = []
    else:
        data["playbook_learning"] = []

    try:
        from services.adaptive_defense_engine import adaptive_defense
        data["adaptive_defense"] = adaptive_defense.get_adaptive_defense_panel(user_email)
        data["sources"].append("adaptive_defense_engine")
    except Exception as exc:
        logger.debug("collect adaptive defense: %s", exc)

    try:
        from services.adaptive_sector_protection_engine import aspe
        data["sector_protection"] = aspe.get_sector_protection_panel(user_email)
        data["sources"].append("adaptive_sector_protection_engine")
    except Exception as exc:
        logger.debug("collect ASPE: %s", exc)

    return data


def build_executive_summary(data: Dict[str, Any]) -> Dict[str, Any]:
    counters = data.get("counters") or {}
    stats = data.get("stats") or {}
    cases = data.get("cases") or []
    security = data.get("security") or {}
    vulns = security.get("vulnerabilities") or []
    executions = data.get("playbook_executions") or []

    open_cases = [c for c in cases if c.get("estado") in ("abierto", "correlacionado")]
    top_case = max(cases, key=lambda c: _risk_score(c.get("nivel_riesgo", "")), default=None)

    inventory = security.get("endpoint_inventory") or []
    risky_devices = sorted(
        [d for d in inventory if isinstance(d.get("hallazgos"), int) and d["hallazgos"] > 0],
        key=lambda d: d.get("hallazgos", 0),
        reverse=True,
    )[:5]

    if top_case:
        main_problem = f"{top_case.get('tipo', 'Caso')} — {top_case.get('id')} ({top_case.get('nivel_riesgo')})"
        confidence = "Alta" if (top_case.get("evidencia") or {}).get("procesos") or (top_case.get("evidencia") or {}).get("puertos") else "Media"
    elif vulns:
        v0 = vulns[0]
        main_problem = f"{v0.get('id', 'Hallazgo')} — {v0.get('nombre', v0.get('descripcion', 'Vulnerabilidad'))[:80]}"
        confidence = v0.get("confianza") or "Media"
    elif counters.get("threats_total"):
        main_problem = f"{counters.get('threats_total')} indicador(es) de amenaza activos"
        confidence = "Media"
    else:
        main_problem = "Sin hallazgos críticos activos en el último escaneo"
        confidence = "Alta" if security.get("threats", {}).get("last_scan") else "Media"

    overall_risk = "CRITICO" if stats.get("criticos") else (
        "ALTO" if open_cases and _risk_score(open_cases[0].get("nivel_riesgo", "")) >= 3 else (
            "MEDIO" if open_cases or vulns else "BAJO"
        )
    )

    remediations = sum(
        1 for e in executions if e.get("estado") == "exitoso" and any(
            "Remediación" in str(a) for a in (e.get("acciones") or [])
        )
    )

    return {
        "estado_general": "Atención requerida" if open_cases else "Estable",
        "nivel_riesgo": overall_risk,
        "nivel_confianza": confidence,
        "problema_principal": main_problem,
        "incidentes_abiertos": stats.get("abiertos", 0),
        "vulnerabilidades_activas": counters.get("vulnerabilities_total") if counters.get("vulnerabilities_total") is not None else len(vulns),
        "playbooks_ejecutados": len(executions),
        "remediaciones_realizadas": remediations,
        "dispositivos_riesgo": [
            {"nombre": d.get("nombre"), "ip": d.get("ip"), "hallazgos": d.get("hallazgos")}
            for d in risky_devices
        ],
        "dispositivos_criticos": len(risky_devices),
        "amenazas_activas": counters.get("threats_total"),
        "endpoints_monitoreados": counters.get("endpoints_total"),
    }


def build_operational_brief(data: Dict[str, Any]) -> Dict[str, str]:
    summary = build_executive_summary(data)
    cases = data.get("cases") or []
    executions = data.get("playbook_executions") or []
    today = datetime.now().strftime("%Y-%m-%d")
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")

    cases_today = [c for c in cases if c.get("fecha") == today]
    cases_yesterday = [c for c in cases if c.get("fecha") == yesterday]

    auto_actions = []
    for e in executions[:10]:
        auto_actions.extend(e.get("acciones") or [])
    for log in (data.get("audit_logs") or [])[:10]:
        if log.get("evento") in ("playbook_execution", "whatsapp_alert", "email_daily_report"):
            auto_actions.append(log.get("detalle", "")[:100])

    attention = []
    for c in cases:
        if c.get("estado") == "abierto" and _risk_score(c.get("nivel_riesgo", "")) >= 3:
            attention.append(f"{c.get('id')} — {c.get('tipo')} ({c.get('nivel_riesgo')})")
    if summary.get("problema_principal") and not attention:
        attention.append(summary["problema_principal"])

    endpoints_val = summary.get("endpoints_monitoreados")
    endpoints_text = endpoints_monitored(endpoints_val) if endpoints_val is None or endpoints_val == 0 else endpoints_val

    return {
        "que_ocurre": (
            f"NOVUS monitorea {endpoints_text} endpoint(s). "
            f"Riesgo {summary.get('nivel_riesgo')}. "
            f"{summary.get('vulnerabilidades_activas') or 0} vulnerabilidad(es) activa(s), "
            f"{summary.get('incidentes_abiertos') or 0} caso(s) abierto(s)."
        ),
        "mayor_riesgo": summary.get("problema_principal") or explain("no_critical_findings"),
        "cambios_desde_ayer": (
            f"Hoy: {len(cases_today)} caso(s) documentado(s). "
            f"Ayer: {len(cases_yesterday)}. "
            f"Playbooks ejecutados recientes: {len(executions)}."
        ),
        "acciones_automaticas": (
            "; ".join(auto_actions[:5]) if auto_actions else "Ninguna acción automática registrada en el periodo reciente."
        ),
        "requiere_atencion": (
            " · ".join(attention[:4]) if attention else "No hay casos críticos abiertos que requieran acción inmediata."
        ),
    }


def build_global_timeline(data: Dict[str, Any], limit: int = 60) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    for case in data.get("cases") or []:
        for t in case.get("timeline") or []:
            events.append({
                "timestamp": t.get("timestamp", f"{case.get('fecha')} {case.get('hora')}"),
                "evento": t.get("evento", "Evento"),
                "detalle": t.get("detalle", ""),
                "origen": "caso",
                "ref_id": case.get("id"),
                "ref_tipo": "case",
            })

    for ex in data.get("playbook_executions") or []:
        events.append({
            "timestamp": ex.get("fecha", ""),
            "evento": f"Playbook: {ex.get('playbook_nombre', ex.get('playbook_id'))}",
            "detalle": f"{ex.get('estado')} — éxito {ex.get('nivel_exito')} — {ex.get('duracion_seg')}s",
            "origen": "playbook",
            "ref_id": ex.get("id"),
            "ref_tipo": "execution",
        })

    for ev in data.get("network_events") or []:
        if isinstance(ev, dict):
            events.append({
                "timestamp": ev.get("time") or ev.get("timestamp", ""),
                "evento": "Red NOVUS",
                "detalle": ev.get("message") or ev.get("detalle", ""),
                "origen": "network",
                "ref_id": None,
                "ref_tipo": "network",
            })
        elif isinstance(ev, str):
            events.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "evento": "Red NOVUS",
                "detalle": ev,
                "origen": "network",
                "ref_id": None,
                "ref_tipo": "network",
            })

    for log in data.get("audit_logs") or []:
        events.append({
            "timestamp": log.get("fecha", ""),
            "evento": log.get("evento", "Log"),
            "detalle": (log.get("detalle") or "")[:200],
            "origen": "historial",
            "ref_id": None,
            "ref_tipo": "log",
        })

    events.sort(key=lambda e: _parse_ts(str(e.get("timestamp", ""))), reverse=True)
    return events[:limit]


def analyze_patterns(data: Dict[str, Any]) -> Dict[str, Any]:
    cases = data.get("cases") or []
    tipo_counts = Counter(c.get("tipo") for c in cases if c.get("tipo"))
    grupo_counts = Counter(c.get("correlacion_grupo") for c in cases if c.get("correlacion_grupo"))
    equipo_counts = Counter(c.get("equipo") for c in cases if c.get("equipo"))
    proceso_counts: Counter = Counter()
    puerto_counts: Counter = Counter()
    ip_counts: Counter = Counter()

    for c in cases:
        ev = c.get("evidencia") or {}
        for p in ev.get("procesos") or []:
            name = p.get("nombre") if isinstance(p, dict) else str(p)
            if name:
                proceso_counts[name] += 1
        for p in ev.get("puertos") or []:
            port = p.get("port") if isinstance(p, dict) else str(p)
            if port:
                puerto_counts[str(port)] += 1
        for ip in ev.get("ips") or []:
            ip_counts[str(ip)] += 1

    recurrent_vulns = [
        f"{g} ({n} casos)" for g, n in grupo_counts.most_common(5) if n > 1
    ]

    return {
        "ataques_repetitivos": [
            f"{t} — {n} ocurrencia(s)" for t, n in tipo_counts.most_common(5) if n > 1
        ],
        "patrones": [
            f"Correlación {g}: {n} casos" for g, n in grupo_counts.most_common(3) if n > 1
        ],
        "vulnerabilidades_recurrentes": recurrent_vulns or ["Sin grupos de correlación repetidos"],
        "dispositivos_problematicos": [
            f"{eq} — {n} caso(s)" for eq, n in equipo_counts.most_common(5) if n > 1
        ],
        "procesos_frecuentes": [f"{p} ({n})" for p, n in proceso_counts.most_common(5)],
        "puertos_recurrentes": [f"Puerto {p} ({n})" for p, n in puerto_counts.most_common(5)],
        "ips_recurrentes": [f"{ip} ({n})" for ip, n in ip_counts.most_common(5)],
        "cambios_red": [
            ev.get("detalle", str(ev))[:120]
            for ev in (data.get("network_events") or [])[:5]
        ] or ["Sin eventos de red recientes registrados"],
    }


def build_recommendations(data: Dict[str, Any], user_email: Optional[str] = None) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    security = data.get("security") or {}
    vulns = security.get("vulnerabilities") or []

    for v in vulns[:8]:
        fid = v.get("id") or v.get("finding_id") or ""
        sev = (v.get("riesgo") or v.get("severidad") or "MEDIO").upper()
        nombre = v.get("nombre") or v.get("descripcion") or fid
        try:
            from services.vulnerability_analyst_service import enrich_finding
            enriched = enrich_finding(dict(v))
            rem = enriched.get("remediacion_sugerida") or enriched.get("accion_recomendada") or ""
        except Exception:
            rem = v.get("remediacion") or ""

        dificultad = "Alta" if "manual" in str(rem).lower() else "Media"
        tiempo = "30-60 min" if dificultad == "Alta" else "10-20 min"
        impacto = "Alto" if "CRIT" in sev or "ALTO" in sev else "Medio"

        recs.append({
            "prioridad": len(recs) + 1,
            "titulo": f"Remediar {fid}" if fid else f"Atender: {nombre[:60]}",
            "por_que": f"Hallazgo activo detectado por NOVUS: {nombre[:120]}",
            "riesgo_reduce": f"Reduce exposición {sev} en el equipo monitoreado",
            "tiempo_estimado": tiempo,
            "dificultad": dificultad,
            "impacto_esperado": impacto,
            "finding_id": fid,
            "accion": rem[:300] if rem else "Ejecutar remediación desde Vulnerabilidades o un Playbook asociado",
        })

    open_critical = [
        c for c in (data.get("cases") or [])
        if c.get("estado") == "abierto" and _risk_score(c.get("nivel_riesgo", "")) >= 3
    ]
    for c in open_critical[:3]:
        recs.append({
            "prioridad": len(recs) + 1,
            "titulo": f"Revisar caso {c.get('id')}",
            "por_que": c.get("lecciones_aprendidas", {}).get("que_ocurrio") or c.get("tipo", "Caso abierto"),
            "riesgo_reduce": f"Cierre del caso {c.get('nivel_riesgo')} documentado en Inteligencia",
            "tiempo_estimado": "15-30 min",
            "dificultad": "Media",
            "impacto_esperado": "Alto",
            "finding_id": c.get("source_ref"),
            "accion": "Abrir expediente en Centro de Inteligencia y aplicar remediación sugerida",
        })

    if not recs:
        recs.append({
            "prioridad": 1,
            "titulo": "Mantener monitoreo continuo",
            "por_que": "No hay hallazgos activos que requieran remediación inmediata según el último escaneo",
            "riesgo_reduce": "Detección temprana de nuevos indicadores",
            "tiempo_estimado": "Continuo",
            "dificultad": "Baja",
            "impacto_esperado": "Preventivo",
            "finding_id": None,
            "accion": "Ejecutar sincronización periódica y playbooks sectoriales",
        })

    return recs[:3]


def build_trends(data: Dict[str, Any]) -> Dict[str, Any]:
    """Tendencias calculadas solo con historial real — sin predicciones."""
    cases = data.get("cases") or []
    executions = data.get("playbook_executions") or []
    network_events = data.get("network_events") or []
    today = datetime.now().date()

    by_date: Counter = Counter()
    by_week: Counter = Counter()
    for c in cases:
        fd = c.get("fecha") or ""
        by_date[fd] += 1
        try:
            dt = datetime.strptime(fd, "%Y-%m-%d").date()
            days = (today - dt).days
            if days <= 7:
                by_week["ultimos_7_dias"] += 1
            elif days <= 14:
                by_week["7_14_dias"] += 1
        except Exception:
            pass

    equipo_counts: Counter = Counter(c.get("equipo") for c in cases if c.get("equipo"))
    tipo_period = Counter(c.get("tipo") for c in cases if c.get("tipo"))

    vuln_now = (data.get("counters") or {}).get("vulnerabilities_total")
    cases_vuln = sum(1 for c in cases if c.get("tipo") == "vulnerabilidad")

    exec_week = sum(
        1 for e in executions
        if e.get("fecha") and str(e.get("fecha", ""))[:10] >= (today - timedelta(days=7)).strftime("%Y-%m-%d")
    )

    if vuln_now is not None:
        trend_vulns = f"{vuln_now} activa(s) ahora · {cases_vuln} caso(s) documentado(s) en historial"
    else:
        trend_vulns = explain("vuln_scan_pending")

    return {
        "incidentes_por_periodo": [
            {"periodo": "Últimos 7 días", "casos": by_week.get("ultimos_7_dias", 0)},
            {"periodo": "7–14 días", "casos": by_week.get("7_14_dias", 0)},
            {"periodo": "Total historial", "casos": len(cases)},
        ],
        "vulnerabilidades_tendencia": trend_vulns,
        "dispositivos_problematicos": [
            {"equipo": eq, "incidencias": n} for eq, n in equipo_counts.most_common(5)
        ],
        "eventos_red_recientes": len(network_events),
        "playbooks_semana": exec_week,
        "tipos_incidencia": [{"tipo": t, "count": n} for t, n in tipo_period.most_common(5)],
        "serie_diaria": [{"fecha": d, "casos": n} for d, n in sorted(by_date.items())[-14:]],
    }


def build_learning(data: Dict[str, Any], user_email: Optional[str] = None) -> Dict[str, Any]:
    """Conocimiento derivado del historial real — sin IA generativa."""
    cases = data.get("cases") or []
    executions = data.get("playbook_executions") or []
    records = data.get("playbook_learning") or []

    tipo_counts = Counter(c.get("tipo") for c in cases if c.get("tipo"))
    equipo_counts = Counter(c.get("equipo") for c in cases if c.get("equipo"))
    pb_counts = Counter(e.get("playbook_id") for e in executions if e.get("playbook_id"))
    motor_counts: Counter = Counter()
    for c in cases:
        for m in c.get("motores") or []:
            motor_counts[str(m)] += 1
    for e in executions:
        for m in e.get("motores") or []:
            motor_counts[str(m)] += 1

    sector_label = explain("generic")
    try:
        from services.sector_shield_service import resolve_sector_for_user
        from services.sector_profile_service import get_sector_profile, normalize_sector
        sk = normalize_sector(resolve_sector_for_user(user_email))
        sector_label = get_sector_profile(sk).get("label", sk)
    except Exception:
        sector_label = explain("generic")

    return {
        "vulnerabilidades_frecuentes": [
            {"tipo": t, "ocurrencias": n} for t, n in tipo_counts.most_common(5) if t == "vulnerabilidad" or "vuln" in str(t).lower()
        ] or [{"tipo": t, "ocurrencias": n} for t, n in tipo_counts.most_common(3)],
        "dispositivos_incidencias": [{"equipo": eq, "casos": n} for eq, n in equipo_counts.most_common(5)],
        "playbooks_mas_usados": [
            {"id": pid, "ejecuciones": n} for pid, n in pb_counts.most_common(5)
        ],
        "ataques_comunes": [{"tipo": t, "count": n} for t, n in tipo_counts.most_common(5)],
        "motores_mas_activos": [{"motor": m, "usos": n} for m, n in motor_counts.most_common(8)],
        "sector_activo": sector_label,
        "registros_aprendizaje_playbook": len(records),
        "ultimo_aprendizaje": records[-1] if records else None,
        "evidencia": f"Basado en {len(cases)} caso(s), {len(executions)} ejecución(es) playbook y {len(records)} registro(s) de aprendizaje.",
    }


def build_company_status(data: Dict[str, Any], user_email: Optional[str] = None) -> Dict[str, Any]:
    summary = build_executive_summary(data)
    cases = data.get("cases") or []
    counters = data.get("counters") or {}
    security = data.get("security") or {}

    last_incident = None
    for c in cases:
        if c.get("tipo") in ("incidente", "amenaza", "ataque") or c.get("nivel_riesgo") in ("CRITICO", "ALTO"):
            last_incident = {
                "id": c.get("id"),
                "tipo": c.get("tipo"),
                "fecha": f"{c.get('fecha')} {c.get('hora', '')}".strip(),
                "riesgo": c.get("nivel_riesgo"),
            }
            break
    if not last_incident and cases:
        c0 = cases[0]
        last_incident = {"id": c0.get("id"), "tipo": c0.get("tipo"), "fecha": c0.get("fecha"), "riesgo": c0.get("nivel_riesgo")}

    response_times = []
    for c in cases:
        try:
            if c.get("tiempo_respuesta_sec"):
                response_times.append(float(c.get("tiempo_respuesta_sec")))
        except (TypeError, ValueError):
            pass
    for e in data.get("playbook_executions") or []:
        if e.get("duracion_seg"):
            response_times.append(float(e["duracion_seg"]))

    avg_response = round(sum(response_times) / len(response_times), 1) if response_times else None

    protections = []
    try:
        from services.sector_shield_service import resolve_sector_for_user, SECTOR_MOTORS
        from services.sector_profile_service import get_sector_profile
        sector_key = resolve_sector_for_user(user_email)
        profile = get_sector_profile(sector_key)
        protections = list(profile.get("controls") or SECTOR_MOTORS.get(sector_key, []))
    except Exception:
        pass

    return {
        "nivel_seguridad_general": summary.get("estado_general"),
        "nivel_riesgo": summary.get("nivel_riesgo"),
        "nivel_confianza": summary.get("nivel_confianza"),
        "infraestructura": {
            "endpoints": counters.get("endpoints_total"),
            "nodos_red": counters.get("nodes_total"),
        },
        "proteccion_activa": protections[:6] if protections else ["Escaneo continuo NOVUS"],
        "amenazas_activas": counters.get("threats_total"),
        "incidentes_abiertos": summary.get("incidentes_abiertos"),
        "remediaciones_automaticas": summary.get("remediaciones_realizadas"),
        "ultimo_incidente": last_incident,
        "tiempo_promedio_respuesta_seg": avg_response,
        "ransomware_activo": security.get("has_active_ransomware", False),
    }


def get_operational_dashboard(user_email: Optional[str] = None) -> Dict[str, Any]:
    data = collect_operational_data(user_email)
    return {
        "status": "success",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "brief": build_operational_brief(data),
        "executive_summary": build_executive_summary(data),
        "company_status": build_company_status(data, user_email),
        "timeline": build_global_timeline(data),
        "analysis": analyze_patterns(data),
        "trends": build_trends(data),
        "learning": build_learning(data, user_email),
        "recommendations": build_recommendations(data, user_email),
        "adaptive_defense": data.get("adaptive_defense") or _get_adaptive_defense_panel(user_email),
        "sector_protection": data.get("sector_protection") or _get_sector_protection_panel(user_email),
        "sources": data.get("sources", []),
        "stats": data.get("stats", {}),
    }


def _get_adaptive_defense_panel(user_email: Optional[str] = None) -> Dict[str, Any]:
    try:
        from services.adaptive_defense_engine import adaptive_defense
        return adaptive_defense.get_adaptive_defense_panel(user_email)
    except Exception as exc:
        logger.debug("adaptive defense panel: %s", exc)
        return {"motor": "Adaptive Defense Engine", "estado_actual": NO_DATA}


def _get_sector_protection_panel(user_email: Optional[str] = None) -> Dict[str, Any]:
    try:
        from services.adaptive_sector_protection_engine import aspe
        return aspe.get_sector_protection_panel(user_email)
    except Exception as exc:
        logger.debug("ASPE panel: %s", exc)
        return {"motor": "Adaptive Sector Protection Engine", "sector_key": NO_DATA}


def answer_kernel_query(question: str, user_email: Optional[str] = None) -> Optional[str]:
    q = (question or "").lower()
    triggers = (
        "inteligencia", "centro de intel", "threat intel", "qué ocurrió hoy", "que ocurrio hoy",
        "incidente más importante", "incidente mas importante", "qué aprendió", "que aprendio",
        "qué cambió", "que cambio", "esta semana", "dónde debo", "donde debo", "concentrarme",
        "casos abiertos", "mayor riesgo", "revisar primero", "debo revisar",
    )
    if not any(t in q for t in triggers):
        return None

    dash = get_operational_dashboard(user_email)
    brief = dash.get("brief") or {}
    summary = dash.get("executive_summary") or {}

    if "hoy" in q or "ocurrió" in q or "ocurrio" in q:
        return (
            f"Hoy en NOVUS:\n"
            f"• {brief.get('que_ocurre', NO_DATA)}\n"
            f"• Acciones automáticas: {brief.get('acciones_automaticas', NO_DATA)}\n"
            f"• Requiere atención: {brief.get('requiere_atencion', NO_DATA)}"
        )
    if "importante" in q or "mayor riesgo" in q:
        return f"Mayor riesgo actual: {brief.get('mayor_riesgo', NO_DATA)}. Nivel: {summary.get('nivel_riesgo')}."
    if "aprend" in q:
        learning = collect_operational_data(user_email).get("playbook_learning") or []
        if learning:
            last = learning[-1]
            return (
                f"Último aprendizaje registrado (playbook {last.get('playbook_id')}): "
                f"resultado {last.get('resultado')}, éxito {last.get('nivel_exito')}, "
                f"{len(last.get('acciones') or [])} acción(es)."
            )
        return "Sin registros de aprendizaje de playbooks aún. Ejecute playbooks para acumular evidencia."
    if "semana" in q or "cambió" in q or "cambio" in q:
        return brief.get("cambios_desde_ayer", NO_DATA)
    if "concentr" in q or "prioridad" in q or "revisar" in q:
        recs = dash.get("recommendations") or []
        if recs:
            top = recs[0]
            return f"Prioridad: {top.get('titulo')}. {top.get('por_que')} Impacto: {top.get('impacto_esperado')}."
        return brief.get("requiere_atencion", NO_DATA)

    return (
        f"Centro de Inteligencia NOVUS:\n"
        f"• Estado: {summary.get('estado_general')} — Riesgo {summary.get('nivel_riesgo')}\n"
        f"• {summary.get('incidentes_abiertos', 0)} casos abiertos, "
        f"{summary.get('vulnerabilidades_activas', 0)} vulns activas\n"
        f"• Problema principal: {summary.get('problema_principal')}\n"
        f"• Atención: {brief.get('requiere_atencion')}"
    )
