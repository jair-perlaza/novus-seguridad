"""
Secciones profesionales del expediente NDCI — solo telemetría verificable.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

NO_EVIDENCE = "No se detectó evidencia verificable de este tipo en el ciclo analizado."


def _collect_topology_snapshot() -> dict:
    try:
        from services.topology_service import build_topology_payload
        topo = build_topology_payload(force_refresh=False)
        return {
            "timestamp": topo.get("timestamp"),
            "digital_twin": topo.get("digital_twin") or {},
            "connections": topo.get("connections") or [],
            "categories": topo.get("categories") or [],
            "summary": topo.get("summary") or {},
            "nodes_count": len(topo.get("nodes") or []),
            "organizacion": (topo.get("digital_twin") or {}).get("communication_model"),
        }
    except Exception as exc:
        return {"nota_ausencia": f"Topología no disponible: {exc}"}


def build_inventory_table(ndr_nodes: List[dict]) -> List[dict]:
    rows = []
    for n in ndr_nodes:
        conf = n.get("confidence") or {}
        if isinstance(conf, dict) and "score" not in conf:
            conf = {"score": n.get("confidence_score"), "label": n.get("confidence_label")}
        rows.append({
            "nombre": n.get("hostname") or n.get("name") or n.get("ip"),
            "tipo": n.get("device_type"),
            "ip": n.get("ip"),
            "mac": n.get("mac"),
            "sistema_operativo": n.get("os_estimate_short") or "No identificable sin fingerprinting",
            "fabricante": n.get("vendor"),
            "estado": "Desconocido" if n.get("is_unknown") else "Conocido",
            "nivel_riesgo": n.get("risk_level"),
            "confianza": f"{conf.get('label', 'N/A')} ({conf.get('score', '?')}%)",
            "tiempo_conectado": n.get("connected_since") or n.get("first_seen"),
        })
    return rows


def build_network_analysis(red: dict, topo: dict, ndr: dict) -> dict:
    meta = (ndr.get("meta") or {}) if ndr else {}
    nodes = ndr.get("nodes") or []
    top = ndr.get("top_traffic") or []
    exec_sum = ndr.get("executive_summary") or {}

    protocols = set()
    for n in nodes:
        for p in n.get("open_ports") or []:
            svc = (p.get("service") or "").upper()
            if svc:
                protocols.add(svc)

    return {
        "como_funciona": (
            f"Red {meta.get('network_range') or 'local'} con gateway {meta.get('gateway') or 'N/D'}. "
            f"Los dispositivos se descubren por ARP; el host NOVUS ({meta.get('local_ip')}) monitoriza "
            f"conexiones activas vía psutil."
        ),
        "arquitectura": red.get("arquitectura") or meta.get("network_range"),
        "gateway": meta.get("gateway"),
        "segmentacion": meta.get("network_range"),
        "flujo_comunicacion": (topo.get("digital_twin") or {}).get("communication_model"),
        "velocidad_mbps": red.get("velocidad_estimada_mbps"),
        "latencia": "Medida por ICMP solo en hosts que responden al ping del escáner",
        "estabilidad": exec_sum.get("network_health", "Evaluada desde alertas NDR"),
        "consumo_ancho_banda": red.get("consumo_ancho_banda") or {},
        "protocolos_observados": sorted(protocols) or ["Sin puertos identificados en escaneo activo"],
        "dispositivo_mayor_trafico": red.get("dispositivo_mayor_trafico") or (top[0] if top else None),
        "dispositivo_menor_trafico": red.get("dispositivo_menor_trafico"),
        "conexiones_documentadas": len(topo.get("connections") or []),
    }


def build_professional_kernel_analysis(exp: dict) -> dict:
    sec = exp.get("seguridad") or {}
    threats = exp.get("amenazas") or {}
    red = exp.get("red") or {}
    vuln_n = len(sec.get("vulnerabilidades") or [])
    threat_n = sum(len(threats.get(c) or []) for c in threats if not str(c).startswith("_"))

    findings = []
    if vuln_n:
        findings.append(
            f"Se documentaron {vuln_n} vulnerabilidad(es) con evidencia de motores NOVUS. "
            "Impacto: exposición de superficie de ataque en endpoints del segmento analizado."
        )
    else:
        findings.append(
            "No se registraron vulnerabilidades activas en el último ciclo. "
            "Esto indica entorno limpio o escaneo aún en progreso."
        )

    if threat_n:
        findings.append(
            f"Se categorizaron {threat_n} indicador(es) de amenaza. "
            "Requiere validación humana antes de escalar a incidente."
        )

    devices = (exp.get("inventario_completo") or [])
    unknown_n = sum(1 for d in devices if d.get("estado") == "Desconocido")
    if unknown_n:
        findings.append(
            f"{unknown_n} dispositivo(s) desconocido(s) en inventario. "
            "Riesgo: activos no autorizados en la red. Acción: identificar y aprobar o aislar."
        )

    impact = []
    if vuln_n >= 3:
        impact.append("Probabilidad elevada de explotación si no se remedia en 30 días.")
    if unknown_n:
        impact.append("Superficie de ataque ampliada por activos no inventariados.")
    if not impact:
        impact.append("Riesgo contenido según telemetría actual; mantener monitoreo continuo.")

    recommendations = []
    for r in (exp.get("recomendaciones") or {}).get("criticas") or []:
        recommendations.append(r.get("motivo", r))
    if not recommendations:
        recommendations.append("Mantener cadencia de escaneo y revisión de dispositivos desconocidos.")

    return {
        "analista": "Kernel IA NOVUS — síntesis determinística desde expediente",
        "que_encontro": findings,
        "que_significa": (
            f"El análisis cubre {len(devices)} dispositivo(s), segmento {red.get('arquitectura') or 'N/D'}, "
            f"nivel de riesgo general {exp.get('nivel_riesgo')}."
        ),
        "impacto": impact,
        "si_no_se_corrige": (
            "Sin remediación, las vulnerabilidades documentadas permanecen explotables; "
            "los dispositivos desconocidos siguen sin control de acceso verificado."
            if vuln_n or unknown_n else
            "El perfil de riesgo actual es estable; la degradación dependería de nuevos activos o amenazas."
        ),
        "recomendaciones": recommendations[:8],
        "conclusiones_tecnicas": (exp.get("kernel_ia") or {}).get("conclusiones_tecnicas") or [],
    }


def build_prediction(exp: dict) -> dict:
    risk = str(exp.get("nivel_riesgo") or "MEDIO").upper()
    vuln_n = len((exp.get("seguridad") or {}).get("vulnerabilidades") or [])
    unknown_n = sum(1 for d in (exp.get("inventario_completo") or []) if d.get("estado") == "Desconocido")

    base = 25
    if "CRIT" in risk:
        base = 75
    elif "ALTO" in risk:
        base = 55
    elif "MEDIO" in risk:
        base = 35
    base += min(20, vuln_n * 3) + min(15, unknown_n * 5)
    base = min(95, base)

    def _horizon(days: int, factor: float) -> dict:
        score = min(99, int(base * factor))
        return {
            "dias": days,
            "riesgo_estimado_pct": score,
            "nivel": "Alto" if score >= 70 else "Medio" if score >= 40 else "Bajo",
            "base": "Evidencia del expediente: vulnerabilidades, dispositivos desconocidos y nivel de riesgo actual.",
        }

    return {
        "metodologia": "Proyección heurística basada en evidencia del expediente — no predicción ML.",
        "horizontes": {
            "30_dias": _horizon(30, 1.0),
            "90_dias": _horizon(90, 1.15),
            "180_dias": _horizon(180, 1.25),
            "365_dias": _horizon(365, 1.35),
        },
    }


def build_simulations(exp: dict) -> List[dict]:
    layers = [
        "Network NDR (detección ARP y comportamiento)",
        "Adaptive Defense Engine (contención)",
        "Adaptive Sector Protection (ASPE)",
        "Vulnerability Analyst",
        "Threat Intelligence",
    ]
    scenarios = [
        ("ransomware", "Cifrado masivo de archivos", "Adaptive Defense + aislamiento de proceso"),
        ("malware", "Ejecución de código malicioso", "Advanced Detector + terminación de proceso"),
        ("movimiento_lateral", "Propagación SMB/RDP interna", "NDR alertas + bloqueo de puerto"),
        ("fuerza_bruta", "Intentos repetidos de autenticación", "Registro en amenazas + rate limiting sectorial"),
    ]
    vuln_n = len((exp.get("seguridad") or {}).get("vulnerabilidades") or [])
    result = []
    for key, desc, response in scenarios:
        result.append({
            "escenario": key,
            "descripcion": desc,
            "que_ocurriria": (
                f"NOVUS registraría indicadores en amenazas y timeline. "
                f"Con {vuln_n} vulnerabilidad(es) documentada(s), la probabilidad de explotación aumenta."
            ),
            "capas_novus": layers,
            "respuesta_esperada": response,
            "nota": "Simulación basada en capacidades documentadas de motores NOVUS — no ejecución real.",
        })
    return result


def build_compliance(exp: dict) -> dict:
    sec = exp.get("seguridad") or {}
    vuln_n = len(sec.get("vulnerabilidades") or [])
    inv = exp.get("inventario_completo") or []
    unknown_n = sum(1 for d in inv if d.get("estado") == "Desconocido")

    def _check(framework: str, controls: List[str]) -> dict:
        return {
            "marco": framework,
            "controles_evaluados": controls,
            "nota": "Comparación orientativa — NO es certificación oficial ni auditoría acreditada.",
        }

    gaps = []
    if unknown_n:
        gaps.append("Inventario incompleto de activos (A.8.1 ISO / CIS 1)")
    if vuln_n:
        gaps.append(f"{vuln_n} vulnerabilidad(es) sin remediación documentada (A.12.6 ISO)")
    if not gaps:
        gaps.append("Sin brechas críticas documentadas en este ciclo")

    return {
        "disclaimer": "Evaluación técnica orientativa. No constituye certificación ISO 27001, NIST ni CIS.",
        "iso_27001": _check("ISO 27001", ["A.8 Inventario de activos", "A.12 Gestión de vulnerabilidades", "A.16 Gestión de incidentes"]),
        "nist_csf": _check("NIST CSF", ["Identify", "Protect", "Detect", "Respond"]),
        "cis_controls": _check("CIS Controls", ["CIS 1 Inventario", "CIS 7 Gestión de vulnerabilidades", "CIS 13 Monitoreo de red"]),
        "owasp": _check("OWASP", ["Superficie de ataque API/web cuando aplica al segmento analizado"]),
        "brechas_identificadas": gaps,
        "cumplimiento_estimado": "Parcial" if gaps and vuln_n else "Aceptable en ciclo analizado",
    }


def build_historical_comparison(case_id: str, current_exp: dict) -> dict:
    try:
        from services.ndci_service import ndci_service
        cases = ndci_service.list_cases(limit=10)
        prev = next((c for c in cases if c.get("id") != case_id), None)
        if not prev:
            return {"nota": "Primer caso o sin historial previo para comparar."}
        prev_full = ndci_service.get_case(prev["id"])
        pe = (prev_full or {}).get("expediente") or {}
        cur_inv = {d.get("ip") for d in (current_exp.get("inventario_completo") or []) if d.get("ip")}
        prev_inv = {d.get("ip") for d in (pe.get("inventario_completo") or []) if d.get("ip")}
        return {
            "caso_anterior": prev["id"],
            "fecha_anterior": prev.get("fecha"),
            "riesgo_anterior": pe.get("nivel_riesgo"),
            "riesgo_actual": current_exp.get("nivel_riesgo"),
            "mejoro": (
                pe.get("nivel_riesgo") in ("CRITICO", "ALTO") and
                current_exp.get("nivel_riesgo") in ("MEDIO", "BAJO")
            ),
            "empeoro": (
                current_exp.get("nivel_riesgo") in ("CRITICO", "ALTO") and
                pe.get("nivel_riesgo") in ("MEDIO", "BAJO")
            ),
            "dispositivos_nuevos": sorted(cur_inv - prev_inv),
            "dispositivos_desaparecidos": sorted(prev_inv - cur_inv),
            "vulns_anterior": len((pe.get("seguridad") or {}).get("vulnerabilidades") or []),
            "vulns_actual": len((current_exp.get("seguridad") or {}).get("vulnerabilidades") or []),
        }
    except Exception as exc:
        return {"nota": f"Comparación no disponible: {exc}"}


def build_learning(case_id: str, exp: dict) -> dict:
    return {
        "novus_aprendio": [
            f"Inventario de {len(exp.get('inventario_completo') or [])} dispositivo(s) en caso {case_id}",
            f"Patrón de riesgo {exp.get('nivel_riesgo')} en sector {(exp.get('identificacion') or {}).get('sector')}",
        ],
        "kernel_aprendio": (exp.get("kernel_ia") or {}).get("conclusiones_tecnicas") or [],
        "patrones_nuevos": [
            a.get("title") for a in (exp.get("evidencias") or {}).get("hallazgos") or []
            if isinstance(a, dict) and a.get("title")
        ][:10],
        "reglas_derivadas": [
            "Refuerzo de monitoreo en dispositivos desconocidos",
            "Priorización de remediación según impacto de vulnerabilidades",
        ],
        "persistido_en": "data/ndci/knowledge.jsonl",
    }


def enrich_expedient_sections(exp: dict, case_id: Optional[str] = None) -> dict:
    """Añade secciones profesionales al expediente."""
    try:
        from services.network_ndr_service import build_ndr_payload
        ndr = build_ndr_payload(force_refresh=False)
    except Exception:
        ndr = {}

    nodes = ndr.get("nodes") or []
    red = exp.get("red") or {}
    topo = _collect_topology_snapshot()

    exp["topologia"] = topo
    exp["inventario_completo"] = build_inventory_table(nodes)
    exp["analisis_red"] = build_network_analysis(red, topo, ndr)
    exp["analisis_seguridad"] = {
        "vulnerabilidades": (exp.get("seguridad") or {}).get("vulnerabilidades") or [],
        "puertos_abiertos": (exp.get("seguridad") or {}).get("puertos_abiertos") or [],
        "servicios": (exp.get("seguridad") or {}).get("servicios_expuestos") or [],
        "riesgos": (exp.get("seguridad") or {}).get("riesgos") or [],
        "nivel_confianza_promedio": (
            sum(n.get("confidence_score") or 0 for n in nodes) / len(nodes) if nodes else 0
        ),
        "evidencias": (exp.get("evidencias") or {}).get("hallazgos") or [],
    }
    exp["kernel_ia"] = build_professional_kernel_analysis(exp)
    exp["prediccion"] = build_prediction(exp)
    try:
        from services.v1_runtime_surface import ndci_simulations_enabled

        if ndci_simulations_enabled():
            exp["simulaciones"] = build_simulations(exp)
        else:
            exp["simulaciones"] = []
            exp["simulaciones_unavailable"] = (
                "Escenarios what-if no disponibles en runtime de producción — "
                "NOVUS no muestra simulaciones como datos reales."
            )
    except Exception:
        exp["simulaciones"] = []
    exp["cumplimiento"] = build_compliance(exp)
    exp["comparacion_historica"] = build_historical_comparison(case_id or "", exp) if case_id else {}
    exp["aprendizaje"] = build_learning(case_id or "DRAFT", exp)

    iden = exp.get("identificacion") or {}
    exp["resumen_ejecutivo_detallado"] = {
        "objetivo": iden.get("consulta") or "Análisis integral de seguridad y red del entorno NOVUS",
        "infraestructura": f"{len(exp['inventario_completo'])} dispositivo(s) en {(topo.get('summary') or {}).get('segment', 'segmento local')}",
        "nivel_seguridad": exp.get("nivel_riesgo"),
        "conclusion_ejecutiva": exp.get("resumen_ejecutivo"),
        "principales_hallazgos": (exp.get("kernel_ia") or {}).get("que_encontro") or [],
    }
    return exp
