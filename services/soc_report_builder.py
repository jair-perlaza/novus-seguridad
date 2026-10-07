"""
Generador de informes SOC/XDR para el Kernel IA NOVUS.
Transforma datos de motores reales en informes de analista senior.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from services.ai_orchestrator import SOC_INTENTS

# Motores solicitados por el usuario que aún no existen como capacidad independiente
UNIMPLEMENTED_ENGINES = {
    "radar": "Radar de red — requiere desarrollo adicional",
    "virustotal": "VirusTotal API — requiere configuración de clave API",
    "spf_dkim_dmarc": "Validación SPF/DKIM/DMARC completa — requiere desarrollo adicional",
    "dhcp_analyzer": "Analizador DHCP — requiere desarrollo adicional",
    "latency_monitor": "Monitor de latencia — requiere desarrollo adicional",
    "dns_deep": "Análisis DNS profundo — parcial vía network scanner",
    "port_scanner_standalone": "Port Scanner independiente — cubierto por advanced_detector + deep scan",
    "file_scanner_standalone": "File Scanner independiente — cubierto por deep_scan_engine",
    "threat_engine_standalone": "Threat Engine — cubierto por novus_security_integration",
}

INTENT_ENGINE_WISHES = {
    "network_status": ["network.scanner", "traffic.stats", "connections.active", "firewall.ports"],
    "wifi_intrusion": ["network.scanner", "connections.active"],
    "vulnerabilities": ["security.vulnerabilities", "vulnerability.scanner", "security.threats"],
    "malware": ["advanced_detector.malware", "security.threats", "deep_scan.engine"],
    "gmail": ["gmail.analyzer"],
    "full_computer_analysis": ["deep_scan.engine"],
    "enterprise_security": ["deep_scan.engine", "security.sector_shield"],
}


def _risk_from_data(data: dict) -> Tuple[str, int]:
    score = 0
    vulns = data.get("vulnerabilities") or []
    sec = data.get("security") or {}
    sys_d = data.get("system") or {}
    if (sec.get("threat_count") or 0) > 0:
        score += 3
    if len(vulns) > 3:
        score += 2
    elif vulns:
        score += 1
    if sec.get("suspicious_processes"):
        score += 2
    if (sys_d.get("cpu") or 0) > 85:
        score += 1
    if (sys_d.get("ram") or 0) > 90:
        score += 1
    if score >= 5:
        return "ALTO", score
    if score >= 3:
        return "MEDIO", score
    if score >= 1:
        return "BAJO", score
    return "NOMINAL", score


def _vuln_exploit_hint(v: dict) -> str:
    vid = str(v.get("id", "")).upper()
    desc = str(v.get("descripcion", "")).lower()
    if "PROC" in vid or "proceso" in str(v.get("nombre", "")).lower():
        return "Un atacante podría usar este proceso para persistencia, exfiltración o escalada de privilegios."
    if "PORT" in vid or "puerto" in str(v.get("nombre", "")).lower():
        return "Exposición de servicio en red local/LAN; posible pivoting o explotación de servicio vulnerable."
    if "malware" in desc or "sospech" in desc:
        return "Ejecución de código no autorizado; posible robo de credenciales o movimiento lateral."
    return "Vector dependiente del componente afectado; revisar superficie de ataque expuesta."


def _severity_score(item: dict) -> int:
    """Puntuación de impacto para priorización — basada en datos reales del motor."""
    risk = str(item.get("riesgo") or item.get("severidad") or item.get("risk") or "").upper()
    mapping = {"CRITICO": 100, "CRÍTICO": 100, "CRITICAL": 100, "ALTO": 80, "HIGH": 80,
               "MEDIO": 50, "MEDIUM": 50, "BAJO": 25, "LOW": 25, "DETECTADO": 30}
    for k, v in mapping.items():
        if k in risk:
            return v
    vid = str(item.get("id", "")).upper()
    if "PROC" in vid:
        return 70
    if "PORT" in vid:
        return 55
    return 30


def _prioritize_findings(vulns: List[dict], suspicious: List[dict]) -> List[dict]:
    """Ordena hallazgos por impacto — no por orden de aparición."""
    items = []
    for v in vulns or []:
        items.append({**v, "_kind": "vulnerability", "_score": _severity_score(v)})
    for sp in suspicious or []:
        items.append({
            "id": f"PROC-{sp.get('pid')}",
            "nombre": sp.get("name"),
            "descripcion": sp.get("description", sp.get("command_line", "")),
            "riesgo": "ALTO",
            "_kind": "process",
            "_score": 75,
        })
    items.sort(key=lambda x: x.get("_score", 0), reverse=True)
    return items


def _explain_finding(item: dict, risk_level: str) -> List[str]:
    """Explicación profesional: qué, por qué importa, riesgo, impacto, recomendación."""
    kind = item.get("_kind", "vulnerability")
    name = item.get("nombre") or item.get("name") or item.get("id", "Hallazgo")
    lines = [
        f"▸ QUÉ: {name}",
        f"  Por qué importa: {_vuln_exploit_hint(item) if kind == 'vulnerability' else 'Proceso con comportamiento atípico detectado por el motor XDR.'}",
        f"  Riesgo: {item.get('riesgo', item.get('risk', 'EVALUAR'))} | Impacto en postura global: {risk_level}",
        f"  Impacto al cliente: posible degradación de rendimiento, exposición de datos o persistencia de amenaza.",
        f"  Recomendación: {_vuln_remediation(item)}",
        "  Acción automática: disponible solo con política de remediación activa y confirmación del operador.",
        "  Requiere autorización: sí — para terminar procesos o modificar configuración.",
    ]
    return lines


def _vuln_remediation(v: dict) -> str:
    vid = str(v.get("id", "")).upper()
    if "PROC" in vid:
        return "Terminar proceso, verificar ruta y firma digital, escanear con Defender, revisar persistencia."
    if "PORT" in vid:
        return "Cerrar puerto si no es necesario, restringir en firewall, actualizar servicio asociado."
    return v.get("descripcion", "Aplicar parche o hardening según componente afectado.")


def _detect_inconsistencies(data: dict) -> List[str]:
    issues = []
    sec = data.get("security") or {}
    vulns = data.get("vulnerabilities") or []
    net = data.get("network") or {}
    nodes = net.get("nodes") or []
    threat_count = sec.get("threat_count") or 0
    sus = sec.get("suspicious_processes") or []

    if threat_count > 0 and not vulns and not sus:
        issues.append(
            f"Motor XDR reporta {threat_count} amenaza(s) pero no hay vulnerabilidades ni procesos sospechosos en telemetía fusionada."
        )
    if sus and not any("PROC" in str(v.get("id", "")) for v in vulns):
        issues.append(
            f"{len(sus)} proceso(s) sospechoso(s) en detector avanzado no reflejados como hallazgos de vulnerabilidades."
        )
    endpoints = data.get("endpoints") or []
    if nodes and endpoints and abs(len(nodes) - len(endpoints)) > 2:
        issues.append(
            f"Discrepancia de inventario: red={len(nodes)} dispositivos vs endpoints={len(endpoints)}."
        )
    sys_d = data.get("system") or {}
    if (sys_d.get("cpu") or 0) > 90:
        procs = data.get("processes") or []
        if not procs:
            issues.append("CPU crítica (>90%) sin lista de procesos top — datos incompletos para diagnóstico.")
    return issues


def _missing_engine_notes(intent_id: str, executed: List[str]) -> List[str]:
    notes = []
    wished = INTENT_ENGINE_WISHES.get(intent_id, [])
    catalog_labels = executed  # capability ids already executed

    if intent_id in ("network_status", "wifi_intrusion"):
        if "network.scanner" not in catalog_labels:
            notes.append(UNIMPLEMENTED_ENGINES.get("dns_deep", "Network scanner no ejecutado"))
        notes.append(f"NOTA: {UNIMPLEMENTED_ENGINES['radar']}")
        notes.append(f"NOTA: {UNIMPLEMENTED_ENGINES['dhcp_analyzer']}")
        notes.append(f"NOTA: {UNIMPLEMENTED_ENGINES['latency_monitor']}")

    if intent_id == "gmail":
        notes.append(f"NOTA: {UNIMPLEMENTED_ENGINES['spf_dkim_dmarc']}")
        notes.append(f"NOTA: {UNIMPLEMENTED_ENGINES['virustotal']}")

    if intent_id in ("malware", "full_computer_analysis", "deep_scan"):
        notes.append(f"NOTA: {UNIMPLEMENTED_ENGINES['virustotal']}")

    for cap in wished:
        if cap not in catalog_labels and cap != "deep_scan.engine":
            label = cap.replace(".", " / ")
            notes.append(f"Motor '{label}' no ejecutado en este ciclo.")

    return notes


def build_soc_report(
    intent: dict,
    data: dict,
    message: str,
    actions_executed: Optional[List[dict]] = None,
    started_at: Optional[datetime] = None,
    timeline: Optional[List[str]] = None,
    deep_scan_report: Optional[dict] = None,
) -> dict:
    """Construye informe SOC completo a partir de datos reales."""
    actions_executed = actions_executed or []
    timeline = timeline or []
    started_at = started_at or datetime.now()
    finished_at = datetime.now()
    elapsed = (finished_at - started_at).total_seconds()

    pid = intent.get("primary_intent", "general_status")
    caps = data.get("capabilities_executed") or intent.get("capabilities") or []
    modules = data.get("modules_queried") or intent.get("active_modules") or []
    risk_label, risk_score = _risk_from_data(data)

    lines: List[str] = []
    ui_actions: List[dict] = []

    # ── Encabezado ──
    lines.append("╔══════════════════════════════════════════════════════════════╗")
    lines.append("║           INFORME SOC/XDR — KERNEL IA NOVUS                  ║")
    lines.append("╚══════════════════════════════════════════════════════════════╝")
    sector_label = intent.get("sector_label") or data.get("sector_label")
    sector_key = intent.get("sector_key") or data.get("sector_key")
    if sector_label or sector_key:
        lines.append(f"Perfil sectorial: {sector_label or sector_key}")
    lines.append("")

    # ── Resumen ejecutivo ──
    lines.append("═══ RESUMEN EJECUTIVO ═══")
    vulns = data.get("vulnerabilities") or []
    sec = data.get("security") or {}
    net = data.get("network") or {}
    nodes = net.get("nodes") or []
    sus = sec.get("suspicious_processes") or []

    if pid == "vulnerabilities":
        lines.append(
            f"Se identificaron {len(vulns)} vulnerabilidad(es)/hallazgo(s) tras ejecutar motores de seguridad en tiempo real."
        )
    elif pid in ("network_status", "wifi_intrusion"):
        lines.append(
            f"Estado de red: {len(nodes)} dispositivo(s) detectado(s) por escáner ARP activo. "
            f"Nivel de riesgo: {risk_label}."
        )
    elif pid == "malware":
        lines.append(
            f"Análisis antimalware: {len(sus)} indicador(es) de procesos sospechosos, "
            f"{sec.get('threat_count', 0)} amenaza(s) en motor XDR."
        )
    elif pid == "performance_slow":
        sys_d = data.get("system") or {}
        lines.append(
            f"Diagnóstico de rendimiento: CPU {sys_d.get('cpu', 'N/D')}%, RAM {sys_d.get('ram', 'N/D')}%. "
            f"Motores de procesos y memoria ejecutados."
        )
    elif pid == "enterprise_security":
        lines.append(
            f"Evaluación de postura de seguridad empresarial. "
            f"{len(vulns)} hallazgos, {len(nodes)} dispositivos en red, riesgo {risk_label}."
        )
    elif pid == "daily_summary":
        siem = data.get("siem") or {}
        incs = data.get("incidents") or []
        lines.append(
            f"Resumen del día: {siem.get('total', 0)} eventos SIEM/red, "
            f"{len(incs)} incidente(s) registrados."
        )
    else:
        lines.append(
            f"Análisis completado. Intención: {intent.get('primary_label', pid)}. "
            f"Riesgo global: {risk_label} (score {risk_score})."
        )
    lines.append("")

    # ── Objetivo ──
    lines.append("═══ OBJETIVO DEL ANÁLISIS ═══")
    lines.append(f"Consulta del operador: «{message}»")
    lines.append(f"Intención clasificada: {intent.get('primary_label')} [{pid}]")
    if intent.get("secondary_intents"):
        sec_labels = [SOC_INTENTS.get(s, {}).get("label", s) for s in intent["secondary_intents"]]
        lines.append(f"Intenciones secundarias: {', '.join(sec_labels)}")
    lines.append("")

    # ── Motores ejecutados ──
    lines.append("═══ MOTORES EJECUTADOS ═══")
    lines.append(f"Total: {len(caps)} capacidad(es) | Módulos: {', '.join(modules) or 'N/D'}")
    for i, cap in enumerate(caps, 1):
        lines.append(f"  {i}. {cap}")
    done_actions = [a for a in actions_executed if a.get("executed")]
    if done_actions:
        lines.append("Acciones orquestadas:")
        for a in done_actions:
            lines.append(f"  [OK] {a.get('action')}: {a.get('message')}")
    failed = data.get("capabilities_failed") or []
    if failed:
        lines.append(f"Motores con error ({len(failed)}):")
        for f in failed[:5]:
            lines.append(f"  [FAIL] {f.get('id', '?')}: {f.get('error', '')[:80]}")
    lines.append("")

    # ── Cronología ──
    lines.append("═══ CRONOLOGÍA DEL ANÁLISIS ═══")
    lines.append(f"Inicio: {started_at.strftime('%H:%M:%S')} | Fin: {finished_at.strftime('%H:%M:%S')} | Duración: {elapsed:.1f}s")
    if timeline:
        for step in timeline:
            lines.append(f"  → {step}")
    else:
        lines.append("  → Clasificación de intención")
        lines.append("  → Ejecución de motores (force_refresh=True)")
        lines.append("  → Fusión de evidencias")
        lines.append("  → Generación de informe")
    lines.append("")

    # ── Deep scan phases if available ──
    if deep_scan_report:
        lines.append("═══ ANÁLISIS POR FASES (DEEP SCAN) ═══")
        sections = deep_scan_report.get("sections") or {}
        phase_order = [
            ("system", "Fase 1 — Sistema"),
            ("processes", "Fase 2 — Procesos"),
            ("services", "Fase 3 — Servicios"),
            ("network", "Fase 4 — Red"),
            ("files", "Fase 5 — Archivos"),
            ("vulnerabilities", "Fase 6 — Vulnerabilidades"),
            ("threats", "Fase 7 — Amenazas"),
            ("recommendations", "Fase 8 — Recomendaciones"),
        ]
        for key, label in phase_order:
            sec_data = sections.get(key) or {}
            status = sec_data.get("status", "N/D")
            note = sec_data.get("note", "")
            count = sec_data.get("data", {}).get("count") if isinstance(sec_data.get("data"), dict) else None
            extra = f" ({count} elementos)" if count is not None else ""
            lines.append(f"  {label}: {status}{extra}")
            if note and status == "pending":
                lines.append(f"    ↳ {note}")
        lines.append("")

    # ── Resultados detallados ──
    lines.append("═══ RESULTADOS ═══")

    prioritized = _prioritize_findings(vulns, sus)
    if prioritized:
        lines.append("\n▸ HALLAZGOS PRIORIZADOS POR IMPACTO")
        lines.append(f"  Total: {len(prioritized)} (ordenados por severidad, no por aparición)")
        for item in prioritized[:12]:
            vid = item.get("id", "?")
            lines.append("")
            lines.extend(_explain_finding(item, risk_label))
            if item.get("_kind") == "vulnerability":
                ui_actions.append({
                    "label": f"Remediar {vid}",
                    "type": "confirm_remediate",
                    "target_id": vid,
                    "target_type": "vulnerability",
                })
        if len(prioritized) > 12:
            lines.append(f"\n  ... y {len(prioritized) - 12} hallazgo(s) adicional(es). Ver /vulnerabilidades")
        ui_actions.append({"label": "Ver todas las vulnerabilidades", "type": "navigate", "url": "/vulnerabilidades"})
    elif pid in ("vulnerabilities", "malware", "performance_slow"):
        lines.append("\n▸ HALLAZGOS PRIORIZADOS POR IMPACTO")
        lines.append("  No se detectaron hallazgos con evidencia suficiente en los motores ejecutados.")

    if "network" in modules or nodes:
        meta = net.get("meta") or {}
        lines.append("\n▸ RED Y DISPOSITIVOS")
        lines.append(f"  IP local: {meta.get('local_ip', 'N/D')} | Gateway: {meta.get('gateway', 'N/D')}")
        lines.append(f"  Rango: {meta.get('network_range', 'N/D')} | Dispositivos: {len(nodes)}")
        for n in nodes[:12]:
            lines.append(
                f"  • {n.get('ip', '?')} — {n.get('name', n.get('hostname', 'Sin nombre'))} "
                f"MAC {n.get('mac', 'N/D')} [{n.get('vendor', n.get('type', ''))}]"
            )
        if not nodes:
            lines.append("  Sin dispositivos detectados en escaneo ARP actual.")
        ui_actions.append({"label": "Abrir Network", "type": "navigate", "url": "/network"})

    if "traffic" in modules or data.get("traffic"):
        tr = data.get("traffic") or {}
        lines.append("\n▸ TRÁFICO")
        lines.append(
            f"  Recibido: {tr.get('bytes_recv_mb', 'N/D')} MB | "
            f"Enviado: {tr.get('bytes_sent_mb', 'N/D')} MB | "
            f"Conexiones activas: {tr.get('active_connections', 'N/D')}"
        )

    if "processes" in modules or sus:
        procs = data.get("processes") or []
        lines.append("\n▸ PROCESOS")
        if isinstance(procs, list):
            for p in procs[:8]:
                if isinstance(p, dict):
                    lines.append(
                        f"  • PID {p.get('pid')} {p.get('name')} — CPU {p.get('cpu_percent', 0):.1f}% "
                        f"RAM {p.get('memory_percent', p.get('ram_percent', 0)):.1f}%"
                    )
        lines.append(f"  Procesos sospechosos: {len(sus)}")
        for sp in sus[:6]:
            lines.append(
                f"  ⚠ {sp.get('name', '?')} PID {sp.get('pid')} — {sp.get('description', sp.get('reason', ''))[:80]}"
            )

    if "connections" in modules or data.get("connections"):
        conn = data.get("connections") or {}
        lines.append("\n▸ CONEXIONES ACTIVAS")
        lines.append(f"  Establecidas: {conn.get('established', 0)} | Total: {conn.get('total', 0)}")
        samples = conn.get("samples") or conn.get("connections") or []
        for c in (samples[:6] if isinstance(samples, list) else []):
            if isinstance(c, dict):
                lines.append(f"  • {c.get('local', c.get('laddr', '?'))} → {c.get('remote', c.get('raddr', '?'))}")

    ports = (data.get("firewall") or {}).get("open_ports") or sec.get("open_ports") or []
    if ports or "firewall" in modules:
        lines.append("\n▸ PUERTOS / FIREWALL")
        lines.append(f"  Puertos abiertos detectados: {len(ports)}")
        for p in ports[:8]:
            lines.append(f"  • Puerto {p.get('port')} — {p.get('description', p.get('service', ''))}")

    if "gmail" in modules or data.get("gmail"):
        gm = data.get("gmail") or {}
        stats = gm.get("stats") or {}
        conn = gm.get("connection") or {}
        lines.append("\n▸ CORREO (Gmail Analyzer)")
        lines.append(f"  OAuth configurado: {conn.get('oauth_configured', False)}")
        lines.append(
            f"  Analizados: {stats.get('total_analyzed', 0)} | "
            f"Seguros: {stats.get('safe', 0)} | Sospechosos: {stats.get('suspicious', 0)} | "
            f"Maliciosos: {stats.get('malicious', 0)}"
        )
        lines.append(f"  NOTA: {UNIMPLEMENTED_ENGINES['spf_dkim_dmarc']}")
        lines.append(f"  NOTA: {UNIMPLEMENTED_ENGINES['virustotal']}")

    if "siem" in modules or data.get("siem"):
        siem = data.get("siem") or {}
        audit = siem.get("audit_logs") or []
        net_ev = siem.get("network_events") or []
        lines.append("\n▸ SIEM / EVENTOS DEL DÍA")
        lines.append(f"  Fecha: {siem.get('date', 'N/D')} | Total eventos: {siem.get('total', 0)}")
        for log in audit[:8]:
            lines.append(f"  • [{log.get('fecha')}] {log.get('evento')}: {str(log.get('detalle', ''))[:60]}")
        for ev in net_ev[:5]:
            if isinstance(ev, dict):
                lines.append(f"  • Red: {ev.get('type', ev.get('event', 'evento'))} — {str(ev.get('detail', ev.get('message', '')))[:50]}")

    if "playbooks" in modules or data.get("playbooks"):
        pbs = data.get("playbooks")
        if isinstance(pbs, dict):
            pbs = pbs.get("playbooks", [])
        pbs = pbs or []
        lines.append(f"\n▸ PLAYBOOKS / AUTOMATIZACIÓN ({len(pbs)} configurados)")
        for pb in (pbs[:5] if isinstance(pbs, list) else []):
            if isinstance(pb, dict):
                lines.append(f"  • {pb.get('id', '?')}: {pb.get('nombre', 'N/D')} [{pb.get('estado', '')}]")

    sys_d = data.get("system") or {}
    if sys_d and pid not in ("network_status", "daily_summary"):
        lines.append("\n▸ SISTEMA (contexto operativo)")
        lines.append(
            f"  CPU: {sys_d.get('cpu', 'N/D')}% | RAM: {sys_d.get('ram', 'N/D')}% | "
            f"Disco: {sys_d.get('disk', 'N/D')}%"
        )

    lines.append("")

    # ── Hallazgos ──
    lines.append("═══ HALLAZGOS ═══")
    findings = []
    if vulns:
        findings.append(f"{len(vulns)} vulnerabilidades/hallazgos")
    if sus:
        findings.append(f"{len(sus)} procesos sospechosos")
    if sec.get("threat_count"):
        findings.append(f"{sec.get('threat_count')} amenazas XDR")
    if ports and len(ports) > 5:
        findings.append(f"{len(ports)} puertos expuestos")
    lines.append("  " + ("; ".join(findings) if findings else "Sin hallazgos críticos en este ciclo."))

    inconsistencies = _detect_inconsistencies(data)
    if inconsistencies:
        lines.append("\n▸ INCONSISTENCIAS DETECTADAS")
        for inc in inconsistencies:
            lines.append(f"  ⚠ {inc}")

    missing = _missing_engine_notes(pid, caps)
    gaps = data.get("gaps") or []
    if missing or gaps:
        lines.append("\n▸ CAPACIDADES NO DISPONIBLES / DATOS FALTANTES")
        for m in missing:
            lines.append(f"  ! {m}")
        for g in gaps[:5]:
            lines.append(f"  ! {g}")

    lines.append("")
    lines.append(f"═══ NIVEL DE RIESGO: {risk_label} (score {risk_score}/10) ═══")
    lines.append("")

    # ── Evidencias ──
    lines.append("═══ EVIDENCIAS ═══")
    lines.append(f"  Timestamp recolección: {data.get('collected_at', 'N/D')}")
    lines.append(f"  Motores con datos: {len(caps)}")
    if deep_scan_report:
        summary = deep_scan_report.get("summary") or {}
        lines.append(
            f"  Deep Scan: {summary.get('processes', 0)} procesos, {summary.get('files', 0)} archivos, "
            f"{summary.get('threats', 0)} amenazas"
        )
    lines.append("")

    # ── Recomendaciones ──
    lines.append("═══ RECOMENDACIONES ═══")
    if vulns:
        lines.append("  → Priorizar remediación de hallazgos críticos en /vulnerabilidades")
    if sus:
        lines.append("  → Investigar procesos sospechosos en /amenazas (XDR)")
    if len(nodes) > 10:
        lines.append("  → Validar dispositivos desconocidos en la red")
    if not findings:
        lines.append("  → Mantener monitorización continua y programar Deep Scan periódico")
    lines.append("")

    # ── Acciones sugeridas ──
    lines.append("═══ ACCIONES SUGERIDAS ═══")
    kernel_actions = []
    if vulns:
        kernel_actions.append("Remediar hallazgos (requiere confirmación)")
        lines.append("  • Remediar hallazgos individuales — botones disponibles abajo")
    if sus:
        kernel_actions.append("Analizar procesos sospechosos en XDR")
        lines.append("  • Analizar procesos sospechosos en módulo XDR")
    if pid in ("network_status", "wifi_intrusion"):
        kernel_actions.append("Re-escaneo ARP bajo demanda")
        lines.append("  • Re-escaneo de red ARP disponible")
    lines.append("  • Generar informe formal en /reportes")
    lines.append("  • Deep Scan integral: «Escanea mi portátil»")
    lines.append("")

    # UI actions dedupe
    seen = set()
    unique_actions = []
    for a in ui_actions:
        key = (a.get("type"), a.get("url"), a.get("target_id"), a.get("label"))
        if key not in seen:
            seen.add(key)
            unique_actions.append(a)
    unique_actions.extend([
        {"label": "XDR / Amenazas", "type": "navigate", "url": "/amenazas"},
        {"label": "Reportes", "type": "navigate", "url": "/reportes"},
    ])

    return {
        "reply": "\n".join(lines),
        "actions": unique_actions[:12],
        "confirm_required": False,
        "risk_level": risk_label,
        "risk_score": risk_score,
        "modules_used": modules,
        "capabilities_used": caps,
        "primary_intent": pid,
        "inconsistencies": inconsistencies,
        "kernel_actions": kernel_actions,
        "data_snapshot": {
            "risk_score": risk_score,
            "modules": modules,
            "capabilities": caps,
            "vuln_count": len(vulns),
            "device_count": len(nodes),
            "threat_count": sec.get("threat_count", 0),
        },
    }
