"""
Transforma informes persistidos (JSON completo) en vista ejecutiva legible.
Los datos crudos se conservan en almacenamiento; aquí solo se proyectan campos humanos.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

NO_EVIDENCE = "Sin evidencia verificable."

INTERNAL_KEYS = frozenset({
    "learning_summary",
    "trust_factors",
    "classification_reason",
    "confidence_score",
    "confidence_label",
    "admin_action",
    "asset_status_label",
    "response_time_ms",
    "times_seen",
    "first_seen",
    "last_seen",
    "trust_score",
    "trust_display",
    "is_pending_approval",
    "requires_attention",
    "is_unknown",
    "is_known",
    "known_label",
    "admin_tag",
    "network_segment",
    "risk_color",
    "traffic",
    "recent_change",
    "connected_since",
    "open_ports_count",
    "vulnerabilities_count",
    "status_display",
    "asset_status",
    "is_new",
    "online",
})

FORBIDDEN_UI_PATTERNS = (
    re.compile(r"^\s*\{"),
    re.compile(r"^\s*\[\s*[\{'\"]"),
    re.compile(r"'\w+'\s*:\s*"),
    re.compile(r"\blearning_summary\b"),
    re.compile(r"\btrust_factors\b"),
    re.compile(r"\bclassification_reason\b"),
    re.compile(r"\bconfidence_score\b"),
    re.compile(r"\bconfidence_label\b"),
    re.compile(r"\badmin_action\b"),
    re.compile(r"\basset_status_label\b"),
    re.compile(r"\bresponse_time_ms\b"),
    re.compile(r"\btimes_seen\b"),
    re.compile(r"\bfirst_seen\b"),
    re.compile(r"\blast_seen\b"),
    re.compile(r"\[object Object\]"),
)


def audit_presentation_leaks(presentation: dict) -> Optional[str]:
    """Recorre valores de texto de la vista ejecutiva buscando fugas prohibidas."""

    def walk(obj: Any) -> Optional[str]:
        if isinstance(obj, dict):
            for v in obj.values():
                hit = walk(v)
                if hit:
                    return hit
            return None
        if isinstance(obj, list):
            for v in obj:
                hit = walk(v)
                if hit:
                    return hit
            return None
        if isinstance(obj, str):
            return presentation_has_forbidden_leak(obj)
        return None

    return walk(presentation)


def presentation_has_forbidden_leak(text: str) -> Optional[str]:
    """Devuelve el motivo si el texto parece filtrar estructura interna."""
    if not text:
        return None
    sample = text if len(text) < 8000 else text[:8000]
    for pat in FORBIDDEN_UI_PATTERNS:
        if pat.search(sample):
            return pat.pattern
    return None


def _clean_label(value: Any, fallback: str = "—") -> str:
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return fallback
    s = str(value).strip()
    if not s or s in ("{}", "[]"):
        return fallback
    if s.startswith("{") or s.startswith("["):
        return fallback
    return s


def _normalize_severity(raw: Any) -> str:
    s = _clean_label(raw, "Medio").lower()
    if "crit" in s or "crít" in s:
        return "Crítico"
    if "high" in s or "alto" in s or "alta" in s:
        return "Alto"
    if "med" in s:
        return "Medio"
    if "low" in s or "bajo" in s or "baja" in s:
        return "Bajo"
    if "info" in s or "detect" in s:
        return "Informativo"
    return _clean_label(raw, "Medio")


def _priority_bucket(severity: str) -> str:
    sev = _normalize_severity(severity)
    if sev in ("Crítico", "Alto"):
        return "alta"
    if sev == "Medio":
        return "media"
    return "baja"


def _split_datetime(fecha: Any) -> Tuple[str, str]:
    raw = _clean_label(fecha, "—")
    if " " in raw:
        parts = raw.split(" ", 1)
        return parts[0], parts[1][:8] if len(parts) > 1 else "—"
    return raw, "—"


def _humanize_evidence(item: Any) -> str:
    if item is None:
        return ""
    if isinstance(item, str):
        t = item.strip()
        if t.startswith("{") or t.startswith("["):
            return ""
        return t
    if isinstance(item, dict):
        parts = []
        for key in (
            "title", "nombre", "descripcion", "description", "evidence", "evidencia",
            "event", "evento", "detail", "detalle", "service", "puerto", "port",
        ):
            if key in item and item[key] not in (None, "", {}):
                val = item[key]
                if isinstance(val, dict):
                    sub = _humanize_evidence(val)
                    if sub:
                        parts.append(sub)
                elif not isinstance(val, (list, dict)):
                    parts.append(f"{key.replace('_', ' ').title()}: {val}")
        if "puerto" in item or "port" in item:
            p = item.get("puerto") or item.get("port")
            svc = item.get("service") or item.get("descripcion") or ""
            if p:
                parts.append(f"Puerto {p} ({svc})".strip())
        return "; ".join(dict.fromkeys(parts)) if parts else ""
    if isinstance(item, list):
        bits = [_humanize_evidence(x) for x in item[:5]]
        return "; ".join(b for b in bits if b)
    return _clean_label(item, "")


def _device_row(node: dict) -> dict:
    name = (
        node.get("hostname")
        or node.get("name")
        or node.get("ip")
        or "Dispositivo de red"
    )
    os_guess = node.get("os_estimate_short") or node.get("os") or node.get("sistema_operativo")
    if os_guess and "No identificable" in str(os_guess):
        os_guess = "No identificado en este escaneo"
    return {
        "nombre": _clean_label(name),
        "ip": _clean_label(node.get("ip")),
        "mac": _clean_label(node.get("mac")),
        "tipo": _clean_label(node.get("device_type") or node.get("type") or "Dispositivo"),
        "estado": _clean_label(node.get("status") or node.get("estado") or "Detectado"),
        "sistema_operativo": _clean_label(os_guess, "No identificado"),
        "fabricante": _clean_label(node.get("vendor"), "No identificado"),
    }


def _port_row(port: dict, host_ip: str = "") -> dict:
    pnum = port.get("port") or port.get("puerto") or "—"
    svc = port.get("service") or port.get("servicio") or "Servicio no identificado"
    desc = port.get("description") or port.get("descripcion") or f"Puerto {pnum} en {host_ip or 'equipo'}"
    risk = _normalize_severity(port.get("risk") or port.get("riesgo") or port.get("risk_level"))
    return {
        "puerto": str(pnum),
        "servicio": _clean_label(svc),
        "estado": _clean_label(port.get("status") or port.get("estado") or "Abierto"),
        "nivel_riesgo": risk,
        "descripcion": _clean_label(desc),
    }


def _vuln_row(v: dict, default_host: str = "") -> dict:
    name = v.get("nombre") or v.get("title") or v.get("tipo_vulnerabilidad") or "Hallazgo de seguridad"
    desc = (
        v.get("descripcion_sencilla")
        or v.get("descripcion")
        or v.get("description")
        or v.get("descripcion_tecnica")
        or NO_EVIDENCE
    )
    sev = _normalize_severity(
        v.get("impacto_nivel") or v.get("severidad") or v.get("riesgo") or v.get("risk")
    )
    host = v.get("ip") or v.get("equipo") or default_host or "—"
    ev = v.get("evidencia") or v.get("evidence") or v.get("evidencias")
    ev_text = _humanize_evidence(ev)
    if not ev_text and isinstance(v.get("evidencias"), list):
        ev_text = "; ".join(_humanize_evidence(x) for x in v["evidencias"] if _humanize_evidence(x))
    recs = v.get("acciones_cliente") or v.get("recomendaciones") or v.get("recommendation")
    if isinstance(recs, list):
        rec = recs[0] if recs else NO_EVIDENCE
    else:
        rec = recs or NO_EVIDENCE
    return {
        "nombre": _clean_label(name),
        "descripcion": _clean_label(desc),
        "criticidad": sev,
        "equipo": _clean_label(host),
        "evidencias": ev_text or NO_EVIDENCE,
        "recomendacion": _clean_label(rec),
    }


def _collect_devices(report: dict) -> List[dict]:
    devices: List[dict] = []
    seen_ips = set()

    sections = report.get("sections") or {}
    red = sections.get("red") or {}
    for node in red.get("nodos") or []:
        if not isinstance(node, dict):
            continue
        row = _device_row(node)
        ip = row.get("ip")
        if ip and ip in seen_ips:
            continue
        if ip:
            seen_ips.add(ip)
        devices.append(row)

    if not devices:
        host = report.get("equipo_afectado")
        tech = report.get("technical") or {}
        ip = None
        for key in ("recursos_afectados", "evidencias"):
            for item in tech.get(key) or []:
                if isinstance(item, str) and re.match(r"^\d+\.\d+\.\d+\.\d+", item):
                    ip = item
                    break
        if host or ip:
            devices.append({
                "nombre": _clean_label(host or ip),
                "ip": _clean_label(ip, "—"),
                "mac": "—",
                "tipo": _clean_label(tech.get("tipo_vulnerabilidad") or report.get("tipo")),
                "estado": _clean_label(report.get("estado") or tech.get("estado")),
                "sistema_operativo": "No identificado",
                "fabricante": "No identificado",
            })
    return devices


def _collect_ports(report: dict) -> List[dict]:
    ports: List[dict] = []
    sections = report.get("sections") or {}
    for node in (sections.get("red") or {}).get("nodos") or []:
        if not isinstance(node, dict):
            continue
        ip = _clean_label(node.get("ip"), "")
        for p in node.get("open_ports") or []:
            if isinstance(p, dict):
                ports.append(_port_row(p, ip))

    tech = report.get("technical") or {}
    fid = report.get("finding_id") or ""
    if "PORT" in str(fid).upper():
        for ev in tech.get("evidencias") or []:
            text = _humanize_evidence(ev)
            if "puerto" in text.lower() or "port" in text.lower():
                m = re.search(r"(\d{1,5})", text)
                ports.append({
                    "puerto": m.group(1) if m else "—",
                    "servicio": _clean_label(tech.get("tipo_vulnerabilidad")),
                    "estado": "Abierto",
                    "nivel_riesgo": _normalize_severity(report.get("severidad")),
                    "descripcion": text,
                })
    return ports


def _collect_vulnerabilities(report: dict) -> List[dict]:
    vulns: List[dict] = []
    seen = set()

    def add(v: dict, host: str = "") -> None:
        row = _vuln_row(v, host)
        key = (row["nombre"], row["equipo"])
        if key in seen:
            return
        seen.add(key)
        vulns.append(row)

    sections = report.get("sections") or {}
    for node in (sections.get("red") or {}).get("nodos") or []:
        if not isinstance(node, dict):
            continue
        ip = _clean_label(node.get("ip"), "")
        for v in node.get("vulnerabilities") or []:
            if isinstance(v, dict):
                add(v, ip)

    for block_key in ("vulnerabilidades", "incidentes"):
        block = sections.get(block_key)
        if isinstance(block, dict):
            for v in block.get("items") or block.get("lista") or []:
                if isinstance(v, dict):
                    add(v)
            text_list = block.get("detalle") or block.get("hallazgos")
            if isinstance(text_list, list):
                for v in text_list:
                    if isinstance(v, dict):
                        add(v)

    for d in report.get("technical_details") or []:
        if isinstance(d, dict):
            add(d)

    tech = report.get("technical") or {}
    for h in tech.get("hallazgos") or []:
        if isinstance(h, dict):
            add(h)

    if not vulns and report.get("tipo") != "Centro de Defensa":
        add({
            "nombre": tech.get("tipo_vulnerabilidad") or report.get("tipo"),
            "descripcion_sencilla": tech.get("que_ocurrio") or report.get("resumen_ejecutivo"),
            "impacto_nivel": report.get("severidad"),
            "ip": report.get("equipo_afectado"),
            "evidencias": tech.get("evidencias"),
            "acciones_cliente": tech.get("recomendaciones"),
        })

    return vulns[:50]


def _collect_evidences(report: dict) -> List[str]:
    out: List[str] = []
    tech = report.get("technical") or {}

    for item in tech.get("evidencias") or []:
        h = _humanize_evidence(item)
        if h and h not in out:
            out.append(h)

    for v in _collect_vulnerabilities(report)[:15]:
        if v.get("evidencias") and v["evidencias"] != NO_EVIDENCE:
            out.append(f"{v['nombre']}: {v['evidencias']}")

    for d in report.get("technical_details") or []:
        if isinstance(d, dict):
            h = _humanize_evidence(d.get("evidencia") or d.get("descripcion"))
            if h:
                out.append(h)

    return out[:25] or [NO_EVIDENCE]


def _collect_recommendations(report: dict, vulns: List[dict]) -> Dict[str, List[str]]:
    buckets: Dict[str, List[str]] = {"alta": [], "media": [], "baja": []}

    def push(text: Any, severity: str = "Medio") -> None:
        t = _clean_label(text, "")
        if not t or t == NO_EVIDENCE:
            return
        b = _priority_bucket(severity)
        if t not in buckets[b]:
            buckets[b].append(t)

    tech = report.get("technical") or {}
    for r in tech.get("recomendaciones") or tech.get("pasos_correccion") or []:
        push(r, report.get("severidad") or tech.get("severidad"))
    for r in tech.get("recomendaciones_opcionales") or []:
        push(r, "Bajo")

    exec_sum = report.get("executive_summary") or {}
    if exec_sum.get("recomendacion_principal"):
        push(exec_sum["recomendacion_principal"], report.get("severidad") or "Alto")

    cover = report.get("cover") or {}
    if cover.get("resumen_ejecutivo_breve"):
        pass  # ya en resumen; no duplicar como recomendación

    for v in vulns:
        push(v.get("recomendacion"), v.get("criticidad"))

    for d in report.get("technical_details") or []:
        if isinstance(d, dict):
            for r in d.get("recomendaciones") or []:
                push(r, d.get("riesgo") or d.get("severidad"))

    dr = report.get("defense_report") or {}
    kernel = dr.get("kernel_analysis") or report.get("kernel_analysis") or {}
    for r in kernel.get("recommendations") or kernel.get("recomendaciones") or []:
        push(r, "Alto")

    if not any(buckets.values()):
        buckets["media"].append("Revise el informe con su equipo de seguridad y aplique las acciones sugeridas por NOVUS.")
    return buckets


def _kernel_analysis_block(report: dict, vulns: List[dict], ports: List[dict], devices: List[dict]) -> dict:
    tech = report.get("technical") or {}
    exec_sum = report.get("executive_summary") or {}
    cover = report.get("cover") or {}

    what = (
        cover.get("resumen_ejecutivo_breve")
        or exec_sum.get("texto_ejecutivo")
        or report.get("resumen_ejecutivo")
        or tech.get("que_ocurrio")
        or NO_EVIDENCE
    )

    dr = report.get("defense_report") or {}
    kernel = dr.get("kernel_analysis") or report.get("kernel_analysis") or {}
    if kernel.get("summary"):
        what = _clean_label(kernel.get("summary"), what)

    meaning_parts = []
    if devices:
        meaning_parts.append(
            f"Se analizaron {len(devices)} dispositivo(s) en la red supervisada."
        )
    if ports:
        meaning_parts.append(
            f"Se identificaron {len(ports)} puerto(s) expuesto(s) que amplían la superficie de ataque."
        )
    if vulns:
        meaning_parts.append(
            f"Se documentaron {len(vulns)} hallazgo(s) de seguridad con evidencia verificable."
        )
    meaning = " ".join(meaning_parts) if meaning_parts else (
        tech.get("descripcion_sencilla") or tech.get("impacto_potencial") or NO_EVIDENCE
    )

    risks = []
    top = vulns[0] if vulns else None
    if top:
        risks.append(f"Prioridad {top['criticidad']}: {top['nombre']} en {top['equipo']}.")
    elif ports:
        risks.append(f"Exposición de servicios en puertos {', '.join(p['puerto'] for p in ports[:5])}.")
    else:
        risks.append(_clean_label(tech.get("consecuencias") or tech.get("impacto_potencial"), NO_EVIDENCE))

    priority = _normalize_severity(
        report.get("severidad")
        or exec_sum.get("nivel_seguridad")
        or cover.get("nivel_seguridad")
        or tech.get("riesgo_sistema")
    )

    actions = []
    for bucket, label in (("alta", "Alta"), ("media", "Media"), ("baja", "Baja")):
        recs = _collect_recommendations(report, vulns).get(bucket) or []
        for r in recs[:3]:
            actions.append(f"[{label}] {r}")

    return {
        "titulo": "Análisis del Kernel IA",
        "que_encontro": _clean_label(what),
        "que_significa": _clean_label(meaning),
        "riesgos": risks[:8] or [NO_EVIDENCE],
        "prioridad": priority,
        "acciones_recomendadas": actions[:12] or [NO_EVIDENCE],
    }


def _scan_summary(report: dict, devices: List[dict], ports: List[dict], vulns: List[dict]) -> dict:
    sections = report.get("sections") or {}
    red = sections.get("red") or {}
    exec_sum = report.get("executive_summary") or {}
    meta = report.get("metadata") or {}

    tiempo = report.get("tiempo_resolucion") or meta.get("duracion") or tech_duration(report)
    return {
        "equipos_detectados": red.get("dispositivos") or exec_sum.get("dispositivos_monitoreados") or len(devices) or "—",
        "equipos_nuevos": red.get("nuevos") or red.get("equipos_nuevos") or "—",
        "equipos_desconocidos": red.get("desconocidos") or "—",
        "endpoints": exec_sum.get("dispositivos_monitoreados") or len(devices) or "—",
        "servicios_analizados": len(ports) if ports else "—",
        "tiempo_analisis": _clean_label(tiempo, "—"),
    }


def tech_duration(report: dict) -> str:
    tech = report.get("technical") or {}
    for key in ("duracion", "tiempo_analisis", "scan_duration"):
        if tech.get(key):
            return _clean_label(tech[key])
    return "—"


def build_executive_presentation(report: dict) -> Dict[str, Any]:
    """Vista ejecutiva unificada para UI, PDF y Kernel IA."""
    if not report or not report.get("id"):
        raise ValueError("Informe inválido")

    meta = report.get("metadata") or {}
    cover = report.get("cover") or {}
    exec_sum = report.get("executive_summary") or {}
    gs = report.get("general_status") or {}
    tech = report.get("technical") or {}

    fecha_raw = (
        cover.get("fecha")
        or meta.get("fecha")
        or report.get("fecha")
        or report.get("generated_at")
        or "—"
    )
    fecha, hora = _split_datetime(fecha_raw)
    if cover.get("hora"):
        hora = _clean_label(cover.get("hora"), hora)

    devices = _collect_devices(report)
    ports = _collect_ports(report)
    vulns = _collect_vulnerabilities(report)

    estado_general = (
        exec_sum.get("estado_general")
        or gs.get("estado_general")
        or report.get("estado")
        or tech.get("estado")
        or "—"
    )
    nivel_riesgo = _normalize_severity(
        exec_sum.get("nivel_seguridad")
        or cover.get("nivel_seguridad")
        or gs.get("nivel_riesgo")
        or report.get("severidad")
        or tech.get("riesgo_sistema")
    )

    executive = {
        "fecha": fecha,
        "hora": hora,
        "usuario": _clean_label(meta.get("generado_por") or report.get("generado_por"), "Operador NOVUS"),
        "equipo": _clean_label(report.get("equipo_afectado") or meta.get("hostname"), "—"),
        "red_analizada": _clean_label(
            ((report.get("sections") or {}).get("red") or {}).get("gateway")
            or meta.get("subred")
            or meta.get("red"),
            "Red local supervisada",
        ),
        "estado_general": _clean_label(estado_general),
        "nivel_riesgo": nivel_riesgo,
        "prioridad": nivel_riesgo,
        "resumen": _clean_label(
            cover.get("resumen_ejecutivo_breve")
            or exec_sum.get("texto_ejecutivo")
            or report.get("resumen_ejecutivo")
            or tech.get("que_ocurrio"),
            NO_EVIDENCE,
        ),
    }

    return {
        "title": "INFORME DE SEGURIDAD NOVUS",
        "report_id": report["id"],
        "tipo": _clean_label(report.get("tipo") or report.get("report_type") or "Informe de seguridad"),
        "executive": executive,
        "scan_summary": _scan_summary(report, devices, ports, vulns),
        "devices": devices,
        "open_ports": ports,
        "vulnerabilities": vulns,
        "kernel_analysis": _kernel_analysis_block(report, vulns, ports, devices),
        "recommendations": _collect_recommendations(report, vulns),
        "evidences": _collect_evidences(report),
    }


def build_kernel_context_brief(report: dict) -> Dict[str, Any]:
    """Contexto compacto para consultas Kernel IA (sin volcar JSON crudo)."""
    pres = build_executive_presentation(report)
    return {
        "report_id": report.get("id"),
        "tipo": pres.get("tipo"),
        "executive": pres.get("executive"),
        "scan_summary": pres.get("scan_summary"),
        "devices_count": len(pres.get("devices") or []),
        "open_ports_count": len(pres.get("open_ports") or []),
        "vulnerabilities_sample": (pres.get("vulnerabilities") or [])[:8],
        "kernel_analysis": pres.get("kernel_analysis"),
        "recommendations": pres.get("recommendations"),
        "evidences": (pres.get("evidences") or [])[:10],
    }


def serialize_technical_audit(report: dict) -> str:
    """JSON completo para pestaña administrador (auditoría / depuración)."""
    return json.dumps(report, ensure_ascii=False, indent=2, default=str)
