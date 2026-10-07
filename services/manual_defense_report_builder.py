"""Construcción de informes profesionales del Centro de Defensa — solo telemetría real."""
from __future__ import annotations

import json
import platform
from typing import Any, Dict, List, Optional, Tuple

from utils.host_data import get_local_ip

# Amenazas comprobables por mecanismo: solo se listan en «No se encontró» si el análisis se completó.
# match_keywords: si algún hallazgo contiene alguna clave (JSON lower), se considera encontrada.
MECHANISM_VERIFIED_THREATS: Dict[str, List[Dict[str, Any]]] = {
    "host_scan_full": [
        {"id": "malware_files", "label": "Malware en archivos analizados", "match": ["malware", "malicioso", "trojan", "virus", "ransom"]},
        {"id": "critical_process", "label": "Procesos críticos / anómalos", "match": ["critical", "high", "minero", "miner", "shell"]},
        {"id": "persistence", "label": "Persistencia maliciosa", "match": ["persist", "run key", "autorun malici"]},
    ],
    "host_scan_processes": [
        {"id": "suspicious_process", "label": "Procesos sospechosos (heurística)", "match": ["high", "critical", "medium", "threat"]},
    ],
    "host_malware_known": [
        {"id": "known_malware", "label": "Malware conocido", "match": ["malware", "malicioso", "trojan", "virus"]},
    ],
    "host_ransomware": [
        {"id": "ransomware", "label": "Indicadores de ransomware", "match": ["ransom", "entrop", "encrypt"]},
    ],
    "host_miners": [
        {"id": "miners", "label": "Mineros cripto", "match": ["miner", "xmrig", "cryptonight"]},
    ],
    "host_rootkit": [
        {"id": "rootkit", "label": "Rootkits / drivers ocultos", "match": ["rootkit", "hidden driver", "dkom"]},
    ],
    "host_dll_injection": [
        {"id": "dll_injection", "label": "Inyección DLL", "match": ["dll", "inyec", "inject"]},
    ],
    "host_hidden_processes": [
        {"id": "hidden_proc", "label": "Procesos ocultos", "match": ["oculto", "hidden", "sin ejecutable"]},
    ],
    "net_mitm": [
        {"id": "mitm", "label": "Indicadores MITM / túnel", "match": ["mitm", "tunnel", "proxy", "compromet"]},
    ],
    "net_arp_spoofing": [
        {"id": "arp", "label": "ARP spoofing / conflicto ARP", "match": ["arp", "spoof", "conflict"]},
    ],
    "net_rogue_dhcp": [
        {"id": "rogue_dhcp", "label": "Servidor DHCP rogue", "match": ["dhcp", "rogue"]},
    ],
    "net_open_ports": [
        {"id": "risky_ports", "label": "Puertos de alto riesgo expuestos", "match": ["23", "445", "3389", "5900", "4444", "high", "critical"]},
    ],
    "web_phishing": [
        {"id": "phishing", "label": "Phishing en URL analizada", "match": ["phish", "block", "high", "critical"]},
    ],
    "web_malware": [
        {"id": "web_malware", "label": "Malware / descarga maliciosa (web)", "match": ["malware", "malici", "block"]},
    ],
}

CATEGORY_SECTION_TITLES = {
    "equipo": "Protección del equipo",
    "red": "Protección de red",
    "web": "Protección web",
    "correo": "Protección de correo",
    "endpoint": "Protección de endpoints",
    "sectorial": "Protección sectorial",
    "cloud": "Protección Cloud",
}


def _finding_blob(f: dict) -> str:
    try:
        return json.dumps(f, ensure_ascii=False).lower()
    except Exception:
        return str(f).lower()


def _stats(result: Dict[str, Any]) -> Dict[str, Any]:
    raw = result.get("raw_summary") or {}
    stats = raw.get("stats") if isinstance(raw.get("stats"), dict) else {}
    if not stats and isinstance(result.get("evidence"), list):
        for ev in result["evidence"]:
            if isinstance(ev, dict) and ev.get("scan_id"):
                try:
                    from services.deep_scan_engine import deep_scan_engine

                    st = deep_scan_engine.get_status(ev["scan_id"])
                    if st and st.get("stats"):
                        stats = st["stats"]
                except Exception:
                    pass
    return stats or {}


def _risk_level(findings: List[dict]) -> str:
    high = {"high", "critical", "alto", "crítico", "medium", "medio"}
    for f in findings:
        if not isinstance(f, dict):
            continue
        r = str(f.get("risk") or f.get("severity") or "").lower()
        if r in high:
            return "Alta" if r in ("high", "critical", "alto", "crítico") else "Media"
    return "Informativa" if not findings else "Media"


def compute_verified_not_found(
    mechanism_id: str,
    result: Dict[str, Any],
    findings: List[dict],
    mech: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Devuelve (verified_checks, not_found_verified)."""
    status = (result.get("status") or "").lower()
    if status not in ("completed", "ok", "no_data"):
        return [], []

    checks_def = list(MECHANISM_VERIFIED_THREATS.get(mechanism_id, []))
    if not checks_def and mech:
        exec_type = (mech.get("exec") or "").lower()
        generic = {
            "deep_scan": [{"id": "scan_anomalies", "label": "Anomalías críticas en escaneo profundo", "match": ["critical", "high", "malware", "ransom"]}],
            "network_scan": [{"id": "ndr_alert", "label": "Alertas NDR en descubrimiento", "match": ["unknown", "rogue", "alert", "critical", "high"]}],
            "web_url": [{"id": "web_threat", "label": "Amenaza web en URL analizada", "match": ["block", "high", "critical", "phish", "malware"]}],
            "mail": [{"id": "mail_threat", "label": "Amenaza en correo sincronizado", "match": ["phish", "malware", "spam", "bec"]}],
            "open_ports": [{"id": "risky_ports", "label": "Puertos de alto riesgo", "match": ["23", "445", "3389", "5900", "4444"]}],
        }.get(exec_type, [])
        checks_def = generic
    if not checks_def:
        return [], []

    verified: List[Dict[str, Any]] = []
    not_found: List[Dict[str, Any]] = []
    blobs = [_finding_blob(f) for f in findings if isinstance(f, dict)]

    for chk in checks_def:
        keywords = [k.lower() for k in (chk.get("match") or [])]
        found = False
        if keywords:
            for blob in blobs:
                if any(kw in blob for kw in keywords):
                    found = True
                    break
        elif findings:
            found = True

        entry = {
            "id": chk["id"],
            "label": chk["label"],
            "verified": True,
            "found": found,
        }
        verified.append(entry)
        if not found:
            not_found.append({"id": chk["id"], "label": chk["label"]})

    return verified, not_found


def _section(key: str, title: str, content: Any, *, note: Optional[str] = None) -> Dict[str, Any]:
    return {"key": key, "title": title, "content": content, "note": note}


def _build_equipo_sections(result: Dict[str, Any], stats: Dict[str, Any], findings: List[dict]) -> List[Dict[str, Any]]:
    sections: List[Dict[str, Any]] = []
    sections.append(
        _section(
            "general",
            "Información general",
            {
                "host": platform.node(),
                "ip_local": get_local_ip(),
                "sistema": f"{platform.system()} {platform.release()}",
                "duracion_segundos": result.get("duration_sec"),
                "elementos_analizados": result.get("analyzed"),
                "estado_ejecucion": result.get("status"),
            },
        )
    )
    sections.append(
        _section(
            "inventory",
            "Alcance del análisis",
            {
                "archivos_analizados": stats.get("files_analyzed") or stats.get("files_scanned"),
                "carpetas_analizadas": stats.get("folders_analyzed"),
                "procesos_analizados": stats.get("processes_analyzed") or stats.get("processes_scanned"),
                "servicios_analizados": stats.get("services_analyzed"),
                "programas_instalados": stats.get("programs_analyzed") or stats.get("installed_analyzed"),
                "inicio_automatico": stats.get("startup_analyzed") or stats.get("autorun_analyzed"),
                "registro_windows": stats.get("registry_analyzed") if platform.system().lower() == "windows" else None,
                "conexiones": stats.get("connections_analyzed"),
                "puertos_verificados": stats.get("ports_analyzed"),
                "tareas_programadas": stats.get("tasks_analyzed"),
            },
            note="Conteos provienen del motor ejecutado; valores nulos indican fase no ejecutada en este perfil.",
        )
    )
    by_cat: Dict[str, List[dict]] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        cat = (f.get("category") or "general").lower()
        by_cat.setdefault(cat, []).append(f)

    sections.append(_section("findings_malware", "Malware / amenazas detectadas", by_cat.get("malware") or by_cat.get("threat") or []))
    sections.append(_section("findings_vuln", "Vulnerabilidades y anomalías", findings[:80]))
    sections.append(_section("processes", "Procesos relevantes", [f for f in findings if "process" in _finding_blob(f)][:40]))
    sections.append(_section("evidence", "Evidencias", (result.get("evidence") or [])[:50]))
    sections.append(_section("actions", "Acciones realizadas", result.get("auto_actions") or []))
    sections.append(_section("recommendations", "Recomendaciones operativas", result.get("recommendations") or []))
    return sections


def _build_red_sections(result: Dict[str, Any], findings: List[dict]) -> List[Dict[str, Any]]:
    evidence = result.get("evidence") or []
    dns_gw = {}
    for ev in evidence:
        if isinstance(ev, dict):
            if "dns" in ev or "dns_servers" in ev:
                dns_gw["dns"] = ev.get("dns") or ev.get("dns_servers") or ev
            if ev.get("gateway") or ev.get("active") is not None:
                dns_gw["gateway"] = ev
    return [
        _section("general", "Información general", {"analizados": result.get("analyzed"), "duracion_segundos": result.get("duration_sec")}),
        _section("devices", "Dispositivos detectados", findings if findings else []),
        _section("network_meta", "Gateway / DNS / estabilidad", dns_gw or evidence[:5]),
        _section("ports_services", "Puertos y servicios", findings if any("port" in _finding_blob(f) for f in findings) else []),
        _section("events", "Eventos de conexión / seguridad", findings),
        _section("evidence", "Evidencias", evidence[:40]),
        _section("risks", "Riesgos identificados", result.get("risks") or []),
        _section("actions", "Acciones realizadas", result.get("auto_actions") or []),
    ]


def _build_web_sections(result: Dict[str, Any], findings: List[dict]) -> List[Dict[str, Any]]:
    evidence = result.get("evidence") or []
    return [
        _section("urls", "URLs / sitios analizados", evidence[:10]),
        _section("certificates", "Certificados SSL/TLS", [e for e in evidence if isinstance(e, dict) and ("cert" in json.dumps(e).lower() or "ssl" in json.dumps(e).lower())]),
        _section("reputation", "Reputación y veredicto", findings or evidence[:5]),
        _section("downloads", "Descargas / archivos inspeccionados", findings),
        _section("evidence", "Evidencias", evidence[:20]),
        _section("recommendations", "Recomendaciones", result.get("recommendations") or []),
    ]


def _build_mail_sections(result: Dict[str, Any], findings: List[dict]) -> List[Dict[str, Any]]:
    evidence = result.get("evidence") or []
    return [
        _section("integration", "Estado de integración", evidence[:3]),
        _section("messages", "Correos / eventos analizados", {"conteo": result.get("analyzed"), "hallazgos": len(findings)}),
        _section("phishing_bec", "Phishing / BEC / suplantación", findings),
        _section("malware_attachments", "Malware y adjuntos", findings),
        _section("headers_domains", "Encabezados y dominios", evidence[:15]),
        _section("evidence", "Evidencias", evidence[:30]),
        _section("actions", "Acciones realizadas", result.get("auto_actions") or []),
    ]


def _build_generic_sections(result: Dict[str, Any], findings: List[dict], category: str) -> List[Dict[str, Any]]:
    return [
        _section("general", "Información general", {"categoria": category, "analizados": result.get("analyzed")}),
        _section("findings", "Hallazgos", findings[:100]),
        _section("evidence", "Evidencias", (result.get("evidence") or [])[:50]),
        _section("actions", "Acciones realizadas", result.get("auto_actions") or []),
        _section("limitations", "Limitaciones", result.get("limitations") or []),
    ]


def build_kernel_analysis(
    *,
    mechanism_title: str,
    category: str,
    result: Dict[str, Any],
    findings: List[dict],
    verified: List[Dict[str, Any]],
    not_found: List[Dict[str, Any]],
    limitations: List[str],
) -> Dict[str, Any]:
    """Resumen determinista del Kernel IA — sin inventar hallazgos."""
    n_find = len(findings)
    sev = _risk_level(findings)
    risks_found = []
    for f in findings[:15]:
        if not isinstance(f, dict):
            continue
        title = f.get("title") or f.get("name") or f.get("path") or f.get("ip") or "Hallazgo"
        risks_found.append(
            {
                "label": str(title)[:120],
                "risk": f.get("risk") or f.get("severity") or "info",
                "detail": (f.get("description") or f.get("reason") or "")[:200],
            }
        )

    recs = list(result.get("recommendations") or [])[:8]
    if not recs and limitations:
        recs = limitations[:3]

    priorities: List[str] = []
    if sev == "Alta":
        priorities.append("Prioridad 1: Contener y validar hallazgos de severidad alta antes de continuar operación.")
    if n_find:
        priorities.append("Prioridad 2: Revisar evidencias adjuntas y correlacionar en XDR / vulnerabilidades.")
    else:
        priorities.append("Prioridad 2: Mantener monitoreo; no se registraron hallazgos en telemetría de este mecanismo.")
    if not_found:
        priorities.append(
            "Prioridad 3: Amenazas verificadas sin indicadores en este paso — mantener controles y repetir según política."
        )
    elif limitations:
        priorities.append("Prioridad 3: Respetar limitaciones del análisis; no extrapolar cobertura no ejecutada.")

    summary_parts = [
        f"Análisis «{mechanism_title}» ({CATEGORY_SECTION_TITLES.get(category, category)}).",
        f"Estado: {result.get('status')}. Hallazgos registrados: {n_find}. Severidad agregada: {sev}.",
    ]
    if verified:
        summary_parts.append(f"Controles de amenaza evaluados: {len(verified)}.")
    if limitations:
        summary_parts.append(f"Limitaciones declaradas: {len(limitations)}.")

    return {
        "summary": " ".join(summary_parts),
        "risks_found": risks_found,
        "risks_not_found_verified": [{"label": x["label"]} for x in not_found],
        "recommendations": recs,
        "priorities": priorities,
        "disclaimer": "Este bloque resume únicamente la telemetría del mecanismo ejecutado; no sustituye un análisis forense externo.",
    }


def build_defense_report_payload(
    *,
    mechanism_id: str,
    mechanism_title: str,
    category: str,
    result: Dict[str, Any],
    user_email: Optional[str] = None,
    aggregate: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from services.manual_defense_catalog import get_kernel_doc, get_mechanism

    mech = get_mechanism(mechanism_id) or {}
    findings = [f for f in (result.get("findings") or []) if isinstance(f, dict)]
    stats = _stats(result)
    verified, not_found = compute_verified_not_found(mechanism_id, result, findings, mech)
    limitations = list(result.get("limitations") or [])
    kdoc = get_kernel_doc(mechanism_id) or {}

    if category == "equipo":
        sections = _build_equipo_sections(result, stats, findings)
    elif category == "red":
        sections = _build_red_sections(result, findings)
    elif category == "web":
        sections = _build_web_sections(result, findings)
    elif category == "correo":
        sections = _build_mail_sections(result, findings)
    else:
        sections = _build_generic_sections(result, findings, category)

    kernel = build_kernel_analysis(
        mechanism_title=mechanism_title,
        category=category,
        result=result,
        findings=findings,
        verified=verified,
        not_found=not_found,
        limitations=limitations,
    )

    exec_summary = (
        f"{mechanism_title} — {platform.node()} ({get_local_ip() or 'IP local'}). "
        f"Estado {result.get('status')}. {len(findings)} hallazgo(s). "
    )
    if stats:
        exec_summary += (
            f"Archivos: {stats.get('files_analyzed', 0)}, procesos: {stats.get('processes_analyzed', 0)}, "
            f"servicios: {stats.get('services_analyzed', 0)}."
        )

    conclusion = kernel["summary"]
    if aggregate and aggregate.get("steps"):
        conclusion += f" Defensa completa: {len(aggregate['steps'])} mecanismos ejecutados."

    return {
        "schema_version": 1,
        "mechanism_id": mechanism_id,
        "mechanism_title": mechanism_title,
        "category": category,
        "category_label": CATEGORY_SECTION_TITLES.get(category, category),
        "operator": user_email,
        "engine_doc": {
            "what": kdoc.get("what"),
            "limitations": kdoc.get("limitations"),
            "evidence_generated": kdoc.get("evidence_generated"),
        },
        "executive_summary": exec_summary.strip(),
        "sections": sections,
        "verified_checks": verified,
        "not_found_verified": not_found,
        "limitations": limitations,
        "kernel_analysis": kernel,
        "conclusion": conclusion,
        "aggregate": aggregate,
    }
