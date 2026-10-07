#!/usr/bin/env python3
"""
Genera las 3 auditorías solicitadas: datos falsos, APIs, protección general.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

OUT = os.path.join(ROOT, "data")


def audit_fake_data():
    findings = [
        {
            "ubicacion": "services/dashboard_priority_service.py:57",
            "dato": "Fecha de último análisis inventada (datetime.now())",
            "causa": "Fallback cuando no había last_scan",
            "correccion": "Retorna 'Sin datos disponibles'",
            "estado": "CORREGIDO",
        },
        {
            "ubicacion": "services/topology_service.py:122",
            "dato": "traffic_intensity=15 fijo en aristas LAN",
            "causa": "Default visual sin medición",
            "correccion": "intensity=null si no hay conexiones medidas",
            "estado": "CORREGIDO",
        },
        {
            "ubicacion": "templates/topology.html:272",
            "dato": "Fallback intensity || 20",
            "causa": "Default frontend",
            "correccion": "intensity baja neutra solo si traffic_measured",
            "estado": "CORREGIDO",
        },
        {
            "ubicacion": "api/dashboard.py nodos_red",
            "dato": "0 nodos sin escaneo previo",
            "causa": "len([]) como fallback",
            "correccion": "'Sin datos disponibles' sin last_scan",
            "estado": "CORREGIDO",
        },
        {
            "ubicacion": "novus_security_integration total_threats",
            "dato": "Conteo de procesos sin evidencia",
            "causa": "len(threats)+len(processes) bruto",
            "correccion": "_count_verified_threats() con evidencia",
            "estado": "CORREGIDO",
        },
        {
            "ubicacion": "security_report_service list_reports",
            "dato": "Reportes TEST/DB-VULN en índice",
            "causa": "Índice filesystem sin filtro",
            "correccion": "_report_is_stale_or_test() excluye artefactos",
            "estado": "CORREGIDO",
        },
        {
            "ubicacion": "threat_intelligence_service sync Alerta",
            "dato": "Incidentes resueltos/high_entropy en intel",
            "causa": "Sync SQLite sin filtro",
            "correccion": "Skip RESOLVED_LEVEL y high_entropy",
            "estado": "CORREGIDO",
        },
        {
            "ubicacion": "routes/main.py playbook ejecuciones",
            "dato": "ejecuciones_mes='0' por defecto",
            "causa": "playbook.get('ejecuciones', 0)",
            "correccion": "'Sin datos disponibles' si no hay dato",
            "estado": "CORREGIDO",
        },
        {
            "ubicacion": "data/reports/SEC-*-TEST-PORT-9999.json",
            "dato": "Reporte de prueba QA",
            "causa": "test_production_readiness.py",
            "correccion": "Excluido de list_reports; archivo puede permanecer archivado",
            "estado": "MITIGADO",
        },
        {
            "ubicacion": "adaptive_defense_engine protection %",
            "dato": "Piso 20% en protección endpoint",
            "causa": "Heurística max(20, ...)",
            "correccion": "No modificado — heurística derivada de hallazgos reales, documentado como limitación",
            "estado": "DOCUMENTADO",
        },
    ]
    return {
        "titulo": "Auditoría 1 — Eliminación de datos falsos/estáticos",
        "generado": datetime.now(timezone.utc).isoformat(),
        "total_hallazgos": len(findings),
        "corregidos": sum(1 for f in findings if f["estado"] == "CORREGIDO"),
        "confirmacion": "Los contadores de amenazas, nodos y fechas ya no inventan valores; sin evidencia muestran 'Sin datos disponibles'.",
        "hallazgos": findings,
    }


def audit_api_security():
    from core.app import create_app
    app = create_app()
    api_count = sum(1 for r in app.url_map.iter_rules() if "/api/" in r.rule)
    audit_path = os.path.join(OUT, "api_security_audit.json")
    prior = {}
    if os.path.exists(audit_path):
        with open(audit_path, encoding="utf-8") as f:
            prior = json.load(f)
    return {
        "titulo": "Auditoría 2 — Seguridad de APIs",
        "generado": datetime.now(timezone.utc).isoformat(),
        "apis_revisadas": prior.get("total_apis_reviewed", api_count),
        "proteccion_global": prior.get("global_protections", [
            "auth_global_before_request",
            "rate_limit 120/min",
            "rate_limit sensible 30/min",
            "sqli query scan",
            "json 1MB limit",
            "api_auth_failed logging",
        ]),
        "endurecidas_explicitas": prior.get("apis_explicitly_hardened", 14),
        "autenticacion": "Flask-Login + hook global 401 en /api/*",
        "autorizacion": "Sesión por usuario; sin RBAC granular",
        "validacion": "api_security_service + @api_hardened en 14 rutas críticas",
        "registro": "defense_evidence_registry + Log seguridad",
        "riesgos_residuales": prior.get("residual_risks", []),
        "recomendaciones": prior.get("recommendations", []),
        "pruebas": os.path.join(OUT, "api_hardening_test_results.json"),
    }


def audit_general_protection():
    return {
        "titulo": "Auditoría 3 — Nivel de protección general NOVUS",
        "generado": datetime.now(timezone.utc).isoformat(),
        "fortalezas": [
            "Motor unificado novus_security_integration con cache verificada",
            "Contadores canónicos platform_metrics_service (fuente única)",
            "Adaptive Defense + ASPE + UCE integrados con gates de evidencia",
            "NDR con investigate real y topology basada en ARP/psutil",
            "135 APIs con middleware de seguridad",
            "Dashboard interactivo con drill-down a NDR/Kernel/remediación",
            "Reconciliación de alertas históricas (Resuelto-FalsoPositivo)",
        ],
        "debilidades": [
            "Sin IDS/packet inspection (DNS/DHCP spoofing no verificable)",
            "Bloqueo IP en SQLite — no firewall OS universal",
            "OAuth Gmail sin state anti-CSRF",
            "Sector móvil sin agente/SDK",
            "Login lento por escaneos síncronos en apply_sector_profile",
            "Persistencia histórica (NDCI, reportes) puede mostrar casos antiguos hasta purga manual",
        ],
        "riesgos_residuales": [
            "Endpoints MEDIO sin @api_hardened explícito",
            "Rate limit solo por IP",
            "Upload scan/file sin límite tamaño multipart",
            "Heurísticas de severidad en intel (ALTO/MEDIO fijos en algunos hallazgos)",
        ],
        "recomendaciones": [
            "Purgar periódicamente data/reports y NDCI sin evidencia activa",
            "Desacoplar escaneo de red del login",
            "Rate limit por usuario autenticado",
            "Agente móvil para sector shield completo",
            "WAF externo en despliegue producción",
        ],
        "clasificacion": "Pre-producción empresarial (piloto hostil) — basada en scripts test_* y implementación real",
        "limitaciones_explicitas": "No se afirma producción plena; MITM completo requiere NOVUS_EXPECTED_CERT_PIN",
    }


def main():
    os.makedirs(OUT, exist_ok=True)
    reports = {
        "audit_1_fake_data": audit_fake_data(),
        "audit_2_api_security": audit_api_security(),
        "audit_3_general_protection": audit_general_protection(),
    }
    json_path = os.path.join(OUT, "platform_truthfulness_audits.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2, ensure_ascii=False)

    md_lines = ["# Auditorías NOVUS — Veracidad de datos y protección\n"]
    for key, rep in reports.items():
        md_lines.append(f"## {rep['titulo']}\n")
        md_lines.append(f"Generado: {rep['generado']}\n")
        if "hallazgos" in rep:
            md_lines.append(f"**Hallazgos:** {rep['total_hallazgos']} | **Corregidos:** {rep.get('corregidos', 0)}\n")
            md_lines.append(f"*{rep.get('confirmacion', '')}*\n")
            for h in rep["hallazgos"]:
                md_lines.append(f"- **{h['estado']}** `{h['ubicacion']}`: {h['dato']} → {h['correccion']}")
        if "fortalezas" in rep:
            md_lines.append("### Fortalezas\n")
            for x in rep["fortalezas"]:
                md_lines.append(f"- {x}")
            md_lines.append("\n### Debilidades\n")
            for x in rep["debilidades"]:
                md_lines.append(f"- {x}")
            md_lines.append(f"\n**Clasificación:** {rep['clasificacion']}\n")
        md_lines.append("")

    md_path = os.path.join(OUT, "platform_truthfulness_audits.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print(f"JSON: {json_path}")
    print(f"MD:   {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
