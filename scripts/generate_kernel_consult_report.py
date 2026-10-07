#!/usr/bin/env python3
"""Informe final — Consultar Kernel IA + Auditoría Integral."""
import json
import os
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

report = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "titulo": "Implementación Consultar Kernel IA + Auditoría Integral de Seguridad",
    "kernel_ia": {
        "botones_corregidos": [
            "partials/kernel_consult_btn.html (sidebar universal)",
            "partials/ai_kernel_panel.html consultModule()",
            "dashboard index.html (sector + investigation)",
            "topology.html consultKernel()",
            "network.html investigación",
            "vulnerabilidades.html finding_id",
            "casos_estudio.html case_id",
            "xdr.html NovusModuleExtra threat_id",
            "inteligencia.html NovusModuleExtra case_id",
            "reportes.html NovusModuleExtra report_id",
            "incidentes.html NovusModuleExtra incident_id",
        ],
        "modulos_actualizados": [
            "module_kernel_context.py — UCE/ASPE/ADE en todo contexto",
            "api/ai.py — POST execute con extra completo",
            "13 módulos con build_consult_prompt",
        ],
        "comportamiento": [
            "Abre panel Kernel IA automáticamente",
            "POST /api/ai/module-consult con execute:true",
            "Envía contexto verificado sin chat vacío",
            "Respuesta estructurada: qué/por qué/evidencia/riesgo/defensa/recomendación",
        ],
    },
    "auditoria_integral": {
        "nombre_nuevo": "Auditoría Integral de Seguridad",
        "nombre_legacy": "Auditoría de Datos Reales (compat API)",
        "modos": {
            "quick": "integral_security_audit_service.run_quick_audit — OS, procesos, servicios, red, amenazas",
            "deep": "deep_scan_engine profile=full — análisis exhaustivo async",
        },
        "apis": [
            "POST /api/audit/integral/run",
            "GET /api/audit/integral/deep/<id>/status",
            "GET /api/audit/integral/deep/<id>/report",
            "GET /api/audit/data-sources (compat)",
        ],
        "ui": "templates/configuracion.html",
    },
    "evidencias": {
        "test_script": "scripts/test_kernel_consult_and_audit.py",
        "result_file": "data/kernel_consult_audit_test.json",
    },
}

test_path = os.path.join(DATA, "kernel_consult_audit_test.json")
if os.path.exists(test_path):
    with open(test_path, encoding="utf-8") as f:
        report["evidencias"]["test_results"] = json.load(f)

out_json = os.path.join(DATA, "kernel_consult_implementation_report.json")
out_md = os.path.join(DATA, "kernel_consult_implementation_report.md")
with open(out_json, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

lines = [
    "# Informe — Consultar Kernel IA + Auditoría Integral\n",
    f"Generado: {report['generated_at']}\n",
    "## Botones corregidos\n",
] + [f"- {x}" for x in report["kernel_ia"]["botones_corregidos"]]
lines += ["\n## Capacidades nuevas\n"] + [f"- {x}" for x in report["kernel_ia"]["comportamiento"]]
lines += ["\n## Auditoría Integral\n", f"- Modo rápido: {report['auditoria_integral']['modos']['quick']}\n", f"- Modo profundo: {report['auditoria_integral']['modos']['deep']}\n"]
if report["evidencias"].get("test_results"):
    tr = report["evidencias"]["test_results"]
    lines.append(f"\n## Validación: {tr.get('pass', 0)} PASS / {tr.get('fail', 0)} FAIL\n")
with open(out_md, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
print(out_json)
print(out_md)
