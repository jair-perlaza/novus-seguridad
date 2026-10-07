#!/usr/bin/env python3
"""Genera informe técnico consolidado rendimiento + seguridad NOVUS."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")


def load(name: str) -> dict:
    path = os.path.join(SCRIPTS, name)
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def compare_endpoints(before: dict, after: dict) -> list:
    before_map = {e["path"]: e.get("ms_avg", e.get("ms", 0)) for e in before.get("endpoints", [])}
    rows = []
    for ep in after.get("endpoints", []):
        path = ep["path"]
        after_ms = ep.get("ms_avg", 0)
        before_ms = before_map.get(path)
        if before_ms:
            delta = after_ms - before_ms
            pct = round((delta / before_ms) * 100, 1) if before_ms else 0
            rows.append({
                "path": path,
                "before_ms": before_ms,
                "after_ms": after_ms,
                "delta_ms": round(delta),
                "delta_pct": pct,
            })
        else:
            rows.append({"path": path, "before_ms": None, "after_ms": after_ms})
    return rows


def build_report() -> dict:
    before = load("performance_before.json")
    after = load("performance_after.json")
    defense = load("defense_validation_report.json")
    comprehensive = load("defense_comprehensive_audit.json")
    hardening = load("defense_hardening_audit.json")

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "executive_summary": {
            "optimization_goal": "Máximo rendimiento sin reducir seguridad",
            "defense_suites_pass": defense.get("all_pass"),
            "defense_tests": comprehensive.get("summary", {}),
            "hardening_tests": hardening.get("summary", {}),
        },
        "performance": {
            "before": before,
            "after": after,
            "comparison": compare_endpoints(before, after),
            "kernel_ia_ms_after": after.get("kernel_ia_ms"),
            "motor_internal_ms_after": after.get("motor_internal_ms"),
        },
        "optimizations_applied": [
            "Sector shield status: solo lectura caché + TTL 12s (sin escaneos síncronos)",
            "Platform counters: caché agregado 8s + conteo procesos/conexiones 20s",
            "Threat scan: reutiliza procesos/puertos ya escaneados (deduplicación)",
            "NDR inventario: carga bulk SQLite (1 query vs N por MAC)",
            "Topology/ASPE panel: caché TTL 12s via performance_cache",
            "monitor_endpoints: cpu_percent interval=0 (sin bloqueo 500ms)",
            "DB: índices Log.evento y Log.fecha para auditoría auth",
            "Password spraying: detección multi-IP por cuenta en audit logs",
        ],
        "security_audit": {
            "mechanisms_reviewed": comprehensive.get("mechanisms_reviewed", []),
            "threat_coverage": comprehensive.get("threat_coverage", {}),
            "sector_coverage": comprehensive.get("sector_coverage", {}),
            "limitations": comprehensive.get("limitations", []),
            "strengthened": hardening.get("strengthened", []),
        },
        "residual_risks": comprehensive.get("limitations", []),
        "production_readiness": {
            "classification": "Beta avanzada / Piloto controlado",
            "strengths": [
                "Motores de defensa validados 33/33 + 6 suites",
                "Background scanners activos (threat 30s, network 60s)",
                "Caché seguro en rutas de lectura sin desactivar validaciones",
            ],
            "gaps": [
                "Sin IDS/packet inspection",
                "Sector móvil sin agente",
                "Enforcement firewall OS limitado",
            ],
        },
        "prioritized_recommendations": [
            {"priority": "P1", "item": "Integrar agente móvil/SDK para telemetría UI/SIM/runtime"},
            {"priority": "P1", "item": "OAuth Gmail/Microsoft para BEC/Phishing con evidencia real"},
            {"priority": "P2", "item": "NOVUS_EXPECTED_CERT_PIN en entornos con TLS crítico"},
            {"priority": "P2", "item": "Firewall OS-level para bloqueo IP remoto"},
            {"priority": "P3", "item": "IDS/mirror SPAN para DNS/DHCP spoofing"},
        ],
    }


def build_markdown(report: dict) -> str:
    lines = [
        "# Informe Técnico — Optimización Rendimiento y Auditoría Seguridad NOVUS",
        f"\n**Generado:** {report['generated_at']}",
        "\n## Resumen ejecutivo",
        f"- Objetivo: {report['executive_summary']['optimization_goal']}",
        f"- Suites defensa: {'PASS' if report['executive_summary'].get('defense_suites_pass') else 'FAIL'}",
        f"- Pruebas integrales: {report['executive_summary'].get('defense_tests', {})}",
        "\n## Mejoras de rendimiento implementadas",
    ]
    for opt in report.get("optimizations_applied", []):
        lines.append(f"- {opt}")

    lines.append("\n## Métricas antes / después (endpoints HTTP)")
    lines.append("\n| Endpoint | Antes (ms) | Después (ms) | Δ |")
    lines.append("|----------|------------|--------------|---|")
    for row in report.get("performance", {}).get("comparison", []):
        b = row.get("before_ms", "—")
        a = row.get("after_ms", "—")
        d = row.get("delta_pct")
        dstr = f"{d}%" if d is not None else "—"
        lines.append(f"| {row['path']} | {b} | {a} | {dstr} |")

    perf = report.get("performance", {}).get("after", {})
    lines.append("\n## Métricas adicionales (después)")
    lines.append(f"- Kernel IA: {perf.get('kernel_ia_ms')} ms")
    lines.append(f"- Login: {perf.get('login_ms')} ms")
    lines.append(f"- CPU sistema: {perf.get('cpu_pct')}%")
    lines.append(f"- RAM sistema: {perf.get('ram_pct')}%")
    lines.append(f"- RAM proceso benchmark: {perf.get('ram_process_mb')} MB")
    for k, v in (perf.get("motor_internal_ms") or {}).items():
        lines.append(f"- Motor {k}: {v} ms")

    lines.append("\n## Auditoría de seguridad")
    lines.append(f"- Mecanismos revisados: {len(report.get('security_audit', {}).get('mechanisms_reviewed', []))}")
    lines.append("\n### Cobertura por sector")
    for sk, info in (report.get("security_audit", {}).get("sector_coverage") or {}).items():
        lines.append(f"- **{sk}**: {info.get('modules')} módulos — {info.get('label')}")

    lines.append("\n### Limitaciones / riesgos residuales")
    for lim in report.get("residual_risks", []):
        lines.append(f"- {lim}")

    lines.append("\n## Preparación para producción")
    pr = report.get("production_readiness", {})
    lines.append(f"- Clasificación: **{pr.get('classification')}**")
    lines.append("\n### Fortalezas")
    for s in pr.get("strengths", []):
        lines.append(f"- {s}")
    lines.append("\n### Gaps")
    for g in pr.get("gaps", []):
        lines.append(f"- {g}")

    lines.append("\n## Recomendaciones priorizadas")
    for rec in report.get("prioritized_recommendations", []):
        lines.append(f"- **{rec['priority']}**: {rec['item']}")

    return "\n".join(lines) + "\n"


def main():
    report = build_report()
    json_path = os.path.join(SCRIPTS, "performance_security_audit_report.json")
    md_path = os.path.join(SCRIPTS, "performance_security_audit_report.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(build_markdown(report))
    print(f"Informe JSON: {json_path}")
    print(f"Informe MD:   {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
