#!/usr/bin/env python3
"""Auditoría objetiva de preparación para producción — basada en evidencia."""
from __future__ import annotations

import json
import os
from datetime import datetime

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    path = os.path.join(SCRIPTS, name)
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def score_readiness(tests: dict, defense: dict) -> dict:
    """Puntuación conservadora — no inflar clasificación."""
    passed = tests.get("summary", {}).get("passed", 0)
    total = tests.get("summary", {}).get("total", 1)
    defense_ok = defense.get("summary", {}).get("all_pass", False)

    criteria = {
        "evidence_registry": any(t["pass"] for t in tests.get("tests", []) if "registry" in t["name"]),
        "active_defense_gates": any(t["pass"] for t in tests.get("tests", []) if "gate" in t["name"] or "ADE" in t["name"]),
        "auth_containment": any(t["pass"] for t in tests.get("tests", []) if "brute" in t["name"]),
        "recovery": any(t["pass"] for t in tests.get("tests", []) if "recuperación" in t["name"] or "unblock" in t["name"]),
        "hostile_detection": any(t["pass"] for t in tests.get("tests", []) if "hostil" in t["name"]),
        "defense_suite": defense_ok,
        "test_ratio": passed / max(total, 1),
    }

    score = sum(1 for v in criteria.values() if v is True) / len(criteria) * 100
    if score >= 85 and defense_ok and passed == total:
        classification = "Pre-producción empresarial (piloto hostil)"
    elif score >= 70:
        classification = "Beta avanzada — progreso hacia producción"
    else:
        classification = "Piloto controlado"

    return {
        "score_pct": round(score, 1),
        "classification": classification,
        "criteria_met": {k: v for k, v in criteria.items()},
    }


def main():
    prod_tests = load("production_readiness_tests.json")
    defense = load("defense_comprehensive_audit.json")
    perf = load("performance_after.json")

    readiness = score_readiness(prod_tests, defense)

    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "classification": readiness["classification"],
        "readiness_score_pct": readiness["score_pct"],
        "criteria": readiness["criteria_met"],
        "production_tests": prod_tests.get("summary", {}),
        "defense_tests": defense.get("summary", {}),
        "strengths": [
            "Registro central de evidencias (defense_evidence_registry) — JSONL + DB",
            "Defensa activa con gate de evidencia para CRITICO/aislamiento",
            "Contención automática IP en brute force con trazabilidad",
            "Recuperación reversible (revert_containment)",
            "Detección entorno hostil (NDR: densidad, desconocidos, auth flood)",
            "Rate limiting login/API activo",
            f"Rendimiento endpoints optimizado (dashboard live ~{next((e['ms_avg'] for e in perf.get('endpoints', []) if e['path']=='/api/dashboard/live'), 'N/D')}ms)",
        ],
        "weaknesses": prod_tests.get("limitations", []),
        "residual_risks": [
            "Sin validación a escala >100 dispositivos en red real",
            "Sin agente móvil ni OAuth email",
            "Enforcement red OS-level limitado",
        ],
        "requirements_for_full_production": [
            "IDS/SPAN o sensor de red para spoofing DNS/DHCP",
            "Agente móvil + telemetría app",
            "Integración OAuth correo (BEC/phishing)",
            "Firewall OS para bloqueo IP remoto",
            "Pruebas de carga multi-tenant documentadas",
            "NOVUS_EXPECTED_CERT_PIN en entornos TLS críticos",
        ],
        "evidence_files": [
            "scripts/production_readiness_tests.json",
            "scripts/defense_comprehensive_audit.json",
            "scripts/performance_after.json",
            "data/defense_registry/events.jsonl",
        ],
    }

    json_path = os.path.join(SCRIPTS, "production_readiness_audit.json")
    md_path = os.path.join(SCRIPTS, "production_readiness_audit.md")

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    lines = [
        f"# Auditoría Preparación Producción NOVUS",
        f"\n**Fecha:** {report['generated_at']}",
        f"\n## Clasificación: **{report['classification']}**",
        f"\n**Puntuación preparación:** {report['readiness_score_pct']}%",
        f"\n## Pruebas: producción {prod_tests.get('summary', {})} | defensa {defense.get('summary', {})}",
        "\n## Fortalezas",
    ]
    for s in report["strengths"]:
        lines.append(f"- {s}")
    lines.append("\n## Debilidades / limitaciones")
    for w in report["weaknesses"]:
        lines.append(f"- {w}")
    lines.append("\n## Requisitos pendientes para producción plena")
    for r in report["requirements_for_full_production"]:
        lines.append(f"- {r}")

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print(f"Clasificación: {report['classification']}")
    print(f"JSON: {json_path}")
    print(f"MD: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
