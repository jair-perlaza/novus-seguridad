#!/usr/bin/env python3
"""Informe detallado de cobertura avanzada por sector."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "data", "sector_threat_coverage")


def main():
    os.makedirs(OUT, exist_ok=True)

    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "test_sector_threat_coverage.py")],
        capture_output=True, text=True, cwd=ROOT, timeout=300,
    )

    from services.threat_coverage_service import threat_coverage
    from services.active_defense_orchestrator import active_defense
    import json as _json

    with open(os.path.join(ROOT, "config", "threat_coverage_map.json"), encoding="utf-8") as fh:
        catalog = _json.load(fh)

    live = threat_coverage.evaluate_live_coverage()
    sectors = {s: threat_coverage.get_sector_coverage(s) for s in catalog.get("sectors", [])}

    not_validated = [
        cid for cid, p in live.get("categories", {}).items()
        if p.get("implemented") and not p.get("validated")
    ]

    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "principle": catalog.get("principle"),
        "live_coverage": live,
        "sectors": sectors,
        "active_defense_state": active_defense.verify_and_reconcile_active_incidents(),
        "limitations": [p.get("limitations") for p in live.get("categories", {}).values() if p.get("limitations")][:15],
        "not_validated_live": not_validated,
        "validation_test_exit": proc.returncode,
    }

    json_path = os.path.join(OUT, "coverage_audit_report.json")
    md_path = os.path.join(OUT, "coverage_audit_report.md")

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    md = [
        "# Auditoría — Cobertura Avanzada de Defensa por Sector",
        "",
        f"**Generado:** {report['generated_at']}",
        "",
        "## Resumen",
        "",
        f"- Categorías totales: **{live.get('total_categories')}**",
        f"- Implementadas: **{live.get('implemented_count')}** ({live.get('implementation_rate_pct')}%)",
        f"- Validadas en vivo: **{live.get('validated_count')}** ({live.get('validation_rate_pct')}%)",
        "",
        "## Cobertura por sector",
        "",
    ]
    for sk, sd in sectors.items():
        md.append(f"### {sk}")
        md.append(f"- Categorías aplicables: {sd.get('categories_count')}")
        md.append(f"- Validadas en vivo: {sd.get('validated_count')} ({sd.get('coverage_pct')}%)")
        md.append("")

    md.extend([
        "## Categorías implementadas sin validación live",
        "",
    ])
    for cid in not_validated:
        p = live["categories"].get(cid, {})
        md.append(f"- **{cid}** ({p.get('label')}): {p.get('limitations', [''])[0] if p.get('limitations') else 'ver probe'}")

    md.extend([
        "",
        "## Riesgos residuales",
        "",
        "- Sin inspección de paquetes (DNS/DHCP spoofing no soportado)",
        "- Sector móvil sin agente/SDK nativo",
        "- BEC/Phishing requieren OAuth email",
        "- Supply chain VT requiere VIRUSTOTAL_API_KEY",
        "- DDoS: rate limit app, no mitigación volumétrica ISP",
        "",
        "## Defensa activa",
        "",
        f"- Incidentes activos tras reconcile: {report['active_defense_state'].get('active_count')}",
        f"- Resueltos: {len(report['active_defense_state'].get('resolved', []))}",
        "",
        f"Prueba validación: exit {proc.returncode}",
    ])

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))

    print(f"JSON: {json_path}")
    print(f"MD: {md_path}")
    print(f"Validación: {live.get('validated_count')}/{live.get('total_categories')} categorías")
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
