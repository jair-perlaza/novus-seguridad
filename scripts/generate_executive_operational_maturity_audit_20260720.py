#!/usr/bin/env python3
"""
Informe ejecutivo independiente — madurez operativa NOVUS (2026-07-20).
No modifica data/executive_maturity_audit.* ni otras auditorías previas.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

OUT_DIR = os.path.join(ROOT, "data", "executive_operational_maturity_audit_20260720")
JSON_OUT = os.path.join(OUT_DIR, "executive_operational_maturity_audit.json")
MD_OUT = os.path.join(OUT_DIR, "executive_operational_maturity_audit.md")


def _section_md(title: str, sec: dict, num: int) -> list[str]:
    lines = [
        f"## {num}. {title}",
        "",
        f"**Madurez calculada:** {sec.get('percent', 'N/D')}% ({sec.get('passed')}/{sec.get('total')} criterios)",
        "",
        "| Criterio | OK | Módulo | Símbolo | Evidencia |",
        "|----------|:--:|--------|---------|-----------|",
    ]
    for c in sec.get("checks") or []:
        ev = (c.get("evidence") or "")[:120].replace("|", "/")
        lines.append(
            f"| {c.get('label')} | {c.get('passed')} | `{c.get('module')}` | `{c.get('symbol')}` | {ev} |"
        )
    if sec.get("limitations"):
        lines.append("")
        lines.append("**Limitaciones:**")
        for lim in sec["limitations"]:
            lines.append(f"- {lim}")
    if sec.get("confidence_level"):
        lines.append(f"\n**Nivel de confianza (datos sensibles):** {sec['confidence_level']}")
    if sec.get("ddos_volumetric_infra") is False:
        lines.append("\n**DDoS volumétrico infra:** no implementado.")
    lines.append("")
    return lines


def render_md(report: dict) -> str:
    lines = [
        "# Auditoría ejecutiva — Madurez y preparación operativa NOVUS",
        "",
        f"**Generado:** {report.get('generated_at')}",
        "",
        "> Informe **nuevo e independiente**. No sobrescribe `data/executive_maturity_audit.md`, "
        "`data/security_hardening_audit_20260720/` ni `data/official_defense_technical_audit_*`.",
        "",
        "## Metodología",
        "",
        f"- {report.get('method')}",
        f"- Fórmula: `{report.get('formula')}`",
        f"- Cobertura amenazas (snapshot): {report.get('threat_coverage_snapshot')}",
        "",
    ]
    titles = [
        ("section_1_general", "Preparación general de NOVUS"),
        ("section_2_hostile", "Entorno hostil"),
        ("section_3_controlled", "Entorno controlado"),
        ("section_4_uncontrolled", "Entorno no controlado"),
        ("section_5_fintech", "Sector Fintech"),
        ("section_6_logistics", "Sector Logística"),
        ("section_7_mobile", "Aplicaciones móviles"),
        ("section_8_other_sectors", "Otros sectores (adaptación)"),
        ("section_9_sensitive_data", "Manejo de datos sensibles"),
        ("section_10_kernel_ia", "Kernel IA"),
    ]
    for i, (key, title) in enumerate(titles, 1):
        lines.extend(_section_md(title, report.get(key) or {}, i))

    lines += ["## 11. PyMEs — escenarios", ""]
    pymes = report.get("section_11_pymes") or {}
    for name, sec in pymes.items():
        lines.append(f"### {name}: **{sec.get('percent')}%** ({sec.get('passed')}/{sec.get('total')})")
        for c in sec.get("checks") or []:
            lines.append(f"- {'✓' if c.get('passed') else '✗'} {c.get('label')} — `{c.get('module')}` :: {c.get('evidence')[:100]}")
        lines.append("")

    lines += ["## 12. Riesgos residuales", ""]
    for r in report.get("section_12_residual_risks") or []:
        lines.append(f"- **{r.get('risk')}** — {r.get('evidence')}")

    lines += ["", "## 13. Fortalezas comprobadas", ""]
    for s in (report.get("section_13_strengths") or [])[:25]:
        lines.append(f"- [{s.get('area')}] {s.get('capability')}: {s.get('evidence')[:140]}")

    lines += ["", "## 14. Limitaciones", ""]
    for lim in report.get("section_14_limitations") or []:
        lines.append(f"- {lim}")

    lines += ["", "## 15. Hoja de ruta (90 % / 95 % / enterprise)", ""]
    for block in report.get("section_15_roadmap") or []:
        lines.append(f"### {block.get('section')} — actual {block.get('current_percent')}%")
        lines.append("- **Hacia 90 %:**")
        for x in block.get("to_90") or []:
            lines.append(f"  - {x}")
        lines.append("- **Hacia 95 %:**")
        for x in block.get("to_95") or []:
            lines.append(f"  - {x}")
        lines.append("- **Nivel empresarial:**")
        for x in block.get("enterprise") or []:
            lines.append(f"  - {x}")
        lines.append("")

    lines += [
        "## Verificación complementaria",
        "",
        f"- `scripts/verify_security_hardening.py`: {report.get('verify_hardening', 'no ejecutado')}",
        f"- Servidor local :5000: {report.get('server_check', 'no comprobado')}",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)

    verify = {"passed": False, "exit_code": -1}
    vpath = os.path.join(ROOT, "scripts", "verify_security_hardening.py")
    if os.path.isfile(vpath):
        proc = subprocess.run([sys.executable, vpath], capture_output=True, text=True, cwd=ROOT, timeout=300)
        verify = {"passed": proc.returncode == 0, "exit_code": proc.returncode}

    from services.executive_operational_maturity_service import compute_full_executive_audit

    report = compute_full_executive_audit()
    report["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report["verify_hardening"] = verify
    report["output_dir"] = OUT_DIR

    try:
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:5000/", timeout=10) as resp:
            report["server_check"] = f"HTTP {resp.status} en puerto 5000"
    except Exception as exc:
        report["server_check"] = f"no respondió: {exc}"

    with open(JSON_OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    with open(MD_OUT, "w", encoding="utf-8") as fh:
        fh.write(render_md(report))

    print(f"JSON: {JSON_OUT}")
    print(f"MD:   {MD_OUT}")
    print(f"General: {report['section_1_general']['percent']}%")
    print(f"Hostil: {report['section_2_hostile']['percent']}%")
    print(f"Fintech: {report['section_5_fintech']['percent']}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
