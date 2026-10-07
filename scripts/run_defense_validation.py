#!/usr/bin/env python3
"""Ejecuta todas las suites de defensa y genera informe técnico consolidado."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")

SUITES = [
    ("test_defense_comprehensive.py", "Validación integral motores"),
    ("test_defense_hardening.py", "Auditoría fortalecimiento"),
    ("test_network_ndr.py", "Network NDR"),
    ("test_ndci_manual.py", "NDCI casos manuales"),
    ("test_topology_ndci.py", "Topology + NDCI"),
    ("test_threat_intelligence.py", "Centro Inteligencia"),
]


def run_suite(script: str) -> dict:
    path = os.path.join(SCRIPTS, script)
    if not os.path.isfile(path):
        return {"script": script, "skipped": True, "exit_code": -1, "output_tail": "no existe"}
    t0 = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, path],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return {
        "script": script,
        "exit_code": proc.returncode,
        "elapsed_sec": round(time.perf_counter() - t0, 2),
        "passed": proc.returncode == 0,
        "output_tail": (proc.stdout + proc.stderr)[-2000:],
    }


def load_json(name: str) -> dict:
    path = os.path.join(SCRIPTS, name)
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def build_markdown(report: dict) -> str:
    lines = [
        "# Informe Técnico — Validación Defensa NOVUS",
        f"\n**Generado:** {report['generated_at']}",
        f"\n**Resultado global:** {'TODAS PASS' if report['all_pass'] else 'HAY FALLOS'}",
        f"\n**Suites:** {report['suites_passed']}/{report['suites_total']}",
        "\n## Suites ejecutadas\n",
    ]
    for s in report["suites"]:
        status = "PASS" if s.get("passed") else ("SKIP" if s.get("skipped") else "FAIL")
        lines.append(f"- **{s['script']}** — {status} ({s.get('elapsed_sec', 0)}s)")

    comp = report.get("comprehensive") or {}
    if comp:
        lines.append("\n## Mecanismos revisados\n")
        for m in comp.get("mechanisms_reviewed") or []:
            lines.append(f"- {m}")
        lines.append("\n## Resultados por categoría\n")
        for cat, data in (comp.get("categories") or {}).items():
            lines.append(f"- **{cat}:** {data.get('passed', 0)}/{data.get('total', 0)}")
        lines.append("\n## Rendimiento\n")
        perf = comp.get("performance") or {}
        for k, v in perf.items():
            lines.append(f"- {k}: {v}")
        lines.append("\n## Cobertura amenazas\n")
        for threat, info in (comp.get("threat_coverage") or {}).items():
            impl = "implementado" if info.get("implemented") else "limitado"
            val = "validado" if info.get("validated") else "pendiente entorno real"
            lines.append(f"- **{threat}** ({impl}, {val}): {info.get('motor', '')}")
        lines.append("\n## Limitaciones técnicas\n")
        for lim in comp.get("limitations") or []:
            lines.append(f"- {lim}")

    hard = report.get("hardening") or {}
    if hard.get("strengthened"):
        lines.append("\n## Mejoras implementadas (sesión)\n")
        for item in hard["strengthened"]:
            lines.append(f"- {item}")

    return "\n".join(lines) + "\n"


def main():
    results = []
    for script, _desc in SUITES:
        print(f"\n>>> Ejecutando {script}...")
        results.append(run_suite(script))

    all_pass = all(r.get("passed") or r.get("skipped") for r in results)
    passed_count = sum(1 for r in results if r.get("passed"))

    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "suites": results,
        "suites_passed": passed_count,
        "suites_total": len([r for r in results if not r.get("skipped")]),
        "all_pass": all_pass,
        "comprehensive": load_json("defense_comprehensive_audit.json"),
        "hardening": load_json("defense_hardening_audit.json"),
    }

    json_path = os.path.join(SCRIPTS, "defense_validation_report.json")
    md_path = os.path.join(SCRIPTS, "defense_technical_report.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(build_markdown(report))

    print(f"\n=== VALIDACIÓN GLOBAL: {passed_count}/{len(SUITES)} suites OK ===")
    print(f"JSON: {json_path}")
    print(f"MD:   {md_path}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
