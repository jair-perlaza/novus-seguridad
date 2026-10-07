#!/usr/bin/env python3
"""
Auditoría diferencial Threat Intelligence Enterprise — misma metodología oficial.
NO modifica criterios, ponderaciones ni fórmula.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "threat_intelligence_enterprise"
OUT.mkdir(parents=True, exist_ok=True)
OFF = ROOT / "data" / "audit_security_capabilities_20260725"
BASELINE_GLOBAL = 86.2
FOCUS = [
    "Kernel IA",
    "Swarm Defense",
    "Endpoint",
    "Red",
    "Centro de Defensa",
    "Compliance",
]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    live = json.loads((OUT / "LIVE_PROOF_THREAT_INTELLIGENCE.json").read_text(encoding="utf-8"))
    pentest = json.loads((OUT / "PENTEST_THREAT_INTELLIGENCE.json").read_text(encoding="utf-8"))
    matrix = json.loads((OUT / "MATRIZ_THREAT_INTELLIGENCE.json").read_text(encoding="utf-8"))

    prev_evidence_path = OFF / "EVIDENCE_SECURITY_CAPABILITIES.json"
    prev = {}
    if prev_evidence_path.is_file():
        prev = json.loads(prev_evidence_path.read_text(encoding="utf-8"))

    probe_path = OFF / "LIVE_READONLY_PROBE.json"
    probe = {}
    if probe_path.is_file():
        probe = json.loads(probe_path.read_text(encoding="utf-8"))
    probe["threat_intelligence_enterprise"] = {
        "ok": bool(live.get("ok")),
        "pentest_ok": bool(pentest.get("ok")),
        "connectors": [c["name"] for c in matrix.get("connectors", [])],
        "capabilities": len(matrix.get("capabilities", [])),
        "live_proof": str(OUT / "LIVE_PROOF_THREAT_INTELLIGENCE.json"),
    }
    probe_path.write_text(json.dumps(probe, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_security_capabilities_audit_reports.py")],
        cwd=str(ROOT),
    )
    if r.returncode != 0:
        print(f"Official scorer failed: {r.returncode}")
        return r.returncode

    evidence = json.loads((OFF / "EVIDENCE_SECURITY_CAPABILITIES.json").read_text(encoding="utf-8"))
    areas = {a["area"]: a for a in evidence.get("areas") or []}
    prev_areas = {a["area"]: a for a in (prev.get("areas") or [])}

    rows = []
    for name in FOCUS:
        now_a = areas.get(name) or {}
        prev_a = prev_areas.get(name) or {}
        now_pct = float(now_a.get("porcentaje") or now_a.get("pct") or 0)
        prev_pct = float(prev_a.get("porcentaje") or prev_a.get("pct") or 0)
        rows.append({
            "area": name,
            "antes_pct": prev_pct,
            "ahora_pct": now_pct,
            "delta_pp": round(now_pct - prev_pct, 1),
        })

    glob = evidence.get("global") or {}
    now_global = float(glob.get("porcentaje") or glob.get("pct") or 0)
    prev_global = float((prev.get("global") or {}).get("porcentaje") or (prev.get("global") or {}).get("pct") or BASELINE_GLOBAL)

    diff = {
        "generated_at_utc": utc(),
        "methodology": "scripts/build_security_capabilities_audit_reports.py — sin cambio de criterios/ponderaciones/fórmula",
        "live_ok": live.get("ok"),
        "pentest_ok": pentest.get("ok"),
        "areas": rows,
        "global": {
            "antes_pct": prev_global,
            "ahora_pct": now_global,
            "delta_pp": round(now_global - prev_global, 1),
        },
        "attribution": {
            "tie_changes_official_criteria": False,
            "note": (
                "TIE aporta feeds externos reales, inteligencia propia anonimizada, "
                "enriquecimiento para Kernel IA, dashboard, API, Swarm IOC publish. "
                "No se añadieron criterios nuevos al scorer oficial. "
                "Cualquier Δ=0 es el resultado esperado y honesto."
            ),
        },
    }
    (OUT / "AUDITORIA_DIFERENCIAL_TIE.json").write_text(
        json.dumps(diff, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    md = []
    md.append("# INFORME DIFERENCIAL — Threat Intelligence Enterprise\n\n")
    md.append(f"**Generado:** {utc()}\n\n")
    md.append("## Metodología\n\n")
    md.append("Se ejecutó el scorer oficial **sin modificar criterios, ponderaciones ni fórmula**.\n\n")
    md.append("## Resultados por Área\n\n")
    md.append("| Área | Antes (%) | Ahora (%) | Δ (pp) |\n|------|-----------|-----------|--------|\n")
    for r in rows:
        md.append(f"| {r['area']} | {r['antes_pct']:.1f} | {r['ahora_pct']:.1f} | {r['delta_pp']:+.1f} |\n")
    md.append(f"\n## Madurez Global\n\n")
    md.append(f"- **Antes:** {prev_global:.1f}%\n")
    md.append(f"- **Ahora:** {now_global:.1f}%\n")
    md.append(f"- **Δ:** {round(now_global - prev_global, 1):+.1f} pp\n\n")
    md.append("## Atribución\n\n")
    md.append(diff["attribution"]["note"] + "\n\n")
    md.append("## LIVE Proof\n\n")
    md.append(f"- LIVE: {'✅ APROBADO' if live.get('ok') else '❌ FALLO'}\n")
    md.append(f"- Pentest: {'✅ APROBADO' if pentest.get('ok') else '❌ FALLO'}\n")

    (OUT / "INFORME_DIFERENCIAL_THREAT_INTELLIGENCE.md").write_text("".join(md), encoding="utf-8")

    try:
        from fpdf import FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "INFORME DIFERENCIAL - Threat Intelligence Enterprise", ln=True, align="C")
        pdf.set_font("Helvetica", "", 9)
        for line in "".join(md).split("\n"):
            safe = line.encode("latin-1", "replace").decode("latin-1")
            if safe.strip():
                pdf.multi_cell(180, 4, safe)
            else:
                pdf.ln(3)
        pdf.output(str(OUT / "INFORME_THREAT_INTELLIGENCE.pdf"))
    except Exception as exc:
        print(f"PDF warning: {exc}")

    print(f"\nAuditoría diferencial completada.")
    print(f"  Global: {prev_global:.1f}% -> {now_global:.1f}% (delta {round(now_global - prev_global, 1):+.1f} pp)")
    print(f"  Entregables en: {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
