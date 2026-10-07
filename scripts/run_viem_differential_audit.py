#!/usr/bin/env python3
"""Auditoria diferencial VIEM."""
from __future__ import annotations
import json, os, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); os.chdir(ROOT)
OUT = ROOT / "data" / "viem"; OUT.mkdir(parents=True, exist_ok=True)
OFF = ROOT / "data" / "audit_security_capabilities_20260725"
BASELINE = 86.2
FOCUS = ["Kernel IA", "Swarm Defense", "Centro de Defensa", "Endpoint", "Compliance"]

def utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def main() -> int:
    live = json.loads((OUT / "LIVE_PROOF_VIEM.json").read_text(encoding="utf-8"))
    pentest = json.loads((OUT / "PENTEST_VIEM.json").read_text(encoding="utf-8"))
    matrix = json.loads((OUT / "MATRIZ_VIEM.json").read_text(encoding="utf-8"))

    prev = json.loads((OFF / "EVIDENCE_SECURITY_CAPABILITIES.json").read_text(encoding="utf-8")) if (OFF / "EVIDENCE_SECURITY_CAPABILITIES.json").is_file() else {}

    probe_path = OFF / "LIVE_READONLY_PROBE.json"
    probe = json.loads(probe_path.read_text(encoding="utf-8")) if probe_path.is_file() else {}
    probe["viem"] = {"ok": bool(live.get("ok")), "pentest_ok": bool(pentest.get("ok")), "capabilities": len(matrix.get("capabilities", []))}
    probe_path.write_text(json.dumps(probe, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_security_capabilities_audit_reports.py")], cwd=str(ROOT))
    if r.returncode != 0: return r.returncode

    evidence = json.loads((OFF / "EVIDENCE_SECURITY_CAPABILITIES.json").read_text(encoding="utf-8"))
    areas = {a["area"]: a for a in evidence.get("areas") or []}
    prev_areas = {a["area"]: a for a in (prev.get("areas") or [])}
    rows = []
    for name in FOCUS:
        now_a = areas.get(name) or {}; prev_a = prev_areas.get(name) or {}
        now_pct = float(now_a.get("porcentaje") or now_a.get("pct") or 0)
        prev_pct = float(prev_a.get("porcentaje") or prev_a.get("pct") or 0)
        rows.append({"area": name, "antes_pct": prev_pct, "ahora_pct": now_pct, "delta_pp": round(now_pct - prev_pct, 1)})

    glob = evidence.get("global") or {}
    now_g = float(glob.get("porcentaje") or glob.get("pct") or 0)
    prev_g = float((prev.get("global") or {}).get("porcentaje") or (prev.get("global") or {}).get("pct") or BASELINE)

    diff = {
        "generated_at_utc": utc(), "methodology": "scorer oficial sin cambio de criterios",
        "live_ok": live.get("ok"), "pentest_ok": pentest.get("ok"), "areas": rows,
        "global": {"antes_pct": prev_g, "ahora_pct": now_g, "delta_pp": round(now_g - prev_g, 1)},
        "attribution": {"viem_changes_criteria": False, "note": "VIEM aporta gestion de vulnerabilidades, risk scoring, ASM correlation, TIE enrichment. Sin criterios nuevos."},
    }
    (OUT / "AUDITORIA_DIFERENCIAL_VIEM.json").write_text(json.dumps(diff, indent=2, ensure_ascii=False), encoding="utf-8")

    md = [f"# INFORME DIFERENCIAL -- VIEM\n\n**Generado:** {utc()}\n\n"]
    md.append("## Metodologia\n\nScorer oficial sin modificar criterios.\n\n")
    md.append("| Area | Antes (%) | Ahora (%) | Delta (pp) |\n|------|-----------|-----------|------------|\n")
    for r in rows: md.append(f"| {r['area']} | {r['antes_pct']:.1f} | {r['ahora_pct']:.1f} | {r['delta_pp']:+.1f} |\n")
    md.append(f"\n## Madurez Global\n\n- Antes: {prev_g:.1f}%\n- Ahora: {now_g:.1f}%\n- Delta: {round(now_g - prev_g, 1):+.1f} pp\n")
    (OUT / "INFORME_DIFERENCIAL_VIEM.md").write_text("".join(md), encoding="utf-8")

    try:
        from fpdf import FPDF
        pdf = FPDF(); pdf.add_page(); pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "INFORME DIFERENCIAL VIEM", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.set_font("Helvetica", "", 9)
        for line in "".join(md).split("\n"):
            safe = line.encode("latin-1", "replace").decode("latin-1")
            if safe.strip(): pdf.multi_cell(180, 4, safe)
            else: pdf.ln(3)
        pdf.output(str(OUT / "INFORME_VIEM.pdf"))
    except Exception as exc: print(f"PDF: {exc}")

    print(f"\nAuditoria diferencial completada.\n  Global: {prev_g:.1f}% -> {now_g:.1f}% (delta {round(now_g - prev_g, 1):+.1f} pp)")
    return 0

if __name__ == "__main__": sys.exit(main())
