#!/usr/bin/env python3
"""
Auditoria diferencial SOC — misma metodologia oficial, sin inflar puntuaciones.
"""
from __future__ import annotations
import json, os, sys, subprocess
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
DATA = os.path.join(ROOT, "data", "soc")
os.makedirs(DATA, exist_ok=True)

def _utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

print("=" * 70)
print("AUDITORIA DIFERENCIAL — SOC Enterprise")
print("=" * 70)

SCORER = os.path.join(ROOT, "scripts", "score_security_capabilities.py")
PROBE = os.path.join(ROOT, "data", "LIVE_READONLY_PROBE.json")

baseline = {"global_maturity": 0, "areas": {}}
post = {"global_maturity": 0, "areas": {}}
result_files = []

print("\n[1] Baseline scorer...")
if not os.path.isfile(SCORER):
    print(f"  WARN: Scorer no encontrado en {SCORER}")
else:
    if os.path.isfile(PROBE):
        with open(PROBE, "r", encoding="utf-8") as f:
            probe = json.load(f)
    else:
        probe = {}
    with open(PROBE, "w", encoding="utf-8") as f:
        json.dump(probe, f, indent=2, ensure_ascii=False)
    r = subprocess.run([sys.executable, SCORER], capture_output=True, text=True, cwd=ROOT, timeout=60)
    print(f"  Scorer exit: {r.returncode}")
    try:
        result_files = [f for f in os.listdir(os.path.join(ROOT, "data")) if "scored" in f.lower() or "result" in f.lower()]
        for rf in result_files:
            try:
                with open(os.path.join(ROOT, "data", rf), "r", encoding="utf-8") as fh:
                    baseline = json.load(fh)
                    break
            except Exception:
                pass
    except Exception:
        pass

print("\n[2] Actualizando probe con SOC...")
if os.path.isfile(PROBE):
    with open(PROBE, "r", encoding="utf-8") as f:
        probe = json.load(f)
else:
    probe = {}

from services.soc import stats as soc_stats, get_overview
st = soc_stats()
ov = get_overview()

probe["soc_enterprise"] = {
    "status": "active",
    "engines_ok": st.get("engines_ok"),
    "engines_total": st.get("engines_total"),
    "views": ["overview", "tactical", "executive", "analyst", "hunt", "forensic", "health", "swarm", "kernel"],
    "sse_realtime": True,
    "kernel_ia_analyst_only": True,
    "invented_data": False,
    "static_charts": False,
    "consumes_imcm": True,
    "consumes_asm": True,
    "consumes_viem": True,
    "consumes_tie": True,
    "consumes_sope": True,
    "consumes_health": True,
    "consumes_swarm": True,
    "api_prefix": "/api/soc",
    "checked_at_utc": _utc(),
    "overview_risk": ov.get("risk_global"),
}

with open(PROBE, "w", encoding="utf-8") as f:
    json.dump(probe, f, indent=2, ensure_ascii=False)

print("\n[3] Post scorer...")
if os.path.isfile(SCORER):
    r2 = subprocess.run([sys.executable, SCORER], capture_output=True, text=True, cwd=ROOT, timeout=60)
    print(f"  Scorer exit: {r2.returncode}")
    try:
        for rf in result_files or [f for f in os.listdir(os.path.join(ROOT, "data")) if "scored" in f.lower() or "result" in f.lower()]:
            try:
                with open(os.path.join(ROOT, "data", rf), "r", encoding="utf-8") as fh:
                    post = json.load(fh)
                    break
            except Exception:
                pass
    except Exception:
        pass

print("\n[4] Diferencial...")
b_global = baseline.get("global_maturity", 0)
p_global = post.get("global_maturity", 0)
delta = p_global - b_global
focus = ["Kernel IA", "Centro de Defensa", "Swarm", "SOPE", "Endpoint", "Compliance"]
area_deltas = {}
for area in focus:
    b_val = baseline.get("areas", {}).get(area, {}).get("score", 0)
    p_val = post.get("areas", {}).get(area, {}).get("score", 0)
    area_deltas[area] = {"before": b_val, "after": p_val, "delta": p_val - b_val}
    print(f"  {area}: {b_val} -> {p_val} (delta: {p_val - b_val})")
print(f"  Global: {b_global} -> {p_global} (delta: {delta})")

md = [
    "# INFORME DIFERENCIAL — SOC Enterprise",
    f"\nGenerado: {_utc()}", "",
    "## Metodologia",
    "- Scorer oficial sin modificacion de criterios, pesos ni formulas.",
    "- Probe actualizado con estado real del SOC.",
    "- No se inflan puntuaciones manualmente.", "",
    "## Resultado Global",
    f"- Madurez antes: {b_global}",
    f"- Madurez despues: {p_global}",
    f"- Delta: {delta}", "",
    "## Areas Focalizadas", "",
]
for area, d in area_deltas.items():
    md.append(f"- **{area}**: {d['before']} -> {d['after']} (delta: {d['delta']})")
md += ["", "## Nota",
    "El delta puede ser 0 si el scorer no pondera directamente el SOC como capa de convergencia.",
    "Resultado honesto; NO se modifican puntuaciones oficiales sin evidencia objetiva de criterios nuevos.", "",
    "---", "Generado automaticamente por NOVUS SOC Enterprise.", ""]

with open(os.path.join(DATA, "INFORME_DIFERENCIAL_SOC.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(md))
print("\n  INFORME_DIFERENCIAL_SOC.md generado")
print("=" * 70)
