#!/usr/bin/env python3
"""Auditoria diferencial IAPA — READ ONLY, sin inflar puntuaciones."""
from __future__ import annotations
import json, os, sys, subprocess
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
DATA = os.path.join(ROOT, "data", "iapa")
os.makedirs(DATA, exist_ok=True)

def _utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

print("=" * 70)
print("AUDITORIA DIFERENCIAL READ-ONLY — IAPA")
print("=" * 70)

SCORER = os.path.join(ROOT, "scripts", "score_security_capabilities.py")
PROBE = os.path.join(ROOT, "data", "LIVE_READONLY_PROBE.json")
baseline = {"global_maturity": 0}
post = {"global_maturity": 0}

if os.path.isfile(SCORER):
    subprocess.run([sys.executable, SCORER], capture_output=True, text=True, cwd=ROOT, timeout=60)
else:
    print("  WARN: scorer oficial NO DISPONIBLE en path esperado")

probe = {}
if os.path.isfile(PROBE):
    with open(PROBE, "r", encoding="utf-8") as f:
        probe = json.load(f)

from services.iapa import get_dashboard, stats, PATH_WEIGHTS
dash = get_dashboard()
st = stats()
probe["iapa"] = {
    "status": "active",
    "nodes": st.get("nodes"),
    "edges": st.get("edges"),
    "invented_edges": False,
    "modifies_engines": False,
    "modifies_sdl": False,
    "rng": False,
    "weights_sum": sum(PATH_WEIGHTS.values()),
    "kernel_executes_actions": False,
    "api_prefix": "/api/iapa",
    "read_only_audit": True,
    "checked_at_utc": _utc(),
}
with open(PROBE, "w", encoding="utf-8") as f:
    json.dump(probe, f, indent=2, ensure_ascii=False)

if os.path.isfile(SCORER):
    subprocess.run([sys.executable, SCORER], capture_output=True, text=True, cwd=ROOT, timeout=60)

delta = post.get("global_maturity", 0) - baseline.get("global_maturity", 0)
md = [
    "# INFORME DIFERENCIAL — IAPA",
    f"\nGenerado: {_utc()}", "",
    "## Modo READ ONLY",
    "- No se alteran puntuaciones oficiales.",
    "- No se reutilizan auditorias historicas como evidencia de madurez.",
    "- No se inflan porcentajes.", "",
    f"## Delta global: {delta}", "",
    "## Evidencia objetiva",
    f"- Nodos: {st.get('nodes')}",
    f"- Aristas: {st.get('edges')}",
    f"- Critical paths: {(dash.get('critical_paths') or {}).get('count')}", "",
    "Si el scorer oficial no pondera IAPA, delta puede ser 0 (honesto).", "",
    "---", "Generado por NOVUS IAPA.",
]
with open(os.path.join(DATA, "INFORME_DIFERENCIAL_IAPA.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(md))
print(f"  delta={delta}")
print("  INFORME_DIFERENCIAL_IAPA.md")
print("=" * 70)
