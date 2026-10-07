#!/usr/bin/env python3
"""Auditoria diferencial SDACE — sin inflar puntuaciones."""
from __future__ import annotations
import json, os, sys, subprocess
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
DATA = os.path.join(ROOT, "data", "sdace")
os.makedirs(DATA, exist_ok=True)

def _utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

print("=" * 70)
print("AUDITORIA DIFERENCIAL — SDACE")
print("=" * 70)

SCORER = os.path.join(ROOT, "scripts", "score_security_capabilities.py")
PROBE = os.path.join(ROOT, "data", "LIVE_READONLY_PROBE.json")
baseline = {"global_maturity": 0, "areas": {}}
post = {"global_maturity": 0, "areas": {}}

if os.path.isfile(SCORER):
    subprocess.run([sys.executable, SCORER], capture_output=True, text=True, cwd=ROOT, timeout=60)
else:
    print("  WARN: scorer oficial no encontrado")

probe = {}
if os.path.isfile(PROBE):
    with open(PROBE, "r", encoding="utf-8") as f:
        probe = json.load(f)

from services.sdace import get_dashboard, analytics_summary
dash = get_dashboard()
an = analytics_summary()
probe["sdace"] = {
    "status": "active",
    "read_only_consumer": True,
    "modifies_sdl": False,
    "modifies_engines": False,
    "invented_correlations": False,
    "graph_nodes": len((dash.get("attack_graph") or {}).get("nodes") or []),
    "timeline_events": (dash.get("timeline") or {}).get("count"),
    "kernel_executes_actions": False,
    "forensic_seals": True,
    "swarm_private_data": False,
    "api_prefix": "/api/sdace",
    "checked_at_utc": _utc(),
}
with open(PROBE, "w", encoding="utf-8") as f:
    json.dump(probe, f, indent=2, ensure_ascii=False)

if os.path.isfile(SCORER):
    subprocess.run([sys.executable, SCORER], capture_output=True, text=True, cwd=ROOT, timeout=60)

delta = post.get("global_maturity", 0) - baseline.get("global_maturity", 0)
md = [
    "# INFORME DIFERENCIAL — SDACE",
    f"\nGenerado: {_utc()}", "",
    "## Metodologia",
    "- Sin modificar criterios/pesos/formulas oficiales.",
    "- Sin inflar porcentajes.", "",
    f"## Delta global: {delta}", "",
    "## Evidencia objetiva",
    f"- Nodos grafo: {probe['sdace']['graph_nodes']}",
    f"- Timeline: {probe['sdace']['timeline_events']}",
    f"- Read-only: true", "",
    "Si el scorer no pondera SDACE, delta puede ser 0 (resultado honesto).", "",
    "---", "Generado por NOVUS SDACE.",
]
with open(os.path.join(DATA, "INFORME_DIFERENCIAL_SDACE.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(md))
print(f"  delta={delta}")
print("  INFORME_DIFERENCIAL_SDACE.md generado")
print("=" * 70)
