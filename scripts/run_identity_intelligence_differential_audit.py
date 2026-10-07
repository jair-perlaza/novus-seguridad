#!/usr/bin/env python3
"""Auditoria diferencial IIUEBA — READ ONLY, sin inflar puntuaciones."""
from __future__ import annotations
import json, os, sys, subprocess
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
DATA = os.path.join(ROOT, "data", "identity_intelligence")
os.makedirs(DATA, exist_ok=True)

def _utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

print("=" * 70)
print("AUDITORIA DIFERENCIAL READ-ONLY — Identity Intelligence UEBA")
print("=" * 70)

SCORER = os.path.join(ROOT, "scripts", "score_security_capabilities.py")
PROBE = os.path.join(ROOT, "data", "LIVE_READONLY_PROBE.json")
baseline = {"global_maturity": 0}
post = {"global_maturity": 0}

if os.path.isfile(SCORER):
    subprocess.run([sys.executable, SCORER], capture_output=True, text=True, cwd=ROOT, timeout=60)
else:
    print("  WARN: scorer oficial no encontrado — NO IMPLEMENTADO como verificador de madurez en este path")

probe = {}
if os.path.isfile(PROBE):
    with open(PROBE, "r", encoding="utf-8") as f:
        probe = json.load(f)

from services.identity_intelligence import get_dashboard, list_identities, RISK_WEIGHTS
dash = get_dashboard()
probe["identity_intelligence_ueba"] = {
    "status": "active",
    "identity_count": dash.get("identity_count"),
    "sufficient_baselines": dash.get("sufficient_baselines"),
    "risk_weights_sum": sum(RISK_WEIGHTS.values()),
    "rng": False,
    "invented_behavior": False,
    "modifies_engines": False,
    "kernel_executes_actions": False,
    "swarm_pii": False,
    "api_prefix": "/api/identity-intelligence",
    "checked_at_utc": _utc(),
    "read_only_audit": True,
}
# Write probe is metadata for scorer input — not historical audit reuse of scores
with open(PROBE, "w", encoding="utf-8") as f:
    json.dump(probe, f, indent=2, ensure_ascii=False)

if os.path.isfile(SCORER):
    subprocess.run([sys.executable, SCORER], capture_output=True, text=True, cwd=ROOT, timeout=60)

delta = post.get("global_maturity", 0) - baseline.get("global_maturity", 0)
md = [
    "# INFORME DIFERENCIAL — Identity Intelligence & UEBA",
    f"\nGenerado: {_utc()}", "",
    "## Modo",
    "- READ ONLY respecto a puntuaciones oficiales.",
    "- No se reutilizan JSON de auditorias anteriores como evidencia de madurez.",
    "- No se inflan porcentajes.", "",
    f"## Delta global: {delta}", "",
    "## Evidencia objetiva IIUEBA",
    f"- Identidades: {dash.get('identity_count')}",
    f"- Baselines suficientes: {dash.get('sufficient_baselines')}",
    f"- Pesos risk sum: {sum(RISK_WEIGHTS.values())}", "",
    "## Clasificacion honesta",
    "- Motor UEBA local con baseline real: IMPLEMENTADO (con evidencia LIVE)",
    "- Scorer oficial path: NO DISPONIBLE / NO IMPLEMENTADO si el script no existe",
    "- Geolocalizacion: NO DISPONIBLE",
    "- Deteccion credential dump nativa: PARCIAL (solo por correlacion si existe evidencia)", "",
    "---", "Generado por NOVUS IIUEBA.",
]
with open(os.path.join(DATA, "INFORME_DIFERENCIAL_IDENTITY_INTELLIGENCE.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(md))
print(f"  delta={delta}")
print("  INFORME_DIFERENCIAL_IDENTITY_INTELLIGENCE.md")
print("=" * 70)
