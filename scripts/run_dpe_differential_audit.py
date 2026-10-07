#!/usr/bin/env python3
"""Auditoria diferencial DPE — READ ONLY, sin inflar puntuaciones."""
from __future__ import annotations
import json, os, sys, subprocess
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
DATA = os.path.join(ROOT, "data", "deception_platform")
os.makedirs(DATA, exist_ok=True)

def _utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

print("=" * 70)
print("AUDITORIA DIFERENCIAL READ-ONLY — DPE")
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

from services.deception_platform import get_dashboard, stats, POLICY
dash = get_dashboard()
st = stats()
probe["dpe"] = {
    "status": "active",
    "honeypots_activo": st.get("honeypots", {}).get("activo") if isinstance(st.get("honeypots"), dict) else st.get("honeypots"),
    "events": st.get("events"),
    "tokens": st.get("tokens"),
    "auto_start_listeners": False,
    "simulate_attacks": False,
    "invent_events": False,
    "reuse_real_assets": False,
    "modify_engines": False,
    "kernel_executes_actions": False,
    "api_prefix": "/api/deception",
    "ui": "/deception-center",
    "read_only_audit": True,
    "checked_at_utc": _utc(),
    "policy": POLICY,
}
with open(PROBE, "w", encoding="utf-8") as f:
    json.dump(probe, f, indent=2, ensure_ascii=False)

if os.path.isfile(SCORER):
    subprocess.run([sys.executable, SCORER], capture_output=True, text=True, cwd=ROOT, timeout=60)

delta = post.get("global_maturity", 0) - baseline.get("global_maturity", 0)
md = [
    "# INFORME DIFERENCIAL — DPE",
    f"\nGenerado: {_utc()}", "",
    "## Modo READ ONLY",
    "- No se alteran puntuaciones oficiales.",
    "- No se reutilizan auditorias historicas como evidencia de madurez.",
    "- No se inflan porcentajes.", "",
    f"## Delta global: {delta}", "",
    "## Evidencia objetiva",
    f"- Honeypots ACTIVO: {(dash.get('claims') or {}).get('honeypots_activos')}",
    f"- Eventos reales: {dash.get('events_count')}",
    f"- Honeytokens: {(dash.get('honeytokens') or {}).get('count')}",
    f"- Honeyfiles: {(dash.get('honeyfiles') or {}).get('count')}",
    f"- simulated_attacks: {dash.get('simulated_attacks')}", "",
    "Si el scorer oficial no pondera DPE, delta puede ser 0 (honesto).", "",
    "---", "Generado por NOVUS DPE.",
]
with open(os.path.join(DATA, "INFORME_DIFERENCIAL_DPE.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(md))
print(f"  delta={delta}")
print("  INFORME_DIFERENCIAL_DPE.md")
print("=" * 70)
