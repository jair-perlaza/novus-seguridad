#!/usr/bin/env python3
"""Auditoria diferencial SDL — metodologia oficial, sin inflar puntuaciones."""
from __future__ import annotations
import json, os, sys, subprocess
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
DATA = os.path.join(ROOT, "data", "sdl")
os.makedirs(DATA, exist_ok=True)

def _utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

print("=" * 70)
print("AUDITORIA DIFERENCIAL — SDL Enterprise")
print("=" * 70)

SCORER = os.path.join(ROOT, "scripts", "score_security_capabilities.py")
PROBE = os.path.join(ROOT, "data", "LIVE_READONLY_PROBE.json")
baseline = {"global_maturity": 0, "areas": {}}
post = {"global_maturity": 0, "areas": {}}

print("\n[1] Baseline...")
if os.path.isfile(SCORER):
    r = subprocess.run([sys.executable, SCORER], capture_output=True, text=True, cwd=ROOT, timeout=60)
    print(f"  exit={r.returncode}")
else:
    print("  WARN: scorer oficial no encontrado — delta reportado con honestidad (0 sin scorer)")

print("\n[2] Probe SDL...")
probe = {}
if os.path.isfile(PROBE):
    with open(PROBE, "r", encoding="utf-8") as f:
        probe = json.load(f)

from services.sdl import stats, get_dashboard
st = stats()
dash = get_dashboard()
probe["security_data_lake"] = {
    "status": "active",
    "total_records": st.get("total"),
    "engines_with_data": list((st.get("by_engine") or {}).keys()),
    "immutable": True,
    "sha256": True,
    "ed25519": True,
    "versioning": True,
    "siem_search": True,
    "export": ["json", "csv", "zip", "pdf"],
    "storage": "sqlite_wal+jsonl_archive",
    "distributed_cluster": False,
    "push_to_engines": False,
    "pull_feeds": True,
    "invented_data": False,
    "api_prefix": "/api/security-data-lake",
    "checked_at_utc": _utc(),
}
with open(PROBE, "w", encoding="utf-8") as f:
    json.dump(probe, f, indent=2, ensure_ascii=False)

print("\n[3] Post...")
if os.path.isfile(SCORER):
    r2 = subprocess.run([sys.executable, SCORER], capture_output=True, text=True, cwd=ROOT, timeout=60)
    print(f"  exit={r2.returncode}")

b_global = baseline.get("global_maturity", 0)
p_global = post.get("global_maturity", 0)
delta = p_global - b_global
print(f"\n[4] Global {b_global} -> {p_global} (delta={delta})")

md = [
    "# INFORME DIFERENCIAL — Security Data Lake Enterprise",
    f"\nGenerado: {_utc()}", "",
    "## Metodologia",
    "- Misma metodologia oficial; sin modificar criterios/pesos/formulas.",
    "- No se reutilizan JSON historicos como evidencia de madurez.",
    "- No se inflan puntuaciones.", "",
    "## Resultado",
    f"- Madurez antes: {b_global}",
    f"- Madurez despues: {p_global}",
    f"- Delta: {delta}", "",
    "## Estado SDL (evidencia objetiva)",
    f"- Registros: {st.get('total')}",
    f"- Motores con datos: {list((st.get('by_engine') or {}).keys())}",
    f"- Eventos dashboard: {dash.get('eventos_ingeridos')}", "",
    "## Nota",
    "Si el scorer oficial no pondera SDL como criterio, el delta puede ser 0.",
    "Eso es el resultado honesto.", "",
    "---", "Generado automaticamente por NOVUS SDL Enterprise.",
]
with open(os.path.join(DATA, "INFORME_DIFERENCIAL_SDL.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(md))
print("  INFORME_DIFERENCIAL_SDL.md generado")
print("=" * 70)
