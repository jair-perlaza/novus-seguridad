#!/usr/bin/env python3
"""LIVE proof — AI Kernel Brain prompt integration."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "data", "ai_kernel_brain")
os.makedirs(OUT, exist_ok=True)

results = []


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ok(n, d=""):
    results.append({"test": n, "status": "PASS", "detail": d, "ts": _utc()})


def _fail(n, d=""):
    results.append({"test": n, "status": "FAIL", "detail": d, "ts": _utc()})


print("=" * 60)
print("NOVUS AI KERNEL BRAIN — LIVE PROOF")
print("=" * 60)

from services.ai_kernel_brain.kernel_prompt import get_kernel_brain
from services.module_kernel_context import build_consult_prompt
from services.kernel_agent import kernel_agent

brain = get_kernel_brain()
greeting = brain.get_time_based_greeting()
prompt = brain.get_system_prompt()

if greeting in ("Buenos días", "Buenas tardes", "Buenas noches"):
    _ok("time_greeting_live", greeting)
else:
    _fail("time_greeting_live", greeting)

if "executes_actions=false" in prompt and "No ejecutar aislamiento" in prompt:
    _ok("prompt_policy_aligned", "analyze-only")
else:
    _fail("prompt_policy_aligned", "missing policy lines")

consult = build_consult_prompt("dashboard")
if consult.get("system_prompt") and consult.get("greeting"):
    _ok("module_consult_wired", consult.get("module"))
else:
    _fail("module_consult_wired", str(consult.keys()))

greply = kernel_agent._greeting_response({}, {"sector_label": "SOC"})
if any(x in greply for x in ("Buenos días", "Buenas tardes", "Buenas noches")):
    _ok("kernel_agent_greeting", greply.split("\n")[0][:40])
else:
    _fail("kernel_agent_greeting", greply[:60])

try:
    import requests
    r = requests.get("http://127.0.0.1:5000/login", timeout=8)
    if r.status_code == 200:
        _ok("http_login_200", str(r.status_code))
    else:
        _fail("http_login_200", str(r.status_code))
except Exception as exc:
    _fail("http_login_200", str(exc)[:80])

pass_n = sum(1 for x in results if x["status"] == "PASS")
fail_n = sum(1 for x in results if x["status"] == "FAIL")

evidence = {
    "module": "ai_kernel_brain",
    "generated_at_utc": _utc(),
    "pass": pass_n,
    "fail": fail_n,
    "test_results": results,
    "greeting": greeting,
    "system_prompt_excerpt": prompt[:500],
    "consult_keys": list(consult.keys()),
    "sigma_rule": "NOT PROVIDED",
    "yara_rule": "NOT PROVIDED",
    "executes_actions_default": False,
    "invented": False,
}

with open(os.path.join(OUT, "LIVE_PROOF_AI_KERNEL_BRAIN.json"), "w", encoding="utf-8") as f:
    json.dump(evidence, f, indent=2, ensure_ascii=False)

with open(os.path.join(OUT, "INFORME_AI_KERNEL_BRAIN.md"), "w", encoding="utf-8") as f:
    f.write(f"""# INFORME AI KERNEL BRAIN

Generado: {_utc()}

## Resultados LIVE: {pass_n}/{pass_n + fail_n} PASS

## Integrado
- NOVUSKernelBrain → services/ai_kernel_brain/kernel_prompt.py
- Saludo horario → kernel_agent._greeting_response
- Prompt maestro → module_kernel_context.build_consult_prompt + /api/ai/context

## Ajustado respecto al código original
- "Ejecutar bloqueo/aislamiento autónomo" → recomendación + confirmación admin/Swarm
- executes_actions=false explícito en prompt

## Pendiente
- Regla Sigma (no proporcionada)
- Regla YARA (no proporcionada)

Delta madurez oficial: 0
""")

print(f"\nRESULTADO: {pass_n} PASS | {fail_n} FAIL")
print(f"Entregables: {OUT}")
