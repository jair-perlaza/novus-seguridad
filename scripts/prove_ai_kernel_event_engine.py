#!/usr/bin/env python3
"""LIVE proof — AI Kernel Event Engine."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "data", "ai_kernel_event_engine")
os.makedirs(OUT, exist_ok=True)

results = []


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ok(name, detail=""):
    results.append({"test": name, "status": "PASS", "detail": detail, "ts": _utc()})


def _fail(name, detail=""):
    results.append({"test": name, "status": "FAIL", "detail": detail, "ts": _utc()})


print("=" * 60)
print("NOVUS AI KERNEL EVENT ENGINE — LIVE PROOF")
print("=" * 60)

from services.ai_kernel_event_engine.event_engine import get_ai_kernel_engine, analyze_security_event
from services.ai_kernel_event_engine.knowledge_adapter import get_knowledge_adapter
from services.ai_kernel_event_engine.kernel_insights import build_kernel_event_engine_context

evento = {
    "mac": "AA:BB:CC:44:55:66",
    "ip": "192.168.1.30",
    "device_type": "PORTATIL",
    "attack_count": 1,
    "details": "cmd.exe iniciado por winword.exe",
}

kernel = get_ai_kernel_engine()
v1 = kernel.analyze_event("ANOMALOUS_PROCESS", evento)
if v1.get("executes_actions") is False and v1.get("action_executed_autonomously") is False:
    _ok("first_inference_no_auto_execute", v1.get("recommended_action", ""))
else:
    _fail("first_inference_no_auto_execute", str(v1)[:120])

adapter = get_knowledge_adapter()
adapter.learn_from_feedback(
    mac="AA:BB:CC:44:55:66",
    original_verdict=v1.get("recommended_action", ""),
    admin_action="OVERRIDE_UNBLOCK",
    reason="Script de mantenimiento de TI interno autorizado",
)
v2 = kernel.analyze_event("ANOMALOUS_PROCESS", evento)
if v2.get("recommended_action") == "ALLOW":
    _ok("learning_adaptation", f"risk={v2.get('calculated_risk')}")
else:
    _fail("learning_adaptation", str(v2)[:120])

ctx = build_kernel_event_engine_context()
if ctx.get("executes_actions") is False:
    _ok("kernel_context_analyze_only", f"exceptions={(ctx.get('learning') or {}).get('exceptions_n')}")
else:
    _fail("kernel_context_analyze_only", str(ctx)[:80])

# Defense controller integration
try:
    from services.network_device_defense.defense_controller import get_defense_controller

    ctrl = get_defense_controller()
    atk = ctrl.register_attack("AA:BB:CC:44:55:66", "escaneo de puertos", auto_isolate=False)
    ka = (atk.get("kernel_analysis") or {})
    if ka.get("executes_actions") is False:
        _ok("defense_controller_kernel_wired", ka.get("recommendation", ""))
    else:
        _fail("defense_controller_kernel_wired", str(ka)[:80])
except Exception as exc:
    _fail("defense_controller_kernel_wired", str(exc)[:80])

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
    "module": "ai_kernel_event_engine",
    "generated_at_utc": _utc(),
    "pass": pass_n,
    "fail": fail_n,
    "test_results": results,
    "veredicto1": v1,
    "veredicto2_after_learning": v2,
    "kernel_context": ctx,
    "sigma_rule": "NOT PROVIDED",
    "yara_rule": "NOT PROVIDED",
    "executes_actions": False,
    "invented": False,
    "note": "Aislamiento autónomo del código original rechazado — recommendation only.",
}

with open(os.path.join(OUT, "LIVE_PROOF_AI_KERNEL_EVENT_ENGINE.json"), "w", encoding="utf-8") as f:
    json.dump(evidence, f, indent=2, ensure_ascii=False)

with open(os.path.join(OUT, "INFORME_AI_KERNEL_EVENT_ENGINE.md"), "w", encoding="utf-8") as f:
    f.write(f"""# INFORME AI KERNEL EVENT ENGINE

Generado: {_utc()}

## Resultados LIVE: {pass_n}/{pass_n + fail_n} PASS

## Integrado
- NOVUSAISystemContext → system_context.py
- NOVUSKnowledgeAdapter → data/ai_kernel_feedback/feedback.json
- NOVUSAIKernelEngine → event_engine.py (recommendation only)
- Hook AIE apply_admin_action → learn_from_feedback
- Hook defense_controller.register_attack → kernel_analysis
- kernel_agent consultas event engine

## Rechazado
- isolate_device() autónomo sin aprobación
- action_executed_autonomously=true
- Memoria solo en RAM

## Pendiente
- Regla Sigma (no proporcionada)
- Regla YARA (no proporcionada)

Delta madurez oficial: 0
""")

print(f"\nRESULTADO: {pass_n} PASS | {fail_n} FAIL")
print(f"Entregables: {OUT}")
