#!/usr/bin/env python3
"""Unit tests — AI Kernel Event Engine."""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def test_anomalous_process_recommends_not_executes():
    from services.ai_kernel_event_engine.event_engine import analyze_security_event

    v = analyze_security_event(
        "ANOMALOUS_PROCESS",
        {
            "mac": "AA:BB:CC:44:55:66",
            "ip": "192.168.1.30",
            "device_type": "PORTATIL",
            "attack_count": 1,
            "details": "cmd.exe iniciado por winword.exe",
        },
    )
    assert v.get("executes_actions") is False
    assert v.get("action_executed_autonomously") is False
    assert v.get("recommended_action") in ("RECOMMEND_ISOLATE", "RECOMMEND_MONITOR")
    assert v.get("calculated_risk", 0) > 0


def test_feedback_reduces_risk():
    from services.ai_kernel_event_engine.knowledge_adapter import NOVUSKnowledgeAdapter
    from services.ai_kernel_event_engine.event_engine import NOVUSAIKernelEngine

    adapter = NOVUSKnowledgeAdapter()
    adapter.learn_from_feedback(
        "AA:BB:CC:44:55:66",
        "RECOMMEND_ISOLATE",
        "OVERRIDE_UNBLOCK",
        "Script de mantenimiento autorizado",
    )
    engine = NOVUSAIKernelEngine()
    engine.adapter = adapter
    v1 = engine.analyze_event(
        "ANOMALOUS_PROCESS",
        {
            "mac": "AA:BB:CC:44:55:66",
            "ip": "192.168.1.30",
            "device_type": "PORTATIL",
            "attack_count": 1,
            "details": "cmd.exe iniciado por winword.exe",
        },
    )
    assert v1.get("recommended_action") == "ALLOW"


def test_confirm_attack_increases_modifier():
    from services.ai_kernel_event_engine.knowledge_adapter import NOVUSKnowledgeAdapter

    adapter = NOVUSKnowledgeAdapter()
    adapter.learn_from_feedback(
        "BB:CC:DD:EE:FF:00",
        "RECOMMEND_MONITOR",
        "CONFIRM_ATTACK",
        "Ataque confirmado",
    )
    assert adapter.get_risk_modifier("BB:CC:DD:EE:FF:00") == 1.5


def test_kernel_insights_analyze_only():
    from services.ai_kernel_event_engine.kernel_insights import build_kernel_event_engine_context

    ctx = build_kernel_event_engine_context()
    assert ctx.get("executes_actions") is False
    assert ctx.get("capabilities", {}).get("executes") is False


TESTS = [
    test_anomalous_process_recommends_not_executes,
    test_feedback_reduces_risk,
    test_confirm_attack_increases_modifier,
    test_kernel_insights_analyze_only,
]


def main():
    passed = 0
    for fn in TESTS:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except Exception as exc:
            print(f"FAIL {fn.__name__}: {exc}")
    print(f"\n{passed}/{len(TESTS)} PASS")
    return 0 if passed == len(TESTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
