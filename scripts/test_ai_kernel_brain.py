#!/usr/bin/env python3
"""Unit tests — AI Kernel Brain prompt."""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def test_time_greeting():
    from services.ai_kernel_brain.kernel_prompt import NOVUSKernelBrain

    g = NOVUSKernelBrain().get_time_based_greeting()
    assert g in ("Buenos días", "Buenas tardes", "Buenas noches")


def test_system_prompt_no_auto_isolate():
    from services.ai_kernel_brain.kernel_prompt import get_master_system_prompt

    p = get_master_system_prompt()
    assert "executes_actions=false" in p
    assert "No ejecutar aislamiento" in p
    assert "Ejecutar el bloqueo" not in p


def test_greeting_response_wired():
    from services.kernel_agent import kernel_agent

    reply = kernel_agent._greeting_response({"total_interactions": 0}, {"sector_label": "Test"})
    assert "Analista SOC/XDR NOVUS" in reply
    assert any(x in reply for x in ("Buenos días", "Buenas tardes", "Buenas noches"))


def test_consult_prompt_includes_header():
    from services.module_kernel_context import build_consult_prompt

    r = build_consult_prompt("dashboard")
    assert r.get("system_prompt")
    assert r.get("greeting")
    assert "CONSULTA AUTOMÁTICA" in r.get("prompt", "")


TESTS = [
    test_time_greeting,
    test_system_prompt_no_auto_isolate,
    test_greeting_response_wired,
    test_consult_prompt_includes_header,
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
