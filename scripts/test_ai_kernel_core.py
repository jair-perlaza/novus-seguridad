#!/usr/bin/env python3
"""Unit tests — AI Kernel Core facade."""
from __future__ import annotations

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def test_system_prompt_modules():
    from services.ai_kernel_core.system_prompt_factory import NOVUSSystemPromptFactory

    p = NOVUSSystemPromptFactory.build_system_prompt()
    assert "M3 Escaneo" in p
    assert "executes_actions=false" in p
    st = NOVUSSystemPromptFactory.module_status()
    assert st.get("executes_network_block") is False
    assert st.get("M8_sigma_yara") == "yara_partial_sigma_not_provided"


def test_greeting_no_execute():
    from services.ai_kernel_core.request_router import process_user_request

    r = process_user_request("Hola")
    assert r.get("type") == "GREETING"
    assert r.get("executes_actions") is False


def test_isolate_recommendation_only():
    from services.ai_kernel_core.request_router import process_user_request

    r = process_user_request("Aisla el equipo", {"mac": "AA:BB:CC:11:22:33", "ip": "192.168.1.1"})
    assert r.get("executes_network_block") is False
    assert r.get("executes_actions") is False


def test_yara_engine_has_keylogging_rule():
    from services.endpoint_enterprise.yara_engine import reload_engine, get_engine_status

    reload_engine()
    st = get_engine_status()
    assert st.get("ok"), st.get("error")
    names = st.get("rules_files") or []
    assert any("keylogging" in n for n in names)


def test_yara_scan_finding():
    from services.endpoint_enterprise.yara_engine import reload_engine, scan_file

    reload_engine()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(b"GetAsyncKeyState\x00SetWindowsHookEx\x00BitBlt")
        path = tf.name
    try:
        hits = scan_file(path)
        assert any("Keylogging" in (h.get("rule") or "") for h in hits)
    finally:
        os.unlink(path)


TESTS = [
    test_system_prompt_modules,
    test_greeting_no_execute,
    test_isolate_recommendation_only,
    test_yara_engine_has_keylogging_rule,
    test_yara_scan_finding,
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
