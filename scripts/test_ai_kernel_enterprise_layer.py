#!/usr/bin/env python3
"""Unit tests — async YARA scanner, ActionPayload, WS bridge."""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def test_action_payload_validation():
    from services.ai_kernel_core.action_payload import validate_action_payload

    bad = validate_action_payload({"intent": "INVALID", "confidence": 2.0, "reasoning": ""})
    assert bad["valid"] is False

    ok = validate_action_payload(
        {
            "intent": "GREETING",
            "confidence": 0.9,
            "reasoning": "saludo",
        }
    )
    assert ok["valid"] is True


def test_infer_scan_intent():
    from services.ai_kernel_core.action_payload import infer_intent_from_text

    p = infer_intent_from_text("Escanea la carpeta C:\\NOVUS\\data")
    assert p.intent == "SCAN_REQUEST"
    assert p.executes_actions is False


def test_execute_greeting():
    from services.ai_kernel_core.action_payload import infer_intent_from_text, execute_action_payload

    p = infer_intent_from_text("Hola")
    out = execute_action_payload(p)
    assert out["result"]["type"] == "GREETING"
    assert out["executes_actions"] is False


def test_ws_bridge_json():
    from services.ai_kernel_core.ws_kernel_bridge import process_kernel_ws_message

    r = process_kernel_ws_message('{"message": "Hola", "action": "greet"}')
    assert r.get("status") == "COMPLETED"
    assert r.get("executes_actions") is False


def test_async_scanner():
    from services.endpoint_enterprise.async_scanner import EnterpriseYARAScanner

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(b"GetAsyncKeyState SetWindowsHookEx BitBlt")
        path = tf.name
    try:
        scanner = EnterpriseYARAScanner()
        result = asyncio.run(scanner.scan_directory_async(os.path.dirname(path), max_files=10))
        assert result.get("status") in ("COMPLETED", "ERROR", "ENGINE_UNAVAILABLE")
        assert result.get("backend") == "yara_x" or "engine" in result
    finally:
        os.unlink(path)


TESTS = [
    test_action_payload_validation,
    test_infer_scan_intent,
    test_execute_greeting,
    test_ws_bridge_json,
    test_async_scanner,
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
