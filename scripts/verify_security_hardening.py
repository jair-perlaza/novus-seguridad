#!/usr/bin/env python3
"""Verificación real de endurecimiento — sin datos simulados."""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

FAILURES: list[str] = []


def ok(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  OK  {name}" + (f" — {detail}" if detail else ""))
    else:
        FAILURES.append(name)
        print(f" FAIL {name}" + (f" — {detail}" if detail else ""))


def main() -> int:
    print("=== verify_security_hardening ===")

    from services.platform_protection_score_service import compute_protection_score

    score = compute_protection_score()
    ok("protection_score_core", score.get("core_total", 0) > 0, f"core={score.get('core_protection_percent')}%")
    ok("protection_score_method", score.get("method") == "binary_verifiable_checks")

    from services.malware_behavior_engine import analyze_process

    benign = analyze_process({
        "pid": 12345,
        "name": "notepad.exe",
        "path": r"C:\Windows\System32\notepad.exe",
        "command_line": "notepad.exe",
    })
    ok("malware_engine_benign", len(benign) == 0)
    evil = analyze_process({
        "pid": 9999,
        "name": "powershell.exe",
        "command_line": "powershell -enc ABC123",
    })
    ok("malware_engine_powershell", len(evil) >= 1 and evil[0].get("technique") == "powershell_malicioso")

    from services.http_abuse_guard import _BOT_UA

    ok("http_abuse_bot_pattern", bool(_BOT_UA.search("sqlmap/1.0")))

    from services.network_baseline_service import compare_to_baseline

    cmp = compare_to_baseline([])
    ok("network_baseline_compare", cmp.get("verified") is True)

    from services.kernel_threat_explainer import explain_threat

    ex = explain_threat({"title": "Test", "risk": "high", "motor": "unit_test", "description": "evidencia"})
    ok("kernel_explainer", "summary" in ex and "evidencia" in ex.get("why_detected", ""))

    from services.web_shield_analyzer import analyze_url

    js = analyze_url("javascript:alert(1)")
    ok("web_shield_javascript_url", js.get("risk_score", 0) >= 35)

    from services.advanced_detector_service import advanced_detector

    proc = advanced_detector.scan_running_processes()
    ok("advanced_detector_process_scan", isinstance(proc, list))

    from services.sensitive_operations_audit import log_sensitive_operation

    log_sensitive_operation("verify_hardening", actor="verify_script", outcome="success", detail={"test": True})
    ok("sensitive_ops_audit", True)

    try:
        from services.network_ndr_service import build_ndr_payload

        payload = build_ndr_payload(force_refresh=False)
        ok("ndr_payload_baseline_field", "network_baseline" in payload)
    except Exception as exc:
        ok("ndr_payload_baseline_field", False, str(exc))

    print(f"\nOverall protection (computed): core {score.get('core_protection_percent')}% / all {score.get('overall_protection_percent')}%")
    if FAILURES:
        print("FAILED:", ", ".join(FAILURES))
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
