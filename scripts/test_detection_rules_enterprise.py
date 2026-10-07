#!/usr/bin/env python3
"""Tests unitarios — detection rules enterprise (sin afirmar malware)."""
from __future__ import annotations
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def test_office_detection_returns_list():
    from services.endpoint_enterprise.detection_rules.office_child_process import detect_office_suspicious_children
    r = detect_office_suspicious_children()
    assert isinstance(r, list)
    for f in r:
        assert f.get("finding_type") == "office_suspicious_child"
        assert "malware" not in (f.get("message") or "").lower()
        assert f.get("invented") is False


def test_masquerading_returns_list():
    from services.endpoint_enterprise.detection_rules.process_masquerading import detect_process_masquerading
    r = detect_process_masquerading()
    assert isinstance(r, list)
    for f in r:
        assert f.get("finding_type") == "process_masquerading"
        assert f.get("invented") is False


def test_evidence_builder_na_fields():
    from services.endpoint_enterprise.detection_rules.evidence_builder import build_process_evidence, NA
    ev = build_process_evidence(
        detection_type="test",
        detection_id="TEST-1",
        process_name="test.exe",
    )
    assert ev.get("sha256") == NA or ev.get("sha256") is None or len(str(ev.get("sha256"))) == 64
    assert ev.get("invented") is False


def test_heuristics_includes_detection_rules():
    from services.endpoint_enterprise.heuristics import scan_running_processes
    r = scan_running_processes(limit=5)
    assert isinstance(r, list)


def test_network_tracker_recommendation_only():
    from core.network_tracker import evaluate_login_zero_trust
    zt = evaluate_login_zero_trust(
        user="test", is_admin=True, origin_ip="203.0.113.1", user_agent="curl/7"
    )
    assert zt.get("executes_actions") is False
    assert "RECOMMEND" in zt.get("recommendation", "") or zt.get("recommendation") == "ALLOW"
    assert zt.get("invented") is False


def test_correlator_office_weak_alone():
    from services.behavioral_threat_detection.correlator import correlate_findings, WEAK_ALONE
    assert "office_suspicious_child" in WEAK_ALONE
    single = correlate_findings([{
        "finding_type": "office_suspicious_child",
        "severity": "medium",
        "confidence": "medium",
    }])
    assert single.get("enough_evidence") is False


if __name__ == "__main__":
    tests = [
        test_office_detection_returns_list,
        test_masquerading_returns_list,
        test_evidence_builder_na_fields,
        test_heuristics_includes_detection_rules,
        test_network_tracker_recommendation_only,
        test_correlator_office_weak_alone,
    ]
    ok = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            ok += 1
        except Exception as exc:
            print(f"FAIL {t.__name__}: {exc}")
    print(f"\n{ok}/{len(tests)} PASS")
    sys.exit(0 if ok == len(tests) else 1)
