#!/usr/bin/env python3
"""Unit tests — network device defense (classifier + controller)."""
from __future__ import annotations

import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def test_classifier_hostname_mobile():
    from services.network_device_defense.device_classifier import NOVUSDeviceClassifier

    assert NOVUSDeviceClassifier.classify("", 64, "Redmi-Note-12", "Xiaomi") == "Celular"


def test_classifier_hostname_laptop():
    from services.network_device_defense.device_classifier import NOVUSDeviceClassifier

    assert NOVUSDeviceClassifier.classify("", 128, "DESKTOP-PC", "Dell") == "PC"
    assert NOVUSDeviceClassifier.classify("", None, "MacBook-Pro", "Apple") == "Laptop"


def test_classify_device_from_node_fallback():
    from services.network_device_defense.device_classifier import classify_device_from_node

    dtype = classify_device_from_node({"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "HP"})
    assert isinstance(dtype, str) and dtype


def test_defense_controller_no_auto_firewall():
    from services.network_device_defense.defense_controller import NOVUSDefenseController

    ctrl = NOVUSDefenseController()
    iso = ctrl.isolate_device("AA:BB:CC:11:22:33", admin_request=False)
    assert iso.get("executes_network_block") is False
    assert iso.get("executes_actions") is False
    assert iso.get("status") in ("RECOMMENDATION", "ERROR")


def test_register_attack_recommend_only():
    from services.network_device_defense.defense_controller import NOVUSDefenseController

    ctrl = NOVUSDefenseController()
    r = ctrl.register_attack("00:00:00:00:00:00", "test", auto_isolate=True)
    assert r.get("executes_actions") is False


def test_on_radar_returns_evidence():
    from services.network_device_defense.defense_controller import NOVUSDefenseController

    ctrl = NOVUSDefenseController()
    out = ctrl.on_radar_device_found(
        ip="192.168.1.99",
        mac="DE:AD:BE:EF:00:01",
        hostname="Redmi-Note-12",
        ttl=64,
        vendor="Xiaomi",
    )
    assert out.get("device_type") == "Celular"
    assert out.get("executes_actions") is False
    assert out.get("evidence", {}).get("invented") is False


TESTS = [
    test_classifier_hostname_mobile,
    test_classifier_hostname_laptop,
    test_classify_device_from_node_fallback,
    test_defense_controller_no_auto_firewall,
    test_register_attack_recommend_only,
    test_on_radar_returns_evidence,
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
