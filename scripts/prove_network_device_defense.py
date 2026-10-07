#!/usr/bin/env python3
"""LIVE proof — network device defense integration."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "data", "network_device_defense")
os.makedirs(OUT, exist_ok=True)

results = []


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ok(name, detail=""):
    results.append({"test": name, "status": "PASS", "detail": detail, "ts": _utc()})


def _fail(name, detail=""):
    results.append({"test": name, "status": "FAIL", "detail": detail, "ts": _utc()})


print("=" * 60)
print("NOVUS NETWORK DEVICE DEFENSE — LIVE PROOF")
print("=" * 60)

from services.network_device_defense.device_classifier import (
    NOVUSDeviceClassifier,
    classify_device_from_node,
    classification_evidence,
)
from services.network_device_defense.defense_controller import get_defense_controller
from services.network_ndr_service import estimate_device_type, build_ndr_payload

# Classifier LIVE
mobile = NOVUSDeviceClassifier.classify("AA:BB:CC:11:22:33", 64, "Redmi-Note-12", "Xiaomi")
if mobile == "Celular":
    _ok("classifier_mobile_live", mobile)
else:
    _fail("classifier_mobile_live", mobile)

# NDR estimate_device_type integration
ndr_type = estimate_device_type(
    {"ip": "192.168.1.45", "mac": "AA:BB:CC:11:22:33", "name": "Redmi-Note-12", "vendor": "Xiaomi", "ttl": 64}
)
if ndr_type == "Celular":
    _ok("ndr_estimate_integrated", ndr_type)
else:
    _fail("ndr_estimate_integrated", ndr_type)

# Defense controller — recommendation only isolate
ctrl = get_defense_controller()
found = ctrl.on_radar_device_found(
    ip="192.168.1.45",
    mac="AA:BB:CC:11:22:33",
    hostname="Redmi-Note-12",
    ttl=64,
    vendor="Xiaomi",
)
if found.get("device_type") == "Celular" and found.get("executes_actions") is False:
    _ok("radar_device_found", f"type={found.get('device_type')}")
else:
    _fail("radar_device_found", str(found)[:120])

iso = ctrl.isolate_device("AA:BB:CC:11:22:33", admin_request=False)
if iso.get("executes_network_block") is False and iso.get("executes_actions") is False:
    _ok("isolate_recommendation_only", iso.get("status", ""))
else:
    _fail("isolate_recommendation_only", str(iso)[:120])

attack = ctrl.register_attack("AA:BB:CC:11:22:33", "Intento de escaneo de puertos", auto_isolate=True)
if attack.get("executes_actions") is False:
    _ok("register_attack_no_auto_block", f"count={attack.get('attack_count')}")
else:
    _fail("register_attack_no_auto_block", str(attack)[:120])

# NDR payload readable
try:
    payload = build_ndr_payload(force_refresh=False)
    nodes = payload.get("nodes") or []
    _ok("ndr_payload", f"nodes={len(nodes)}")
except Exception as exc:
    _fail("ndr_payload", str(exc)[:80])

# Server HTTP
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
    "module": "network_device_defense",
    "generated_at_utc": _utc(),
    "pass": pass_n,
    "fail": fail_n,
    "test_results": results,
    "sample_radar_found": found,
    "sample_isolate": iso,
    "sample_attack": attack,
    "classifier_sample": classification_evidence(
        {"ip": "192.168.1.45", "mac": "AA:BB:CC:11:22:33", "name": "Redmi-Note-12", "vendor": "Xiaomi", "ttl": 64}
    ),
    "sigma_rule": "NOT PROVIDED",
    "yara_rule": "NOT PROVIDED",
    "executes_network_block": False,
    "invented": False,
    "note": "NOVUSNetworkIsolator (iptables/netsh) no integrado — aislamiento = inventario AIE + recomendación.",
}

with open(os.path.join(OUT, "LIVE_PROOF_NETWORK_DEVICE_DEFENSE.json"), "w", encoding="utf-8") as f:
    json.dump(evidence, f, indent=2, ensure_ascii=False)

with open(os.path.join(OUT, "EVIDENCIA_NETWORK_DEVICE_DEFENSE.json"), "w", encoding="utf-8") as f:
    json.dump(evidence, f, indent=2, ensure_ascii=False)

with open(os.path.join(OUT, "INFORME_NETWORK_DEVICE_DEFENSE.md"), "w", encoding="utf-8") as f:
    f.write(f"""# INFORME NETWORK DEVICE DEFENSE

Generado: {_utc()}

## Resultados LIVE: {pass_n}/{pass_n + fail_n} PASS

## Integrado
- NOVUSDeviceClassifier → `estimate_device_type` + `sync_asset_from_node`
- NOVUSDefenseController → AIE inventario + learning_json attack_count
- Aislamiento: recomendación o acción admin AIE (`executes_network_block: false`)

## Rechazado (duplicado / incompatible)
- NOVUSNetworkIsolator iptables/netsh directo
- auto_isolate con firewall automático
- Base de datos en memoria (usa SQLite AIE + device_connection_events)

## Pendiente
- Regla Sigma (no proporcionada)
- Regla YARA (no proporcionada)

Delta madurez oficial: 0
""")

print(f"\nRESULTADO: {pass_n} PASS | {fail_n} FAIL")
print(f"Entregables: {OUT}")
