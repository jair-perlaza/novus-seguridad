#!/usr/bin/env python3
"""Verifica acción stop_discovery en monitoreo de red."""
from __future__ import annotations

import json
import re
import sys

import requests

sys.path.insert(0, r"C:\NOVUS")
from scripts.reports_regression_probe import BASE, login

QA_EMAIL = __import__("scripts.reports_root_cause_probe", fromlist=["QA_EMAIL"]).QA_EMAIL


def main() -> int:
    s = requests.Session()
    login(s)
    cfg = s.get(BASE + "/api/monitoring/network-config", timeout=60)
    assert cfg.status_code == 200, cfg.text[:200]
    csrf = s.get(BASE + "/configuracion", timeout=60)
    m = re.search(r'id="csrf-token"\s+value="([^"]+)"', csrf.text)
    assert m, "csrf missing"
    token = m.group(1)
    stop = s.post(
        BASE + "/api/monitoring/network-config/action",
        json={"action": "stop_discovery"},
        headers={"X-CSRF-Token": token},
        timeout=60,
    )
    assert stop.status_code == 200, stop.text[:300]
    body = stop.json()
    assert body.get("action_result", {}).get("paused") is True, body
    assert body.get("discovery_paused") is True, body
    cfg2 = s.get(BASE + "/api/monitoring/network-config", timeout=60)
    assert cfg2.json().get("discovery_paused") is True
    resume = s.post(
        BASE + "/api/monitoring/network-config/action",
        json={"action": "resume_discovery"},
        headers={"X-CSRF-Token": token},
        timeout=60,
    )
    assert resume.status_code == 200, resume.text[:300]
    assert resume.json().get("discovery_paused") is False, resume.json()
    discover = s.post(
        BASE + "/api/monitoring/network-config/action",
        json={"action": "discover_now"},
        headers={"X-CSRF-Token": token},
        timeout=60,
    )
    assert discover.status_code == 200, discover.text[:300]
    assert discover.json().get("discovery_paused") is False
    prov = cfg2.json().get("provenance") or stop.json().get("provenance")
    print(json.dumps({
        "status": "VERIFIED",
        "stop": body.get("action_result"),
        "resume_ok": resume.json().get("status") == "success",
        "provenance_present": bool(prov),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
