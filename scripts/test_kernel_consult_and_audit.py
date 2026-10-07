#!/usr/bin/env python3
"""Valida Consultar Kernel IA y Auditoría Integral de Seguridad."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODULES = [
    "dashboard", "xdr", "vulnerabilidades", "network", "topology",
    "endpoints", "inteligencia", "reportes", "playbooks", "incidentes",
    "casos_estudio", "configuracion", "aspe",
]

RESULTS = []


def check(name, fn):
    try:
        ok, detail = fn()
        RESULTS.append({"test": name, "pass": ok, "detail": str(detail)[:300]})
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
        return ok
    except Exception as exc:
        RESULTS.append({"test": name, "pass": False, "detail": str(exc)})
        print(f"[FAIL] {name}: {exc}")
        return False


def main():
    from main import app
    from services.module_kernel_context import build_consult_prompt
    from services.integral_security_audit_service import run_quick_audit

    client = app.test_client()
    client.post(
        "/login",
        data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!"},
        follow_redirects=True,
    )

    for mod in MODULES:
        def _test(m=mod):
            r = client.post(
                "/api/ai/module-consult",
                json={"module": m, "extra": {}, "execute": True},
                content_type="application/json",
            )
            d = r.get_json()
            ok = r.status_code == 200 and d.get("status") == "success"
            has = d.get("has_real_data") or d.get("prompt") or d.get("reply")
            return ok and bool(has), f"HTTP {r.status_code} has_data={d.get('has_real_data')}"
        check(f"kernel_consult_{mod}", _test)

    check("module_consult_prompt_structure", lambda: (
        len(build_consult_prompt("topology", "novus.qa.jul2026@example.com", {"ip": "10.0.0.1"})["prompt"]) > 200,
        "prompt length ok",
    ))

    def _quick_audit_test():
        r = run_quick_audit("novus.qa.jul2026@example.com")
        ok = r.get("status") == "completed"
        return ok, r.get("current_risk")

    check("integral_audit_quick", _quick_audit_test)

    r = client.post("/api/audit/integral/run", json={"mode": "quick"})
    def _api_quick():
        d = r.get_json()
        return (
            r.status_code == 200
            and d.get("status") == "success"
            and d.get("mode") == "quick"
            and d.get("audit_state") == "completed"
        ), d.get("current_risk")
    check("api_integral_quick", _api_quick)

    r2 = client.post("/api/audit/integral/run", json={"mode": "deep"})
    d2 = r2.get_json()
    scan_id = d2.get("scan_id")
    check("api_integral_deep_start", lambda: (
        r2.status_code == 200 and bool(scan_id),
        scan_id,
    ))

    r3 = client.get("/api/audit/data-sources")
    check("audit_data_sources_compat", lambda: (
        r3.status_code == 200 and "audit_display_name" in r3.get_json(),
        r3.get_json().get("audit_display_name"),
    ))

    passed = sum(1 for x in RESULTS if x["pass"])
    failed = len(RESULTS) - passed
    out = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "kernel_consult_audit_test.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"pass": passed, "fail": failed, "results": RESULTS}, f, indent=2)
    print(f"\n=== {passed} PASS / {failed} FAIL ===")
    print(f"Results: {out}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
