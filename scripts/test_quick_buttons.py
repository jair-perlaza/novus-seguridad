#!/usr/bin/env python3
"""Prueba accesos rápidos del Kernel IA."""
from __future__ import annotations

import sys
import time
import urllib.request

sys.path.insert(0, ".")

from services.kernel_coordinator import kernel_coordinator
from services.kernel_operator import kernel_operator

QUICK = [
    ("Deep Scan", "Deep Scan"),
    ("Red", "escanear red"),
    ("Vulns", "buscar vulnerabilidades"),
    ("Sistema", "analizar sistema"),
    ("Devices", "dispositivos conectados"),
]

NAV = ["/", "/network", "/reportes", "/amenazas", "/incidentes"]


def test_msg(label: str, msg: str) -> tuple:
    sid = f"quick-{label.replace(' ', '-')}"
    try:
        r = kernel_operator.process(sid, msg, user_id=1, user_email="t@test.local")
        if r is None:
            return label, "FAIL", "result is None"
        if r.get("working") and r.get("operation_id"):
            op = r["operation_id"]
            for _ in range(90):
                st = kernel_coordinator.get_status(op)
                if st and st.get("status") in ("completed", "error"):
                    res = kernel_coordinator.get_result(op) or {}
                    if st.get("status") == "error":
                        return label, "FAIL", res.get("reply", st.get("live_message", "error"))
                    n = len(res.get("engines_executed") or [])
                    return label, "PASS", f"operation completed, engines={n}"
                time.sleep(1)
            return label, "TIMEOUT", op
        if r.get("soc_workflow") or r.get("deep_scan"):
            return label, "PASS", f"workflow scan_id={r.get('scan_id')}"
        reply = r.get("reply") or ""
        if reply.startswith("Error en operador"):
            return label, "FAIL", reply[:120]
        return label, "PASS", f"reply_len={len(reply)} type={r.get('request_type')}"
    except Exception as exc:
        return label, "EXCEPTION", str(exc)


def test_nav(url: str) -> tuple:
    try:
        req = urllib.request.Request(f"http://10.196.213.166:5000{url}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return url, "PASS", str(resp.status)
    except Exception as exc:
        return url, "FAIL", str(exc)


def main():
    print("=" * 60)
    print("Quick buttons (kernel_operator → kernel_agent → planner)")
    print("=" * 60)
    passed = 0
    for label, msg in QUICK:
        row = test_msg(label, msg)
        print(f"  [{row[1]}] {row[0]}: {row[2]}")
        if row[1] == "PASS":
            passed += 1

    print("\n" + "=" * 60)
    print("Navigation routes HTTP :5000")
    print("=" * 60)
    nav_pass = 0
    for url in NAV:
        row = test_nav(url)
        print(f"  [{row[1]}] {row[0]}: {row[2]}")
        if row[1] == "PASS":
            nav_pass += 1

    total = len(QUICK) + len(NAV)
    ok = passed + nav_pass
    print(f"\nTotal: {ok}/{total}")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
