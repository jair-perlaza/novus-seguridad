#!/usr/bin/env python3
"""Validación Ngrok Connection Manager."""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [OK] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")


def main():
    from services.ngrok_connection_manager import (
        get_manager_status,
        start_ngrok_connection_manager,
        _check_novus,
        _port,
    )

    port = _port()
    check("novus port configured", port == 5000)

    # Simular arranque del manager (requiere NOVUS activo en :5000)
    if not _check_novus(port):
        print("  [WARN] NOVUS no responde en :5000 — inicie main.py para validación completa")
        return 1

    status = start_ngrok_connection_manager()
    check("manager starts", status.get("manager_active") or status.get("enabled"))

    ok = False
    public_url = None
    for _ in range(20):
        st = get_manager_status()
        public_url = st.get("public_url")
        if st.get("connection_status") == "conectado" and public_url:
            ok = True
            break
        time.sleep(2)

    st = get_manager_status()
    check("novus status activo", st.get("novus_status") == "activo")
    check("ngrok status activo", st.get("ngrok_status") == "activo")
    check("public url present", bool(public_url))
    check("connection conectado", st.get("connection_status") == "conectado")
    check("events logged", len(st.get("recent_events") or []) >= 1)

    if public_url:
        import urllib.request
        req = urllib.request.Request(
            f"{public_url}/login",
            headers={"ngrok-skip-browser-warning": "69420"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                check("public login HTTP 200", resp.status == 200)
        except Exception as exc:
            check("public login HTTP 200", False)
            print(f"    remote error: {exc}")

    report_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ngrok")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "audit_report.md")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(
            f"# Auditoría Ngrok Connection Manager\n\n"
            f"- NOVUS: {st.get('novus_status')}\n"
            f"- ngrok: {st.get('ngrok_status')}\n"
            f"- Conexión: {st.get('connection_status')}\n"
            f"- URL local: {st.get('local_url')}\n"
            f"- URL pública: {public_url}\n"
            f"- Reconexiones: {st.get('reconnect_count')}\n"
            f"- Limitación plan: {st.get('plan_limitation')}\n"
            f"- Tests: {PASS} OK / {FAIL} FAIL\n"
        )
    print(f"\nInforme: {report_path}")
    print(f"=== RESULTADO: {PASS} OK, {FAIL} FAIL ===")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
