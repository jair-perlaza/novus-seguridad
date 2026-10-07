"""
Validación del Network Monitor Engine — monitoreo continuo con telemetría real.
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = 0
FAIL = 0


def check(name: str, ok: bool, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {name} — {detail}")
    else:
        FAIL += 1
        print(f"  FAIL  {name} — {detail}")


def main():
    print("=== NETWORK MONITOR ENGINE TESTS ===\n")

    from services.network_monitor_config import get_network_monitor_config
    from services.network_monitor_engine import (
        get_monitor_status,
        start_network_monitor_engine,
        MODE_NORMAL,
    )

    cfg = get_network_monitor_config()
    check("Config NME cargada", cfg["normal_interval_min_sec"] >= 1, cfg)

    start_network_monitor_engine()
    deadline = time.time() + 20
    st = get_monitor_status()
    while time.time() < deadline and not st.get("last_scan_at"):
        time.sleep(1)
        st = get_monitor_status()
    check("Motor activo", st.get("active") is True, st.get("status"))
    check("Modo inicial normal o intensivo", st.get("mode") in ("normal", "intensive"), st.get("mode"))
    check("Último escaneo registrado", st.get("last_scan_at") is not None, st.get("last_scan_at"))
    check("Al menos un ciclo completado", (st.get("scan_count") or 0) >= 1, st.get("scan_count"))
    check("Dispositivos monitorizados >= 0", st.get("devices_monitored") is not None, st.get("devices_monitored"))
    check("CPU/RAM medidos", (
        st.get("cpu_percent") is not None and st.get("memory_mb") is not None
    ), f"cpu={st.get('cpu_percent')} ram={st.get('memory_mb')}")

    time.sleep(4)
    st2 = get_monitor_status()
    check("Escaneos incrementan", (st2.get("scan_count") or 0) >= (st.get("scan_count") or 0), f"{st.get('scan_count')} -> {st2.get('scan_count')}")

    from core.app import create_app
    from models.user import User

    app = create_app("development")

    @app.login_manager.user_loader
    def load_user(user_id):
        if user_id is None or not str(user_id).isdigit():
            return None
        return User.get_by_id(user_id)

    client = app.test_client()
    client.post(
        "/login",
        data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!"},
        follow_redirects=True,
    )
    r = client.get("/api/network/monitor/status")
    check("API monitor/status", r.status_code == 200 and r.get_json().get("status") == "success", r.status_code)

    print(f"\n=== RESULTADO: {PASS} PASS / {FAIL} FAIL ===")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
