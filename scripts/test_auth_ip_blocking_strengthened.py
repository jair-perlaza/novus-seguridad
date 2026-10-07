"""
Tests de bloqueo IP reforzado y monitoreo de conexiones de dispositivos.
Solo eventos reales — sin datos simulados en producción.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Base, SessionLocal, DeviceConnectionEvent, engine

Base.metadata.create_all(bind=engine)

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
    print("=== AUTH IP BLOCKING + DEVICE CONNECTION TESTS ===\n")

    from services.auth_protection_config import get_auth_protection_config, save_auth_protection_config
    from services.device_connection_monitor import process_scan_presence, list_events, get_device_history

    cfg = get_auth_protection_config()
    check("Config auth protection cargada", cfg["block_attempt"] == 5, cfg)

    saved = save_auth_protection_config({"first_block_minutes": 45})
    check("Config persistida", saved.get("first_block_minutes") == 45, saved.get("first_block_minutes"))
    save_auth_protection_config({"first_block_minutes": 30})

    mac_a = "aa:bb:cc:dd:ee:01"
    mac_b = "aa:bb:cc:dd:ee:02"
    stats1 = process_scan_presence([
        {"mac": mac_a, "ip": "192.168.1.10", "name": "host-a", "vendor": "TestVendor", "device_type": "pc"},
    ])
    check("Detecta conexión", stats1.get("connected") == 1, stats1)

    stats2 = process_scan_presence([
        {"mac": mac_a, "ip": "192.168.1.10", "name": "host-a"},
        {"mac": mac_b, "ip": "192.168.1.11", "name": "host-b", "vendor": "TestVendor2", "device_type": "phone"},
    ])
    check("Detecta segunda conexión", stats2.get("connected") == 1, stats2)

    stats3 = process_scan_presence([
        {"mac": mac_a, "ip": "192.168.1.10", "name": "host-a"},
    ])
    check("Detecta desconexión", stats3.get("disconnected") == 1, stats3)

    events = list_events(limit=20)
    check("Eventos persistidos en DB", len(events) >= 3, f"count={len(events)}")
    connect_ev = [e for e in events if e.get("event_type") == "connect"]
    check("Eventos connect con IP/MAC", any(e.get("ip") and e.get("mac") for e in connect_ev), "ok")

    hist = get_device_history(mac=mac_a)
    check("Historial dispositivo", hist.get("connect_count", 0) >= 1, hist.get("connect_count"))

    db = SessionLocal()
    try:
        count = db.query(DeviceConnectionEvent).count()
        check("Tabla device_connection_events accesible", count >= 3, count)
    finally:
        db.close()

    print(f"\n=== RESULTADO: {PASS} PASS / {FAIL} FAIL ===")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
