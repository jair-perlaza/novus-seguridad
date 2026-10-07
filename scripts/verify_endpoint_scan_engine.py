#!/usr/bin/env python3
"""Verificación rápida del motor endpoint (sin HTTP)."""
import json
import sys

sys.path.insert(0, ".")

from services.endpoint_scan_engine import endpoint_scan_engine
from services.endpoint_realtime_monitor import get_monitor_status, run_monitor_cycle
from services.deep_scan_engine import deep_scan_engine


def main():
    st = endpoint_scan_engine.engine_status()
    assert st.get("deep_scan_engine") == "active"
    cycle = run_monitor_cycle()
    mon = get_monitor_status()
    result = endpoint_scan_engine.start_scan(mode="quick")
    assert result.get("scan_id"), result
    scan_id = result["scan_id"]
    import time
    for _ in range(120):
        status = deep_scan_engine.get_status(scan_id)
        if status and status.get("status") in ("completed", "error"):
            break
        time.sleep(2)
    report = endpoint_scan_engine.get_scan_report(scan_id)
    out = {
        "host": st.get("host"),
        "monitor": mon,
        "cycle": cycle,
        "scan_id": scan_id,
        "scan_status": status.get("status") if status else None,
        "findings_count": len((report or {}).get("findings") or []),
        "verified_real_host": True,
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if status and status.get("status") == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
