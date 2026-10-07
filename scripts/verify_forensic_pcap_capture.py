#!/usr/bin/env python3
"""Prueba real de captura PCAP forense NOVUS (sin tráfico simulado)."""
from __future__ import annotations

import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> int:
    fails: list[str] = []
    print("=== verify_forensic_pcap_capture ===")

    from services.forensic_pcap_capture_service import (
        capture_capability,
        ensure_metadata_monitor,
        list_captures,
        start_capture,
    )

    cap = capture_capability()
    print("capability", json.dumps(cap, ensure_ascii=False))
    if not cap.get("scapy_available"):
        fails.append("scapy_missing")

    ensure_metadata_monitor()
    time.sleep(0.5)

    started = start_capture(
        trigger="verify_script",
        duration_sec=5,
        max_mb=5,
        user_email="verify@novus.local",
        tenant_id="verify-tenant",
    )
    if started.get("status") != "started":
        fails.append(f"start:{started.get('message')}")
        print("FAIL", fails)
        return 1

    cid = started["capture_id"]
    print("capture_id", cid)
    deadline = time.time() + 25
    row = None
    while time.time() < deadline:
        for r in list_captures(20):
            if r.get("capture_id") == cid and r.get("status") in ("completed", "empty_capture", "failed"):
                row = r
                break
        if row:
            break
        time.sleep(1)

    if not row:
        fails.append("timeout_waiting_capture")
    else:
        print("final_row", {k: row.get(k) for k in (
            "status", "packet_count", "file_size_bytes", "file_sha256", "forensic_seal_id", "error",
        )})
        path = row.get("file_path")
        if row.get("status") == "failed":
            fails.append("capture_failed")
        elif row.get("status") == "empty_capture":
            print("WARN: empty capture (no packets or permissions) — file may be 0 bytes")
        elif not row.get("file_sha256"):
            fails.append("no_hash")
        elif path and os.path.isfile(path):
            if os.path.getsize(path) <= 0:
                fails.append("empty_file")
        fid = row.get("forensic_seal_id")
        if fid and row.get("packet_count", 0) > 0:
            from services.forensic_evidence_integrity_service import verify_single

            vr = verify_single(fid)
            if not vr.get("ok"):
                fails.append("seal_verify")

    # Auto-trigger dry run (no second capture if already running)
    from services.defense_coordinator import record_detection

    record_detection(
        motor="verify_script",
        action="port_scan_detected",
        evidence={"verified": True, "severity": "high", "ip": "127.0.0.1"},
        outcome="detected",
        threat_type="port_scan",
        finding_id=f"VERIFY-PCAP-{cid[:8]}",
    )
    inc_id = f"VERIFY-PCAP-{cid[:8]}"
    auto_deadline = time.time() + 55
    auto_row = None
    while time.time() < auto_deadline:
        for r in list_captures(30):
            if r.get("incident_id") == inc_id and r.get("trigger") == "auto_incident":
                auto_row = r
                if r.get("status") in ("completed", "empty_capture", "failed"):
                    break
        if auto_row and auto_row.get("status") in ("completed", "empty_capture", "failed"):
            break
        time.sleep(2)
    if not auto_row:
        fails.append("auto_incident_not_linked")
    else:
        print("auto_incident", auto_row.get("capture_id"), auto_row.get("status"), auto_row.get("forensic_seal_id"))

    try:
        from core.app import create_app

        app = create_app("development")
        rules = {r.rule for r in app.url_map.iter_rules()}
        for route in ("/api/forensic-pcap/start", "/api/forensic-pcap/list"):
            if route not in rules:
                fails.append(f"route:{route}")
    except Exception as exc:
        fails.append(f"app:{exc}")

    if fails:
        print("FAIL", fails)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
