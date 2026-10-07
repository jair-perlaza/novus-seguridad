#!/usr/bin/env python3
"""Verifica historial de seguridad de red (solo eventos verificables)."""
from __future__ import annotations

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> int:
    print("=== verify_network_security_history ===")
    fails = []

    from services import network_security_history_service as nsh

    ctx = nsh.get_connected_network_context()
    if not ctx.get("collected_at"):
        fails.append("network_context")
    else:
        print("context subnet", ctx.get("subnet"), "devices", ctx.get("visible_devices_count"))

    sid = nsh.network_scope_id(ctx)
    if not sid:
        fails.append("scope_id")

    with tempfile.TemporaryDirectory() as tmp:
        orig = nsh.HISTORY_ROOT
        nsh.HISTORY_ROOT = tmp
        try:
            boot = nsh.ensure_network_monitoring_started(ctx)
            if not boot.get("scope_id"):
                fails.append("ensure_started")
            boot2 = nsh.ensure_network_monitoring_started(ctx)
            if boot2.get("created"):
                fails.append("ensure_idempotent")

            prof = nsh.get_network_profile(scope_id=boot["scope_id"])
            if not prof.get("scope_id"):
                fails.append("profile")

            nsh.bootstrap_network_history_on_login(
                "verify@novus.local",
                "LS-verify-session",
                client={"os_name": "Windows", "browser": "verify", "device_type": "Desktop"},
                ip="127.0.0.1",
            )
            sessions = nsh.list_analysis_sessions(scope_id=boot["scope_id"], limit=5)
            if not sessions:
                fails.append("sessions")

            insights = nsh.build_kernel_network_insights(scope_id=boot["scope_id"])
            if "sufficient_data" not in insights:
                fails.append("kernel_insights")

            row = nsh.append_network_security_event(
                "network_alert",
                title="verify test event",
                evidence={"verified": True, "test": True},
                motor="verify_script",
                scope_id=boot["scope_id"],
            )
            if not row or not row.get("id"):
                fails.append("append")
            events = nsh.list_network_security_events(scope_id=boot["scope_id"], limit=10)
            if len(events) < 2:
                fails.append("list_events")
            summary = nsh.get_network_history_summary(scope_id=boot["scope_id"])
            if summary.get("event_count", 0) < 2:
                fails.append("summary_count")
            if not summary.get("disclaimer"):
                fails.append("disclaimer")
        finally:
            nsh.HISTORY_ROOT = orig

    from services.continuous_monitoring_orchestrator import activate_all_defense_motors_on_login

    act = activate_all_defense_motors_on_login("verify@novus.local")
    if not act.get("motors"):
        fails.append("activate_motors")
    else:
        print("motors activated", len(act["motors"]))

    try:
        from core.app import create_app

        app = create_app("development")
        rules = [r.rule for r in app.url_map.iter_rules()]
        if "/api/network-security-history/summary" not in rules:
            fails.append("api_summary_route")
        if "/api/network-security-history/profile" not in rules:
            fails.append("api_profile_route")
        if "/api/network-security-history/kernel-insights" not in rules:
            fails.append("api_kernel_route")
        if "/historial-seguridad-red" not in rules:
            fails.append("page_route")
    except Exception as exc:
        fails.append(f"app_routes:{exc}")

    from services.defense_coordinator import record_detection

    record_detection(
        "network_ndr_service",
        "arp_anomaly_detected",
        {"verified": True, "ip": "192.0.2.1"},
        threat_type="arp_spoofing",
        detail="verify mapping",
    )

    if fails:
        print("FAIL", fails)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
