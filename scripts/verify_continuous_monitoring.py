#!/usr/bin/env python3
"""Verifica monitoreo automático post-login (sin datos simulados)."""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> int:
    print("=== verify_continuous_monitoring ===")
    fails = []

    from services.continuous_monitoring_orchestrator import (
        run_phase1_immediate_analysis,
        ensure_continuous_monitors,
        get_monitoring_status_for_user,
    )

    m = ensure_continuous_monitors()
    print("monitors", m.get("motors"))
    if not m.get("motors"):
        fails.append("ensure_continuous_monitors")

    p1 = run_phase1_immediate_analysis("verify@novus.local", "127.0.0.1")
    if not p1.get("finished_at") or p1.get("duration_sec") is None:
        fails.append("phase1")
    else:
        print(f"phase1 OK in {p1.get('duration_sec')}s processes={p1.get('counts', {}).get('processes')}")

    from services.auto_monitoring_report_builder import build_executive_auto_report

    rep = build_executive_auto_report(
        user_email="verify@novus.local",
        session_audit_id="LS-verifytest",
        phase1=p1,
        motors_activated=m.get("motors") or [],
    )
    if not rep.get("id") or "AUTO-LS-verifytest" not in rep["id"]:
        fails.append("report_build")
    else:
        print("report id", rep["id"])

    from services.deep_scan_engine import PROFILE_PHASES

    if "login_session" not in PROFILE_PHASES:
        fails.append("login_session_profile")
    else:
        print("login_session profile phases", len(PROFILE_PHASES["login_session"]))

    st = get_monitoring_status_for_user("nonexistent@test.local")
    if st.get("active") is not False:
        fails.append("status_inactive")

    if fails:
        print("FAIL", fails)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
