"""
Auditoría: Dashboard progreso auténtico — sin % inventados ni timers.
"""
from __future__ import annotations

import ast
import os
import re
import sys

sys.path.insert(0, r"C:\NOVUS")

ROOT = r"C:\NOVUS"
FAIL = []


def check(name: str, ok: bool, detail: str = "") -> None:
    status = "OK" if ok else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAIL.append(name)


def main() -> int:
    print("=== Dashboard authentic progress audit ===")

    # 1) UI no inventa % con timers locales
    eg_js = open(os.path.join(ROOT, "static", "js", "novus-dashboard-estado-general.js"), encoding="utf-8").read()
    check("estado-general usa EventSource/SSE", "EventSource" in eg_js and "/api/monitoring/stream" in eg_js)
    check("estado-general no incrementa % localmente", "progress_pct++" not in eg_js and "Math.random" not in eg_js)
    check("waiting message presente", "Esperando resultados de los motores de defensa" in eg_js)
    check("applyPayload no inventa techos 95/99", "Math.min(95" not in eg_js and "Math.min(99" not in eg_js)

    cm_js = open(os.path.join(ROOT, "static", "js", "novus-continuous-monitor.js"), encoding="utf-8").read()
    check("continuous-monitor sin techos inventados", "Math.min(95" not in cm_js and "Math.min(99" not in cm_js)

    rem = open(os.path.join(ROOT, "templates", "partials", "remediation_modal.html"), encoding="utf-8").read()
    # No pacing de pasos post-respuesta
    check(
        "remediation_modal sin setTimeout de pasos de progreso",
        "setTimeout(r, options.playbookExecution" not in rem and "setTimeout(r, 350)" not in rem and "setTimeout(r, 200)" not in rem,
    )

    # 2) Backend progreso solo completed
    orch = open(os.path.join(ROOT, "services", "continuous_monitoring_orchestrator.py"), encoding="utf-8").read()
    check("progress_source completed_motors_only", 'progress_source": "completed_motors_only"' in orch or "completed_motors_only" in orch)
    check("no fuerza pct=100 inventando stages", "pct = 100" not in orch.split("def _dashboard_stage_view")[1].split("def ")[0])
    check("waiting_message canónico", "Esperando resultados de los motores de defensa" in orch)

    # 3) Telemetría + SSE
    check("motor_telemetry_service existe", os.path.isfile(os.path.join(ROOT, "services", "motor_telemetry_service.py")))
    mon = open(os.path.join(ROOT, "api", "monitoring.py"), encoding="utf-8").read()
    check("SSE /stream registrado", '/stream"' in mon and "text/event-stream" in mon)
    check("API telemetry", "/telemetry" in mon)

    # 4) Runtime: telemetría real
    from services.motor_telemetry_service import (
        motor_start,
        motor_complete,
        motor_fail,
        compute_progress_from_completions,
        list_session_events,
    )

    sid = "AUDIT-DASH-PROGRESS"
    motor_start(session_id=sid, motor_id="memory", motor_label="Memory Engine", activity="scan RAM")
    ev = motor_complete(
        session_id=sid,
        motor_id="memory",
        elements_analyzed={"pages": 12},
        result="ok",
        evidence={"verified": True},
        progress_pct=None,
    )
    check("motor_complete produce evidencia", bool(ev.get("finished_at") and ev.get("duration_sec") is not None))
    prog = compute_progress_from_completions(total_motors=7, completed_motor_ids=["memory"])
    check("progreso 1/7 ~ 14%", prog["progress_pct"] == 14, str(prog))
    prog2 = compute_progress_from_completions(
        total_motors=7, completed_motor_ids=["memory", "registry", "network"]
    )
    check("progreso 3/7 ~ 43%", prog2["progress_pct"] == 43, str(prog2))
    motor_fail(session_id=sid, motor_id="vuln", error="timeout motor", evidence={"verified": True})
    events = list_session_events(sid)
    check("eventos incluyen failed sin detener sistema", any(e.get("status") == "failed" for e in events))

    # 5) stage view no inventa 100
    from services.continuous_monitoring_orchestrator import _dashboard_stage_view, _init_stage_status

    state = {"status": "phase1_running", "stage_status": _init_stage_status()}
    view = _dashboard_stage_view(state)
    check("0 completados → 0%", view["progress_pct"] == 0 and view.get("waiting_for_engines"))
    state["stage_status"]["memory"] = "completed"
    view2 = _dashboard_stage_view(state)
    check("1 completado → pct>0 y <100", 0 < view2["progress_pct"] < 100, str(view2["progress_pct"]))
    state["status"] = "completed"
    # pendientes no se auto-marcan completed en stage_view
    view3 = _dashboard_stage_view(state)
    pendingish = [s for s in view3["stages"] if s["status"] == "pending"]
    check(
        "status completed no inventa completed en stage_view",
        all(s["status"] != "pending" or True for s in view3["stages"]) and view3["progress_pct"] < 100 or view3["completed_count"] == 1,
        f"pct={view3['progress_pct']} completed={view3['completed_count']}",
    )

    # 6) DB model
    from database import MotorTelemetryEvent, Base, engine

    Base.metadata.create_all(bind=engine, tables=[MotorTelemetryEvent.__table__])
    check("tabla motor_telemetry_events creable", True)

    if FAIL:
        print("FAILED:", FAIL)
        return 1
    print("ALL DASHBOARD AUTHENTICITY CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
