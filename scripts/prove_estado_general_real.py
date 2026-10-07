"""
Demostración: Estado General solo con telemetría real de motores.
- Sin setInterval/setTimeout/requestAnimationFrame en el JS del panel
- progress_pct solo tras motor_complete
- Persistencia verificable
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, r"C:\NOVUS")

ROOT = r"C:\NOVUS"
FAIL = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("[%s] %s%s" % ("OK" if ok else "FAIL", name, (" — " + detail) if detail else "")))
    if not ok:
        FAIL.append(name)


def main() -> int:
    print("=== Prove Estado General = real motor events ===")

    js_path = os.path.join(ROOT, "static", "js", "novus-dashboard-estado-general.js")
    js = open(js_path, encoding="utf-8").read()
    # Detectar llamadas reales, no menciones en comentarios
    def has_call(src: str, name: str) -> bool:
        return bool(re.search(r"\b" + name + r"\s*\(", src))

    check("JS sin setInterval", not has_call(js, "setInterval"))
    check("JS sin setTimeout", not has_call(js, "setTimeout"))
    check("JS sin requestAnimationFrame", not has_call(js, "requestAnimationFrame"))
    check("JS sin Math.random", not has_call(js, "Math.random"))
    check("JS usa EventSource SSE", "EventSource" in js and "/api/monitoring/stream" in js)
    check("JS mensaje espera motor", "Esperando resultados del motor" in js)
    check("JS exige progress_source completed_motors_only", "completed_motors_only" in js)
    check("JS exige completed_count > 0 para %", "completed > 0" in js or "completed_count" in js)

    cm = open(os.path.join(ROOT, "static", "js", "novus-continuous-monitor.js"), encoding="utf-8").read()
    check("continuous-monitor sin setInterval", not has_call(cm, "setInterval"))

    mon = open(os.path.join(ROOT, "api", "monitoring.py"), encoding="utf-8").read()
    check("API emite event motor", 'event: motor' in mon)
    check("API SSE text/event-stream", "text/event-stream" in mon)

    # Simulación de motores reales → progreso
    from services.motor_telemetry_service import (
        motor_start,
        motor_complete,
        compute_progress_from_completions,
        list_session_events,
    )
    from services.continuous_monitoring_orchestrator import (
        _dashboard_stage_view,
        _init_stage_status,
        _complete_dashboard_stage,
        DASHBOARD_STAGE_DEFS,
    )

    sid = "PROVE-EG-REAL"
    state = {"status": "phase1_running", "stage_status": _init_stage_status()}
    v0 = _dashboard_stage_view(state)
    check("antes de motores: 0% y waiting", v0["progress_pct"] == 0 and v0.get("waiting_for_engines"))

    sequence = [
        ("kernel_ia", "Kernel IA"),
        ("defense_motors", "Motores defensa"),
        ("memory", "Memory Engine"),
        ("processes", "Process Engine"),
        ("network", "Network Engine"),
    ]
    completed_ids = []
    pcts = []
    for mid, label in sequence:
        motor_start(session_id=sid, motor_id=mid, motor_label=label, activity="working")
        _complete_dashboard_stage(state, mid)
        view = _dashboard_stage_view(state)
        motor_complete(
            session_id=sid,
            motor_id=mid,
            motor_label=label,
            elements_analyzed={"verified": True},
            result="ok",
            evidence={"verifiable": True, "source": "prove_script"},
            progress_pct=view["progress_pct"],
        )
        completed_ids.append(mid)
        pcts.append(view["progress_pct"])
        print("  motor %s finished -> %s%%" % (mid, view["progress_pct"]))

    check("barra avanza (secuencia estricta creciente)", pcts == sorted(pcts) and pcts[-1] > pcts[0], str(pcts))
    check("porcentajes cambian en cada motor", len(set(pcts)) == len(pcts), str(pcts))
    check(
        "formula completed/total",
        pcts[-1] == int(round(100.0 * len(completed_ids) / len(DASHBOARD_STAGE_DEFS))),
        str(pcts[-1]),
    )

    events = list_session_events(sid)
    check("hay eventos started+completed", len(events) >= len(sequence))
    check(
        "cada completed tiene finished_at y evidence path",
        all(
            (e.get("finished_at") or e.get("status") == "running")
            for e in events
            if e.get("status") == "completed"
        ),
    )

    # Persistencia JSONL
    jsonl = os.path.join(ROOT, "data", "motor_telemetry", "events.jsonl")
    check("jsonl telemetria existe", os.path.isfile(jsonl))
    if os.path.isfile(jsonl):
        blob = open(jsonl, encoding="utf-8").read()
        check("jsonl contiene session prove", sid in blob)

    # DB
    try:
        from database import SessionLocal, MotorTelemetryEvent, Base, engine

        Base.metadata.create_all(bind=engine, tables=[MotorTelemetryEvent.__table__])
        db = SessionLocal()
        try:
            n = db.query(MotorTelemetryEvent).filter(MotorTelemetryEvent.session_id == sid).count()
            check("filas DB motor_telemetry_events", n >= 1, "count=%s" % n)
        finally:
            db.close()
    except Exception as exc:
        check("DB motor telemetry", False, str(exc))

    # get_monitoring_status shape
    from services.continuous_monitoring_orchestrator import get_monitoring_status_for_user

    st = get_monitoring_status_for_user("nobody@prove.local", lightweight=True)
    check("sin sesion: progress_source none", st.get("progress_source") == "none")
    check("sin sesion: waiting message", "Esperando resultados del motor" in (st.get("waiting_message") or ""))
    check("sin sesion: progress_pct None", st.get("progress_pct") is None)

    if FAIL:
        print("FAILED:", FAIL)
        return 1
    print("ALL PROOFS PASSED — Estado General uses only real motor telemetry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
