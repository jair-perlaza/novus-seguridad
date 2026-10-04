"""API de monitoreo continuo post-login — status + SSE de telemetría real."""
from __future__ import annotations

import json
import time
import threading

from flask import Blueprint, Response, jsonify, request, stream_with_context
from flask_login import current_user, login_required

from utils.logger import logger

monitoring_api_bp = Blueprint("monitoring_api", __name__, url_prefix="/api/monitoring")


@monitoring_api_bp.route("/status", methods=["GET"])
@login_required
def api_monitoring_status():
    try:
        from services.continuous_monitoring_orchestrator import get_monitoring_status_for_user

        email = getattr(current_user, "email", None)
        lightweight = request.args.get("poll") in ("1", "true", "yes")
        payload = get_monitoring_status_for_user(email or "", lightweight=lightweight)
        return jsonify({"status": "success", **payload}), 200
    except Exception as exc:
        logger.error("monitoring status: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "No se pudo leer el estado de monitoreo"}), 500


@monitoring_api_bp.route("/stream", methods=["GET"])
@login_required
def api_monitoring_stream():
    """
    Server-Sent Events — empuja el mismo payload canónico que /status.
    Solo avanza cuando hay cambio real (progreso/motores/estado).
    """
    email = getattr(current_user, "email", None) or ""

    @stream_with_context
    def generate():
        from services.continuous_monitoring_orchestrator import get_monitoring_status_for_user
        from services.motor_telemetry_service import register_wake_event, unregister_wake_event

        wake = threading.Event()
        register_wake_event(wake)
        last_sig = None
        try:
            yield ": connected\n\n"
            while True:
                try:
                    payload = get_monitoring_status_for_user(email, lightweight=True)
                    sig = json.dumps(
                        {
                            "status": payload.get("status"),
                            "progress_pct": payload.get("progress_pct"),
                            "completed_count": payload.get("completed_count"),
                            "finished_count": payload.get("finished_count"),
                            "failed_count": payload.get("failed_count"),
                            "report_id": payload.get("report_id"),
                            "has_summary": bool(payload.get("executive_summary")),
                            "current_label": payload.get("current_label"),
                            "updated_at": payload.get("updated_at"),
                            "motor_error": payload.get("motor_error"),
                            "active_n": len(payload.get("active_motor_telemetry") or []),
                            "events_n": len(payload.get("motor_events") or []),
                        },
                        sort_keys=True,
                        default=str,
                    )
                    if sig != last_sig:
                        last_sig = sig
                        data = json.dumps({"status": "success", **payload}, ensure_ascii=False, default=str)
                        yield f"event: monitoring\ndata: {data}\n\n"
                        # Evento dedicado de motores cuando hay telemetría nueva
                        motors_payload = {
                            "motor_events": payload.get("motor_events") or [],
                            "active_motor_telemetry": payload.get("active_motor_telemetry") or [],
                            "progress_pct": payload.get("progress_pct"),
                            "progress_source": payload.get("progress_source"),
                            "completed_count": payload.get("completed_count"),
                            "total_stages": payload.get("total_stages"),
                            "stages": payload.get("stages"),
                            "scan_running": payload.get("scan_running"),
                            "status": payload.get("status"),
                            "waiting_for_engines": payload.get("waiting_for_engines"),
                            "waiting_message": payload.get("waiting_message"),
                            "defense_motors": payload.get("defense_motors"),
                            "current_label": payload.get("current_label"),
                            "current_mechanism": payload.get("current_mechanism"),
                            "elements_analyzed": payload.get("elements_analyzed"),
                            "elapsed_sec": payload.get("elapsed_sec"),
                            "session_audit_id": payload.get("session_audit_id"),
                            "motor_error": payload.get("motor_error"),
                        }
                        yield f"event: motor\ndata: {json.dumps(motors_payload, ensure_ascii=False, default=str)}\n\n"
                    # Heartbeat SSE (comentario — no inventa progreso)
                    yield ": ping\n\n"
                except GeneratorExit:
                    break
                except Exception as exc:
                    err = json.dumps({"status": "error", "message": str(exc)[:200]})
                    yield f"event: error\ndata: {err}\n\n"
                wake.clear()
                wake.wait(timeout=1.5)
        finally:
            unregister_wake_event(wake)

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }
    return Response(generate(), headers=headers)


@monitoring_api_bp.route("/monitors", methods=["GET"])
@login_required
def api_monitoring_monitors():
    try:
        from services.continuous_monitoring_orchestrator import ensure_continuous_monitors

        return jsonify({"status": "success", "monitors": ensure_continuous_monitors()}), 200
    except Exception as exc:
        logger.error("monitoring monitors: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "Error al consultar monitores"}), 500


@monitoring_api_bp.route("/endpoint-enterprise", methods=["GET"])
@login_required
def api_endpoint_enterprise():
    """Estado EDR Endpoint Enterprise + YARA (datos reales)."""
    try:
        from services.endpoint_enterprise import (
            get_endpoint_enterprise_status,
            get_engine_status,
            run_endpoint_enterprise_cycle,
        )
        from services.endpoint_enterprise.kernel_insights import build_kernel_endpoint_context
        from services.endpoint_enterprise.rootkit_indicators import LIMITATIONS
        from services.lazy_engine_manager import start_if_needed, engine_status

        boot = start_if_needed("endpoint")

        cycle = None
        if request.args.get("cycle") in ("1", "true", "yes"):
            cycle = run_endpoint_enterprise_cycle(force_heavy=request.args.get("heavy") in ("1", "true"))
        return jsonify(
            {
                "status": "success",
                "lazy_engine": boot,
                "engine_status": engine_status("endpoint"),
                "enterprise": get_endpoint_enterprise_status(),
                "yara": get_engine_status(),
                "kernel_context": build_kernel_endpoint_context(),
                "limitations": LIMITATIONS,
                "cycle": cycle,
            }
        ), 200
    except Exception as exc:
        logger.error("endpoint enterprise api: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)[:240]}), 500


@monitoring_api_bp.route("/network-endpoint-enterprise", methods=["GET"])
@login_required
def api_network_endpoint_enterprise():
    """Estado del sensor Red+Endpoint Enterprise + XDR federado (datos reales)."""
    try:
        from services.network_endpoint_enterprise import get_enterprise_status, run_enterprise_cycle
        from services.network_endpoint_enterprise.xdr_federation import build_federated_xdr_payload
        from services.network_endpoint_enterprise.local_inventory import load_previous_inventory
        from services.network_endpoint_enterprise.kernel_insights import build_kernel_net_endpoint_context

        if request.args.get("cycle") in ("1", "true", "yes"):
            cycle = run_enterprise_cycle(force_heavy=request.args.get("heavy") in ("1", "true"))
        else:
            cycle = None
        return jsonify(
            {
                "status": "success",
                "enterprise": get_enterprise_status(),
                "inventory": load_previous_inventory(),
                "xdr_federated": build_federated_xdr_payload(),
                "kernel_context": build_kernel_net_endpoint_context(),
                "cycle": cycle,
            }
        ), 200
    except Exception as exc:
        logger.error("nee api: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)[:240]}), 500


@monitoring_api_bp.route("/network-config", methods=["GET"])
@login_required
def api_network_monitoring_config():
    try:
        from services.network_monitoring_service import build_network_monitoring_payload

        return jsonify(build_network_monitoring_payload(current_user)), 200
    except Exception as exc:
        logger.error("network monitoring config: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "No se pudo leer la configuración de monitoreo"}), 500


@monitoring_api_bp.route("/network-config/action", methods=["POST"])
@login_required
def api_network_monitoring_action():
    try:
        from services.csrf_service import validate_csrf_token
        from services.network_monitoring_service import (
            build_network_monitoring_payload,
            restart_monitoring,
            run_discovery_now,
            set_monitoring_enabled,
        )

        if not validate_csrf_token(
            request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        ):
            return jsonify({"status": "error", "message": "CSRF inválido"}), 403
        body = request.get_json(silent=True) or {}
        action = body.get("action") or request.form.get("action") or ""
        action = action.strip().lower()
        if action == "refresh":
            payload = build_network_monitoring_payload(current_user)
            return jsonify({"status": "success", **payload}), 200
        if action == "discover_now":
            result = run_discovery_now(current_user)
        elif action == "restart":
            result = restart_monitoring(current_user)
        elif action == "enable":
            result = set_monitoring_enabled(current_user, enabled=True)
        elif action == "disable":
            result = set_monitoring_enabled(current_user, enabled=False)
        elif action == "stop_discovery":
            from services.network_monitoring_service import stop_discovery

            result = stop_discovery(current_user)
        elif action == "resume_discovery":
            from services.network_monitoring_service import resume_discovery

            result = resume_discovery(current_user)
        else:
            return jsonify({"status": "error", "message": "Acción no reconocida"}), 400
        if not result.get("ok"):
            return jsonify({"status": "error", **result}), 400
        payload = build_network_monitoring_payload(current_user)
        return jsonify({"status": "success", "action_result": result, **payload}), 200
    except Exception as exc:
        logger.error("network monitoring action: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": "Error al ejecutar acción"}), 500


@monitoring_api_bp.route("/telemetry", methods=["GET"])
@login_required
def api_monitoring_telemetry():
    """Lista eventos de telemetría de motores (verificables)."""
    try:
        from services.motor_telemetry_service import list_session_events, recent_events
        from services.continuous_monitoring_orchestrator import get_monitoring_status_for_user

        email = getattr(current_user, "email", None) or ""
        st = get_monitoring_status_for_user(email, lightweight=True)
        sid = st.get("session_audit_id")
        if sid:
            events = list_session_events(sid, limit=100)
        else:
            events = recent_events(50)
        return jsonify(
            {
                "status": "success",
                "session_audit_id": sid,
                "events": events,
                "progress_source": st.get("progress_source"),
                "progress_pct": st.get("progress_pct"),
            }
        ), 200
    except Exception as exc:
        logger.error("monitoring telemetry: %s", exc, exc_info=True)
        return jsonify({"status": "error", "message": str(exc)[:200]}), 500