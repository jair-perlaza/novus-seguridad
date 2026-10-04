"""
API Swarm Defense Engine — lectura + acciones con aprobación.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request, session

from utils.logger import logger

swarm_defense_api_bp = Blueprint(
    "swarm_defense_api",
    __name__,
    url_prefix="/api/swarm-defense",
)


def _require_login() -> bool:
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


def _user_email():
    return session.get("user_email") or session.get("email")


@swarm_defense_api_bp.route("/status", methods=["GET"])
def swarm_status():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.swarm_defense import swarm_defense_engine

    return jsonify(swarm_defense_engine.status())


@swarm_defense_api_bp.route("/events", methods=["GET"])
def swarm_events():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.swarm_defense.event_bus import swarm_event_bus

    limit = min(int(request.args.get("limit", 30)), 100)
    return jsonify({"ok": True, "events": swarm_event_bus.recent(limit)})


@swarm_defense_api_bp.route("/correlations", methods=["GET"])
def swarm_correlations():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.swarm_defense import swarm_defense_engine

    limit = min(int(request.args.get("limit", 20)), 50)
    return jsonify({"ok": True, "correlations": swarm_defense_engine.recent_correlations(limit)})


@swarm_defense_api_bp.route("/actions/execute", methods=["POST"])
def swarm_action_execute():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.swarm_defense import swarm_defense_engine

    body = request.get_json(silent=True) or {}
    action_id = body.get("action_id")
    if not action_id:
        return jsonify({"ok": False, "error": "action_id_required"}), 400
    result = swarm_defense_engine.execute_action(
        str(action_id),
        correlation=body.get("correlation"),
        origin_event=body.get("origin_event"),
        user_email=_user_email(),
        confirmed=bool(body.get("confirmed")),
        reason=str(body.get("reason") or ""),
        params=body.get("params") or {},
    )
    code = 200
    if result.get("status") == "needs_approval":
        code = 202
    elif result.get("status") in ("denied",):
        code = 403
    elif result.get("status") in ("error", "unknown"):
        code = 400
    return jsonify({"ok": bool(result.get("ok")), "result": result}), code


@swarm_defense_api_bp.route("/observability", methods=["GET"])
def swarm_observability():
    """Panel técnico Swarm — métricas reales únicamente."""
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.swarm_defense import swarm_defense_engine

    return jsonify(swarm_defense_engine.observability())


@swarm_defense_api_bp.route("/audit", methods=["GET"])
def swarm_audit():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.swarm_defense.response_policy import recent_action_audits
    from services.swarm_defense.learning import recent_learning

    return jsonify(
        {
            "ok": True,
            "actions": recent_action_audits(min(int(request.args.get("limit", 40)), 100)),
            "learning": recent_learning(min(int(request.args.get("learning_limit", 20)), 50)),
        }
    )


@swarm_defense_api_bp.route("/simulate-ingest", methods=["POST"])
def swarm_simulate_ingest():
    """
    NO genera datos falsos de amenaza.
    Solo re-procesa un payload de detección ya existente enviado por el cliente autenticado
    (útil para pruebas de integración con evidencia real del caller).
    """
    from services.v1_runtime_surface import swarm_simulate_ingest_allowed

    if not swarm_simulate_ingest_allowed():
        return jsonify({
            "ok": False,
            "error": "lab_runtime_required",
            "message": "simulate-ingest solo disponible con NOVUS_ALLOW_LAB_RUNTIME explícito.",
        }), 403
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    body = request.get_json(silent=True) or {}
    event = body.get("event")
    if not isinstance(event, dict) or not event.get("motor") or not event.get("evidence"):
        return jsonify(
            {
                "ok": False,
                "error": "event_required",
                "message": "Se requiere event.motor + event.evidence reales. Swarm no inventa telemetría.",
            }
        ), 400
    if not (event.get("evidence") or {}).get("verified"):
        return jsonify(
            {
                "ok": False,
                "error": "evidence_not_verified",
                "message": "evidence.verified debe ser true — no se aceptan payloads no verificados",
            }
        ), 400
    from services.swarm_defense import swarm_defense_engine

    result = swarm_defense_engine.process_event(event)
    return jsonify({"ok": True, "correlation": result})
