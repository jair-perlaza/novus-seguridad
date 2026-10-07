"""
CLOUD-P1 — cheap liveness/readiness for Cloud Run style probes.

GET /healthz — process alive + optional DB ping.
Does not start scanners, workers, AI, or discovery.
"""
from __future__ import annotations

from flask import Blueprint, jsonify

healthz_bp = Blueprint("healthz", __name__)


@healthz_bp.route("/healthz", methods=["GET"], endpoint="healthz")
def healthz():
    """
    200: process up and database reachable.
    503: process up but database unreachable (never masked as 200).
    """
    payload = {
        "ok": True,
        "status": "ok",
        "process": "alive",
        "database": {"ok": False, "backend": None},
    }
    try:
        from database import SessionLocal, database_backend_info
        from sqlalchemy import text

        info = database_backend_info()
        payload["database"]["backend"] = info.get("backend")
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
            payload["database"]["ok"] = True
        finally:
            db.close()
    except Exception as exc:
        payload["ok"] = False
        payload["status"] = "degraded"
        payload["database"]["ok"] = False
        payload["database"]["error"] = type(exc).__name__
        return jsonify(payload), 503

    if not payload["database"]["ok"]:
        payload["ok"] = False
        payload["status"] = "degraded"
        return jsonify(payload), 503

    try:
        from services.cloud_runtime_service import runtime_info

        payload["runtime"] = runtime_info().get("runtime")
    except Exception:
        pass

    return jsonify(payload), 200
