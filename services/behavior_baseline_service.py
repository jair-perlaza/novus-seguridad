"""
Compatibilidad: hooks legacy delegan al Adaptive Profile Engine (interno).
No exponer resumen de aprendizaje al Dashboard.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from utils.logger import logger


def record_activity(**kwargs) -> Dict[str, Any]:
    from services.adaptive_profile_engine import observe

    return observe(**kwargs)


def rebuild_baseline(user_email: str) -> Dict[str, Any]:
    from services.adaptive_profile_engine import rebuild_defense_profile

    return rebuild_defense_profile(user_email)


def get_dashboard_behavior_summary(user_email: str) -> Dict[str, Any]:
    """Opaco a propósito: el aprendizaje no se muestra al cliente."""
    return {
        "available": True,
        "visible": False,
        "message": "Perfil adaptativo interno activo (no visible en interfaz)",
        "engine": "adaptive_profile_engine",
    }


def record_login_activity_async(
    user_email: str,
    ip: str,
    session_audit_id: str,
    *,
    browser: Optional[str] = None,
    os_name: Optional[str] = None,
) -> None:
    def _run():
        try:
            from services.adaptive_profile_engine import observe
            from services.notification_center_service import emit_notification

            observe(
                user_email=user_email,
                event_type="login",
                ip=ip,
                session_audit_id=session_audit_id,
                browser=browser,
                evidence={"os_name": os_name} if os_name else None,
                source_motor="login_session_audit",
                mechanisms=["login", "session_audit"],
            )
            emit_notification(
                user_email=user_email,
                category="sistema",
                notification_kind="system",
                priority="info",
                title="Sesión iniciada",
                description=f"Login registrado para {user_email} desde {ip or 'IP no disponible'}.",
                related_user=user_email,
                detail_url="/dashboard",
                source_motor="login_session_audit",
                source_ref=session_audit_id,
            )
        except Exception as exc:
            logger.error("record_login_activity_async→APE: %s", exc)

    from services.bounded_background import submit_background

    submit_background(_run, name="APE-LoginHook")


def record_scan_activity_async(
    user_email: str,
    session_audit_id: str,
    *,
    risk_level: Optional[str] = None,
    mechanisms: Optional[List[str]] = None,
    duration_sec: Optional[float] = None,
    report_id: Optional[str] = None,
) -> None:
    def _run():
        try:
            from services.adaptive_profile_engine import observe
            from services.notification_center_service import emit_notification

            observe(
                user_email=user_email,
                event_type="auto_scan",
                session_audit_id=session_audit_id,
                session_duration_sec=int(duration_sec) if duration_sec is not None else None,
                risk_level=risk_level,
                mechanisms=mechanisms or ["continuous_monitoring"],
                evidence={"report_id": report_id},
                source_motor="continuous_monitoring_orchestrator",
            )
            emit_notification(
                user_email=user_email,
                category="sistema",
                notification_kind="system",
                priority="info"
                if (risk_level or "").lower() not in ("alto", "crítico", "critical", "high")
                else "high",
                title="Escaneo automático finalizado",
                description=(
                    "Escaneo finalizado"
                    + (f" — riesgo: {risk_level}" if risk_level else "")
                    + (f" — informe {report_id}" if report_id else "")
                ),
                related_user=user_email,
                detail_url=f"/reportes?highlight={report_id}" if report_id else "/dashboard",
                incident_url="/reportes",
                source_motor="continuous_monitoring_orchestrator",
                source_ref=session_audit_id,
            )
        except Exception as exc:
            logger.error("record_scan_activity_async→APE: %s", exc)

    from services.bounded_background import submit_background

    submit_background(_run, name="APE-ScanHook")
