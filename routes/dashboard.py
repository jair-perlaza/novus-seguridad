"""
Dashboard routes for NOVUS
Main dashboard and system overview
"""
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from services.tenant_scope_service import get_tenant_context, tenant_may_read_platform_telemetry
from services.http_shell_service import dashboard_shell_metrics, schedule_platform_counters_warmup
from utils.logger import logger
from utils.user_helpers import get_current_user_data
import threading


dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/', endpoint='dashboard_principal')
@dashboard_bp.route('/dashboard', endpoint='dashboard_principal')
@login_required
def dashboard_principal():
    """
    Dashboard shell — HTML inmediato; métricas LIVE vía APIs en el cliente.
    """
    try:
        try:
            from flask import session as flask_session, request as flask_request
            from core.security import get_client_ip
            from services.continuous_monitoring_orchestrator import (
                ensure_post_login_monitoring_for_session,
            )

            audit_id = flask_session.get("_novus_login_session_id")
            if audit_id and getattr(current_user, "email", None):
                email = current_user.email
                uid = int(getattr(current_user, "id", 0) or 0) or None
                ip = get_client_ip() or (flask_request.remote_addr or "127.0.0.1")
                threading.Thread(
                    target=ensure_post_login_monitoring_for_session,
                    kwargs={
                        "user_email": email,
                        "user_id": uid,
                        "ip": ip,
                        "session_audit_id": audit_id,
                    },
                    daemon=True,
                    name="EnsurePostLoginMon",
                ).start()
        except Exception as mon_exc:
            logger.warning("ensure post-login monitoring: %s", mon_exc)

        tenant_ctx = get_tenant_context(current_user)
        monitoring_ok = tenant_may_read_platform_telemetry(tenant_ctx)

        if monitoring_ok:
            schedule_platform_counters_warmup()

        metricas = dashboard_shell_metrics(monitoring_ok=monitoring_ok)
        if not monitoring_ok:
            metricas["monitoring_not_configured"] = True
            metricas["monitoring_message"] = tenant_ctx.get("message")

        # Prioridad: hidratación progresiva vía /api/dashboard/priority (evita bloquear HTML)
        return render_template(
            'index.html',
            user=get_current_user_data(),
            sector_profile=get_current_user_data(),
            current_priority=None,
            **metricas,
            siem_enabled=False,
        )

    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        metricas_fallback = dashboard_shell_metrics(monitoring_ok=False)
        return render_template(
            'index.html',
            user=get_current_user_data(),
            current_priority=None,
            **metricas_fallback,
        )
