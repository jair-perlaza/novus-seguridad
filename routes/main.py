"""
Main routes for NOVUS
All other routes including vulnerabilities, automation, reports, XDR, etc.
"""
from flask import Blueprint, render_template, request, redirect, url_for, jsonify
from flask_login import login_required, current_user
from services.system_monitor import system_monitor
from services.network_scanner import network_scanner
from utils.logger import logger
from utils.sectores_config import SECTORES_NOVUS
from utils.host_data import get_local_ip, format_ip_or_unavailable, get_disk_usage
from utils.security_helpers import count_node_findings, compute_risk_summary, get_node_id
from utils.user_helpers import get_current_user_data
from utils.rbac import require_module
from services.v1_runtime_surface import v1_nav_route_guard
from datetime import datetime
from typing import Optional
import time
import psutil
import socket
import platform


main_bp = Blueprint('main', __name__)


@main_bp.route('/vulnerabilidades', endpoint='ruta_vulnerabilidades')
@login_required
def vulnerabilidades():
    """
    Vulnerabilities route with real system data and advanced vulnerability scanning
    """
    try:
        from services.advanced_detector_service import advanced_detector
        
        user_info = get_current_user_data()
        
        from services.system_monitor import system_monitor

        status = system_monitor.get_system_status()
        try:
            cpu_actual = float(status.get("cpu") if status.get("cpu") is not None else psutil.cpu_percent(interval=0))
        except Exception as cpu_error:
            logger.error(f"Error in cpu_percent: {cpu_error}")
            cpu_actual = 0.0

        try:
            memoria_actual = float(status.get("ram") if status.get("ram") is not None else psutil.virtual_memory().percent)
        except Exception as mem_error:
            logger.error(f"Error in virtual_memory: {mem_error}")
            memoria_actual = 0.0

        try:
            disco_actual = float(status.get("disk") if status.get("disk") is not None else get_disk_usage().percent)
        except Exception as disk_error:
            logger.error(f"Error in disk_usage: {disk_error}")
            disco_actual = 0.0

        procesos_count = status.get("procesos_activos")
        if procesos_count is None:
            try:
                procesos_count = len(list(psutil.process_iter()))
            except Exception:
                procesos_count = 0

        try:
            conexiones = int(status.get("conexiones_activas") or 0)
        except Exception as net_error:
            logger.error(f"Error in net_connections: {net_error}")
            conexiones = 0

        stats_vuln = {
            "cpu": f"{cpu_actual:.1f}%",
            "ram": f"{memoria_actual:.1f}%",
            "disco": f"{disco_actual:.1f}%",
            "procesos": procesos_count,
            "conexiones": conexiones,
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
            "uptime": f"{(time.time() - psutil.boot_time()) / 3600:.1f} horas"
        }
        
        lista_vuln = []
        try:
            from services.novus_security_integration import novus_security
            from services.http_shell_service import (
                get_cached_vulnerabilities_snapshot,
                schedule_vulnerability_scan_if_stale,
            )

            lista_vuln = get_cached_vulnerabilities_snapshot()
            if not lista_vuln and not novus_security._threat_cache.get("last_scan"):
                schedule_vulnerability_scan_if_stale()
        except Exception as e:
            logger.error(f"Error using integrated security motor for vulnerabilities: {e}")

        logger.info(f"Vulnerabilities: {len(lista_vuln)} findings from live scans")
        
        return render_template('vulnerabilidades.html', 
                           user=user_info, 
                           stats=stats_vuln, 
                           vulnerabilidades=lista_vuln)
                           
    except Exception as e:
        logger.error(f"Vulnerabilities error: {e}", exc_info=True)
        return render_template('vulnerabilidades.html', 
                           user=get_current_user_data(), 
                           stats={}, 
                           vulnerabilidades=[])


@main_bp.route('/automatizacion', endpoint='ruta_automatizacion')
@login_required
@require_module('playbooks')
def automatizacion():
    """
    Automation route with real system data using advanced_detector
    """
    try:
        from services.advanced_detector_service import advanced_detector
        from services.system_monitor import system_monitor

        status = system_monitor.get_system_status()
        procesos = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))
        cpu_total = float(status.get("cpu") if status.get("cpu") is not None else psutil.cpu_percent(interval=0))
        memoria_total = psutil.virtual_memory()

        import os
        from services import playbook_service
        saved_playbooks = playbook_service.list_playbooks()

        try:
            from services.novus_security_integration import novus_security
            verified_count = novus_security.get_cached_threat_count() or 0
        except Exception as e:
            logger.error(f"Error using integrated security motor: {e}")
            verified_count = 0

        reglas_ia = []

        if verified_count:
            reglas_ia.append({
                "id": "THREAT-001",
                "nombre": "Amenazas verificadas por motor NOVUS",
                "descripcion": f"{verified_count} amenaza(s) con evidencia verificable en el último escaneo",
                "estado": "Activo",
                "impacto": "Detectado",
                "ejecuciones_mes": "Sin datos disponibles",
                "is_playbook": False,
            })

        for playbook in saved_playbooks:
            reglas_ia.append({
                "id": playbook.get('id', 'PB-000'),
                "nombre": playbook.get('nombre', 'Playbook'),
                "descripcion": playbook.get('accion', playbook.get('trigger', 'Playbook persistido')),
                "estado": playbook.get('estado', 'Activo'),
                "impacto": playbook.get('prioridad', 'Sin datos disponibles'),
                "ejecuciones_mes": (
                    str(playbook["ejecuciones"])
                    if playbook.get("ejecuciones") is not None
                    else "Sin datos disponibles"
                ),
                "is_playbook": True,
                "trigger": playbook.get('trigger'),
                "accion": playbook.get('accion'),
            })

        stats_auto = {
            "procesos_totales": len(procesos),
            "procesos_criticos": len([p for p in procesos if p.info.get('cpu_percent', 0) > 80]),
            "cpu_actual": f"{cpu_total:.1f}%",
            "memoria_usada": f"{memoria_total.percent:.1f}%",
            "reglas_activas": len(reglas_ia),
            "amenazas_detectadas": verified_count,
            "ejecuciones_mes": "Sin datos disponibles",
            "uptime": f"{(time.time() - psutil.boot_time()) / 3600:.1f} horas"
        }
        
        logger.info(f"Automation: {len(reglas_ia)} active rules - CPU: {cpu_total}pct, RAM: {memoria_total.percent}pct")
        
        return render_template('automatizacion.html', 
                           user=get_current_user_data(), 
                           reglas=reglas_ia, 
                           stats=stats_auto)
                           
    except Exception as e:
        logger.error(f"Automation error: {e}", exc_info=True)
        return render_template('automatizacion.html', 
                           user=get_current_user_data(), 
                           reglas=[], 
                           stats={})


@main_bp.route('/xdr', endpoint='ruta_amenazas_realtime')
@main_bp.route('/amenazas', endpoint='ruta_amenazas_realtime')
@login_required
@require_module('xdr')
def amenazas_realtime():
    """
    XDR/Threats route with detections from the live security motor only.
    """
    try:
        from services.monitoring_telemetry_guard import (
            assert_telemetry_access,
            empty_host_resumen,
            tenant_id_for_user,
        )

        _, blocked_msg = assert_telemetry_access(current_user)
        if blocked_msg:
            return render_template(
                'xdr.html',
                user=get_current_user_data(),
                resumen=empty_host_resumen(),
                eventos=[],
                siem_enabled=False,
                monitoring_not_configured=True,
                monitoring_message=blocked_msg,
            )

        from utils.host_data import get_local_ip, format_ip_or_unavailable, get_disk_usage
        from services.novus_security_integration import novus_security

        from services.system_monitor import system_monitor

        status = system_monitor.get_system_status()
        cpu = status.get("cpu")
        if cpu is None:
            cpu = psutil.cpu_percent(interval=0)
        memoria = psutil.virtual_memory()
        disco = get_disk_usage()
        from services.connections_metrics_service import get_summary_for_dashboard
        conn_val, conn_meta = get_summary_for_dashboard()
        conexiones = conn_val if conn_val is not None else "Sin datos disponibles"
        procesos_activos = status.get("procesos_activos")
        if procesos_activos is None:
            try:
                procesos_activos = len(psutil.pids())
            except Exception:
                procesos_activos = "Sin datos disponibles"
        local_ip = format_ip_or_unavailable(get_local_ip())

        from services.http_shell_service import get_threat_cache_snapshot, schedule_threat_scan_if_stale

        threats_data = get_threat_cache_snapshot()
        if not threats_data.get('last_scan'):
            schedule_threat_scan_if_stale()
        engine_threats = threats_data.get('threats', [])
        verified_count = novus_security.get_cached_threat_count()
        if verified_count is None:
            verified_count = 0

        resumen = {
            "total_eventos": verified_count if verified_count else "Sin amenazas detectadas",
            "conexiones_activas": conexiones,
            "conexiones_meta": conn_meta,
            "procesos_activos": procesos_activos,
            "cpu_actual": f"{cpu:.1f}%",
            "memoria_usada": f"{memoria.percent:.1f}%",
            "memoria_disponible": f"{memoria.available / (1024**3):.1f} GB",
            "disco_usado": f"{disco.percent:.1f}%",
            "disco_libre": f"{disco.free / (1024**3):.1f} GB",
            "nivel_critico": verified_count if verified_count else 0,
            "nivel_critico_texto": "Sin datos disponibles" if not verified_count else "Detectado",
            "estado": "Monitorizado (psutil)",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "salud_nodo": "Sin datos disponibles",
            "amenazas_detectadas": verified_count if verified_count else "Sin amenazas detectadas",
        }

        alertas = []
        try:
            from services.alerts_canonical_service import get_canonical_alerts
            tid = tenant_id_for_user(current_user)
            for alert in get_canonical_alerts(include_resolved=False, limit=80, tenant_id=tid):
                alertas.append({
                    "id": alert.get("id"),
                    "dispositivo": alert.get("motor") or "Motor NOVUS",
                    "ip": alert.get("origin") or local_ip,
                    "amenaza": alert.get("threat_type") or "Amenaza detectada",
                    "sector_focus": "SEGURIDAD",
                    "gravedad": alert.get("risk_level") or "DETECTADO",
                    "timestamp": alert.get("timestamp") or f"{alert.get('date')} {alert.get('time')}",
                    "evidence_summary": alert.get("evidence_summary"),
                    "status": alert.get("status"),
                    "confidence": alert.get("confidence"),
                })
        except Exception as canon_exc:
            logger.debug("XDR canonical alerts fallback: %s", canon_exc)
            for threat in engine_threats:
                details = threat.get("details") or {}
                if isinstance(details, dict) and not (details.get("verified") or details.get("evidence")):
                    continue
                alertas.append({
                    "id": f"THR-{threat.get('type', 'UNK')}",
                    "dispositivo": threat.get("type", "Motor de seguridad"),
                    "ip": local_ip,
                    "amenaza": str(details.get("evidence") or details.get("message") or threat.get("type")),
                    "sector_focus": "SEGURIDAD",
                    "gravedad": str(threat.get("severity", "Detectado")).upper(),
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                })

        logger.info(f"Threats route: {len(alertas)} live detections")

        return render_template(
            'xdr.html',
            user=get_current_user_data(),
            resumen=resumen,
            eventos=alertas,
            siem_enabled=False
        )

    except Exception as e:
        logger.error(f"Threats error: {e}", exc_info=True)
        return render_template(
            'xdr.html',
            user=get_current_user_data(),
            resumen={
                "total_eventos": "Sin datos disponibles",
                "conexiones_activas": "Sin datos disponibles",
                "procesos_activos": "Sin datos disponibles",
                "cpu_actual": "Sin datos disponibles",
                "memoria_usada": "Sin datos disponibles",
                "memoria_disponible": "Sin datos disponibles",
                "disco_usado": "Sin datos disponibles",
                "disco_libre": "Sin datos disponibles",
                "nivel_critico": "Sin datos disponibles",
                "nivel_critico_texto": "Sin datos disponibles",
                "estado": "ERROR",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "salud_nodo": "Sin datos disponibles",
                "amenazas_detectadas": "Sin datos disponibles",
            },
            eventos=[],
            siem_enabled=False
        )


@main_bp.route('/endpoints', endpoint='ruta_endpoints_realtime')
@login_required
def endpoints_realtime():
    """
    Endpoints route — inventario canónico desde platform_metrics (misma fuente que Dashboard).
    """
    try:
        from services.platform_metrics_service import build_endpoint_inventory
        from services.http_shell_service import schedule_platform_counters_warmup

        schedule_platform_counters_warmup()
        from services.monitoring_telemetry_guard import assert_telemetry_access, tenant_id_for_user

        _, blocked_msg = assert_telemetry_access(current_user)
        user_info = get_current_user_data()
        tid = tenant_id_for_user(current_user)
        if blocked_msg:
            return render_template(
                'endpoints.html',
                user=user_info,
                endpoints=[],
                endpoints_total=None,
                monitoring_not_configured=True,
                monitoring_message=blocked_msg,
            )

        endpoints = build_endpoint_inventory(tenant_id=tid)
        from services.performance_cache import peek_cached

        counters = peek_cached(f"platform_counters:{tid or 'default'}") or {}

        return render_template(
            'endpoints.html',
            user=user_info,
            endpoints=endpoints,
            endpoints_total=counters.get('endpoints_total') if counters else len(endpoints) or "LOADING",
        )
    except Exception as e:
        logger.error(f"Endpoints error: {e}", exc_info=True)
        return render_template(
            'endpoints.html',
            user=get_current_user_data(),
            endpoints=[],
            endpoints_total="Sin datos disponibles",
        )


@main_bp.route('/reportes', endpoint='ruta_reportes_realtime')
@login_required
def reportes_realtime():
    """
    Reports route with real system data using advanced_detector
    """
    try:
        from services.advanced_detector_service import advanced_detector
        import os
        import json

        cpu = psutil.cpu_percent(interval=0)
        memoria = psutil.virtual_memory()
        disco = get_disk_usage()
        red = psutil.net_io_counters()
        boot_time = psutil.boot_time()

        procesos = len(list(psutil.process_iter()))
        usuarios = len(psutil.users())

        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'reports')
        os.makedirs(reports_dir, exist_ok=True)

        from services.security_report_service import list_reports
        from services.tenant_isolation_service import require_user_tenant_id

        historial = list_reports(limit=100, tenant_id=require_user_tenant_id(current_user))

        dispositivos_protegidos = len(network_scanner.get_cached_nodes())

        try:
            from services.novus_security_integration import novus_security
            from services.http_shell_service import (
                get_cached_vulnerabilities_snapshot,
                get_threat_cache_snapshot,
                schedule_vulnerability_scan_if_stale,
            )

            threats_data = get_threat_cache_snapshot()
            findings = get_cached_vulnerabilities_snapshot()
            if not findings:
                schedule_vulnerability_scan_if_stale()
            amenazas_detectadas = novus_security.get_cached_threat_count()
            if amenazas_detectadas is None:
                amenazas_detectadas = "Sin datos disponibles"
        except Exception as e:
            logger.error(f"Error using integrated security motor: {e}")
            findings = []
            amenazas_detectadas = "Sin datos disponibles"

        pentest_reports = sum(
            1 for item in historial
            if 'pentest' in str(item.get('tipo', '')).lower()
        )

        threat_count = amenazas_detectadas if isinstance(amenazas_detectadas, int) else 0
        risk = compute_risk_summary(cpu, memoria.percent, disco.percent, threat_count, len(findings))

        resumen = {
            "dispositivos_protegidos": dispositivos_protegidos,
            "pruebas_pentesting": pentest_reports if pentest_reports else "Sin datos disponibles",
            "amenazas_bloqueadas": amenazas_detectadas,
            "vulnerabilidades_detectadas": len(findings),
            "nivel_riesgo": risk["nivel_riesgo"],
            "salud_sistema": risk["salud_sistema"],
            "uso_cpu": f"{cpu:.1f}%",
            "uso_ram": f"{memoria.percent:.1f}%",
            "uso_disco": f"{disco.percent:.1f}%",
            "ram_total": f"{memoria.total / (1024**3):.1f} GB",
            "ram_usada": f"{memoria.used / (1024**3):.1f} GB",
            "disco_total": f"{disco.total / (1024**3):.1f} GB",
            "disco_libre": f"{disco.free / (1024**3):.1f} GB",
            "procesos_activos": procesos,
            "usuarios_conectados": usuarios,
            "network_bytes_sent": f"{red.bytes_sent / (1024**3):.2f} GB",
            "network_bytes_recv": f"{red.bytes_recv / (1024**3):.2f} GB",
            "uptime": f"{(time.time() - boot_time) / 3600:.1f} horas",
            "periodo": datetime.now().strftime("%B %Y"),
            "estado_sistema": risk["estado_sistema"],
            "nivel_critico": risk["nivel_critico"]
        }

        return render_template('reportes.html',
                             user=get_current_user_data(),
                             resumen=resumen,
                             historial=historial)
    except Exception as e:
        logger.error(f"Reports error: {e}", exc_info=True)
        return render_template('reportes.html',
                             user=get_current_user_data(),
                             resumen={},
                             historial=[])


@main_bp.route('/api/reports/generate', methods=['POST'])
@login_required
def generate_report():
    """
    Generate a new report in JSON format
    """
    try:
        import os
        import json
        from datetime import datetime

        data = request.get_json()
        report_type = data.get('tipo', 'Sistema')

        cpu = psutil.cpu_percent(interval=0)
        memoria = psutil.virtual_memory()
        disco = get_disk_usage()
        red = psutil.net_io_counters()
        boot_time = psutil.boot_time()

        report = {
            "id": f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "tipo": report_type,
            "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "metricas": {
                "cpu": f"{cpu:.1f}%",
                "memoria": f"{memoria.percent:.1f}%",
                "disco": f"{disco.percent:.1f}%",
                "procesos": len(list(psutil.process_iter())),
                "uptime": f"{(time.time() - boot_time) / 3600:.1f} horas"
            },
            "red": {
                "bytes_enviados": f"{red.bytes_sent / (1024**3):.2f} GB",
                "bytes_recibidos": f"{red.bytes_recv / (1024**3):.2f} GB"
            }
        }

        # Save report to /data/reports/
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'reports')
        os.makedirs(reports_dir, exist_ok=True)

        filename = f"{report['id']}.json"
        filepath = os.path.join(reports_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Report generated: {report['id']}")

        return jsonify({
            "status": "success",
            "message": "Report generated successfully",
            "report": report
        })

    except Exception as e:
        logger.error(f"Error generating report: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@main_bp.route('/descargar-reporte/<report_id>')
@login_required
def download_report(report_id):
    """Download a report by ID (PDF preferred, JSON fallback)."""
    try:
        import os
        from flask import send_file
        from services.security_report_service import get_report
        from services.report_pdf_service import generate_pdf
        from services.tenant_isolation_service import require_user_tenant_id

        tenant_id = require_user_tenant_id(current_user)
        report = get_report(report_id, tenant_id=tenant_id)
        if report:
            path = generate_pdf(report)
            if path.endswith('.pdf'):
                return send_file(path, as_attachment=True, download_name=f"{report_id}.pdf")
            return send_file(path, as_attachment=True, download_name=f"{report_id}.html")

        reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'reports')
        filepath = os.path.join(reports_dir, f"{report_id}.json")

        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=f"{report_id}.json")
        return "Report not found", 404

    except Exception as e:
        logger.error(f"Error downloading report: {e}")
        return "Error downloading report", 500


@main_bp.route('/configuracion', endpoint='ruta_configuracion')
@login_required
@require_module('configuracion')
def configuracion():
    """
    Configuration route with real system data
    """
    from flask import current_app
    from core.config import Config
    import json
    import os

    from utils.host_data import get_local_ip, format_ip_or_unavailable, get_disk_usage

    user_data = get_current_user_data()

    config_file = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'config',
        'security_config.json'
    )
    if os.path.exists(config_file):
        with open(config_file, 'r', encoding='utf-8') as config_handle:
            security_config = json.load(config_handle)
        whatsapp_status = "Habilitado" if security_config.get('whatsapp_alerts') else "Deshabilitado"
        email_status = "Habilitado" if security_config.get('email_reports') else "Deshabilitado"
        pentest_mode = security_config.get('pentest_mode', 'Sin datos disponibles')
    else:
        whatsapp_status = "Sin configurar"
        email_status = "Sin configurar"
        pentest_mode = "Sin datos disponibles"

    config_actual = {
        "modo_desarrollo": "ACTIVO (Debug On)" if current_app.debug else "PRODUCCIÓN",
        "puerto_escucha": Config.PORT,
        "ip_servidor": format_ip_or_unavailable(get_local_ip()),
        "sector": user_data.get('sector', 'Sin datos disponibles'),
        "sector_activo": (user_data.get('sector') or 'fintech').lower().replace(' ', '_'),
        "intensidad_pentesting": pentest_mode,
        "alertas_whatsapp": whatsapp_status,
        "alertas_email": email_status
    }
    
    stats_config = {
        "uso_cpu_kernel": f"{psutil.cpu_percent()}%",
        "procesos_novus": len([p for p in psutil.process_iter() if 'python' in p.name().lower()]),
        "uptime_sistema": f"{round((time.time() - psutil.boot_time()) / 3600, 1)} Horas"
    }
    
    from services.csrf_service import issue_csrf_token
    csrf_token = issue_csrf_token()

    return render_template('configuracion.html', 
                           user=user_data, 
                           config=config_actual,
                           sectores=SECTORES_NOVUS,
                           stats=stats_config,
                           csrf_token=csrf_token)


def _build_incidents_from_real_sources(tenant_id: Optional[str] = None):
    """Build incident rows from canonical alerts service (evidencia verificable únicamente)."""
    from services.alerts_canonical_service import get_canonical_alerts

    incidentes = []
    for alert in get_canonical_alerts(include_resolved=False, limit=50, tenant_id=tenant_id):
        incidentes.append({
            "id": alert.get("id"),
            "ip": alert.get("origin") or "Sin datos disponibles",
            "tipo": alert.get("threat_type") or "Alerta de seguridad",
            "descripcion": alert.get("evidence_summary") or "",
            "gravedad": alert.get("risk_level") or "HIGH",
            "timestamp": alert.get("timestamp") or f"{alert.get('date')} {alert.get('time')}",
            "status": alert.get("status") or "activo",
            "confidence": alert.get("confidence"),
            "motor": alert.get("motor"),
            "remediation_status": alert.get("remediation_status"),
            "auto_actions": alert.get("auto_actions") or [],
            "evidence_items": alert.get("evidence_items") or [],
            "playbook_id": alert.get("playbook_id"),
            "timeline": alert.get("timeline") or [],
        })

    try:
        from services.security_report_service import auto_generate_for_findings
        findings = []
        for item in incidentes:
            findings.append({
                "id": item["id"],
                "tipo": "incidente",
                "tipo_vulnerabilidad": item.get("tipo"),
                "descripcion": item.get("descripcion"),
                "ip": item.get("ip"),
                "gravedad": item.get("gravedad"),
                "detected_at": item.get("timestamp"),
                "estado": item.get("status") or "Activo",
            })
        auto_generate_for_findings(findings)
    except Exception as exc:
        logger.error(f"Incident report generation error: {exc}")

    return incidentes


def _build_siem_logs_from_real_sources():
    """Build SIEM log stream from audit logs and AI kernel status."""
    from database import SessionLocal, Log
    from services.ai_kernel import ai_kernel

    logs = []
    db = SessionLocal()
    try:
        registros = db.query(Log).order_by(Log.id.desc()).limit(100).all()
        for registro in reversed(registros):
            logs.append({
                "time": registro.fecha,
                "msg": f"{registro.evento}: {registro.detalle}",
            })
    finally:
        db.close()

    logs.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "msg": ai_kernel.get_logs() if ai_kernel else "Sin datos disponibles",
    })
    return logs


@main_bp.route('/mail-shield', endpoint='ruta_mail_shield')
@login_required
@require_module('mail_shield')
def ruta_mail_shield():
    from services.monitoring_telemetry_guard import assert_telemetry_access
    from services.mail_shield_engine import get_engine_status
    from services.mail_shield_config import load_mail_shield_config

    _, blocked_msg = assert_telemetry_access(current_user)
    return render_template(
        'mail_shield.html',
        user=get_current_user_data(),
        active_module='mail_shield',
        engine_status=get_engine_status(getattr(current_user, 'id', None)) if not blocked_msg else None,
        config=load_mail_shield_config() if not blocked_msg else {},
        monitoring_not_configured=bool(blocked_msg),
        monitoring_message=blocked_msg,
    )


@main_bp.route('/web-shield', endpoint='ruta_web_shield')
@login_required
@require_module('web_shield')
def web_shield_page():
    """Panel NOVUS Web Shield — métricas reales del motor."""
    from services.monitoring_telemetry_guard import assert_telemetry_access

    _, blocked_msg = assert_telemetry_access(current_user)
    from services.web_shield_engine import get_engine_status
    from services.web_shield_config import load_web_shield_config

    status = get_engine_status() if not blocked_msg else None
    return render_template(
        'web_shield.html',
        user=get_current_user_data(),
        active_module='web_shield',
        engine_status=status,
        config=load_web_shield_config() if not blocked_msg else {},
        monitoring_not_configured=bool(blocked_msg),
        monitoring_message=blocked_msg,
    )


@main_bp.route('/topology', endpoint='ruta_topology')
@login_required
def topology():
    """Interactive network topology map backed by live scan APIs."""
    return render_template('topology.html', user=get_current_user_data())


@main_bp.route('/inventario-activos', endpoint='ruta_inventario_activos')
@login_required
def inventario_activos():
    """Inventario de activos — gestión AIE (aprobación, trust score, clasificación)."""
    from services.asset_intelligence_engine import list_inventory, get_inventory_summary
    return render_template(
        'inventario_activos.html',
        user=get_current_user_data(),
        active_module='inventario',
        assets=list_inventory(limit=200),
        summary=get_inventory_summary(),
    )


@main_bp.route('/layout_novus', endpoint='ruta_layout_novus')
@login_required
def layout_novus():
    """Operational layout shell with live KPI widgets."""
    return render_template('layout_novus.html', user=get_current_user_data())


@main_bp.route('/casos-estudio', endpoint='ruta_casos_estudio')
@login_required
@require_module('casos_estudio')
def casos_estudio():
    """NOVUS Digital Case Intelligence — expedientes técnicos permanentes."""
    from services.ndci_service import ndci_service
    cases = ndci_service.list_cases(limit=100)
    return render_template(
        'casos_estudio.html',
        user=get_current_user_data(),
        active_module='casos_estudio',
        cases=cases,
    )


@main_bp.route('/inteligencia', endpoint='ruta_inteligencia')
@login_required
def inteligencia():
    """NOVUS Threat Intelligence Center — casos de estudio y base de conocimiento."""
    from services.threat_intelligence_service import threat_intelligence
    stats = threat_intelligence.stats()
    casos = threat_intelligence.list_cases(limit=50)
    return render_template(
        'inteligencia.html',
        user=get_current_user_data(),
        active_module='inteligencia',
        casos=casos,
        stats=stats,
    )


@main_bp.route('/incidentes', endpoint='ruta_incidentes')
@login_required
def incidentes():
    """Incident center populated with real alerts and runtime threats."""
    from services.monitoring_telemetry_guard import assert_telemetry_access, tenant_id_for_user

    _, blocked_msg = assert_telemetry_access(current_user)
    if blocked_msg:
        return render_template(
            'incidentes.html',
            user=get_current_user_data(),
            incidentes=[],
            total_criticos=0,
            monitoring_not_configured=True,
            monitoring_message=blocked_msg,
        )
    incidentes_list = _build_incidents_from_real_sources(tenant_id=tenant_id_for_user(current_user))
    total_criticos = sum(1 for item in incidentes_list if item.get("gravedad") == "CRITICAL")
    logger.info(f"Incidentes route: {len(incidentes_list)} real incidents loaded")
    return render_template(
        'incidentes.html',
        user=get_current_user_data(),
        incidentes=incidentes_list,
        total_criticos=total_criticos,
    )


@main_bp.route('/accesos', endpoint='ruta_historial_accesos')
@login_required
@require_module('accesos')
def historial_accesos():
    """Historial de accesos y auditoría post-login."""
    from services.login_session_audit_service import list_login_sessions
    sessions = list_login_sessions(limit=100)
    logger.info("Access history: %s sessions loaded", len(sessions))
    return render_template(
        'access_history.html',
        user=get_current_user_data(),
        sessions=sessions,
    )


@main_bp.route('/centro-bloqueos', endpoint='ruta_centro_bloqueos')
@login_required
@require_module('centro_bloqueos')
def centro_bloqueos():
    """Centro administrativo de IPs bloqueadas."""
    from services.auth_protection_service import auth_protection
    blocks = auth_protection.list_blocked_ips(limit=100, include_expired=True)
    status = auth_protection.get_protection_status()
    return render_template(
        'centro_bloqueos.html',
        user=get_current_user_data(),
        blocks=blocks,
        protection_status=status,
    )


@main_bp.route('/historial-dispositivos', endpoint='ruta_historial_dispositivos')
@login_required
def historial_dispositivos():
    """Historial permanente de conexiones/desconexiones de dispositivos."""
    from services.device_connection_monitor import list_events, search_devices
    from services.monitoring_telemetry_guard import assert_telemetry_access, tenant_id_for_user

    _, blocked_msg = assert_telemetry_access(current_user)
    if blocked_msg:
        return render_template(
            'historial_dispositivos.html',
            user=get_current_user_data(),
            events=[],
            devices=[],
            monitoring_not_configured=True,
            monitoring_message=blocked_msg,
        )
    tid = tenant_id_for_user(current_user)
    events = list_events(limit=100, tenant_id=tid)
    devices = search_devices(limit=50, tenant_id=tid)
    return render_template(
        'historial_dispositivos.html',
        user=get_current_user_data(),
        events=events,
        devices=devices,
    )


@main_bp.route('/historial-seguridad-red', endpoint='ruta_historial_seguridad_red')
@login_required
def historial_seguridad_red():
    """Historial de seguridad de la red — solo eventos observados por NOVUS."""
    from services.network_security_history_service import get_network_history_summary

    summary = get_network_history_summary()
    return render_template(
        'historial_seguridad_red.html',
        user=get_current_user_data(),
        summary=summary,
    )


@main_bp.route('/centro-casos-estudio-novus', endpoint='ruta_centro_casos_estudio_novus')
@login_required
@require_module('centro_casos_estudio_novus')
def centro_casos_estudio_novus():
    """Centro de Casos de Estudio NOVUS — solo creador; datos anonimizados."""
    from services.enterprise_data_service import get_architecture_status, list_anonymized_study_cases

    return render_template(
        'centro_casos_estudio_novus.html',
        user=get_current_user_data(),
        cases=list_anonymized_study_cases(100),
        architecture=get_architecture_status(),
    )


@main_bp.route('/verificador-evidencias', endpoint='ruta_verificador_evidencias')
@login_required
@require_module('verificador_evidencias')
def verificador_evidencias():
    """Verificador de evidencias — integridad, firma y cadena de hashes."""
    from services.forensic_evidence_integrity_service import get_system_summary

    return render_template(
        'verificador_evidencias.html',
        user=get_current_user_data(),
        summary=get_system_summary(),
    )


@main_bp.route('/swarm-defense', endpoint='ruta_swarm_defense')
@login_required
@v1_nav_route_guard('swarm_obs')
def swarm_defense_observability_page():
    """Panel técnico Swarm Defense — métricas reales vía API."""
    return render_template('swarm_defense_observability.html')


@main_bp.route('/zdde', endpoint='ruta_zdde')
@login_required
@v1_nav_route_guard('zdde_obs')
def zdde_observability_page():
    """Panel técnico ZDDE — correlación multicapa (sin firmas / sin claim CVE 0-day)."""
    from services.lazy_engine_manager import start_if_needed

    engine_boot = start_if_needed("zdde")
    return render_template('zdde_observability.html', engine_boot=engine_boot)


@main_bp.route('/btde', endpoint='ruta_btde_observability')
@login_required
@v1_nav_route_guard('btde_obs')
def btde_observability_page():
    """Panel técnico BTDE — Behavioral Threat Detection (solo lectura LIVE)."""
    from services.lazy_engine_manager import start_if_needed

    engine_boot = start_if_needed("btde")
    return render_template('btde_observability.html', engine_boot=engine_boot)


@main_bp.route('/swarm-mesh', endpoint='ruta_swarm_mesh_observability')
@login_required
@v1_nav_route_guard('mesh_obs')
def swarm_mesh_observability_page():
    """Panel Swarm Mesh — identidad y estado del mesh."""
    return render_template('swarm_mesh_observability.html')


@main_bp.route('/wsae', endpoint='ruta_wsae_observability')
@login_required
@v1_nav_route_guard('wsae_obs')
def wsae_observability_page():
    """Panel WSAE — Web Security Auth Enterprise (estado LIVE)."""
    return render_template('wsae_observability.html')


@main_bp.route('/adaptive-profile', endpoint='ruta_adaptive_profile_observability')
@login_required
@v1_nav_route_guard('adaptive_profile_obs')
def adaptive_profile_observability_page():
    """Panel Adaptive Profile Engine — estado operativo (sin baseline expuesto)."""
    return render_template('adaptive_profile_observability.html')


@main_bp.route('/cryptovault', endpoint='ruta_cryptovault_observability')
@login_required
@v1_nav_route_guard('cryptovault_obs')
def cryptovault_observability_page():
    """Panel CryptoVault — estado verificable vía Health Engine probe."""
    return render_template('cryptovault_observability.html')


@main_bp.route('/compliance-center', endpoint='ruta_compliance_center')
@login_required
@require_module('compliance_center')
def compliance_center():
    """NOVUS Compliance Center — controles técnicos verificables (sin certificaciones inventadas)."""
    from services.compliance_catalog import SECTORS
    from services.compliance_center_service import build_profile, list_audits

    sector_id = "otros"
    try:
        email = getattr(current_user, "email", None)
        if email:
            from services.sector_profile_service import get_kernel_context_for_user
            ctx = get_kernel_context_for_user(email) or {}
            sector_id = (ctx.get("sector_key") or sector_id).lower()
            aliases = {
                "logística": "logistica",
                "aplicaciones_moviles": "movil",
                "móvil": "movil",
                "fintech": "fintech",
            }
            sector_id = aliases.get(sector_id, sector_id)
    except Exception:
        pass

    profile = build_profile(sector_id=sector_id, country="CO")
    # No evaluar en SSR (evita ARP/escaneos largos); la UI dispara /api/compliance/evaluate
    evaluation = {
        "controls": [],
        "counts": {"VERIFICADO": 0, "NO_VERIFICADO": 0, "PENDIENTE": 0, "NO_APLICA": 0},
        "score": {"verified": 0, "total": 0, "label": "Pulse «Evaluar controles» para telemetría real"},
        "frameworks": profile.get("frameworks") or [],
        "profile": profile,
        "limitations": [],
    }
    history = list_audits(limit=20)
    return render_template(
        "compliance_center.html",
        user=get_current_user_data(),
        sectors=SECTORS,
        default_sector=sector_id,
        profile=profile,
        evaluation=evaluation,
        history=history,
    )


@main_bp.route('/platform-health', endpoint='ruta_platform_health')
@login_required
@require_module('platform_health')
def platform_health():
    """Platform Health Center — estado operativo de motores NOVUS."""
    from services.platform_health_service import get_platform_health
    health = get_platform_health()
    return render_template(
        'platform_health.html',
        user=get_current_user_data(),
        health=health,
    )


@main_bp.route('/health-center', endpoint='ruta_health_center')
@login_required
@require_module('platform_health')
def health_center():
    """Health Center Enterprise — shell HTML; telemetría vía API snapshot (sin auto-start engine)."""
    from services.health_engine import get_health_status_response

    dash = get_health_status_response(trigger_refresh=False)
    return render_template(
        'health_center.html',
        user=get_current_user_data(),
        dash=dash,
    )


@main_bp.route('/vulnerability-intelligence', endpoint='ruta_viem_center')
@login_required
@v1_nav_route_guard('viem_center')
def viem_center():
    """Vulnerability Intelligence & Exposure Management Center."""
    return render_template('viem_center.html', user=get_current_user_data())


@main_bp.route('/asset-intelligence', endpoint='ruta_asm_center')
@login_required
@v1_nav_route_guard('asm_center')
def asm_center():
    """Asset Intelligence & Attack Surface Management Center."""
    return render_template('asm_center.html', user=get_current_user_data())


@main_bp.route('/playbook-center', endpoint='ruta_playbook_center')
@login_required
@v1_nav_route_guard('playbook_center')
def playbook_center():
    """Security Orchestration & Playbook Engine Center."""
    return render_template('sope_center.html', user=get_current_user_data())


@main_bp.route('/incident-management', endpoint='ruta_imcm_center')
@login_required
@v1_nav_route_guard('imcm_center')
def imcm_center():
    """Incident Management & Case Management Enterprise Center."""
    return render_template('imcm_center.html', user=get_current_user_data())


@main_bp.route('/security-operations-center', endpoint='ruta_soc_center')
@login_required
@v1_nav_route_guard('soc_center')
def soc_center():
    """Security Operations Center Enterprise — convergencia de motores reales."""
    return render_template('soc_center.html', user=get_current_user_data())


@main_bp.route('/security-data-lake', endpoint='ruta_sdl_center')
@login_required
@v1_nav_route_guard('sdl_center')
def sdl_center():
    """Security Data Lake Enterprise — repositorio central de inteligencia."""
    return render_template('sdl_center.html', user=get_current_user_data())


@main_bp.route('/security-data-analytics', endpoint='ruta_sdace_center')
@login_required
@v1_nav_route_guard('sdace_center')
def sdace_center():
    """Security Data Analytics & Correlation Engine Center."""
    return render_template('sdace_center.html', user=get_current_user_data())


@main_bp.route('/identity-intelligence', endpoint='ruta_identity_intelligence')
@login_required
@v1_nav_route_guard('identity_intelligence')
def identity_intelligence_center():
    """Identity Intelligence & UEBA Enterprise Center."""
    return render_template('identity_intelligence.html', user=get_current_user_data())


@main_bp.route('/identity-attack-path', endpoint='ruta_iapa_center')
@login_required
@v1_nav_route_guard('iapa_center')
def iapa_center():
    """Identity Attack Path Analysis / Attack Path Intelligence Center."""
    return render_template('iapa_center.html', user=get_current_user_data())


@main_bp.route('/deception-center', endpoint='ruta_deception_center')
@login_required
@v1_nav_route_guard('deception_center')
def deception_center():
    """Deception Platform Enterprise Center."""
    return render_template('deception_center.html', user=get_current_user_data())


@main_bp.route('/security-validation-center', endpoint='ruta_csv_bas_center')
@login_required
@v1_nav_route_guard('csv_bas_center')
def csv_bas_center():
    """Continuous Security Validation / BAS Center."""
    return render_template('csv_bas_center.html', user=get_current_user_data())


@main_bp.route('/threat-intelligence-center', endpoint='ruta_tie_center')
@login_required
@v1_nav_route_guard('threat_intel')
def tie_center():
    """Threat Intelligence Enterprise Center."""
    return render_template(
        'tie_center.html',
        user=get_current_user_data(),
    )


@main_bp.route('/centro-defensa', endpoint='ruta_centro_defensa')
@main_bp.route('/centro-defensa-manual', endpoint='ruta_centro_defensa_manual')
@login_required
@require_module('centro_defensa')
def centro_defensa():
    from services.manual_defense_catalog import audit_capabilities, CATEGORIES
    audit = audit_capabilities(getattr(current_user, 'id', None))
    return render_template(
        'manual_defense_center.html',
        user=get_current_user_data(),
        categories=CATEGORIES,
        audit=audit,
    )


@main_bp.route('/centro-evidencias', endpoint='ruta_centro_evidencias')
@login_required
@require_module('centro_evidencias')
def centro_evidencias():
    """Centro de Evidencias — trazabilidad unificada."""
    from services.evidence_center_service import get_evidence_summary, list_evidence
    from services.tenant_isolation_service import require_user_tenant_id

    tenant_id = require_user_tenant_id(current_user)
    summary = get_evidence_summary(tenant_id=tenant_id)
    evidence = list_evidence(limit=100, tenant_id=tenant_id)
    return render_template(
        'centro_evidencias.html',
        user=get_current_user_data(),
        summary=summary,
        evidence=evidence,
    )


@main_bp.route('/siem', endpoint='ruta_siem')
@login_required
@v1_nav_route_guard('siem')
def siem():
    """SIEM live logs from database audit trail and AI kernel."""
    logs = _build_siem_logs_from_real_sources()
    logger.info(f"SIEM route: {len(logs)} real log entries loaded")
    return render_template(
        'siem_dashboard.html',
        logs=logs,
        hostname=socket.gethostname(),
        user=get_current_user_data(),
    )


@main_bp.route('/<path:endpoint>')
@login_required
def gateway_modulos(endpoint):
    """
    Gateway for dynamic module access
    """
    if endpoint.startswith('api/'):
        from flask import abort
        abort(404)

    import os
    from flask import current_app
    
    resource_name = endpoint.replace('.html', '')
    if resource_name.startswith('test_') or resource_name.startswith('test-'):
        from flask import abort
        abort(404)

    target_file = f"{resource_name}.html"
    file_path = os.path.join(current_app.template_folder, target_file)
    
    if os.path.exists(file_path):
        return render_template(target_file, user=get_current_user_data())
    else:
        logger.warning(f"Attempt to access non-existent module: {endpoint}")
        return jsonify({
            "status": "error",
            "message": f"Modulo '{resource_name}' no inicializado en el Kernel",
            "node": get_node_id()
        }), 404
