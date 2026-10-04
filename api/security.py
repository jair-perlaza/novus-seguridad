"""
Security API Blueprint for NOVUS
Real-time security data from integrated security motor
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from utils.logger import logger
from services.novus_security_integration import novus_security
from services.network_scanner import network_scanner
from services.tenant_api_gate import check_tenant_monitoring_or_response
from utils.security_helpers import get_compromised_nodes
from services.http_shell_service import get_threat_cache_snapshot

from utils.host_data import get_disk_usage
import psutil
import socket
import tempfile
import os
from datetime import datetime, timezone

security_api_bp = Blueprint(
    'security_api',
    __name__,
    url_prefix='/api/security'
)


@security_api_bp.route('/summary', methods=['GET'])
@login_required
def api_security_summary():
    """
    P1-CRITICAL-001 remediation (HIGH):
    - Canonical tenant from session (company_id/nit_pyme) — never query/email-domain.
    - Payload via get_unified_security_payload(tenant_id) (existing TENANT vs HOST split).
    - HTTP cache keyed by real tenant_id — never shared platform key for tenant body.
    """
    try:
        from services.tenant_isolation_service import TenantAccessDenied, require_canonical_tenant_id
        from services.http_endpoint_cache import get_or_build
        from services.platform_metrics_service import get_unified_security_payload

        # Ignore any client-supplied tenant_id / company / nit (anti-escalation).
        try:
            tenant_id = require_canonical_tenant_id(current_user)
        except TenantAccessDenied:
            return jsonify({
                "status": "error",
                "message": "NO_TENANT_CONTEXT",
                "reason": "tenant_not_configured",
            }), 403

        _, blocked = check_tenant_monitoring_or_response(current_user, scope="security")
        if blocked:
            blocked_data = blocked.get_json()
            return jsonify({
                "status": "monitoring_not_configured",
                **{k: v for k, v in blocked_data.items() if k != "status"},
            }), 200

        def _build_tenant_summary():
            payload = get_unified_security_payload(tenant_id=tenant_id)
            return {
                "status": "ok",
                "system_health": payload.get("system_health", {}),
                "threats": payload.get("threats", {}),
                "total_threats": payload.get("total_threats"),
                "vulnerabilities": payload.get("vulnerabilities", []),
                "endpoints": payload.get("endpoints", {}),
                "counters": payload.get("counters") or {},
                "endpoint_inventory": payload.get("endpoint_inventory", []),
                "ransomware_active": payload.get("ransomware_active", []),
                "has_active_ransomware": payload.get("has_active_ransomware", False),
                "alerts_active": payload.get("alerts_active"),
                "alerts": payload.get("alerts", []),
                "component_status": payload.get("component_status") or {
                    "endpoint_inventory": "ready",
                    "alerts": "ready",
                    "network_discovery": "ready",
                },
                "timestamp": datetime.now().isoformat(),
                "source": "services.platform_metrics_service.get_unified_security_payload",
                "source_type": "canonical_metrics",
                "confidence": "verified",
                "tenant_id": tenant_id,
            }

        body = get_or_build(
            "/api/security/summary",
            _build_tenant_summary,
            tenant_id=tenant_id,
        )
        return jsonify(body), 200

    except Exception as e:
        logger.error(f"Security summary error: {e}", exc_info=True)

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@security_api_bp.route('/alerts', methods=['GET'])
@login_required
def api_security_alerts():
    """Alertas canónicas verificables — sin JSON crudo al cliente."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="security")
        if blocked:
            return blocked

        from services.alerts_canonical_service import get_canonical_alerts
        from services.tenant_scope_service import resolve_tenant_id

        include_resolved = request.args.get("include_resolved", "").lower() in ("1", "true", "yes")
        limit = min(int(request.args.get("limit", 100)), 200)
        tenant_id = resolve_tenant_id(current_user)
        alerts = get_canonical_alerts(
            include_resolved=include_resolved,
            limit=limit,
            tenant_id=tenant_id,
        )
        return jsonify({
            "status": "ok",
            "count": len(alerts),
            "alerts": alerts,
            "source": "alerts_canonical_service",
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error("Alerts API error: %s", e, exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@security_api_bp.route('/alerts/<alert_id>', methods=['GET'])
@login_required
def api_security_alert_detail(alert_id):
    """Detalle de una alerta — evidencias formateadas; technical_detail solo bajo solicitud."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="security")
        if blocked:
            return blocked

        from services.alerts_canonical_service import get_canonical_alert_by_id, _humanize_evidence
        from services.tenant_scope_service import resolve_tenant_id, get_platform_tenant_id

        tenant_id = resolve_tenant_id(current_user)
        if not tenant_id or tenant_id != get_platform_tenant_id():
            return jsonify({"status": "forbidden", "message": "Sin acceso a telemetría de este nodo"}), 403

        alert = get_canonical_alert_by_id(alert_id)
        if not alert:
            return jsonify({"status": "not_found", "message": "Alerta no encontrada o sin evidencia verificable"}), 404

        include_technical = request.args.get("technical", "").lower() in ("1", "true", "yes")
        payload = dict(alert)
        if not include_technical:
            payload.pop("technical_detail", None)
        else:
            td = alert.get("technical_detail")
            if isinstance(td, dict):
                payload["technical_detail"] = _humanize_evidence(td, td)
            else:
                payload["technical_detail"] = [{"label": "Detalle", "value": str(td)[:2000]}]

        return jsonify({"status": "ok", "alert": payload, "timestamp": datetime.now().isoformat()}), 200
    except Exception as e:
        logger.error("Alert detail API error: %s", e, exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@security_api_bp.route('/threats', methods=['GET'])
@login_required
def api_security_threats():
    """Amenazas verificables — snapshot/cache; misma fuente canónica que Alertas."""
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="security")
        if blocked:
            return blocked

        from services.performance_cache import get_or_compute
        from core.config import Config
        from services.tenant_scope_service import resolve_tenant_id

        tenant_id = resolve_tenant_id(current_user)
        cache_key = f"security_threats_api:{tenant_id or 'default'}"
        ttl = float(getattr(Config, "PANEL_CACHE_TTL", 30) or 30)

        from services.http_shell_service import get_threat_cache_snapshot, schedule_threat_scan_if_stale

        if not get_threat_cache_snapshot().get("last_scan"):
            schedule_threat_scan_if_stale()

        def _build():
            from services.alerts_canonical_service import get_canonical_alerts

            alerts = get_canonical_alerts(include_resolved=False, limit=100, tenant_id=tenant_id)
            threats = []
            for alert in alerts:
                threats.append({
                    "type": (alert.get("threat_type") or "amenaza").lower().replace(" ", "_"),
                    "severity": (alert.get("risk_level") or "medium").lower(),
                    "source": alert.get("motor") or alert.get("source_channel"),
                    "details": {
                        "verified": True,
                        "evidence": alert.get("evidence_summary"),
                        "ip": alert.get("origin_ip") or alert.get("origin"),
                        "source": alert.get("motor"),
                        "timestamp": alert.get("timestamp"),
                    },
                    "id": alert.get("id"),
                })
            cache = get_threat_cache_snapshot()
            last_scan = cache.get("last_scan")
            count = len(threats)
            from utils.data_provenance import analysis_display, attach_operational_provenance

            analysis = analysis_display(
                count=count,
                last_scan=last_scan,
                empty_label="No se detectaron amenazas en el último análisis.",
            )
            payload = {
                "status": "ok" if analysis["analysis_state"] != "NOT_AVAILABLE" else "not_available",
                "threats": threats,
                "suspicious_processes": [],
                "open_ports": [],
                "total_threats": analysis["value"],
                "analysis_state": analysis["analysis_state"],
                "analysis_message": analysis["display"],
                "last_scan": last_scan,
                "source": "alerts_canonical_service",
                "timestamp": datetime.now().isoformat(),
            }
            return attach_operational_provenance(
                payload,
                data_origin=analysis["data_origin"],
                source="alerts_canonical_service",
                tenant_id=str(tenant_id) if tenant_id else None,
                observed_at=last_scan,
                source_engine="threat_engine",
                freshness=analysis["analysis_state"],
            )

        body = get_or_compute(cache_key, ttl, _build)
        return jsonify(body), 200

    except Exception as e:

        logger.error(f"Threats error: {e}", exc_info=True)

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@security_api_bp.route('/network', methods=['GET'])
@login_required
def api_security_network():

    try:

        threats_data = get_threat_cache_snapshot()
        if not threats_data.get('last_scan'):
            from services.http_shell_service import schedule_threat_scan_if_stale

            schedule_threat_scan_if_stale()

        suspicious_connections = []
        dangerous_processes = []

        for threat in threats_data.get("threats") or []:
            details = threat.get("details") or {}
            if not isinstance(details, dict) or details.get("verified") is not True:
                continue
            ip = details.get("ip")
            if ip:
                suspicious_connections.append({
                    "port": details.get("port"),
                    "status": "VERIFIED_THREAT",
                    "description": details.get("evidence") or str(threat.get("type")),
                    "ip": ip,
                })
            proc_name = details.get("process") or details.get("process_name")
            if proc_name:
                dangerous_processes.append({
                    "pid": details.get("pid"),
                    "name": proc_name,
                    "description": details.get("evidence") or proc_name,
                })

        compromised_nodes = get_compromised_nodes(
            threats_data,
            network_scanner.get_cached_nodes(),
        )

        return jsonify({
            "status": "ok",
            "network_status": {
                "suspicious_connections": suspicious_connections,
                "dangerous_processes": dangerous_processes,
                "compromised_nodes": compromised_nodes,
            },
            "timestamp": datetime.now().isoformat()
        }), 200

    except Exception as e:

        logger.error(f"Network security error: {e}", exc_info=True)

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@security_api_bp.route('/vulnerabilities/<finding_id>', methods=['GET'])
@login_required
def api_security_vulnerability_detail(finding_id):
    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="security")
        if blocked:
            blocked_data = blocked.get_json()
            return jsonify({
                "status": "monitoring_not_configured",
                "message": blocked_data.get("message"),
            }), 200

        from services.vulnerability_analyst_service import get_finding_detail
        from services.v1_runtime_surface import blob_contains_lab_marker

        detail = get_finding_detail(finding_id)
        if not detail or blob_contains_lab_marker(detail):
            return jsonify({"status": "not_found", "message": "Hallazgo no encontrado"}), 404
        return jsonify({"status": "ok", "finding": detail})
    except Exception as e:
        logger.error(f"Vulnerability detail error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@security_api_bp.route('/vulnerabilities', methods=['GET'])
@login_required
def api_security_vulnerabilities():

    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="security")
        if blocked:
            blocked_data = blocked.get_json()
            from utils.data_provenance import attach_operational_provenance

            return jsonify(attach_operational_provenance({
                "status": "monitoring_not_configured",
                "vulnerabilities": [],
                "pendientes_verificacion": [],
                "resueltas_historial": [],
                "total_count": None,
                "pending_count": None,
                "audit": {},
                "analysis_state": "NOT_AVAILABLE",
                "analysis_message": "Sin análisis disponible",
                "message": blocked_data.get("message"),
                "cve_intelligence": {
                    "status": "UNAVAILABLE",
                    "message": "CVE intelligence unavailable — OSV/NVD package correlation not implemented in V1",
                    "source": "services/vulnerability_scanner.py (local ports/processes only)",
                },
                "data_freshness": "NOT_AVAILABLE",
                "timestamp": datetime.now().isoformat(),
            },
                data_origin="not_available",
                source="tenant_api_gate",
                tenant_id=None,
                freshness="NOT_AVAILABLE",
            )), 200

        from services.http_shell_service import (
            get_cached_vulnerabilities_snapshot,
            schedule_vulnerability_scan_if_stale,
        )
        from services.http_endpoint_cache import get_or_build
        from services.v1_runtime_surface import filter_lab_runtime_rows
        from services.vulnerability_analyst_service import get_resolved_history
        from utils.data_provenance import analysis_display, attach_operational_provenance

        def _build_vuln_payload():
            vulnerabilities = get_cached_vulnerabilities_snapshot()
            if not vulnerabilities:
                schedule_vulnerability_scan_if_stale()
                vulnerabilities = get_cached_vulnerabilities_snapshot() or []
            vulnerabilities = filter_lab_runtime_rows(vulnerabilities)
            pending = novus_security._threat_cache.get("vulnerabilities_pending") or []
            audit = novus_security._threat_cache.get("vulnerabilities_audit") or {}
            last_vuln_scan = audit.get("timestamp")
            count = len(vulnerabilities) if last_vuln_scan else None
            analysis = analysis_display(
                count=count if count is not None else (0 if last_vuln_scan else None),
                last_scan=last_vuln_scan,
            )
            freshness = "LIVE" if last_vuln_scan else "NOT_AVAILABLE"
            payload = {
                "status": "ok" if analysis["analysis_state"] in ("LIVE", "EMPTY") else analysis["analysis_state"].lower(),
                "vulnerabilities": vulnerabilities,
                "pendientes_verificacion": pending,
                "resueltas_historial": get_resolved_history(limit=20),
                "total_count": analysis["value"],
                "pending_count": len(pending) if last_vuln_scan else None,
                "audit": audit,
                "analysis_state": analysis["analysis_state"],
                "analysis_message": analysis["display"],
                "last_scan": last_vuln_scan,
                "message": analysis["display"] if analysis["analysis_state"] == "EMPTY" else None,
                "cve_intelligence": {
                    "status": "UNAVAILABLE",
                    "message": "CVE intelligence unavailable — OSV/NVD package correlation not implemented in V1",
                    "source": "services/vulnerability_scanner.py (local ports/processes only)",
                },
                "data_freshness": freshness,
                "timestamp": datetime.now().isoformat(),
            }
            return attach_operational_provenance(
                payload,
                data_origin=analysis["data_origin"],
                source="novus_security_integration.scan_vulnerabilities",
                observed_at=last_vuln_scan,
                source_engine="vulnerability_scanner",
                freshness=freshness,
                evidence=audit if audit else None,
            )

        body = get_or_build("/api/security/vulnerabilities", _build_vuln_payload)
        return jsonify(body), 200

    except Exception as e:

        logger.error(f"Vulnerabilities error: {e}", exc_info=True)

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@security_api_bp.route('/endpoints', methods=['GET'])
@login_required
def api_security_endpoints():

    try:
        _, blocked = check_tenant_monitoring_or_response(current_user, scope="security")
        if blocked:
            return blocked

        endpoint_data = novus_security.monitor_endpoints()

        return jsonify({
            "status": "ok",
            "endpoint": endpoint_data.get('endpoint', {}),
            "processes": endpoint_data.get('procesos', []),
            "system_health": endpoint_data.get('system_health', {}),
            "timestamp": datetime.now().isoformat()
        }), 200

    except Exception as e:

        logger.error(f"Endpoints error: {e}", exc_info=True)

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@security_api_bp.route('/processes', methods=['GET'])
@login_required
def api_security_processes():

    try:

        processes = []

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):

            try:

                processes.append({
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "cpu": proc.info['cpu_percent'],
                    "memory": round(proc.info['memory_percent'], 2)
                })

            except:
                pass

        processes = sorted(
            processes,
            key=lambda x: x['cpu'],
            reverse=True
        )

        return jsonify({
            "status": "ok",
            "processes": processes[:25],
            "total_processes": len(processes),
            "timestamp": datetime.now().isoformat()
        }), 200

    except Exception as e:

        logger.error(f"Processes error: {e}", exc_info=True)

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@security_api_bp.route('/system-health', methods=['GET'])
@login_required
def api_security_system_health():

    try:

        cpu_usage = psutil.cpu_percent(interval=1)
        memory_usage = psutil.virtual_memory().percent
        disk_usage = get_disk_usage().percent

        return jsonify({
            "status": "ok",
            "cpu_usage": cpu_usage,
            "memory_usage": memory_usage,
            "disk_usage": disk_usage,
            "timestamp": datetime.now().isoformat()
        }), 200

    except Exception as e:

        logger.error(f"System health error: {e}", exc_info=True)

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@security_api_bp.route('/threat-registry', methods=['GET'])
@login_required
def api_threat_registry():
    """Registro runtime filtrado — solo entradas con evidencia verificable."""
    try:
        from services.alerts_canonical_service import _from_threat_registry

        registry = novus_security.security_engine.threat_registry or []
        filtered = []
        for idx, entry in enumerate(reversed(registry[-100:]), start=1):
            parsed = _from_threat_registry(entry, idx)
            if parsed:
                filtered.append({
                    "time": parsed.get("timestamp"),
                    "threat_type": parsed.get("threat_type"),
                    "source": parsed.get("motor"),
                    "severity": parsed.get("risk_level"),
                    "verified": parsed.get("verified"),
                    "evidence_summary": parsed.get("evidence_summary"),
                    "id": parsed.get("id"),
                })

        return jsonify({
            "status": "ok",
            "threat_registry": filtered,
            "total_registered": len(filtered),
            "source": "alerts_canonical_service",
            "timestamp": datetime.now().isoformat(),
        }), 200

    except Exception as e:

        logger.error(f"Threat registry error: {e}", exc_info=True)

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@security_api_bp.route('/virus-scanner', methods=['GET'])
@login_required
def api_virus_scanner():

    try:

        from services.advanced_detector_service import advanced_detector

        from utils.host_data import get_local_ip, format_ip_or_unavailable

        suspicious_processes = advanced_detector.scan_running_processes()
        open_ports = advanced_detector.scan_open_ports()

        return jsonify({
            "status": "ok",
            "suspicious_processes": suspicious_processes,
            "open_ports": open_ports,
            "high_entropy_files": [],
            "entropy_note": "Análisis por entropía deshabilitado. Solo hallazgos confirmados por proceso o puerto.",
            "total_findings": len(suspicious_processes) + len(open_ports),
            "timestamp": datetime.now().isoformat()
        }), 200

    except Exception as e:

        logger.error(f"Virus scanner error: {e}", exc_info=True)

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@security_api_bp.route('/live-endpoints', methods=['GET'])
@login_required
def api_live_endpoints():

    try:
        from services.platform_metrics_service import (
            build_endpoint_inventory,
            get_platform_counters,
        )

        inventory = build_endpoint_inventory()
        counters = get_platform_counters()

        return jsonify({
            "status": "ok",
            "total_endpoints": counters.get("endpoints_total"),
            "endpoints": inventory,
            "counters": counters,
            "timestamp": datetime.now().isoformat()
        }), 200

    except Exception as e:

        logger.error(f"Live endpoints error: {e}", exc_info=True)

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500