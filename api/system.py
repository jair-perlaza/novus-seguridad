"""
System API Blueprint for NOVUS
Provides real-time system monitoring, automation, and security endpoints
"""
import os
import json
import psutil
import socket
import platform
import time
import uuid
import tempfile
from flask import Blueprint, request, jsonify
from flask_login import login_required
from utils.logger import logger
from services.system_monitor import system_monitor
from services.ai_kernel import ai_kernel
from services.novus_security_integration import novus_security
from services.api_security_service import api_hardened, sanitize_ip_param

system_api_bp = Blueprint('system_api', __name__, url_prefix='/api/system')


@system_api_bp.route('/scan/file', methods=['POST'])
@login_required
@api_hardened(sensitive=True, action_name="scan_file")
def api_scan_file():
    """Endpoint for file scanning using advanced detector"""
    try:
        from services.advanced_detector_service import advanced_detector
        import tempfile
        import os
        
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "No se proporcionó ningún archivo"}), 400
        
        file = request.files['file']
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as temp_file:
            file.save(temp_file.name)
            temp_path = temp_file.name
        
        try:
            # Execute advanced analysis (EICAR first — safe AV signature test)
            eicar = advanced_detector.detect_eicar_file(temp_path)
            entropy = advanced_detector.calculate_entropy(temp_path)
            reputation = advanced_detector.scan_file_reputation(temp_path)
            
            # Heuristic rule: If entropy > 7.2, alert possible Ransomware/obfuscated code
            ransomware_alert = entropy > 7.2
            eicar_hit = bool(eicar.get("detected"))
            blocked = eicar_hit or ransomware_alert or (reputation.get('malicioso', 0) > 0)
            
            return jsonify({
                "filename": file.filename,
                "entropy": entropy,
                "entropy_risk": "ALTO (Posible código oculto/Ransomware)" if ransomware_alert else "NORMAL",
                "eicar": {
                    "detected": eicar_hit,
                    "signature": eicar.get("signature") if eicar_hit else None,
                },
                "global_reputation": reputation,
                "verdict": "BLOQUEADO" if blocked else "PERMITIDO"
            }), 200
        finally:
            # Cleanup
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        logger.error(f"Error scanning file: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/scan/system', methods=['GET'])
@login_required
def api_scan_system():
    """Endpoint for system health scan using advanced detector"""
    try:
        from services.advanced_detector_service import advanced_detector
        
        health_data = advanced_detector.scan_system_health()
        return jsonify({
            "status": "success",
            "data": health_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error scanning system: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/scan/processes', methods=['GET'])
@login_required
def api_scan_processes():
    """Endpoint for scanning suspicious processes"""
    try:
        from services.advanced_detector_service import advanced_detector
        
        threats = advanced_detector.scan_running_processes()
        return jsonify({
            "status": "success",
            "threats_found_count": len(threats),
            "threats": threats
        }), 200
        
    except Exception as e:
        logger.error(f"Error scanning processes: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/scan/ports', methods=['GET'])
@login_required
def api_scan_ports():
    """Endpoint for scanning vulnerable ports"""
    try:
        from services.advanced_detector_service import advanced_detector
        from utils.host_data import get_local_ip, format_ip_or_unavailable

        target_ip = request.args.get('ip') or get_local_ip()
        if target_ip:
            safe_ip = sanitize_ip_param(target_ip)
            if not safe_ip:
                return jsonify({"status": "error", "message": "IP inválida"}), 400
            target_ip = safe_ip
        if not target_ip:
            return jsonify({
                "status": "no_data",
                "message": "Sin datos disponibles. Especifique una IP válida.",
                "open_ports": []
            }), 200

        open_ports = advanced_detector.scan_open_ports(target_ip)

        return jsonify({
            "status": "success",
            "target_ip": target_ip,
            "open_port_count": len(open_ports),
            "open_ports": open_ports
        }), 200
        
    except Exception as e:
        logger.error(f"Error scanning ports: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/vulnerabilities/remediate', methods=['POST'])
@login_required
@api_hardened(sensitive=True, require_json=True, required_fields=["vulnerability_id"], action_name="remediate_vulnerability")
def api_remediate_vulnerability():
    """Endpoint for remediating vulnerabilities with step-by-step results."""
    try:
        from services.remediation_engine import remediate_vulnerability

        data = request.get_json()
        vulnerability_id = data.get('vulnerability_id')

        if not vulnerability_id:
            return jsonify({
                "status": "error",
                "message": "vulnerability_id is required",
                "steps": [],
            }), 400

        result = remediate_vulnerability(vulnerability_id)
        logger.info(f"Remediated vulnerability: {vulnerability_id}")

        return jsonify({
            "status": result.get("status", "success"),
            "message": result.get("message", "Remediación completada"),
            "vulnerability_id": vulnerability_id,
            "steps": result.get("steps", []),
            "report_id": result.get("report_id"),
            "final_status": result.get("final_status"),
            "elapsed": result.get("elapsed"),
            "resolved": result.get("resolved"),
            "requires_manual": result.get("requires_manual"),
            "manual_guide": result.get("manual_guide"),
            "strategies_attempted": result.get("strategies_attempted"),
        }), 200

    except Exception as e:
        logger.error(f"Error remediating vulnerability: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": str(e),
            "steps": [],
        }), 500


_LAUNCH_TOOL_WHITELIST = frozenset({
    "wf.msc", "services.msc", "taskmgr", "secpol.msc",
    "ms-settings:", "windowsdefender:", "explorer", "explorer_select",
})


@system_api_bp.route('/launch-tool', methods=['POST'])
@login_required
@api_hardened(sensitive=True, require_json=True, required_fields=["tool"], action_name="launch_tool")
def api_launch_tool():
    """Abre herramientas Windows preaprobadas (firewall, servicios, etc.)."""
    import subprocess
    try:
        payload = request.get_json(silent=True) or {}
        tool = (payload.get("tool") or "").strip()
        path = (payload.get("path") or "").strip()

        if tool not in _LAUNCH_TOOL_WHITELIST:
            return jsonify({"status": "error", "message": f"Herramienta no permitida: {tool}"}), 400

        if tool == "explorer":
            if not path or not os.path.exists(path):
                folder = os.path.dirname(path) if path else ""
                if folder and os.path.isdir(folder):
                    os.startfile(folder)
                else:
                    return jsonify({"status": "error", "message": "Ruta no válida para explorer"}), 400
            elif os.path.isdir(path):
                os.startfile(path)
            else:
                os.startfile(os.path.dirname(path) or path)
        elif tool == "explorer_select":
            if not path or not os.path.exists(path):
                return jsonify({"status": "error", "message": "Archivo no encontrado"}), 400
            subprocess.Popen(["explorer", "/select,", os.path.abspath(path)])
        elif tool.endswith(":"):
            os.startfile(tool)
        else:
            os.startfile(tool)

        return jsonify({"status": "success", "message": f"Herramienta '{tool}' abierta.", "tool": tool})
    except Exception as e:
        logger.error(f"Launch tool error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/config/save', methods=['POST'])
@login_required
@api_hardened(sensitive=True, require_json=True, action_name="config_save")
def api_save_config():
    """Endpoint for saving security configuration"""
    try:
        from flask_login import current_user
        from database import SessionLocal, Usuario
        from services.config_service import save_config, get_pentest_limits, get_config_effects

        data = request.get_json()
        config_data = save_config({
            "pentest_mode": data.get('pentest_mode', 'estandar'),
            "whatsapp_alerts": data.get('whatsapp_alerts', True),
            "email_reports": data.get('email_reports', False),
            "sector_activo": data.get('sector_activo'),
        })
        effects = get_config_effects()

        if config_data.get("sector_activo"):
            try:
                from services.sector_shield_service import normalize_sector
                from services.sector_profile_service import apply_sector_profile_for_user
                normalized = normalize_sector(config_data["sector_activo"])
                config_data["sector_activo"] = normalized
                db = SessionLocal()
                try:
                    usuario = db.query(Usuario).filter(Usuario.email == current_user.email).first()
                    if usuario:
                        usuario.sector = config_data["sector_activo"]
                        db.commit()
                finally:
                    db.close()
                apply_sector_profile_for_user(current_user.email)
            except Exception as db_error:
                logger.error(f"Error updating user sector: {db_error}")
        
        logger.info(f"Configuration saved: {config_data}")

        sector_shield = None
        if config_data.get("sector_activo"):
            sector_shield = novus_security.security_engine.build_sector_protection(
                config_data["sector_activo"]
            )
        
        return jsonify({
            "status": "success",
            "message": "Configuración guardada y aplicada inmediatamente.",
            "config": config_data,
            "sector_shield": sector_shield,
            "pentest_limits": get_pentest_limits(),
            "effects": effects,
            "requires_restart": False,
        }), 200
        
    except Exception as e:
        logger.error(f"Error saving config: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@system_api_bp.route('/config/load', methods=['GET'])
@login_required
def api_load_config():
    """Endpoint for loading security configuration"""
    try:
        from services.config_service import load_config
        config_data = load_config()
        
        return jsonify({
            "status": "success",
            "config": config_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error loading config: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@system_api_bp.route('/automation/playbook/create', methods=['POST'])
@login_required
def api_create_playbook():
    """Create playbook — delegates to database-backed playbook service."""
    try:
        from services import playbook_service
        data = request.get_json(silent=True) or {}
        if not all([data.get('nombre'), data.get('trigger'), data.get('accion')]):
            return jsonify({"status": "error", "message": "nombre, trigger y accion son requeridos"}), 400
        playbook = playbook_service.create_playbook(data)
        return jsonify({"status": "success", "message": "Playbook creado", "playbook": playbook}), 201
    except Exception as e:
        logger.error(f"Error creating playbook: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/search', methods=['GET'])
@login_required
def search_global():
    """Global search — delegates to unified search index (tenant-scoped)."""
    try:
        from services.global_search_index import global_search
        from services.tenant_isolation_service import TenantAccessDenied, require_canonical_tenant_id
        from flask_login import current_user

        query = (request.args.get('q') or '').strip()
        if not query:
            return jsonify({"status": "error", "message": "Query parameter required"}), 400
        # P0-3: deny-by-default sin tenant canónico (no email-domain).
        try:
            tenant_id = require_canonical_tenant_id(current_user)
        except TenantAccessDenied:
            return jsonify({
                "status": "error",
                "message": "NO_TENANT_CONTEXT",
                "reason": "tenant_not_configured",
                "results": [],
                "count": 0,
            }), 403
        results = global_search(query, limit=25, tenant_id=tenant_id)
        return jsonify({"status": "success", "query": query, "results": results, "count": len(results)})
    except Exception as e:
        logger.error(f"Search error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e), "results": []}), 500


# ==================== 12 CAPAS DE PROTECCIÓN ====================

@system_api_bp.route('/security/ato/analyze', methods=['POST'])
@login_required
def api_ato_analyze():
    """Anti Account Takeover - Analyze access risk"""
    try:
        data = request.get_json()
        user_id = data.get('user_id', 'unknown')
        access_data = data.get('access_data', {})
        history = data.get('history', {})
        
        result = novus_security.security_engine.analyze_ato_risk(user_id, access_data, history)
        
        return jsonify({
            "status": "success",
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"ATO analysis error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/security/api/validate', methods=['POST'])
@login_required
def api_api_validate():
    """API Shield - Validate API request"""
    try:
        data = request.get_json()
        client_ip = data.get('client_ip', request.remote_addr)
        endpoint_path = data.get('endpoint_path', '/unknown')
        
        result = novus_security.security_engine.validate_api_request(client_ip, endpoint_path)
        
        return jsonify({
            "status": "success",
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"API validation error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/security/phishing/inspect', methods=['POST'])
@login_required
def api_phishing_inspect():
    """Phishing Shield - Inspect email integrity"""
    try:
        data = request.get_json()
        email_metadata = data.get('email_metadata', {})
        content_body = data.get('content_body', '')
        
        result = novus_security.security_engine.inspect_email_integrity(email_metadata, content_body)
        
        return jsonify({
            "status": "success",
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"Phishing inspection error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/security/mitm/verify', methods=['POST'])
@login_required
def api_mitm_verify():
    """MITM Shield - Verify tunnel integrity"""
    try:
        data = request.get_json()
        connection_metadata = data.get('connection_metadata', {})
        
        result = novus_security.security_engine.verify_tunnel_integrity(connection_metadata)
        
        return jsonify({
            "status": "success",
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"MITM verification error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/security/ransom/monitor', methods=['POST'])
@login_required
def api_ransom_monitor():
    """Ransom Sentinel - Monitor filesystem activity"""
    try:
        data = request.get_json()
        activity_report = data.get('activity_report', {})
        
        result = novus_security.security_engine.monitor_filesystem_activity(activity_report)
        
        return jsonify({
            "status": "success",
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"Ransom monitoring error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/security/bec/validate', methods=['POST'])
@login_required
def api_bec_validate():
    """BEC Shield - Validate transactional integrity"""
    try:
        data = request.get_json()
        email_data = data.get('email_data', {})
        invoice_metadata = data.get('invoice_metadata', {})
        
        result = novus_security.security_engine.validate_transactional_integrity(email_data, invoice_metadata)
        
        return jsonify({
            "status": "success",
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"BEC validation error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/security/iot/validate', methods=['POST'])
@login_required
def api_iot_validate():
    """IoT Guard - Validate IoT telemetry"""
    try:
        data = request.get_json()
        device_id = data.get('device_id', 'unknown')
        telemetry_data = data.get('telemetry_data', {})
        historical_state = data.get('historical_state', {})
        
        result = novus_security.security_engine.validate_iot_telemetry(device_id, telemetry_data, historical_state)
        
        return jsonify({
            "status": "success",
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"IoT validation error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/security/sqli/sanitize', methods=['POST'])
@login_required
def api_sqli_sanitize():
    """SQLi Shield - Sanitize and validate query"""
    try:
        data = request.get_json()
        user_input = data.get('user_input', '')
        context = data.get('context', 'PORTAL_LOGIN')
        
        result = novus_security.security_engine.sanitize_and_validate_query(user_input, context)
        
        return jsonify({
            "status": "success",
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"SQLi sanitization error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/security/reverse/verify', methods=['POST'])
@login_required
def api_reverse_verify():
    """Anti Reverse Engineering - Verify runtime integrity"""
    try:
        data = request.get_json()
        runtime_env = data.get('runtime_env', {})
        
        result = novus_security.security_engine.verify_runtime_integrity(runtime_env)
        
        return jsonify({
            "status": "success",
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"Reverse engineering verification error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/security/ui/detect-overlay', methods=['POST'])
@login_required
def api_ui_detect_overlay():
    """UI Shield - Detect overlay threats"""
    try:
        data = request.get_json()
        window_context = data.get('window_context', {})
        
        result = novus_security.security_engine.detect_overlay_threat(window_context)
        
        return jsonify({
            "status": "success",
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"UI overlay detection error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/security/identity/verify-sim', methods=['POST'])
@login_required
def api_identity_verify_sim():
    """Identity Shield - Verify SIM and identity"""
    try:
        data = request.get_json()
        device_metadata = data.get('device_metadata', {})
        user_profile = data.get('user_profile', {})
        
        result = novus_security.security_engine.verify_sim_and_identity(device_metadata, user_profile)
        
        return jsonify({
            "status": "success",
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"Identity verification error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/security/ui/validate-interaction', methods=['POST'])
@login_required
def api_ui_validate_interaction():
    """UI Integrity Shield - Validate UI interaction"""
    try:
        data = request.get_json()
        click_event = data.get('click_event', {})
        headers = data.get('headers', {})
        
        result = novus_security.security_engine.validate_ui_interaction(click_event, headers)
        
        return jsonify({
            "status": "success",
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"UI interaction validation error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/protection-score', methods=['GET'])
@login_required
def api_protection_score():
    """Puntuación binaria verificable — no fijada manualmente."""
    try:
        from services.platform_protection_score_service import compute_protection_score

        score = compute_protection_score()
        return jsonify({"status": "success", **score}), 200
    except Exception as e:
        logger.error("protection-score error: %s", e, exc_info=True)
        return jsonify({"status": "error", "message": "No se pudo calcular la puntuación"}), 500


@system_api_bp.route('/security/summary', methods=['GET'])
@login_required
def api_security_summary():
    """Get security summary from all 12 layers + CryptoVault + escudo sectorial."""
    try:
        summary = novus_security.security_engine.get_security_summary()
        vault = novus_security.vault
        vault_active = vault is not None and getattr(vault, 'llave_aes', None) is not None

        sector = request.args.get('sector', '').strip().lower()
        if not sector:
            from flask_login import current_user
            from services.sector_shield_service import resolve_sector_for_user
            sector = resolve_sector_for_user(getattr(current_user, "email", None))
        sector_shield = novus_security.security_engine.build_sector_protection(sector or 'fintech')

        return jsonify({
            "status": "success",
            "summary": summary,
            "vault": {
                "vault_active": vault_active,
                "aes_available": vault_active,
                "tls_label": vault.get_tls_status() if vault else "Sin datos disponibles",
                "key_rotation": "Sin datos disponibles",
            },
            "sector_shield": sector_shield,
        }), 200
        
    except Exception as e:
        logger.error(f"Security summary error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


# ==================== ESCUDO SECTORIAL ====================

@system_api_bp.route('/sector-profile', methods=['GET'])
@login_required
def api_sector_profile():
    """Perfil de protección activo del cliente autenticado."""
    try:
        from flask_login import current_user
        from services.sector_profile_service import get_kernel_context_for_user, get_sector_profile
        email = getattr(current_user, "email", None)
        ctx = get_kernel_context_for_user(email)
        profile = get_sector_profile(ctx.get("sector_key"))
        return jsonify({"status": "success", **ctx, "profile": profile}), 200
    except Exception as e:
        logger.error(f"Sector profile error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/sector-shield/status', methods=['GET'])
@login_required
def api_sector_shield_status():
    try:
        from flask_login import current_user
        from services.sector_shield_service import get_active_shield_status
        return jsonify(get_active_shield_status(getattr(current_user, "email", None))), 200
    except Exception as e:
        logger.error(f"Sector shield status error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/sector-shield/scan', methods=['POST'])
@login_required
def api_sector_shield_scan():
    try:
        from flask_login import current_user
        from services.sector_shield_service import scan_sector
        return jsonify(scan_sector(getattr(current_user, "email", None))), 200
    except Exception as e:
        logger.error(f"Sector shield scan error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e), "steps": []}), 500


@system_api_bp.route('/sector-shield/analyze-vulnerabilities', methods=['POST'])
@login_required
def api_sector_shield_analyze_vulns():
    try:
        from flask_login import current_user
        from services.sector_shield_service import analyze_sector_vulnerabilities
        return jsonify(analyze_sector_vulnerabilities(getattr(current_user, "email", None))), 200
    except Exception as e:
        logger.error(f"Sector vuln analyze error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/sector-shield/remediate', methods=['POST'])
@login_required
@api_hardened(sensitive=True, action_name="sector_shield_remediate")
def api_sector_shield_remediate():
    try:
        from flask_login import current_user
        from services.sector_shield_service import remediate_sector
        result = remediate_sector(getattr(current_user, "email", None))
        code = 200 if result.get("status") == "success" else 500
        return jsonify(result), code
    except Exception as e:
        logger.error(f"Sector remediate error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e), "steps": []}), 500


@system_api_bp.route('/sector-shield/mitigate', methods=['POST'])
@login_required
@api_hardened(sensitive=True, action_name="sector_shield_mitigate")
def api_sector_shield_mitigate():
    try:
        from flask_login import current_user
        from services.sector_shield_service import mitigate_sector
        result = mitigate_sector(getattr(current_user, "email", None))
        code = 200 if result.get("status") == "success" else 500
        return jsonify(result), code
    except Exception as e:
        logger.error(f"Sector mitigate error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e), "steps": []}), 500


@system_api_bp.route('/sector-shield/update-rules', methods=['POST'])
@login_required
def api_sector_shield_update_rules():
    try:
        from flask_login import current_user
        from services.sector_shield_service import update_sector_rules
        return jsonify(update_sector_rules(getattr(current_user, "email", None))), 200
    except Exception as e:
        logger.error(f"Sector rules update error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/sector-shield/policies', methods=['GET'])
@login_required
def api_sector_shield_policies():
    try:
        from flask_login import current_user
        from services.sector_shield_service import get_sector_policies
        return jsonify(get_sector_policies(getattr(current_user, "email", None))), 200
    except Exception as e:
        logger.error(f"Sector policies error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/sector-shield/history', methods=['GET'])
@login_required
def api_sector_shield_history():
    try:
        from flask_login import current_user
        from services.sector_shield_service import get_sector_history
        return jsonify(get_sector_history(getattr(current_user, "email", None))), 200
    except Exception as e:
        logger.error(f"Sector history error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/sector-shield/reports', methods=['GET'])
@login_required
def api_sector_shield_reports():
    try:
        from flask_login import current_user
        from services.sector_shield_service import get_sector_reports
        return jsonify(get_sector_reports(getattr(current_user, "email", None))), 200
    except Exception as e:
        logger.error(f"Sector reports error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


# ==================== UCE / ASPE ====================

@system_api_bp.route('/uce/detect', methods=['GET', 'POST'])
@login_required
def api_uce_detect():
    try:
        from flask_login import current_user
        from services.universal_compatibility_engine import uce
        email = getattr(current_user, "email", None)
        force = request.args.get("force") == "1" or request.method == "POST"
        if force:
            result = uce.detect_infrastructure(email, persist=True)
        else:
            result = uce.get_infrastructure_panel(email)
        return jsonify({"status": "success", "uce": result}), 200
    except Exception as e:
        logger.error(f"UCE detect error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/aspe/status', methods=['GET'])
@login_required
def api_aspe_status():
    try:
        from flask_login import current_user
        from services.adaptive_sector_protection_engine import aspe
        panel = aspe.get_sector_protection_panel(getattr(current_user, "email", None))
        return jsonify({"status": "success", "aspe": panel}), 200
    except Exception as e:
        logger.error(f"ASPE status error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/sector-protection', methods=['GET'])
@login_required
def api_sector_protection():
    """Panel unificado UCE + ASPE para Dashboard."""
    try:
        from flask_login import current_user
        from services.adaptive_sector_protection_engine import aspe
        email = getattr(current_user, "email", None)
        panel = aspe.get_sector_protection_panel(email)
        payload = {"status": "success", **panel}
        if request.args.get("audit") == "1":
            payload["audit"] = aspe.generate_audit_report(email)
        return jsonify(payload), 200
    except Exception as e:
        logger.error(f"Sector protection panel error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/defense-registry', methods=['GET'])
@login_required
def api_defense_registry():
    """Registro central de evidencias y acciones de defensa."""
    try:
        from services.defense_evidence_registry import get_registry_summary, list_recent_events
        limit = min(int(request.args.get("limit", 30)), 200)
        phase = request.args.get("phase")
        return jsonify({
            "status": "success",
            "summary": get_registry_summary(),
            "events": list_recent_events(limit=limit, phase=phase or None),
        }), 200
    except Exception as e:
        logger.error(f"Defense registry error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/instance-fingerprint', methods=['GET'])
def api_instance_fingerprint():
    """Huella de la instancia en ejecución (solo metadatos de build, sin secretos)."""
    import hashlib
    from datetime import datetime
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    rel_paths = (
        "main.py",
        "templates/reportes.html",
        "static/js/novus-reports-module.js",
        "templates/partials/reports_detail_panel.html",
    )
    files = {}
    for rel in rel_paths:
        p = root / rel.replace("/", os.sep)
        if p.is_file():
            raw = p.read_bytes()
            files[rel] = {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "mtime": datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds"),
                "size": len(raw),
            }
    return jsonify({
        "status": "success",
        "project_root": str(root),
        "entrypoint": str(root / "main.py"),
        "reports_ui_build": "reports-rebuild-20260722",
        "process_id": os.getpid(),
        "files": files,
    }), 200


@system_api_bp.route('/platform-health', methods=['GET'])
@login_required
def api_platform_health():
    """Platform Health Center — telemetría real de motores NOVUS."""
    try:
        from services.platform_health_service import get_platform_health
        return jsonify({"status": "success", "health": get_platform_health()}), 200
    except Exception as e:
        logger.error(f"Platform health error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/ngrok-manager', methods=['GET'])
@login_required
def api_ngrok_manager():
    """Estado del Ngrok Connection Manager."""
    try:
        from services.rbac_service import check_module_access, record_access_denied
        from flask_login import current_user
        ok, reason = check_module_access(current_user, "configuracion")
        if not ok:
            record_access_denied(current_user, module="configuracion", resource="ngrok-manager", detail=reason)
            return jsonify({"status": "error", "message": reason, "code": "RBAC_FORBIDDEN"}), 403
        from services.ngrok_connection_manager import get_manager_status
        return jsonify({"status": "success", "ngrok": get_manager_status()}), 200
    except Exception as e:
        logger.error(f"Ngrok manager status error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/evidence-center', methods=['GET'])
@login_required
def api_evidence_center():
    """Centro de Evidencias — historial unificado de acciones y detecciones."""
    try:
        from services.evidence_center_service import (
            backfill_from_defense_registry,
            get_evidence_summary,
            list_evidence,
        )
        from services.tenant_isolation_service import require_user_tenant_id
        from flask_login import current_user

        tenant_id = require_user_tenant_id(current_user)
        if request.args.get("backfill") == "1":
            backfill = backfill_from_defense_registry(limit=min(int(request.args.get("backfill_limit", 500)), 2000))
        else:
            backfill = None
        limit = min(int(request.args.get("limit", 50)), 500)
        categoria = request.args.get("categoria")
        motor = request.args.get("motor")
        items = list_evidence(
            limit=limit, categoria=categoria or None, motor=motor or None, tenant_id=tenant_id
        )
        return jsonify({
            "status": "success",
            "summary": get_evidence_summary(tenant_id=tenant_id),
            "evidence": items,
            "backfill": backfill,
        }), 200
    except Exception as e:
        from services.tenant_isolation_service import TenantAccessDenied
        if isinstance(e, TenantAccessDenied):
            return jsonify({"status": "error", "message": "Acceso no autorizado"}), 403
        logger.error(f"Evidence center error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/auth-protection/status', methods=['GET'])
@login_required
def api_auth_protection_status():
    """Estado de protección de autenticación por origen."""
    try:
        from services.auth_protection_service import auth_protection
        return jsonify({
            "status": "success",
            "protection": auth_protection.get_protection_status(),
        }), 200
    except Exception as e:
        logger.error(f"Auth protection status error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/auth-protection/incidents', methods=['GET'])
@login_required
def api_auth_protection_incidents():
    """Incidentes de acceso no autorizado consultables desde Kernel IA."""
    try:
        from services.auth_protection_service import auth_protection
        incident_id = request.args.get("incident_id")
        limit = min(int(request.args.get("limit", 30)), 200)
        if incident_id:
            inc = auth_protection.get_incident(incident_id)
            if not inc:
                return jsonify({"status": "error", "message": "Incidente no encontrado"}), 404
            return jsonify({"status": "success", "incident": inc}), 200
        return jsonify({
            "status": "success",
            "incidents": auth_protection.list_incidents(limit=limit),
        }), 200
    except Exception as e:
        logger.error(f"Auth protection incidents error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/auth-protection/config', methods=['GET', 'POST'])
@login_required
def api_auth_protection_config():
    """Configuración de umbrales y tiempos de bloqueo IP."""
    try:
        from services.auth_protection_config import get_auth_protection_config, save_auth_protection_config
        if request.method == 'GET':
            return jsonify({"status": "success", "config": get_auth_protection_config()}), 200
        payload = request.get_json(silent=True) or {}
        cfg = save_auth_protection_config(payload)
        return jsonify({"status": "success", "config": cfg, "message": "Configuración de protección actualizada"}), 200
    except Exception as e:
        logger.error(f"Auth protection config error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/hostile-environment/status', methods=['GET'])
@login_required
def api_hostile_environment_status():
    """Telemetría real: accesos, bloqueos, recursos, mecanismos activos."""
    try:
        from services.hostile_environment_service import get_operational_status
        return jsonify({"status": "success", **get_operational_status()}), 200
    except Exception as e:
        logger.error(f"Hostile environment status error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/hostile-environment/config', methods=['GET', 'POST'])
@login_required
def api_hostile_environment_config():
    """Listas blanca/negra, rate limits por ruta, degradación bajo carga."""
    try:
        from services.hostile_hardening_config import (
            get_hostile_hardening_config,
            save_hostile_hardening_config,
        )
        if request.method == 'GET':
            return jsonify({"status": "success", "config": get_hostile_hardening_config()}), 200
        payload = request.get_json(silent=True) or {}
        cfg = save_hostile_hardening_config(payload)
        return jsonify({
            "status": "success",
            "config": cfg,
            "message": "Configuración de endurecimiento actualizada",
        }), 200
    except Exception as e:
        logger.error(f"Hostile environment config error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/blocked-ips', methods=['GET'])
@login_required
def api_blocked_ips():
    """Centro de bloqueos — IPs bloqueadas con evidencia."""
    try:
        from services.auth_protection_service import auth_protection
        ip = request.args.get("ip")
        if ip:
            detail = auth_protection.get_block_detail(ip)
            if not detail:
                return jsonify({"status": "error", "message": "IP no encontrada"}), 404
            return jsonify({"status": "success", "block": detail}), 200
        limit = min(int(request.args.get("limit", 50)), 200)
        query = request.args.get("q")
        include_expired = request.args.get("include_expired", "").lower() in ("1", "true", "yes")
        blocks = auth_protection.list_blocked_ips(limit=limit, query=query, include_expired=include_expired)
        return jsonify({"status": "success", "count": len(blocks), "blocks": blocks}), 200
    except Exception as e:
        logger.error(f"Blocked IPs API error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/blocked-ips/<path:ip>/unblock', methods=['POST'])
@login_required
def api_unblock_ip(ip):
    """Desbloqueo manual autorizado por administrador."""
    try:
        from services.auth_protection_service import auth_protection
        from flask_login import current_user
        admin_email = getattr(current_user, "email", None)
        result = auth_protection.unblock_ip(ip, admin_email=admin_email)
        code = 200 if result.get("success") else 404
        return jsonify({"status": "success" if result.get("success") else "error", **result}), code
    except Exception as e:
        logger.error(f"Unblock IP error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/device-connections', methods=['GET'])
@login_required
def api_device_connections():
    """Historial de conexiones/desconexiones de dispositivos (evidencia ARP/AIE)."""
    try:
        from services.device_connection_monitor import list_events, get_device_history, search_devices
        mac = request.args.get("mac")
        ip = request.args.get("ip")
        event_type = request.args.get("event_type")
        q = request.args.get("q")
        limit = min(int(request.args.get("limit", 100)), 500)
        if mac or ip:
            history = get_device_history(mac=mac, ip=ip)
            return jsonify({"status": "success", "history": history}), 200
        if q:
            devices = search_devices(query=q, limit=limit)
            return jsonify({"status": "success", "count": len(devices), "devices": devices}), 200
        events = list_events(limit=limit, mac=mac, ip=ip, event_type=event_type)
        return jsonify({"status": "success", "count": len(events), "events": events}), 200
    except Exception as e:
        logger.error(f"Device connections API error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/login-sessions', methods=['GET'])
@login_required
def api_login_sessions():
    """Historial de sesiones de acceso con evidencias post-login."""
    try:
        from services.login_session_audit_service import list_login_sessions, get_login_session
        from services.tenant_isolation_service import require_user_tenant_id
        from flask_login import current_user

        tenant_id = require_user_tenant_id(current_user)
        session_id = request.args.get("id")
        if session_id:
            row = get_login_session(session_id, tenant_id=tenant_id)
            if not row:
                return jsonify({"status": "error", "message": "Sesión no encontrada"}), 404
            return jsonify({"status": "success", "session": row}), 200
        limit = min(int(request.args.get("limit", 50)), 200)
        email = request.args.get("email")
        sessions = list_login_sessions(limit=limit, email=email, tenant_id=tenant_id)
        return jsonify({"status": "success", "count": len(sessions), "sessions": sessions}), 200
    except Exception as e:
        from services.tenant_isolation_service import TenantAccessDenied
        if isinstance(e, TenantAccessDenied):
            return jsonify({"status": "error", "message": "Acceso no autorizado"}), 403
        logger.error(f"Login sessions API error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/threat-coverage', methods=['GET'])
@login_required
def api_threat_coverage():
    """Cobertura avanzada de amenazas por categoría y sector."""
    try:
        from services.threat_coverage_service import threat_coverage
        from services.active_defense_orchestrator import active_defense
        sector = request.args.get("sector")
        payload = {
            "status": "success",
            "live_coverage": threat_coverage.evaluate_live_coverage(),
            "active_defense": active_defense.verify_and_reconcile_active_incidents(),
        }
        if sector:
            payload["sector"] = threat_coverage.get_sector_coverage(sector)
        else:
            payload["sectors"] = {
                s: threat_coverage.get_sector_coverage(s, live=payload["live_coverage"])
                for s in ("fintech", "logistica", "aplicaciones_moviles", "otros")
            }
        return jsonify(payload), 200
    except Exception as e:
        logger.error(f"Threat coverage error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@system_api_bp.route('/endpoints/live', methods=['GET'])
@login_required
def get_endpoints_live():
    """
    Get real-time endpoint data
    Returns system information with real metrics
    """
    try:
        from flask_login import current_user
        from services.tenant_api_gate import check_tenant_monitoring_or_response

        _, blocked = check_tenant_monitoring_or_response(current_user, scope="security")
        if blocked:
            return blocked

        nombre_equipo = socket.gethostname()
        sistema_op = platform.system()
        arquitectura = platform.machine()
        
        uso_memoria = psutil.virtual_memory()
        cpu_actual = psutil.cpu_percent(interval=0.5)
        
        from utils.host_data import get_local_ip, format_ip_or_unavailable
        from services.novus_security_integration import novus_security

        ip_local = format_ip_or_unavailable(get_local_ip())
        vuln_count = len(novus_security._threat_cache.get('vulnerabilities') or novus_security.scan_vulnerabilities())
        
        # Get MAC address
        try:
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,8*6,8)][::-1])
        except:
            mac = "Unknown"
        
        # Get active processes with connections
        procesos_con_conexiones = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                conexiones = proc.connections()
                if conexiones:
                    procesos_con_conexiones.append({
                        "pid": proc.info['pid'],
                        "nombre": proc.info['name'],
                        "cpu": proc.info.get('cpu_percent', 0),
                        "memoria": proc.info.get('memory_percent', 0),
                        "conexiones": len(conexiones)
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        from utils.endpoint_status import local_host_status

        endpoint_data = {
            "nombre": nombre_equipo,
            "ip": ip_local,
            "mac": mac,
            "tipo": sistema_op,
            "vulnerabilidades": vuln_count,
            "estado": local_host_status(),
            "icono": "fa-desktop",
            "cpu": f"{cpu_actual:.1f}%",
            "ram": f"{uso_memoria.percent:.1f}%",
            "arquitectura": arquitectura,
            "procesos_activos": len(procesos_con_conexiones),
            "uptime": f"{(time.time() - psutil.boot_time()) / 3600:.1f}h",
            "timestamp": time.time()
        }
        
        return jsonify({
            "status": "success",
            "endpoint": endpoint_data,
            "endpoints": [endpoint_data],
            "procesos": procesos_con_conexiones[:10]  # Limit to top 10
        })
        
    except Exception as e:
        logger.error(f"Error getting live endpoints: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@system_api_bp.route('/status', methods=['GET'])
@login_required
def get_system_status():
    """
    Get current system status
    Returns comprehensive system metrics
    """
    try:
        force_refresh = request.args.get('force', 'false').lower() == 'true'
        status = system_monitor.get_system_status(force_refresh=force_refresh)
        
        response = {
            "status": "success",
            "system": status
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in system status API: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Error retrieving system status"
        }), 500


@system_api_bp.route('/processes', methods=['GET'])
@login_required
def get_processes():
    """
    Get list of system processes
    Returns top processes by CPU usage
    """
    try:
        limit = request.args.get('limit', 50, type=int)
        processes = system_monitor.get_process_list(limit=limit)
        
        response = {
            "status": "success",
            "processes": processes,
            "count": len(processes)
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in processes API: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "processes": [],
            "message": "Error retrieving processes"
        }), 500


@system_api_bp.route('/network', methods=['GET'])
@login_required
def get_network_stats():
    """
    Get network statistics
    Returns network I/O counters and connection count
    """
    try:
        stats = system_monitor.get_network_stats()
        
        response = {
            "status": "success",
            "network": stats
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in network stats API: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Error retrieving network stats"
        }), 500


@system_api_bp.route('/ai/command', methods=['POST'])
@login_required
@api_hardened(sensitive=True, require_json=True, required_fields=["command"], action_name="ai_command")
def ai_command():
    """
    Execute AI command
    Allows frontend to send commands to AI Kernel
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "status": "error",
                "message": "No data provided"
            }), 400
        
        command = data.get('command')
        target = data.get('target')
        
        if not command:
            return jsonify({
                "status": "error",
                "message": "Command is required"
            }), 400
        
        result = ai_kernel.execute_command(command, target)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in AI command API: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Error executing AI command"
        }), 500


@system_api_bp.route('/ai/files', methods=['POST'])
@login_required
def ai_file_manager():
    """
    AI file management — RBAC + path sandbox.
    """
    from services.rbac_service import can_access_api
    from flask_login import current_user as _cu

    if not can_access_api(_cu, "system.ai_files"):
        from utils.rbac import _deny

        return _deny(None, "system.ai_files", "RBAC: system.ai_files requerido")
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "status": "error",
                "message": "No data provided"
            }), 400
        
        action = data.get('accion')
        filepath = data.get('ruta')
        
        if not action or not filepath:
            return jsonify({
                "status": "error",
                "message": "Action and filepath are required"
            }), 400

        from services.web_security_auth_enterprise.path_sandbox import sandbox_check

        sb = sandbox_check(filepath)
        if not sb.get("allowed"):
            return jsonify({
                "status": "error",
                "message": "Ruta fuera del sandbox permitido",
                "code": "PATH_SANDBOX",
                "detail": sb.get("detail"),
            }), 403
        filepath = sb.get("resolved") or filepath
        
        if action == 'borrar':
            result = ai_kernel.delete_file(filepath)
        elif action == 'analizar':
            result = ai_kernel.analyze_file(filepath)
        else:
            return jsonify({
                "status": "error",
                "message": "Invalid action"
            }), 400
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in AI file manager API: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Error in file operation"
        }), 500


@system_api_bp.route('/ai/logs', methods=['GET'])
@login_required
def get_ai_logs():
    """
    Get AI Kernel logs
    Returns current AI Kernel status
    """
    try:
        logs = ai_kernel.get_logs()
        
        response = {
            "status": "success",
            "logs": logs
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in AI logs API: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "Error retrieving AI logs"
        }), 500


@system_api_bp.route('/automation/memory/optimize', methods=['POST'])
@login_required
def optimize_memory():
    """
    Optimize system memory
    Detects high memory processes and provides optimization options
    """
    try:
        procesos = list(psutil.process_iter(['pid', 'name', 'memory_percent']))
        memoria_total = psutil.virtual_memory()
        
        # Get high memory processes
        procesos_alta_memoria = [
            {
                "pid": p.info['pid'],
                "nombre": p.info['name'],
                "memoria_percent": p.info.get('memory_percent', 0)
            }
            for p in procesos
            if p.info.get('memory_percent', 0) > 5
        ]
        
        # Sort by memory usage
        procesos_alta_memoria.sort(key=lambda x: x['memoria_percent'], reverse=True)
        
        return jsonify({
            "status": "success",
            "memoria_total": {
                "percent": memoria_total.percent,
                "available_gb": memoria_total.available / (1024**3),
                "total_gb": memoria_total.total / (1024**3)
            },
            "procesos_alta_memoria": procesos_alta_memoria[:20],
            "accion_recomendada": "Considerar cerrar procesos de alta memoria"
        })
        
    except Exception as e:
        logger.error(f"Error optimizing memory: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@system_api_bp.route('/automation/processes/kill', methods=['POST'])
@login_required
@api_hardened(sensitive=True, require_json=True, required_fields=["pid"], action_name="kill_process")
def kill_process():
    """
    Kill a process by PID — RBAC system.kill_process
    """
    from services.rbac_service import can_access_api
    from flask_login import current_user as _cu

    if not can_access_api(_cu, "system.kill_process"):
        from utils.rbac import _deny

        return _deny(None, "system.kill_process", "RBAC: system.kill_process requerido")
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "status": "error",
                "message": "No data provided"
            }), 400
        
        pid = data.get('pid')
        if not pid:
            return jsonify({
                "status": "error",
                "message": "PID is required"
            }), 400
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return jsonify({"status": "error", "message": "PID debe ser numérico"}), 400
        if pid <= 0:
            return jsonify({"status": "error", "message": "PID inválido"}), 400
        
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            process.terminate()
            
            logger.info(f"Process terminated: PID {pid} ({process_name})")
            
            return jsonify({
                "status": "success",
                "message": f"Process {process_name} (PID {pid}) terminated successfully"
            })
        except psutil.NoSuchProcess:
            return jsonify({
                "status": "error",
                "message": "Process not found"
            }), 404
        except psutil.AccessDenied:
            return jsonify({
                "status": "error",
                "message": "Access denied - insufficient permissions"
            }), 403
        
    except Exception as e:
        logger.error(f"Error killing process: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@system_api_bp.route('/automation/processes/high', methods=['GET'])
@login_required
def get_high_consumption_processes():
    """
    Get processes with high CPU or memory consumption
    Returns list of processes that may need attention
    """
    try:
        procesos = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))
        
        procesos_criticos = []
        for p in procesos:
            cpu = p.info.get('cpu_percent', 0)
            mem = p.info.get('memory_percent', 0)
            
            if cpu > 50 or mem > 10:
                procesos_criticos.append({
                    "pid": p.info['pid'],
                    "nombre": p.info['name'],
                    "cpu_percent": cpu,
                    "memory_percent": mem,
                    "riesgo": "ALTO" if cpu > 80 or mem > 20 else "MEDIO"
                })
        
        # Sort by combined consumption
        procesos_criticos.sort(key=lambda x: x['cpu_percent'] + x['memory_percent'], reverse=True)
        
        return jsonify({
            "status": "success",
            "procesos_criticos": procesos_criticos[:30],
            "total": len(procesos_criticos)
        })
        
    except Exception as e:
        logger.error(f"Error getting high consumption processes: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@system_api_bp.route('/incidents/mitigate', methods=['POST'])
@login_required
@api_hardened(sensitive=True, require_json=True, action_name="mitigate_incident")
def mitigate_incident():
    """Execute incident mitigation with step-by-step results."""
    try:
        from services.remediation_engine import remediate_incident

        payload = request.get_json(silent=True) or {}
        incident_id = payload.get('incident_id', 'Sin datos disponibles')

        result = remediate_incident(incident_id)
        return jsonify({
            "status": result.get("status", "success"),
            "message": result.get("message", f"Mitigación registrada para {incident_id}"),
            "incident_id": incident_id,
            "steps": result.get("steps", []),
            "report_id": result.get("report_id"),
            "final_status": result.get("final_status"),
            "elapsed": result.get("elapsed"),
        })
    except Exception as e:
        logger.error(f"Mitigate incident error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e), "steps": []}), 500


@system_api_bp.route('/runtime-info', methods=['GET'])
@login_required
def api_runtime_info():
    """Identidad del runtime activo — sin secretos. Solo super_admin."""
    import sys
    from datetime import datetime
    from services.rbac_service import get_user_role, ROLE_SUPER_ADMIN
    from flask_login import current_user
    from core.config import Config

    role = get_user_role(current_user)
    if role != ROLE_SUPER_ADMIN:
        return jsonify({"status": "error", "message": "Acceso denegado", "code": "RBAC_FORBIDDEN"}), 403

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    main_path = os.path.join(root, "main.py")
    build_mtime = None
    try:
        build_mtime = datetime.utcfromtimestamp(os.path.getmtime(main_path)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass

    git_head = None
    try:
        head_file = os.path.join(root, ".git", "HEAD")
        if os.path.isfile(head_file):
            with open(head_file, "r", encoding="utf-8") as fh:
                git_head = fh.read().strip()
    except Exception:
        pass

    safe_env_keys = (
        "NOVUS_ENV",
        "NODE_ID",
        "PORT",
        "HOST",
        "NOVUS_PLATFORM_TENANT_ID",
        "NOVUS_ALLOW_LAB_RUNTIME",
        "NOVUS_ALLOW_QA_SEED",
        "NOVUS_ALLOW_REGISTRATION",
        "NOVUS_CEO_EMAIL",
        "FLASK_DEBUG",
        "NOVUS_BEHIND_PROXY",
    )
    env_snapshot = {}
    for key in safe_env_keys:
        val = os.environ.get(key)
        if val is None:
            continue
        if key == "NOVUS_CEO_EMAIL" and val and "@" in val:
            local, domain = val.split("@", 1)
            env_snapshot[key] = (local[:3] + "***@" + domain) if local else "***@" + domain
        else:
            env_snapshot[key] = val

    port = int(os.environ.get("PORT", getattr(Config, "PORT", 5000)))
    host = getattr(Config, "HOST", "0.0.0.0")

    return jsonify({
        "status": "success",
        "runtime": {
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "python_executable": sys.executable,
            "python_version": platform.python_version(),
            "project_root": root,
            "main_py": main_path,
            "main_py_mtime_utc": build_mtime,
            "working_directory": os.getcwd(),
            "host": host,
            "port": port,
            "novus_version": getattr(Config, "VERSION", None),
            "node_id": getattr(Config, "NODE_ID", None),
            "novus_env": os.environ.get("NOVUS_ENV", "development"),
            "git_head": git_head,
            "werkzeug_run_main": os.environ.get("WERKZEUG_RUN_MAIN"),
        },
        "env_safe": env_snapshot,
        "features_on_disk": {
            "registration_approval_service": os.path.isfile(os.path.join(root, "services", "registration_approval_service.py")),
            "email_delivery_service": os.path.isfile(os.path.join(root, "services", "email_delivery_service.py")),
            "production_runtime_guard": os.path.isfile(os.path.join(root, "services", "production_runtime_guard.py")),
        },
        "timestamp_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
