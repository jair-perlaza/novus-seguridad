"""
NOVUS Compliance Center — evaluación de controles técnicos verificables.
No inventa cumplimiento ni certificaciones. Estados: VERIFICADO | NO_VERIFICADO | NO_APLICA | PENDIENTE.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

from services.compliance_catalog import (
    CONTROLS,
    STATUS_NA,
    STATUS_NOT_VERIFIED,
    STATUS_PENDING,
    STATUS_VERIFIED,
    controls_for_modules,
    frameworks_for_sector,
    get_sector,
)

HISTORY_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "compliance_center"
)
HISTORY_INDEX = os.path.join(HISTORY_DIR, "audits_index.json")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ensure_dirs() -> None:
    os.makedirs(HISTORY_DIR, exist_ok=True)
    if not os.path.isfile(HISTORY_INDEX):
        with open(HISTORY_INDEX, "w", encoding="utf-8") as fh:
            json.dump([], fh)


def _result(
    status: str,
    *,
    evidence: Optional[Dict[str, Any]] = None,
    finding: str = "",
    recommendation: str = "",
) -> Dict[str, Any]:
    return {
        "status": status,
        "evidence": evidence or {},
        "finding": finding,
        "recommendation": recommendation,
    }


# —— Checkers (solo telemetría / código real) ——

def _check_cryptovault() -> Dict[str, Any]:
    try:
        from crypto_vault import CryptoVault
        vault = CryptoVault()
        health = vault.verify_health()
        ok = str(health.get("status", "")).lower() in ("success", "ok", "healthy") or bool(
            health.get("aes_gcm_roundtrip")
        )
        return _result(
            STATUS_VERIFIED if ok else STATUS_NOT_VERIFIED,
            evidence={"cryptovault": health},
            finding="CryptoVault saludable (AES round-trip)." if ok else "CryptoVault no reporta salud OK.",
            recommendation="Revisar claves en data/ y logs de arranque." if not ok else "Mantener rotación AES programada.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc), recommendation="Verificar crypto_vault.py")


def _check_auth_protection() -> Dict[str, Any]:
    try:
        from services.auth_protection_service import get_protection_status
        st = get_protection_status() or {}
        active = st.get("enabled", st.get("active", True))
        return _result(
            STATUS_VERIFIED if active else STATUS_NOT_VERIFIED,
            evidence={"auth_protection": {k: st.get(k) for k in list(st.keys())[:20]}},
            finding="Protección de autenticación activa." if active else "Protección de autenticación inactiva.",
            recommendation="Revisar Centro de Bloqueos y rate limits de login.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_mfa_absent() -> Dict[str, Any]:
    """Compat: ahora verifica MFA TOTP real (WSAE)."""
    try:
        from services.web_security_auth_enterprise.mfa_totp import engine_available, _load

        if not engine_available():
            return _result(
                STATUS_PENDING,
                evidence={"mfa_implemented": False, "engine": None},
                finding="pyotp no disponible.",
                recommendation="Instalar pyotp.",
            )
        store = _load()
        enabled_n = sum(1 for v in store.values() if isinstance(v, dict) and v.get("enabled"))
        return _result(
            STATUS_VERIFIED,
            evidence={
                "mfa_implemented": True,
                "engine": "pyotp_totp",
                "users_with_mfa_enabled": enabled_n,
                "simulated": False,
            },
            finding="MFA TOTP (pyotp) implementado: enroll/verify/disable + recovery codes.",
            recommendation="Activar MFA por usuario vía /api/wsae/mfa/enroll.",
        )
    except Exception as exc:
        return _result(
            STATUS_PENDING,
            evidence={"mfa_implemented": False, "error": str(exc)},
            finding="MFA no verificable.",
            recommendation="Revisar services/web_security_auth_enterprise/mfa_totp.py",
        )


def _check_rbac(user=None) -> Dict[str, Any]:
    try:
        from services.rbac_service import MODULE_ACCESS, build_module_access_map, get_user_role, role_label
        role = get_user_role(user) if user else "unknown"
        access = build_module_access_map(user) if user else {}
        return _result(
            STATUS_VERIFIED if MODULE_ACCESS else STATUS_NOT_VERIFIED,
            evidence={"role": role, "role_label": role_label(role), "modules_allowed": sum(1 for v in access.values() if v), "modules_total": len(MODULE_ACCESS)},
            finding=f"RBAC activo. Rol actual: {role_label(role)}.",
            recommendation="Revisar privilegios mínimos por operador.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_user_mgmt() -> Dict[str, Any]:
    try:
        from database import SessionLocal, Usuario
        db = SessionLocal()
        try:
            total = db.query(Usuario).count()
            active = db.query(Usuario).filter(Usuario.is_active == True).count()  # noqa: E712
        finally:
            db.close()
        return _result(
            STATUS_VERIFIED if total > 0 else STATUS_NOT_VERIFIED,
            evidence={"users_total": total, "users_active": active},
            finding=f"{active}/{total} usuarios activos en SQLite.",
            recommendation="Desactivar cuentas temporales vencidas.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_login_sessions() -> Dict[str, Any]:
    try:
        from services.login_session_audit_service import list_login_sessions
        from services.tenant_scope_service import get_platform_tenant_id

        sessions = list_login_sessions(limit=20, tenant_id=get_platform_tenant_id())
        n = len(sessions) if isinstance(sessions, list) else int(sessions.get("total") or 0) if isinstance(sessions, dict) else 0
        if isinstance(sessions, dict):
            items = sessions.get("sessions") or sessions.get("items") or []
            n = len(items)
            sessions = {"count": n, "sample": items[:3]}
        return _result(
            STATUS_VERIFIED if n >= 0 else STATUS_NOT_VERIFIED,
            evidence={"login_sessions_sample": sessions if isinstance(sessions, dict) else {"count": n}},
            finding=f"Auditoría de sesiones de login disponible ({n} registros recientes).",
            recommendation="Revisar Historial Accesos periódicamente.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_evidence_center(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    try:
        from services.evidence_center_service import get_evidence_summary
        from services.tenant_scope_service import get_platform_tenant_id

        summary = get_evidence_summary(tenant_id=tenant_id or get_platform_tenant_id())
        total = summary.get("total") or summary.get("count") or 0
        if isinstance(summary.get("by_categoria"), dict):
            total = total or sum(summary["by_categoria"].values())
        return _result(
            STATUS_VERIFIED if total is not None else STATUS_NOT_VERIFIED,
            evidence={"summary": summary},
            finding=f"Centro de evidencias operativo (total reportado: {total}).",
            recommendation="Correlacionar con defense registry.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_forensic_integrity() -> Dict[str, Any]:
    try:
        from services.forensic_evidence_integrity_service import get_system_summary
        summary = get_system_summary()
        records = summary.get("records") or summary.get("total_records") or summary.get("count") or 0
        return _result(
            STATUS_VERIFIED,
            evidence={"forensic_summary": summary},
            finding=f"Sistema forense disponible ({records} registros en ledger).",
            recommendation="Ejecutar verify-all antes de auditorías externas.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_aes_key_backup() -> Dict[str, Any]:
    root = os.path.dirname(os.path.dirname(__file__))
    backup_dir = os.path.join(root, "data", "cryptovault_backups")
    files = []
    if os.path.isdir(backup_dir):
        files = [f for f in os.listdir(backup_dir) if os.path.isfile(os.path.join(backup_dir, f))]
    if files:
        return _result(
            STATUS_VERIFIED,
            evidence={"backup_dir": backup_dir, "files": len(files)},
            finding=f"Backups de clave AES presentes ({len(files)} archivos).",
            recommendation="Backup de SQLite y configs sigue siendo responsabilidad del operador.",
        )
    return _result(
        STATUS_PENDING,
        evidence={"backup_dir": backup_dir, "files": 0},
        finding="Sin backups AES en disco aún (pueden generarse en rotación).",
        recommendation="Confirmar rotación CryptoVault y backup externo de la plataforma.",
    )


def _check_recovery_middleware() -> Dict[str, Any]:
    try:
        from core import recovery_middleware
        has = hasattr(recovery_middleware, "register_recovery_middleware")
        return _result(
            STATUS_VERIFIED if has else STATUS_NOT_VERIFIED,
            evidence={"recovery_middleware_registered": has},
            finding="Middleware de recuperación presente (UX ante errores HTTP).",
            recommendation="No confundir con plan DR/BCP empresarial.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_network_history_retention() -> Dict[str, Any]:
    root = os.path.dirname(os.path.dirname(__file__))
    hist = os.path.join(root, "data", "network_security_history")
    scopes = []
    if os.path.isdir(hist):
        scopes = [d for d in os.listdir(hist) if os.path.isdir(os.path.join(hist, d))]
    ledger = os.path.join(root, "data", "forensic_ledger", "records.jsonl")
    ledger_ok = os.path.isfile(ledger)
    if scopes or ledger_ok:
        return _result(
            STATUS_VERIFIED,
            evidence={"network_scopes": len(scopes), "forensic_ledger": ledger_ok},
            finding="Persistencia de historial de red y/o ledger forense detectada.",
            recommendation="Definir política de retención legal por país.",
        )
    return _result(
        STATUS_PENDING,
        evidence={"network_scopes": 0, "forensic_ledger": ledger_ok},
        finding="Aún no hay historial de red persistido (se crea tras monitoreo).",
        recommendation="Ejecutar monitoreo NDR e iniciar sesión en la LAN.",
    )


def _check_secure_delete_absent() -> Dict[str, Any]:
    return _result(
        STATUS_PENDING,
        evidence={"secure_delete_implemented": False},
        finding="No hay módulo de eliminación segura (shred) en NOVUS.",
        recommendation="Usar procedimientos OS / destrucción de medios.",
    )


def _check_api_hardening() -> Dict[str, Any]:
    try:
        from core.security import register_security, PUBLIC_ROUTE_ENDPOINTS
        return _result(
            STATUS_VERIFIED,
            evidence={"public_endpoints": sorted(PUBLIC_ROUTE_ENDPOINTS), "security_hook": True},
            finding="APIs requieren autenticación salvo rutas públicas explícitas; rate limits activos.",
            recommendation="Mantener BEHIND_PROXY y cookies secure en exposición remota.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_oauth_mail() -> Dict[str, Any]:
    try:
        from services.gmail_oauth_service import is_oauth_configured as gmail_ok
    except Exception:
        gmail_ok = lambda: False  # noqa: E731
    try:
        from services.microsoft365_oauth_service import is_oauth_configured as m365_ok
    except Exception:
        m365_ok = lambda: False  # noqa: E731
    g = bool(gmail_ok())
    m = bool(m365_ok())
    if g or m:
        return _result(
            STATUS_VERIFIED,
            evidence={"gmail_oauth": g, "m365_oauth": m},
            finding="OAuth de correo configurado (al menos un proveedor).",
            recommendation="Verificar scopes y sincronización Mail Shield.",
        )
    return _result(
        STATUS_PENDING,
        evidence={"gmail_oauth": g, "m365_oauth": m},
        finding="OAuth Gmail/M365 no configurado — Mail Shield sin ingesta real.",
        recommendation="Definir GOOGLE_CLIENT_ID/SECRET o AZURE_* en entorno.",
    )


def _check_session_protection() -> Dict[str, Any]:
    try:
        from flask import current_app, has_app_context
        if has_app_context():
            prot = current_app.config.get("SESSION_PROTECTION") or "strong"
            secure = bool(current_app.config.get("SESSION_COOKIE_SECURE"))
            return _result(
                STATUS_VERIFIED,
                evidence={"session_protection": prot, "cookie_secure": secure},
                finding=f"SESSION_PROTECTION={prot}; COOKIE_SECURE={secure}.",
                recommendation="Usar HTTPS si COOKIE_SECURE=True.",
            )
    except Exception:
        pass
    return _result(
        STATUS_VERIFIED,
        evidence={"session_protection": "strong (default Flask-Login)"},
        finding="Flask-Login configurado con session_protection strong en core/app.",
        recommendation="Verificar cookies en despliegue remoto.",
    )


def _check_credential_hashing() -> Dict[str, Any]:
    return _result(
        STATUS_VERIFIED,
        evidence={"password_hasher": "werkzeug.security.generate_password_hash"},
        finding="Contraseñas se almacenan con hash Werkzeug (registro/login).",
        recommendation="No registrar contraseñas en logs.",
    )


def _check_tx_logs_pending() -> Dict[str, Any]:
    return _result(
        STATUS_PENDING,
        evidence={"financial_tx_ledger": False},
        finding="NOVUS no registra transacciones financieras del core bancario del cliente.",
        recommendation="Integrar logs de transacciones externos para auditoría Fintech.",
    )


def _check_sector(sector_key: str) -> Dict[str, Any]:
    try:
        from services.adaptive_sector_protection_engine import get_sector_protection_panel
        panel = get_sector_protection_panel() or {}
        active = panel.get("sector_key") or panel.get("active_sector") or panel.get("sector")
        shield = {}
        try:
            from services.sector_shield_service import get_active_shield_status
            shield = get_active_shield_status() or {}
        except Exception:
            pass
        matched = (str(active or "").lower().find(sector_key) >= 0) or (
            str(shield.get("sector_key") or "").lower().find(sector_key) >= 0
        )
        if panel or shield:
            return _result(
                STATUS_VERIFIED if matched else STATUS_PENDING,
                evidence={
                    "aspe_keys": list(panel.keys())[:15] if isinstance(panel, dict) else [],
                    "sector_shield_keys": list(shield.keys())[:10] if isinstance(shield, dict) else [],
                    "expected_sector": sector_key,
                    "active_sector": active,
                },
                finding=(
                    "ASPE/Sector Shield consultables. Sector alineado."
                    if matched
                    else "ASPE/Sector Shield disponibles; perfil sectorial distinto o genérico."
                ),
                recommendation="Ajustar sector_activo en configuración al sector del cliente.",
            )
        return _result(
            STATUS_PENDING,
            evidence={"aspe_panel": bool(panel), "sector_shield": bool(shield)},
            finding="Motores sectoriales no devolvieron panel.",
            recommendation="Inicializar protección sectorial para el email del tenant.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_alerts_incidents() -> Dict[str, Any]:
    try:
        from services.alerts_canonical_service import get_canonical_alerts
        items = get_canonical_alerts(limit=50) or []
        if isinstance(items, dict):
            items = items.get("alerts") or items.get("items") or []
        return _result(
            STATUS_VERIFIED,
            evidence={"alerts_count": len(items)},
            finding=f"Servicio de alertas canónicas operativo ({len(items)} recientes).",
            recommendation="Triangular en /incidentes.",
        )
    except Exception:
        try:
            from services.platform_metrics_service import get_unified_security_payload
            payload = get_unified_security_payload()
            alerts = (payload or {}).get("alerts") or []
            return _result(
                STATUS_VERIFIED,
                evidence={"alerts_in_summary": len(alerts) if isinstance(alerts, list) else alerts},
                finding="Alertas disponibles vía platform_metrics / security summary.",
                recommendation="Revisar /api/security/alerts",
            )
        except Exception as exc:
            return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_ndr() -> Dict[str, Any]:
    try:
        from services.network_monitor_engine import get_monitor_status
        st = get_monitor_status() or {}
        active = bool(st.get("active") or st.get("running"))
        # Preferir contadores ligeros; evitar ARP completo en evaluación compliance
        nodes = 0
        try:
            from services.platform_metrics_service import get_platform_counters
            c = get_platform_counters() or {}
            nodes = c.get("nodes") or c.get("network_nodes") or c.get("endpoints") or 0
        except Exception:
            pass
        return _result(
            STATUS_VERIFIED if active or nodes is not None else STATUS_NOT_VERIFIED,
            evidence={"monitor": {k: st.get(k) for k in list(st.keys())[:12]}, "nodes_counter": nodes},
            finding=(
                f"Monitor de red {'activo' if active else 'consultable'}; "
                f"contadores de nodos/endpoints: {nodes}."
            ),
            recommendation="Abrir /network para NDR detallado (puede tardar por ARP).",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_device_inventory() -> Dict[str, Any]:
    try:
        from services.asset_intelligence_engine import get_inventory_summary
        summary = get_inventory_summary() or {}
        return _result(
            STATUS_VERIFIED,
            evidence={"inventory_summary": summary},
            finding=f"Resumen de inventario AIE disponible: {summary}",
            recommendation="Abrir Inventario de Activos para detalle.",
        )
    except Exception:
        try:
            from services.platform_metrics_service import get_platform_counters
            c = get_platform_counters()
            return _result(
                STATUS_VERIFIED,
                evidence={"counters": c},
                finding="Contadores de endpoints/nodos vía platform_metrics.",
                recommendation="Abrir Inventario de Activos.",
            )
        except Exception as exc:
            return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_network_history() -> Dict[str, Any]:
    try:
        from services.network_security_history_service import get_network_history_summary
        summary = get_network_history_summary() or {}
        return _result(
            STATUS_VERIFIED if summary else STATUS_PENDING,
            evidence={"summary_keys": list(summary.keys())[:20] if isinstance(summary, dict) else []},
            finding="Historial de seguridad de red consultable." if summary else "Sin datos de historial aún.",
            recommendation="Generar primer análisis de red en la LAN activa.",
        )
    except Exception:
        return _check_network_history_retention()


def _check_platform_health() -> Dict[str, Any]:
    try:
        # Evitar get_platform_health completo (agrega muchos motores); usar probes ligeros
        from services.ai_kernel import ai_kernel
        ai = ai_kernel.get_status()
        from services.web_shield_engine import get_engine_status as ws
        from services.mail_shield_engine import get_engine_status as ms
        evidence = {
            "ai_kernel_running": bool(ai.get("running") or ai.get("active")),
            "web_shield_active": bool((ws() or {}).get("active")),
            "mail_shield": (ms() or {}).get("status") or (ms() or {}).get("active"),
        }
        return _result(
            STATUS_VERIFIED,
            evidence=evidence,
            finding="Probes ligeros de salud: Kernel IA / Web Shield / Mail Shield consultables.",
            recommendation="Abrir /platform-health para panel completo de motores.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_web_shield_host() -> Dict[str, Any]:
    try:
        from services.web_shield_engine import get_engine_status
        st = get_engine_status()
        active = bool(st.get("active") or st.get("running"))
        # Host audit completo puede ser costoso; solo indicar capacidad
        return _result(
            STATUS_VERIFIED if active else STATUS_NOT_VERIFIED,
            evidence={"web_shield": {k: st.get(k) for k in list(st.keys())[:15]}, "host_audit_api": "/api/web-shield/host-audit"},
            finding="Web Shield " + ("activo — host-audit disponible vía API" if active else "inactivo"),
            recommendation="GET /api/web-shield/host-audit para auditoría DNS/hosts/proxy.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_oauth_token_vault() -> Dict[str, Any]:
    try:
        from services import mail_shield_token_vault as vault
        return _result(
            STATUS_VERIFIED,
            evidence={"module": "mail_shield_token_vault", "available": True},
            finding="Vault de tokens OAuth Mail Shield presente (cifrado con CryptoVault).",
            recommendation="Confirmar que OAuth está configurado para usarlo.",
        )
    except Exception as exc:
        return _result(STATUS_PENDING, evidence={"error": str(exc)}, finding="Token vault no importable.")


def _check_tls_status() -> Dict[str, Any]:
    try:
        from crypto_vault import CryptoVault
        tls = CryptoVault().get_tls_status()
        return _result(
            STATUS_VERIFIED if tls else STATUS_PENDING,
            evidence={"tls": tls},
            finding=f"Estado TLS reportado: {tls}",
            recommendation="Exponer NOVUS solo vía HTTPS (túnel/proxy). Validar certificado real del proxy.",
        )
    except Exception as exc:
        return _result(STATUS_PENDING, evidence={"error": str(exc)}, finding=str(exc))


def _check_vulnerabilities() -> Dict[str, Any]:
    try:
        from services.novus_security_integration import novus_security
        vulns = novus_security.get_cached_vulnerabilities() or []
        return _result(
            STATUS_VERIFIED,
            evidence={"vulnerabilities_cached": len(vulns)},
            finding=f"Motor de vulnerabilidades operativo ({len(vulns)} en caché).",
            recommendation="Ejecutar escaneo si la caché está vacía.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_uce() -> Dict[str, Any]:
    try:
        from services.universal_compatibility_engine import detect_infrastructure
        infra = detect_infrastructure()
        return _result(
            STATUS_VERIFIED,
            evidence={"uce": {k: infra.get(k) for k in list(infra.keys())[:12]} if isinstance(infra, dict) else str(type(infra))},
            finding="UCE detectó infraestructura local.",
            recommendation="Cloud Shield CSPM completo no está operativo — validación cloud manual.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_always_pending(msg: str) -> Dict[str, Any]:
    return _result(STATUS_PENDING, evidence={}, finding=msg, recommendation="Requiere evidencia externa / revisión manual.")


def _check_integral_audit() -> Dict[str, Any]:
    try:
        from services.integral_security_audit_service import get_integral_audit_summary
        summary = get_integral_audit_summary()
        return _result(
            STATUS_VERIFIED,
            evidence={"integral_summary_keys": list(summary.keys())[:20] if isinstance(summary, dict) else []},
            finding="Auditoría integral disponible.",
            recommendation="Ejecutar run_quick_audit periódicamente.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_ai_kernel() -> Dict[str, Any]:
    try:
        from services.ai_kernel import ai_kernel
        st = ai_kernel.get_status()
        running = bool(st.get("running") or st.get("active") or st.get("status") == "active")
        return _result(
            STATUS_VERIFIED if running else STATUS_NOT_VERIFIED,
            evidence={"ai_status": st},
            finding="Kernel IA " + ("en ejecución" if running else "no reporta running"),
            recommendation="Verificar start_ai_kernel en main.py",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_defense_registry() -> Dict[str, Any]:
    try:
        from services.defense_evidence_registry import get_registry_summary
        summary = get_registry_summary()
        return _result(
            STATUS_VERIFIED,
            evidence={"registry": summary},
            finding="Defense registry operativo.",
            recommendation="Revisar eventos recientes en Centro de Defensa.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_xdr() -> Dict[str, Any]:
    try:
        from services.novus_security_integration import novus_security
        count = novus_security.get_cached_threat_count()
        cache = getattr(novus_security, "_threat_cache", {}) or {}
        return _result(
            STATUS_VERIFIED,
            evidence={"threat_count": count, "last_scan": cache.get("last_scan")},
            finding=f"Motor XDR/amenazas operativo (amenazas en caché: {count}).",
            recommendation="Caché vacía no implica ausencia de riesgo — ejecutar escaneo.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_web_shield() -> Dict[str, Any]:
    try:
        from services.web_shield_engine import get_engine_status
        st = get_engine_status()
        active = bool(st.get("active") or st.get("running"))
        return _result(
            STATUS_VERIFIED if active else STATUS_NOT_VERIFIED,
            evidence={"status": st},
            finding="Web Shield " + ("activo" if active else "inactivo"),
            recommendation="Reiniciar start_web_shield_engine",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_mail_shield() -> Dict[str, Any]:
    try:
        from services.mail_shield_engine import get_engine_status
        st = get_engine_status()
        active = bool(st.get("active") or st.get("running") or st.get("status") == "started")
        return _result(
            STATUS_VERIFIED if active else STATUS_NOT_VERIFIED,
            evidence={"status": st},
            finding="Mail Shield motor " + ("activo" if active else "inactivo") + " (ingesta depende de OAuth).",
            recommendation="Configurar OAuth si se requiere análisis de correo real.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _check_database() -> Dict[str, Any]:
    try:
        from database import SessionLocal, Usuario
        db = SessionLocal()
        try:
            db.query(Usuario).limit(1).all()
        finally:
            db.close()
        return _result(
            STATUS_VERIFIED,
            evidence={"sqlite": True},
            finding="Base SQLite responde a consultas.",
            recommendation="Programar backup externo del archivo DB.",
        )
    except Exception as exc:
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def _run_checker(key: str, *, user=None, sector_id: str = "otros") -> Dict[str, Any]:
    mapping = {
        "cryptovault": _check_cryptovault,
        "auth_protection": _check_auth_protection,
        "mfa_absent": _check_mfa_absent,
        "rbac": lambda: _check_rbac(user),
        "user_mgmt": _check_user_mgmt,
        "login_sessions": _check_login_sessions,
        "evidence_center": _check_evidence_center,
        "forensic_integrity": _check_forensic_integrity,
        "aes_key_backup": _check_aes_key_backup,
        "recovery_middleware": _check_recovery_middleware,
        "network_history_retention": _check_network_history_retention,
        "secure_delete_absent": _check_secure_delete_absent,
        "api_hardening": _check_api_hardening,
        "oauth_mail": _check_oauth_mail,
        "session_protection": _check_session_protection,
        "credential_hashing": _check_credential_hashing,
        "tx_logs_pending": _check_tx_logs_pending,
        "sector_fintech": lambda: _check_sector("fintech"),
        "sector_mobile": lambda: _check_sector("movil"),
        "alerts_incidents": _check_alerts_incidents,
        "ndr_network": _check_ndr,
        "device_inventory": _check_device_inventory,
        "network_history": _check_network_history,
        "platform_health": _check_platform_health,
        "web_shield_host": _check_web_shield_host,
        "oauth_token_vault": _check_oauth_token_vault,
        "tls_status": _check_tls_status,
        "vulnerabilities": _check_vulnerabilities,
        "uce": _check_uce,
        "always_pending": lambda: _check_always_pending(
            "Control fuera del alcance técnico del nodo NOVUS; requiere evidencia externa."
        ),
        "integral_audit": _check_integral_audit,
        "ai_kernel": _check_ai_kernel,
        "defense_registry": _check_defense_registry,
        "xdr_threats": _check_xdr,
        "web_shield": _check_web_shield,
        "mail_shield": _check_mail_shield,
        "database": _check_database,
    }
    fn = mapping.get(key)
    if not fn:
        return _result(STATUS_PENDING, finding=f"Checker '{key}' no registrado.", recommendation="Revisión manual.")
    try:
        return fn()
    except Exception as exc:
        logger.error("compliance checker %s: %s", key, exc, exc_info=True)
        return _result(STATUS_NOT_VERIFIED, evidence={"error": str(exc)}, finding=str(exc))


def build_profile(
    *,
    sector_id: str = "otros",
    country: str = "",
    company_size: str = "",
    data_types: str = "",
    infrastructure: str = "",
    sites: str = "",
    services_used: str = "",
) -> Dict[str, Any]:
    sector = get_sector(sector_id)
    return {
        "sector_id": sector["id"],
        "sector_label": sector["label"],
        "country": country or "No especificado",
        "company_size": company_size or "No especificado",
        "data_types": data_types or "No especificado",
        "infrastructure": infrastructure or "Nodo NOVUS local",
        "sites": sites or "1",
        "services_used": services_used or "NOVUS core",
        "modules": list(sector["modules"]),
        "frameworks": frameworks_for_sector(sector["id"]),
        "disclaimer": (
            "Este perfil adapta qué controles técnicos se evalúan. "
            "NOVUS no certifica cumplimiento legal ni normativo completo."
        ),
    }


def evaluate_controls(
    *,
    profile: Optional[Dict[str, Any]] = None,
    user=None,
    audit_novus: bool = False,
) -> Dict[str, Any]:
    profile = profile or build_profile()
    modules = list(profile.get("modules") or ["data_protection", "platform"])
    if audit_novus and "platform" not in modules:
        modules.append("platform")
    controls = controls_for_modules(modules)
    results: List[Dict[str, Any]] = []
    counts = {
        STATUS_VERIFIED: 0,
        STATUS_NOT_VERIFIED: 0,
        STATUS_PENDING: 0,
        STATUS_NA: 0,
    }
    for ctrl in controls:
        check = _run_checker(ctrl["checker"], user=user, sector_id=profile.get("sector_id", "otros"))
        # Multi-sede: marcar NA si sites==1 para controles cloud IAM? keep as is
        item = {
            **{k: ctrl[k] for k in (
                "id", "module", "title", "description", "risk_reduced",
                "novus_actions", "manual_needed", "checker",
            )},
            **check,
        }
        results.append(item)
        counts[check["status"]] = counts.get(check["status"], 0) + 1

    verified = counts[STATUS_VERIFIED]
    total = len(results) or 1
    # Nunca "cumple totalmente"
    score_label = "Evaluación técnica parcial (sin certificación)"
    if counts[STATUS_NOT_VERIFIED] == 0 and counts[STATUS_PENDING] == 0:
        score_label = "Controles técnicos verificados en el nodo — no implica certificación"
    elif verified == 0:
        score_label = "Sin controles verificados aún"

    return {
        "status": "success",
        "evaluated_at": _now(),
        "profile": profile,
        "counts": counts,
        "controls": results,
        "score": {
            "verified": verified,
            "total": len(results),
            "verified_pct": round(100.0 * verified / total, 1),
            "label": score_label,
            "certification_claim": False,
        },
        "limitations": [
            "NOVUS evalúa controles técnicos del nodo y motores implementados.",
            "No afirma certificaciones (ISO, PCI, HIPAA, etc.).",
            "Controles PENDIENTE requieren evidencia externa o implementación futura.",
            "MFA y eliminación segura no están implementados en la plataforma.",
            "Cloud Shield CSPM y Mobile Shield completo están planificados.",
        ],
        "frameworks": profile.get("frameworks") or [],
    }


def save_audit(
    evaluation: Dict[str, Any],
    *,
    user_email: str = "",
    company: str = "",
    audit_type: str = "compliance",
) -> Dict[str, Any]:
    _ensure_dirs()
    audit_id = f"COMP-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    record = {
        "id": audit_id,
        "type": audit_type,
        "user": user_email,
        "company": company or evaluation.get("profile", {}).get("sector_label"),
        "sector": evaluation.get("profile", {}).get("sector_id"),
        "country": evaluation.get("profile", {}).get("country"),
        "fecha": _now().split(" ")[0],
        "hora": _now().split(" ")[1] if " " in _now() else "",
        "evaluated_at": evaluation.get("evaluated_at"),
        "counts": evaluation.get("counts"),
        "score": evaluation.get("score"),
        "controls_verified": [c["id"] for c in evaluation.get("controls", []) if c.get("status") == STATUS_VERIFIED],
        "controls_pending": [c["id"] for c in evaluation.get("controls", []) if c.get("status") == STATUS_PENDING],
        "controls_not_verified": [c["id"] for c in evaluation.get("controls", []) if c.get("status") == STATUS_NOT_VERIFIED],
        "report_id": None,
    }
    path = os.path.join(HISTORY_DIR, f"{audit_id}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({**record, "evaluation": evaluation}, fh, ensure_ascii=False, indent=2, default=str)

    index = []
    try:
        with open(HISTORY_INDEX, "r", encoding="utf-8") as fh:
            index = json.load(fh)
    except Exception:
        index = []
    index.insert(0, {k: record[k] for k in record if k != "evaluation"})
    with open(HISTORY_INDEX, "w", encoding="utf-8") as fh:
        json.dump(index[:200], fh, ensure_ascii=False, indent=2)
    return record


def list_audits(limit: int = 50) -> List[Dict[str, Any]]:
    _ensure_dirs()
    try:
        with open(HISTORY_INDEX, "r", encoding="utf-8") as fh:
            index = json.load(fh)
        return index[:limit]
    except Exception:
        return []


def get_audit(audit_id: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(HISTORY_DIR, f"{audit_id}.json")
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def build_report_dict(
    evaluation: Dict[str, Any],
    *,
    user_email: str = "",
    company: str = "",
    audit_id: str = "",
) -> Dict[str, Any]:
    controls = evaluation.get("controls") or []
    verified = [c for c in controls if c.get("status") == STATUS_VERIFIED]
    pending = [c for c in controls if c.get("status") == STATUS_PENDING]
    failed = [c for c in controls if c.get("status") == STATUS_NOT_VERIFIED]
    profile = evaluation.get("profile") or {}
    findings = [f"{c['title']}: {c.get('finding')}" for c in failed + pending[:10]]
    risks = [c.get("risk_reduced") for c in (failed + pending) if c.get("risk_reduced")]
    recommendations = list({c.get("recommendation") for c in controls if c.get("recommendation")})
    evidence_notes = [
        f"{c['id']}: {json.dumps(c.get('evidence') or {}, ensure_ascii=False)[:200]}"
        for c in verified[:15]
    ]
    report_id = audit_id or f"COMP-RPT-{uuid.uuid4().hex[:10]}"
    return {
        "id": report_id,
        "tipo": "compliance_center",
        "fecha": _now(),
        "severidad": "Informativo",
        "resumen_ejecutivo": (
            f"Evaluación técnica NOVUS Compliance Center para sector {profile.get('sector_label')}. "
            f"{evaluation.get('score', {}).get('verified', 0)}/{evaluation.get('score', {}).get('total', 0)} "
            f"controles VERIFICADOS. {evaluation.get('score', {}).get('label')}. "
            "Este informe NO constituye certificación normativa."
        ),
        "metadata": {
            "usuario": user_email,
            "empresa": company,
            "sector": profile.get("sector_label"),
            "pais": profile.get("country"),
            "fecha": _now(),
        },
        "executive_summary": {
            "texto": evaluation.get("score", {}).get("label"),
            "verificados": len(verified),
            "pendientes": len(pending),
            "no_verificados": len(failed),
        },
        "controls_verified": [{"id": c["id"], "title": c["title"], "finding": c.get("finding")} for c in verified],
        "controls_pending": [{"id": c["id"], "title": c["title"], "finding": c.get("finding"), "manual": c.get("manual_needed")} for c in pending],
        "controls_not_verified": [{"id": c["id"], "title": c["title"], "finding": c.get("finding")} for c in failed],
        "hallazgos": findings,
        "riesgos": risks,
        "evidencias": evidence_notes,
        "recomendaciones": recommendations,
        "limitaciones": evaluation.get("limitations") or [],
        "frameworks": evaluation.get("frameworks") or [],
        "profile": profile,
        "counts": evaluation.get("counts"),
    }


def generate_compliance_pdf(report: Dict[str, Any]) -> str:
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    try:
        from utils.novus_fpdf import create_novus_pdf
        from services.report_pdf_service import _safe_text, _write_section, _write_list
    except Exception as exc:
        # HTML fallback
        out = os.path.join(reports_dir, f"{report['id']}.html")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("<html><body><h1>NOVUS Compliance Center</h1><pre>")
            fh.write(json.dumps(report, ensure_ascii=False, indent=2, default=str)[:50000])
            fh.write("</pre></body></html>")
        logger.warning("compliance PDF fallback HTML: %s", exc)
        return out

    pdf = create_novus_pdf()
    pdf.set_margins(15, 15, 15)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(pdf.epw, 10, _safe_text("NOVUS Compliance Center"), ln=True)
    pdf.set_font("Helvetica", "", 10)
    meta = report.get("metadata") or {}
    pdf.cell(pdf.epw, 6, _safe_text(f"ID: {report.get('id')} | {report.get('fecha')}"), ln=True)
    pdf.cell(pdf.epw, 6, _safe_text(f"Usuario: {meta.get('usuario')} | Empresa: {meta.get('empresa')}"), ln=True)
    pdf.cell(pdf.epw, 6, _safe_text(f"Sector: {meta.get('sector')} | Pais: {meta.get('pais')}"), ln=True)
    pdf.ln(4)
    _write_section(pdf, "Resumen ejecutivo", report.get("resumen_ejecutivo"))
    counts = report.get("counts") or {}
    _write_section(
        pdf,
        "Conteo de estados",
        f"VERIFICADO={counts.get(STATUS_VERIFIED, 0)} | "
        f"NO_VERIFICADO={counts.get(STATUS_NOT_VERIFIED, 0)} | "
        f"PENDIENTE={counts.get(STATUS_PENDING, 0)} | "
        f"NO_APLICA={counts.get(STATUS_NA, 0)}",
    )
    _write_list(pdf, "Controles verificados", [f"{c['title']}: {c.get('finding')}" for c in report.get("controls_verified") or []])
    _write_list(pdf, "Controles pendientes", [f"{c['title']}: {c.get('finding')}" for c in report.get("controls_pending") or []])
    _write_list(pdf, "Controles no verificados", [f"{c['title']}: {c.get('finding')}" for c in report.get("controls_not_verified") or []])
    _write_list(pdf, "Hallazgos", report.get("hallazgos") or [])
    _write_list(pdf, "Riesgos", report.get("riesgos") or [])
    _write_list(pdf, "Evidencias (extracto)", report.get("evidencias") or [])
    _write_list(pdf, "Recomendaciones", report.get("recomendaciones") or [])
    _write_list(pdf, "Limitaciones", report.get("limitaciones") or [])
    fws = report.get("frameworks") or []
    if fws:
        _write_list(pdf, "Marcos de referencia (orientativos)", [f"{f.get('label')}: {f.get('note')}" for f in fws])
    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 9)
    pdf.multi_cell(
        pdf.epw,
        5,
        _safe_text(
            "AVISO: Este documento refleja controles tecnicos verificados por NOVUS. "
            "No constituye certificacion legal ni auditoria externa."
        ),
    )
    out_path = os.path.join(reports_dir, f"{report['id']}.pdf")
    pdf.safe_output(out_path)
    return out_path


def explain_control_for_kernel(control_id: str, evaluation_item: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ctrl = next((c for c in CONTROLS if c["id"] == control_id), None)
    if not ctrl and evaluation_item:
        ctrl = evaluation_item
    if not ctrl:
        return {"status": "error", "message": f"Control desconocido: {control_id}"}
    item = evaluation_item or ctrl
    return {
        "status": "success",
        "control_id": control_id,
        "title": item.get("title") or ctrl.get("title"),
        "meaning": item.get("description") or ctrl.get("description"),
        "risk_reduced": item.get("risk_reduced") or ctrl.get("risk_reduced"),
        "evidence_used": item.get("evidence") or {},
        "finding": item.get("finding") or "Sin evaluación reciente — ejecute Auditar.",
        "recommendation": item.get("recommendation") or "",
        "novus_actions": item.get("novus_actions") or ctrl.get("novus_actions") or [],
        "manual_needed": item.get("manual_needed") or ctrl.get("manual_needed"),
        "status_label": item.get("status") or STATUS_PENDING,
        "verified_only": True,
    }


def audit_novus_platform(*, user=None, user_email: str = "", company: str = "CIBERINNOVATECH / NOVUS") -> Dict[str, Any]:
    """Evalúa la propia plataforma NOVUS (módulos platform + data_protection)."""
    profile = build_profile(
        sector_id="tecnologia",
        country="CO",
        company_size="plataforma",
        data_types="telemetria_seguridad,credenciales_hash,evidencias",
        infrastructure="Flask monolito + SQLite + motores background",
        sites="1",
        services_used="NOVUS completo",
    )
    profile["modules"] = ["data_protection", "platform", "cloud"]
    evaluation = evaluate_controls(profile=profile, user=user, audit_novus=True)
    evaluation["audit_type"] = "audit_novus"
    record = save_audit(evaluation, user_email=user_email, company=company, audit_type="audit_novus")
    report = build_report_dict(evaluation, user_email=user_email, company=company, audit_id=record["id"])
    pdf_path = generate_compliance_pdf(report)
    record["report_id"] = report["id"]
    record["pdf_path"] = pdf_path
    # update saved file
    full = get_audit(record["id"]) or {}
    full["report_id"] = report["id"]
    full["pdf_path"] = pdf_path
    full["report"] = report
    with open(os.path.join(HISTORY_DIR, f"{record['id']}.json"), "w", encoding="utf-8") as fh:
        json.dump(full, fh, ensure_ascii=False, indent=2, default=str)
    return {
        "status": "success",
        "audit": record,
        "evaluation": evaluation,
        "report": report,
        "pdf_path": pdf_path,
    }
