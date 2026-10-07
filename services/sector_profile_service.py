"""
Perfil de protección activo por sector — orquesta componentes existentes de NOVUS.
El sector del cliente (Usuario.sector) define escudos, kernel, playbooks y dashboard.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

from services.sector_shield_service import (
    SECTOR_ENGINE_ACTIONS,
    SECTOR_MOTORS,
    get_active_shield_status,
    normalize_sector,
    resolve_sector_for_user,
    update_sector_rules,
)

CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "security_config.json")

MVP_SECTORS = ("fintech", "logistica", "aplicaciones_moviles", "otros")

# Componentes existentes y su estado de conexión por sector (para auditoría)
COMPONENT_CATALOG = {
    "sector_shield_api": {"module": "api/system.py", "connected": True},
    "security_engine_profile": {"module": "security_engine.py", "connected": True},
    "cryptovault": {"module": "novus_security_integration", "connected": True},
    "kernel_sector_shield_cap": {"module": "ai_capability_registry", "connected": True},
    "playbooks_db": {"module": "playbook_service.py", "connected": True},
    "dashboard_shield_widget": {"module": "templates/index.html", "connected": True},
    "topology": {"module": "routes/main.py /topology", "connected": True},
    "inteligencia": {"module": "api/threat_intel.py", "connected": True},
    "reports": {"module": "security_report_service", "connected": True},
    "bec_shield_motor": {"module": "security_engine", "connected": True, "sectors": ["fintech"]},
    "iot_guard_motor": {"module": "security_engine", "connected": True, "sectors": ["logistica"]},
    "ui_shield_motor": {"module": "security_engine", "connected": True, "sectors": ["aplicaciones_moviles"]},
    "ato_analyzer": {"module": "security_engine", "connected": True, "sectors": ["fintech"]},
    "phishing_shield": {"module": "security_engine", "connected": True, "sectors": ["fintech"]},
    "api_shield": {"module": "security_engine", "connected": True, "sectors": ["fintech"]},
    "mitm_shield": {"module": "security_engine", "connected": True, "sectors": ["logistica"]},
    "network_scanner": {"module": "network_scanner", "connected": True, "sectors": ["logistica", "otros"]},
    "sim_identity": {"module": "security_engine", "connected": True, "sectors": ["aplicaciones_moviles"]},
    "runtime_integrity": {"module": "security_engine", "connected": True, "sectors": ["aplicaciones_moviles"]},
    "sector_telemetry_binding": {"module": "security_engine.build_sector_protection", "connected": True},
    "sector_playbooks_full": {"module": "playbook_service", "connected": "partial"},
    "kernel_sector_memory": {"module": "kernel_memory", "connected": True},
    "uce_engine": {"module": "universal_compatibility_engine", "connected": True},
    "aspe_engine": {"module": "adaptive_sector_protection_engine", "connected": True},
}

SECTOR_PROFILES: Dict[str, Dict[str, Any]] = {
    "fintech": {
        "label": "Fintech",
        "display_sector": "Fintech",
        "shield_action": SECTOR_ENGINE_ACTIONS.get("fintech"),
        "motors": SECTOR_MOTORS["fintech"],
        "controls": ["Fraude BEC", "Integridad de pagos", "Validación cuenta destino"],
        "crypto_models": ["AES-256-GCM (CryptoVault)", "ECC X25519 (identidad)"],
        "kernel_capabilities": [
            "security.sector_shield", "security.threats", "security.vulnerabilities",
            "advanced_detector.malware", "reports.manager", "playbooks.manager",
        ],
        "kernel_priorities": ["fraude BEC", "ATO", "phishing", "transacciones", "API"],
        "kernel_intents_boost": ["enterprise_security", "vulnerabilities", "malware"],
        "playbook_ids": ["PB-SECTOR-FINTECH"],
        "dashboard_focus": ["Transacciones", "Fraude BEC", "CryptoVault", "Amenazas XDR"],
        "dashboard_kpi_emphasis": ["amenazas", "vault", "vulnerabilidades"],
        "modules_active": [
            "dashboard", "xdr", "vulnerabilidades", "reportes", "inteligencia",
            "topology", "network", "incidentes", "playbooks",
        ],
        "validations": ["validate_transactional_integrity", "analyze_ato_risk", "inspect_email_integrity", "validate_api_request"],
        "detections": ["BEC", "ATO", "Phishing", "API abuse"],
        "recommendations_style": "Cumplimiento PCI-DSS, monitoreo transaccional y fraude en tiempo real.",
    },
    "logistica": {
        "label": "Logística",
        "display_sector": "Logística",
        "shield_action": SECTOR_ENGINE_ACTIONS.get("logistica"),
        "motors": SECTOR_MOTORS["logistica"],
        "controls": ["Integridad IoT", "GPS spoofing", "Autenticación telemetría"],
        "crypto_models": ["AES-256-GCM (CryptoVault)", "ECC X25519 (identidad)"],
        "kernel_capabilities": [
            "security.sector_shield", "network.scanner", "network.radar",
            "topology.view", "security.threats", "security.vulnerabilities",
            "reports.manager", "playbooks.manager",
        ],
        "kernel_priorities": ["IoT", "cadena de suministro", "topología", "telemetría", "MITM"],
        "kernel_intents_boost": ["network_status", "enterprise_security"],
        "playbook_ids": ["PB-SECTOR-LOGISTICA"],
        "dashboard_focus": ["Topología de red", "Dispositivos IoT", "Trazabilidad", "Amenazas"],
        "dashboard_kpi_emphasis": ["nodos", "network", "amenazas"],
        "modules_active": [
            "dashboard", "network", "topology", "xdr", "vulnerabilidades",
            "reportes", "inteligencia", "incidentes", "playbooks",
        ],
        "validations": ["validate_iot_telemetry", "verify_tunnel_integrity"],
        "detections": ["IoT anomaly", "GPS spoofing", "MITM", "Network pivot"],
        "recommendations_style": "Protección de flota, telemetría IoT y cadena de suministro.",
    },
    "aplicaciones_moviles": {
        "label": "Aplicaciones móviles",
        "display_sector": "Aplicaciones móviles",
        "shield_action": SECTOR_ENGINE_ACTIONS.get("aplicaciones_moviles"),
        "motors": SECTOR_MOTORS["aplicaciones_moviles"],
        "controls": ["Anti-clickjacking", "Integridad interfaz", "Protección sesión"],
        "crypto_models": ["AES-256-GCM (CryptoVault)", "ECC X25519 (identidad)"],
        "kernel_capabilities": [
            "security.sector_shield", "security.vulnerabilities", "security.threats",
            "advanced_detector.processes", "endpoints.live", "reports.manager",
            "playbooks.manager",
        ],
        "kernel_priorities": ["overlay UI", "SIM swap", "runtime", "sesión móvil", "API"],
        "kernel_intents_boost": ["vulnerabilities", "processes", "enterprise_security"],
        "playbook_ids": ["PB-SECTOR-MOVIL"],
        "dashboard_focus": ["Integridad runtime", "UI Shield", "Endpoints", "Vulnerabilidades"],
        "dashboard_kpi_emphasis": ["endpoints", "vulnerabilidades", "amenazas"],
        "modules_active": [
            "dashboard", "endpoints", "xdr", "vulnerabilidades", "reportes",
            "inteligencia", "incidentes", "playbooks",
        ],
        "validations": ["detect_overlay_threat", "validate_ui_interaction", "verify_sim_and_identity", "verify_runtime_integrity"],
        "detections": ["Overlay", "Clickjacking", "SIM swap", "Runtime tampering"],
        "recommendations_style": "Seguridad de apps móviles, SDK y protección de sesión en dispositivo.",
    },
    "otros": {
        "label": "Otros",
        "display_sector": "Otros",
        "shield_action": None,
        "motors": [
            "Runtime Hardening",
            "Monitoreo de integridad",
            "CryptoVault AES-256-GCM",
            "Advanced Process Detector",
        ],
        "controls": ["Hardening runtime", "Monitoreo integridad", "Aislamiento sesión"],
        "crypto_models": ["AES-256-GCM (CryptoVault)", "Hash credenciales (werkzeug)"],
        "kernel_capabilities": [
            "security.sector_shield", "security.threats", "security.vulnerabilities",
            "system.metrics", "incidents.manager", "reports.manager", "playbooks.manager",
        ],
        "kernel_priorities": ["postura general", "procesos", "vulnerabilidades", "incidentes"],
        "kernel_intents_boost": ["general_status", "enterprise_security"],
        "playbook_ids": ["PB-SECTOR-OTROS"],
        "dashboard_focus": ["Postura general", "Incidentes", "Vulnerabilidades", "Sistema"],
        "dashboard_kpi_emphasis": ["cpu", "ram", "amenazas", "vulnerabilidades"],
        "modules_active": [
            "dashboard", "xdr", "vulnerabilidades", "reportes", "inteligencia",
            "network", "incidentes", "playbooks",
        ],
        "validations": ["monitor_filesystem_activity", "verify_runtime_integrity"],
        "detections": ["Procesos sospechosos", "Puertos expuestos", "Hallazgos genéricos"],
        "recommendations_style": "Hardening corporativo base y monitoreo continuo.",
    },
}

SECTOR_PLAYBOOK_DEFS = {
    "PB-SECTOR-FINTECH": {
        "nombre": "SOC Fintech — Escudo y fraude",
        "trigger": "manual",
        "accion": "sector_shield_scan",
        "prioridad": "Alta",
        "reglas_asociadas": ["sector:fintech", "bec", "ato", "phishing", "pipeline:sector_full"],
        "kernel_respuestas": [
            "security.sector_shield", "security.threats", "gmail.analyzer",
            "security.vulnerabilities", "threat_intelligence.center", "reports.manager",
        ],
        "automatizaciones_asociadas": ["PB-ORCH-CLOSE"],
    },
    "PB-SECTOR-LOGISTICA": {
        "nombre": "SOC Logística — IoT y topología",
        "trigger": "manual",
        "accion": "sector_shield_scan",
        "prioridad": "Alta",
        "reglas_asociadas": ["sector:logistica", "iot", "network", "mitm", "pipeline:traffic_anomaly"],
        "kernel_respuestas": [
            "network.radar", "network.ndr", "topology.view",
            "security.threats", "security.vulnerabilities", "threat_intelligence.center",
        ],
        "automatizaciones_asociadas": ["PB-ORCH-CLOSE"],
    },
    "PB-SECTOR-MOVIL": {
        "nombre": "SOC Apps Móviles — UI y runtime",
        "trigger": "manual",
        "accion": "sector_shield_scan",
        "prioridad": "Alta",
        "reglas_asociadas": ["sector:aplicaciones_moviles", "ui", "sim", "runtime", "pipeline:sector_full"],
        "kernel_respuestas": [
            "security.sector_shield", "security.threats", "security.vault",
            "threat_intelligence.center", "reports.manager",
        ],
        "automatizaciones_asociadas": ["PB-ORCH-CLOSE"],
    },
    "PB-SECTOR-OTROS": {
        "nombre": "SOC Corporativo — Postura base",
        "trigger": "manual",
        "accion": "sector_shield_scan",
        "prioridad": "Media",
        "reglas_asociadas": ["sector:otros", "hardening", "incidentes", "pipeline:platform_close"],
        "kernel_respuestas": [
            "security.threats", "security.vulnerabilities", "system.metrics",
            "threat_intelligence.center", "reports.manager",
        ],
        "automatizaciones_asociadas": ["PB-ORCH-CLOSE"],
    },
}


def get_sector_profile(sector_key: Optional[str] = None) -> Dict[str, Any]:
    key = normalize_sector(sector_key)
    profile = dict(SECTOR_PROFILES.get(key, SECTOR_PROFILES["otros"]))
    profile["sector_key"] = key
    return profile


def get_kernel_context_for_user(email: Optional[str] = None) -> Dict[str, Any]:
    sector_key = resolve_sector_for_user(email)
    profile = get_sector_profile(sector_key)
    shield = get_active_shield_status(email)
    return {
        "sector_key": sector_key,
        "sector_label": profile["label"],
        "sector_profile": profile,
        "shield_status": shield.get("shield_status"),
        "protections_enabled": shield.get("protections_enabled") or [],
        "motors": shield.get("motors") or profile["motors"],
        "kernel_priorities": profile["kernel_priorities"],
        "kernel_capabilities_hint": profile["kernel_capabilities"],
        "recommendations_style": profile["recommendations_style"],
    }


def _save_user_profile_state(email: str, sector_key: str, profile: Dict[str, Any]):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    data: Dict[str, Any] = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            data = {}
    profiles = data.get("user_sector_profiles") or {}
    profiles[email] = {
        "sector_key": sector_key,
        "label": profile.get("label"),
        "applied_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "modules_active": profile.get("modules_active"),
    }
    data["user_sector_profiles"] = profiles
    data["sector_activo"] = sector_key
    with open(CONFIG_FILE, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def _ensure_sector_playbooks(sector_key: str):
    from services.playbook_service import create_playbook, get_playbook

    profile = get_sector_profile(sector_key)
    for pb_id in profile.get("playbook_ids") or []:
        if get_playbook(pb_id):
            from services.playbook_service import update_playbook
            spec = SECTOR_PLAYBOOK_DEFS.get(pb_id)
            if spec:
                update_playbook(pb_id, spec)
            continue
        spec = SECTOR_PLAYBOOK_DEFS.get(pb_id)
        if not spec:
            continue
        try:
            create_playbook({"id": pb_id, **spec})
            logger.info("Playbook sectorial creado: %s", pb_id)
        except Exception as exc:
            logger.debug("Playbook sector %s: %s", pb_id, exc)


def apply_sector_profile_for_user(email: Optional[str] = None) -> Dict[str, Any]:
    """Activa el perfil de protección del sector del cliente (login / cambio de sector)."""
    if not email:
        return {"status": "error", "message": "Email requerido"}

    sector_key = resolve_sector_for_user(email)
    profile = get_sector_profile(sector_key)

    try:
        from database import SessionLocal, Usuario
        db = SessionLocal()
        try:
            usuario = db.query(Usuario).filter(Usuario.email == email.strip().lower()).first()
            if usuario and usuario.sector:
                raw = usuario.sector
                if normalize_sector(raw) != normalize_sector(raw.split("|")[0] if "|" in raw else raw):
                    pass
        finally:
            db.close()
    except Exception as exc:
        logger.debug("Sector profile user sync: %s", exc)

    rules = update_sector_rules(email)
    _ensure_sector_playbooks(sector_key)
    _save_user_profile_state(email, sector_key, profile)

    try:
        from services.kernel_memory import _load_profile, _save_profile, _user_key
        from database import SessionLocal, Usuario
        db = SessionLocal()
        try:
            u = db.query(Usuario).filter(Usuario.email == email.strip().lower()).first()
            uid = u.id if u else None
        finally:
            db.close()
        mem_key = _user_key(uid, email)
        prefs = _load_profile(mem_key)
        prefs["sector_key"] = sector_key
        prefs["sector_label"] = profile["label"]
        _save_profile(mem_key, prefs)
    except Exception as exc:
        logger.debug("Kernel memory sector sync: %s", exc)

    shield = get_active_shield_status(email)

    uce_result = None
    aspe_result = None
    try:
        from services.universal_compatibility_engine import uce
        from services.adaptive_sector_protection_engine import aspe
        uce_result = uce.get_infrastructure_panel(email)
        aspe_result = aspe.initialize_sector_protection(email)
    except Exception as exc:
        logger.debug("UCE/ASPE sector profile sync: %s", exc)

    return {
        "status": "success",
        "email": email,
        "sector_key": sector_key,
        "sector_label": profile["label"],
        "profile": profile,
        "shield": shield,
        "rules_updated": rules.get("updated_at"),
        "applied_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uce": uce_result,
        "aspe": aspe_result,
    }


def apply_sector_to_plan(plan, sector_key: Optional[str] = None) -> None:
    """Prioriza capacidades del Kernel según el perfil sectorial activo."""
    if not sector_key or getattr(plan, "skip_engines", False):
        return
    profile = get_sector_profile(sector_key)
    priority = profile.get("kernel_capabilities") or []
    existing = list(getattr(plan, "capabilities", None) or [])
    plan.capabilities = list(dict.fromkeys(priority + existing))
    intent_id = getattr(plan, "intent_id", "")
    if intent_id in profile.get("kernel_intents_boost") or []:
        plan.rationale.append(
            f"Perfil {profile['label']}: prioridad en {', '.join(profile['kernel_priorities'][:3])}"
        )
    else:
        plan.rationale.append(f"Perfil sectorial activo: {profile['label']}")
    if "security.sector_shield" not in plan.capabilities:
        plan.capabilities.insert(0, "security.sector_shield")


def filter_playbooks_for_sector(playbooks: List[Dict[str, Any]], sector_key: str) -> List[Dict[str, Any]]:
    key = normalize_sector(sector_key)
    profile = get_sector_profile(key)
    allowed_ids = set(profile.get("playbook_ids") or [])
    filtered = []
    for pb in playbooks:
        pb_id = pb.get("id", "")
        rules = pb.get("reglas_asociadas") or []
        if pb_id in allowed_ids:
            filtered.append(pb)
            continue
        if any(f"sector:{key}" in str(r) for r in rules):
            filtered.append(pb)
            continue
        if pb.get("trigger") == "manual" and pb_id.startswith("PB-SECTOR-"):
            if key in pb_id.lower() or (key == "aplicaciones_moviles" and "MOVIL" in pb_id):
                filtered.append(pb)
    if not filtered:
        return [pb for pb in playbooks if pb.get("estado") == "Activo"]
    return filtered


def audit_sector_protection(sector_key: str, email: Optional[str] = None) -> Dict[str, Any]:
    """Auditoría técnica independiente por sector — solo componentes reales conectados."""
    key = normalize_sector(sector_key)
    profile = get_sector_profile(key)
    shield = get_active_shield_status(email) if email else get_active_shield_status()

    from services.playbook_service import list_playbooks
    all_pbs = list_playbooks(active_only=True)
    sector_pbs = filter_playbooks_for_sector(all_pbs, key)

    connected: List[Dict[str, Any]] = []
    partial: List[Dict[str, Any]] = []
    missing: List[Dict[str, Any]] = []

    for comp_id, meta in COMPONENT_CATALOG.items():
        sectors = meta.get("sectors")
        if sectors and key not in sectors and comp_id.endswith("_motor"):
            continue
        entry = {"id": comp_id, "module": meta.get("module"), "status": meta.get("connected")}
        if meta.get("connected") is True:
            connected.append(entry)
        elif meta.get("connected") == "partial":
            partial.append(entry)
        elif meta.get("connected") is False:
            missing.append(entry)

    motor_connected = sum(1 for m in profile["motors"] if m)
    motor_total = len(profile["motors"])
    validations_total = len(profile.get("validations") or [])
    validations_wired = validations_total if profile.get("shield_action") else max(1, validations_total - 2)

    checks = {
        "escudo_sectorial": bool(shield.get("sector_key") == key),
        "motores_asignados": motor_connected >= motor_total * 0.6,
        "cryptovault": bool(shield.get("vault_active")),
        "kernel_sector_cap": "security.sector_shield" in profile["kernel_capabilities"],
        "playbooks_sectoriales": len(sector_pbs) >= 1,
        "dashboard_widget": True,
        "topology_module": "topology" in profile["modules_active"],
        "inteligencia_module": "inteligencia" in profile["modules_active"],
        "reports_module": "reports" in profile["modules_active"] or "reportes" in profile["modules_active"],
        "scan_sector_engine": profile.get("shield_action") is not None or key == "otros",
    }
    passed = sum(1 for v in checks.values() if v)
    coverage_pct = round(passed / len(checks) * 100, 1)

    risks = []
    if not shield.get("vault_active"):
        risks.append("CryptoVault inactivo — cifrado limitado a hash de credenciales")
    if not profile.get("shield_action") and key != "otros":
        risks.append("Motor sectorial primario no mapeado en SECTOR_ENGINE_ACTIONS")
    if len(sector_pbs) < 1:
        risks.append("Sin playbooks sectoriales activos en BD")
    if any(m.get("id") == "sector_telemetry_binding" for m in missing):
        profile_resp = {}
        try:
            from services.novus_security_integration import novus_security
            profile_resp = novus_security.security_engine.build_sector_protection(key).get("response") or {}
        except Exception:
            profile_resp = {}
        if profile_resp.get("status") in ("NO_DATA", "unavailable", None):
            risks.append("Telemetría sectorial en build_sector_protection sin datos verificables")

    return {
        "sector_key": key,
        "sector_label": profile["label"],
        "coverage_pct": coverage_pct,
        "checks_passed": passed,
        "checks_total": len(checks),
        "checks": checks,
        "active_components": {
            "motors": profile["motors"],
            "controls": profile["controls"],
            "crypto_models": shield.get("crypto_models") or profile["crypto_models"],
            "validations": profile.get("validations"),
            "detections": profile.get("detections"),
            "modules": profile["modules_active"],
            "kernel_capabilities": profile["kernel_capabilities"],
            "kernel_priorities": profile["kernel_priorities"],
            "playbooks": [{"id": p["id"], "nombre": p["nombre"]} for p in sector_pbs],
        },
        "shield_status": {
            "name": shield.get("shield_name"),
            "status": shield.get("shield_status"),
            "protection_level": shield.get("protection_level"),
            "current_risk": shield.get("current_risk"),
        },
        "connected": connected,
        "partial": partial,
        "missing_or_disconnected": missing,
        "risks_detected": risks,
        "recommendations": [
            profile["recommendations_style"],
            "Conectar telemetría real del sector para eliminar NO_DATA en perfiles.",
            "Completar playbooks automatizados por trigger sectorial.",
        ],
        "production_ready": coverage_pct >= 75 and len(risks) <= 2,
    }
