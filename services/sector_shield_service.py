"""
Escudo Sectorial NOVUS — orquesta motores existentes (security_engine, novus_security, CryptoVault).
"""
import json
import os
import unicodedata
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "security_config.json")

SECTOR_MOTORS: Dict[str, List[str]] = {
    "fintech": [
        "BEC Shield (validate_transactional_integrity)",
        "ATO Analyzer (analyze_ato_risk)",
        "Phishing Shield (inspect_email_integrity)",
        "CryptoVault AES-256-GCM",
        "API Shield (validate_api_request)",
    ],
    "logistica": [
        "IoT Guard (validate_iot_telemetry)",
        "Network Scanner",
        "MITM Shield (verify_tunnel_integrity)",
        "CryptoVault AES-256-GCM",
        "Advanced Process Detector",
    ],
    "aplicaciones_moviles": [
        "UI Shield (detect_overlay_threat)",
        "Clickjacking Guard (validate_ui_interaction)",
        "SIM Identity (verify_sim_and_identity)",
        "Runtime Integrity (verify_runtime_integrity)",
        "CryptoVault AES-256-GCM",
    ],
}

SECTOR_ENGINE_ACTIONS: Dict[str, str] = {
    "fintech": "bec_shield",
    "logistica": "iot_guard",
    "aplicaciones_moviles": "ui_shield",
}


def _deaccent(value: str) -> str:
    normalized = unicodedata.normalize("NFD", value or "")
    return "".join(c for c in normalized if unicodedata.category(c) != "Mn")


def normalize_sector(raw: Optional[str]) -> str:
    if not raw:
        return "otros"
    key = _deaccent(str(raw).lower().strip()).replace(" ", "_").replace("-", "_")
    aliases = {
        "aplicaciones_moviles": "aplicaciones_moviles",
        "aplicaciones_móviles": "aplicaciones_moviles",
        "movil": "aplicaciones_moviles",
        "móvil": "aplicaciones_moviles",
        "logistica_movil": "logistica",
        "logística": "logistica",
    }
    key = aliases.get(key, key)
    known = {
        "fintech", "logistica", "aplicaciones_moviles", "aplicaciones_digitales",
        "salud", "retail", "industrial", "gobierno", "educacion", "otros",
    }
    return key if key in known else "otros"


def resolve_sector_for_user(email: Optional[str] = None) -> str:
    sector = None
    if email:
        try:
            from database import SessionLocal, Usuario
            db = SessionLocal()
            try:
                user = db.query(Usuario).filter(Usuario.email == email).first()
                if user and user.sector:
                    sector = user.sector
            finally:
                db.close()
        except Exception as exc:
            logger.debug(f"Sector user lookup: {exc}")

    if not sector:
        try:
            from services.config_service import load_config
            sector = load_config().get("sector_activo")
        except Exception:
            pass

    return normalize_sector(sector)


def _load_config_extra() -> Dict[str, Any]:
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data.get("sector_shield_state") or {}
    except Exception:
        return {}


def _save_shield_state(sector: str, patch: Dict[str, Any]):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    data = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            data = {}
    state = data.get("sector_shield_state") or {}
    state.update({"sector": sector, **patch})
    data["sector_shield_state"] = state
    with open(CONFIG_FILE, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def _compute_status(threat_count: int, vuln_count: int, critical_vulns: int) -> str:
    if threat_count > 5 or critical_vulns > 0:
        return "Atención requerida"
    if threat_count > 0 or vuln_count > 8:
        return "Analizando"
    if threat_count == 0 and vuln_count == 0:
        return "Activo"
    return "Protegiendo"


def _compute_risk(threat_count: int, vuln_count: int) -> str:
    if threat_count > 5 or vuln_count > 15:
        return "Alto"
    if threat_count > 0 or vuln_count > 5:
        return "Medio"
    return "Bajo"


def _compute_protection_level(threat_count: int, vault_active: bool) -> str:
    if vault_active and threat_count == 0:
        return "Alta"
    if vault_active and threat_count < 3:
        return "Media"
    return "Baja"


def get_active_shield_status(email: Optional[str] = None) -> Dict[str, Any]:
    """Estado del escudo sectorial — solo lectura de caché (sin escaneos síncronos)."""
    from services.performance_cache import get_or_compute
    from core.config import Config

    return get_or_compute(
        f"shield_status:{email or '_'}",
        Config.PANEL_CACHE_TTL,
        lambda: _build_active_shield_status(email),
    )


def _build_active_shield_status(email: Optional[str] = None) -> Dict[str, Any]:
    from services.novus_security_integration import novus_security

    sector_key = resolve_sector_for_user(email)
    profile = novus_security.security_engine.build_sector_protection(sector_key)
    extra = _load_config_extra()

    threats_data = dict(novus_security._threat_cache or {})
    cache = threats_data
    last_threat_scan = cache.get("last_scan")
    vuln_audit = (cache.get("vulnerabilities_audit") or {}).get("timestamp")
    vulns = novus_security.get_cached_vulnerabilities() if vuln_audit else []
    vulns = vulns or []
    threats_data = cache if last_threat_scan else {}
    suspicious = threats_data.get("suspicious_processes") or []
    threat_count = len(suspicious) if last_threat_scan else None

    critical_vulns = sum(
        1 for v in vulns
        if str(v.get("riesgo", "")).upper() in ("CRITICO", "CRITICAL", "ALTA", "HIGH", "DETECTADO")
        or str(v.get("severidad", "")).lower() in ("crítica", "critica", "alta", "high")
    ) if vuln_audit else 0

    vault = novus_security.vault
    vault_active = vault is not None and getattr(vault, "llave_aes", None) is not None

    last_analysis = last_threat_scan or vuln_audit or extra.get("last_analysis") or "Sin datos disponibles"
    status = _compute_status(threat_count or 0, len(vulns), critical_vulns) if last_threat_scan or vuln_audit else "Sin análisis disponible"

    crypto_models = []
    if vault_active:
        crypto_models = ["AES-256-GCM (CryptoVault)", "ECC X25519 (identidad)"]
    else:
        crypto_models = ["Sin CryptoVault activo"]

    motors_catalog = SECTOR_MOTORS.get(sector_key, [
        "Runtime Hardening",
        "Monitoreo de integridad",
        "CryptoVault" if vault_active else "Hash de credenciales (werkzeug)",
    ])
    try:
        from services.engine_runtime_registry import collect_engine_runtime_rows, RUNTIME_ACTIVE, RUNTIME_RUNNING

        runtime_rows = collect_engine_runtime_rows()
        active_n = sum(
            1 for r in runtime_rows
            if r.get("runtime_status") in (RUNTIME_ACTIVE, RUNTIME_RUNNING)
        )
        motors = [
            {"name": m, "runtime_status": "catalog"}
            if isinstance(m, str)
            else m
            for m in motors_catalog
        ]
        motors_runtime = {"active": active_n, "total": len(motors_catalog)}
    except Exception:
        motors = motors_catalog
        motors_runtime = {"active": None, "total": len(motors_catalog)}

    if last_threat_scan or vuln_audit:
        last_result = (
            f"{len(vulns)} hallazgos, "
            f"{threat_count if threat_count is not None else '—'} amenazas activas, "
            f"{critical_vulns} críticos"
        )
    else:
        last_result = "Sin análisis disponible"

    return {
        "status": "success",
        "sector_key": sector_key,
        "sector_raw": extra.get("sector_raw"),
        "shield_name": profile.get("profile_title", "Escudo Sectorial"),
        "shield_status": status,
        "last_analysis": last_analysis,
        "protections_enabled": profile.get("controls", []),
        "motors": motors,
        "motors_runtime": motors_runtime,
        "protection_level": _compute_protection_level(threat_count or 0, vault_active) if last_threat_scan else "Sin datos disponibles",
        "last_result": last_result,
        "current_risk": _compute_risk(threat_count or 0, len(vulns)) if last_threat_scan else "Sin datos disponibles",
        "vault_active": vault_active,
        "crypto_models": crypto_models,
        "metrics": {
            "vulnerabilities": len(vulns),
            "threats": threat_count,
            "critical_findings": critical_vulns,
            "open_ports": len(threats_data.get("open_ports") or []),
        },
        "profile": profile,
        "integration": {
            "dashboard": True,
            "kernel_ia": True,
            "reportes": True,
            "vulnerabilidades": True,
            "incidentes": True,
            "topology": True,
            "network": True,
        },
    }


def scan_sector(email: Optional[str] = None) -> Dict[str, Any]:
    from services.novus_security_integration import novus_security
    from services.network_scanner import network_scanner
    from services.performance_cache import invalidate

    invalidate(f"shield_status:{email or '_'}")
    sector_key = resolve_sector_for_user(email)
    steps = []

    try:
        network_scanner.scan_network()
        steps.append({"label": "Escaneo de red", "status": "done", "detail": "ARP/network refresh"})
    except Exception as exc:
        steps.append({"label": "Escaneo de red", "status": "warning", "detail": str(exc)})

    vulns = novus_security.scan_vulnerabilities()
    steps.append({"label": "Vulnerabilidades", "status": "done", "detail": f"{len(vulns)} hallazgos"})

    threats = novus_security.detect_threats_realtime()
    proc_count = len(threats.get("suspicious_processes") or [])
    steps.append({"label": "Motor de amenazas", "status": "done", "detail": f"{proc_count} procesos sospechosos"})

    sector_engine = SECTOR_ENGINE_ACTIONS.get(sector_key)
    top_finding = vulns[0] if vulns else None
    if sector_engine == "bec_shield":
        if top_finding:
            result = novus_security.security_engine.inspect_email_integrity(
                {"from": top_finding.get("ip", ""), "subject": top_finding.get("nombre", "")},
                str(top_finding.get("descripcion") or ""),
            )
            steps.append({"label": "BEC Shield", "status": "done", "detail": result.get("status", "analyzed")})
        else:
            result = novus_security.security_engine.get_security_summary()
            steps.append({"label": "BEC Shield", "status": "done", "detail": f"Registro: {result.get('total_threats_neutralized', 0)} eventos"})
    elif sector_engine == "iot_guard":
        nodes = network_scanner.get_cached_nodes()
        if top_finding:
            ev = top_finding.get("evidencia") or {}
            coord = ev.get("current_coord") or {}
            has_telemetry = bool(
                coord.get("lat") or coord.get("lon")
                or ev.get("engine_rpm") or ev.get("speed")
                or ev.get("is_signed_by_hardware")
            )
            if has_telemetry:
                iot = novus_security.security_engine.validate_iot_telemetry(
                    top_finding.get("ip") or "unknown",
                    {
                        "current_coord": coord or {"lat": 0, "lon": 0},
                        "engine_rpm": ev.get("engine_rpm", 0),
                        "speed": ev.get("speed", 0),
                        "is_signed_by_hardware": ev.get("is_signed_by_hardware", False),
                    },
                    {
                        "last_coord": ev.get("last_coord") or {"lat": 0, "lon": 0},
                        "last_time": ev.get("last_time") or __import__("time").time(),
                        "in_signal_zone": ev.get("in_signal_zone", False),
                    },
                )
                steps.append({"label": "IoT Guard", "status": "done", "detail": iot.get("status", f"{len(nodes)} nodos")})
            else:
                steps.append({
                    "label": "IoT Guard",
                    "status": "standby",
                    "detail": f"Sin telemetría IoT real — {len(nodes)} nodos en topología",
                })
        else:
            steps.append({"label": "IoT Guard", "status": "standby", "detail": f"{len(nodes)} nodos — telemetría pendiente"})
    elif sector_engine == "ui_shield":
        ui = novus_security.security_engine.detect_overlay_threat(
            {"foreign_overlay_active": bool((top_finding or {}).get("evidencia", {}).get("overlay_detected")),
             "evidence": (top_finding or {}).get("evidencia") or {}}
        )
        steps.append({"label": "UI Shield", "status": "done", "detail": ui.get("status", "UI_SAFE")})

    aspe_result = None
    if proc_count > 0 or vulns:
        try:
            from services.adaptive_sector_protection_engine import aspe
            incident_finding = top_finding or {
                "id": f"SECTOR-THREAT-{sector_key}",
                "tipo": "threat_scan",
                "motor": "sector_shield",
                "descripcion": f"{proc_count} procesos sospechosos en escaneo sectorial",
                "evidencia": {"processes": proc_count, "vulnerabilities": len(vulns)},
            }
            aspe_result = aspe.evaluate_incident(incident_finding, user_email=email, source="sector_shield_scan")
        except Exception as exc:
            logger.debug("ASPE sector scan: %s", exc)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _save_shield_state(sector_key, {"last_analysis": now, "last_scan_result": f"{len(vulns)} vulns / {proc_count} amenazas"})

    if novus_security.vault:
        try:
            from database import SessionLocal
            db = SessionLocal()
            try:
                novus_security.security_engine.register_threat_event(
                    db, novus_security.vault, f"SECTOR_SCAN_{sector_key.upper()}",
                    {"sector": sector_key, "vulnerabilities": len(vulns), "threats": proc_count},
                )
            finally:
                db.close()
        except Exception as exc:
            logger.debug(f"Sector scan log: {exc}")

    status = get_active_shield_status(email)
    return {
        "status": "success",
        "message": f"Escaneo sectorial completado para {status['shield_name']}",
        "steps": steps,
        "shield": status,
        "aspe": aspe_result,
    }


def analyze_sector_vulnerabilities(email: Optional[str] = None) -> Dict[str, Any]:
    from services.novus_security_integration import novus_security
    from services.security_report_service import auto_generate_for_findings

    sector_key = resolve_sector_for_user(email)
    findings = novus_security.scan_vulnerabilities()
    created = auto_generate_for_findings(findings)

    sector_keywords = {
        "fintech": ("pago", "transacc", "port", "443", "proc", "api"),
        "logistica": ("port", "iot", "gps", "network", "proc"),
        "aplicaciones_moviles": ("port", "ssl", "proc", "session", "ui"),
        "otros": ("proc", "port", "vuln", "servicio", "config"),
    }
    keywords = sector_keywords.get(sector_key, ("proc", "port", "vuln"))

    prioritized = []
    for item in findings:
        text = f"{item.get('nombre', '')} {item.get('descripcion', '')}".lower()
        score = sum(1 for kw in keywords if kw in text)
        prioritized.append({**item, "sector_relevance": score})

    prioritized.sort(key=lambda x: x.get("sector_relevance", 0), reverse=True)

    return {
        "status": "success",
        "message": f"Análisis sectorial: {len(findings)} hallazgos ({len(created)} informes nuevos)",
        "sector_key": sector_key,
        "findings": prioritized[:15],
        "reports_created": len(created),
        "recommendations": [
            "Revise hallazgos prioritarios en Vulnerabilidades.",
            "Ejecute remediación desde el panel del escudo o la vista de Vulnerabilidades.",
        ] if findings else ["Sin hallazgos en el escaneo actual."],
    }


def remediate_sector(email: Optional[str] = None) -> Dict[str, Any]:
    from services.novus_security_integration import novus_security
    from services.remediation_engine import remediate_vulnerability

    sector_key = resolve_sector_for_user(email)
    findings = novus_security.scan_vulnerabilities()
    if not findings:
        return {"status": "success", "message": "Sin hallazgos para remediar", "steps": []}

    target = findings[0]
    result = remediate_vulnerability(target.get("id"))
    return {
        "status": result.get("status", "success"),
        "message": result.get("message", f"Remediación ejecutada sobre {target.get('id')}"),
        "sector_key": sector_key,
        "target_id": target.get("id"),
        "steps": result.get("steps", []),
        "report_id": result.get("report_id"),
    }


def mitigate_sector(email: Optional[str] = None) -> Dict[str, Any]:
    from services.novus_security_integration import novus_security
    from services.remediation_engine import remediate_incident, remediate_vulnerability

    sector_key = resolve_sector_for_user(email)
    threats = novus_security.detect_threats_realtime()
    procs = threats.get("suspicious_processes") or []

    if procs:
        pid = procs[0].get("pid")
        result = remediate_incident(f"RT-PROC-{pid}")
    else:
        vulns = novus_security.scan_vulnerabilities()
        if not vulns:
            return {
                "status": "success",
                "message": "Sin amenazas ni hallazgos activos para mitigar",
                "steps": [{"label": "Estado", "status": "done", "detail": "Sistema estable"}],
            }
        result = remediate_vulnerability(vulns[0].get("id"))

    return {
        "status": result.get("status", "success"),
        "message": result.get("message", "Mitigación sectorial ejecutada"),
        "sector_key": sector_key,
        "steps": result.get("steps", []),
        "report_id": result.get("report_id"),
    }


def update_sector_rules(email: Optional[str] = None) -> Dict[str, Any]:
    from services.novus_security_integration import novus_security

    sector_key = resolve_sector_for_user(email)
    profile = novus_security.security_engine.build_sector_protection(sector_key)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    _save_shield_state(sector_key, {
        "last_rules_update": now,
        "controls": profile.get("controls", []),
        "motors": SECTOR_MOTORS.get(sector_key, []),
    })

    try:
        from services.config_service import load_config, save_config
        cfg = load_config()
        cfg["sector_activo"] = sector_key
        save_config(cfg)
    except Exception as exc:
        logger.debug(f"Config sector sync: {exc}")

    return {
        "status": "success",
        "message": f"Reglas del escudo actualizadas para {profile.get('profile_title')}",
        "sector_key": sector_key,
        "controls": profile.get("controls", []),
        "updated_at": now,
    }


def get_sector_policies(email: Optional[str] = None) -> Dict[str, Any]:
    sector_key = resolve_sector_for_user(email)
    from services.novus_security_integration import novus_security
    profile = novus_security.security_engine.build_sector_protection(sector_key)

    policies = [
        {"id": "controls", "name": "Controles sectoriales", "items": profile.get("controls", [])},
        {"id": "motors", "name": "Motores asignados", "items": SECTOR_MOTORS.get(sector_key, [])},
        {"id": "crypto", "name": "Cifrado", "items": get_active_shield_status(email).get("crypto_models", [])},
    ]
    return {"status": "success", "sector_key": sector_key, "policies": policies}


def get_sector_history(email: Optional[str] = None, limit: int = 20) -> Dict[str, Any]:
    from database import SessionLocal, Log, Alerta

    sector_key = resolve_sector_for_user(email)
    events: List[Dict[str, Any]] = []

    db = SessionLocal()
    try:
        logs = db.query(Log).order_by(Log.id.desc()).limit(limit * 2).all()
        for log in logs:
            if sector_key.upper() in (log.evento or "").upper() or "SECTOR" in (log.evento or "").upper() or "SECURITY" in (log.evento or "").upper():
                events.append({
                    "type": "log",
                    "time": log.fecha,
                    "title": log.evento,
                    "detail": (log.detalle or "")[:120],
                })
            if len(events) >= limit:
                break

        if len(events) < limit:
            for alert in db.query(Alerta).order_by(Alerta.id.desc()).limit(limit).all():
                events.append({
                    "type": "alert",
                    "time": alert.fecha,
                    "title": alert.titulo,
                    "detail": (alert.descripcion or "")[:120],
                })
    finally:
        db.close()

    from services.novus_security_integration import novus_security
    for entry in novus_security.security_engine.threat_registry[-10:]:
        events.append({
            "type": "threat_registry",
            "time": entry.get("time") or entry.get("timestamp", ""),
            "title": entry.get("incident") or entry.get("action", "Evento motor"),
            "detail": str(entry)[:120],
        })

    return {"status": "success", "sector_key": sector_key, "events": events[:limit]}


def get_sector_reports(email: Optional[str] = None) -> Dict[str, Any]:
    from services.security_report_service import list_reports

    sector_key = resolve_sector_for_user(email)
    reports = list_reports(limit=20)
    return {
        "status": "success",
        "sector_key": sector_key,
        "reports": reports,
        "count": len(reports),
    }
