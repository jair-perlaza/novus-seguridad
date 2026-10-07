"""
Adaptive Sector Protection Engine (ASPE) — orquestación sectorial inteligente.

Activa motores existentes de NOVUS según sector, infraestructura (UCE) y evidencia
de amenazas. Los módulos no prioritarios permanecen en standby inteligente.
Activación cruzada temporal cuando la matriz de confianza lo justifica.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

from services.telemetry_resolver import explain

NO_DATA = "Sin datos disponibles"
ASPE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "aspe")
STATE_FILE = os.path.join(ASPE_DIR, "state.json")
ACTIONS_FILE = os.path.join(ASPE_DIR, "actions.jsonl")

DYNAMIC_TTL_MINUTES = 45
CONFIDENCE_THRESHOLD = 0.62
EVIDENCE_MIN_FOR_DYNAMIC = 0.70
MAX_DYNAMIC_MODULES = 2

# Catálogo de módulos — solo motores reales existentes en NOVUS
PROTECTION_MODULES: Dict[str, Dict[str, Any]] = {
    "bec_shield": {
        "label": "BEC Shield / Escudo Fintech",
        "sector": "fintech",
        "method": "validate_transactional_integrity",
        "capability": "security.sector_shield",
    },
    "ato_analyzer": {
        "label": "ATO Analyzer",
        "sector": "fintech",
        "method": "analyze_ato_risk",
        "capability": "security.sector_shield",
    },
    "phishing_shield": {
        "label": "Phishing Shield",
        "sector": "fintech",
        "method": "inspect_email_integrity",
        "capability": "security.sector_shield",
    },
    "api_shield": {
        "label": "API Shield",
        "sector": "fintech",
        "method": "validate_api_request",
        "capability": "security.sector_shield",
    },
    "iot_guard": {
        "label": "IoT Guard / Escudo Logística",
        "sector": "logistica",
        "method": "validate_iot_telemetry",
        "capability": "security.sector_shield",
    },
    "mitm_shield": {
        "label": "MITM Shield",
        "sector": "logistica",
        "method": "verify_tunnel_integrity",
        "capability": "security.sector_shield",
    },
    "network_scanner": {
        "label": "Network Scanner",
        "sector": "logistica",
        "service": "network_scanner",
        "capability": "network.scanner",
    },
    "ui_shield": {
        "label": "UI Shield / Mobile Shield",
        "sector": "aplicaciones_moviles",
        "method": "detect_overlay_threat",
        "capability": "security.sector_shield",
    },
    "clickjacking_guard": {
        "label": "Clickjacking Guard",
        "sector": "aplicaciones_moviles",
        "method": "validate_ui_interaction",
        "capability": "security.sector_shield",
    },
    "sim_identity": {
        "label": "SIM Identity",
        "sector": "aplicaciones_moviles",
        "method": "verify_sim_and_identity",
        "capability": "security.sector_shield",
    },
    "runtime_integrity": {
        "label": "Runtime Integrity",
        "sector": "aplicaciones_moviles",
        "method": "verify_runtime_integrity",
        "capability": "security.sector_shield",
    },
    "sqli_shield": {
        "label": "SQLi Shield",
        "sector": "otros",
        "method": "sanitize_and_validate_query",
        "capability": "security.vulnerabilities",
    },
    "ransom_sentinel": {
        "label": "Ransom Sentinel",
        "sector": "otros",
        "method": "monitor_filesystem_activity",
        "capability": "security.threats",
    },
    "cryptovault": {
        "label": "CryptoVault",
        "sector": None,
        "service": "cryptovault",
        "capability": "security.vault",
    },
    "adaptive_defense": {
        "label": "Adaptive Defense",
        "sector": None,
        "service": "adaptive_defense",
        "capability": "adaptive.defense",
    },
}

SECTOR_PRIORITY: Dict[str, List[str]] = {
    "fintech": [
        "bec_shield", "ato_analyzer", "phishing_shield", "api_shield",
        "cryptovault", "adaptive_defense",
    ],
    "logistica": [
        "iot_guard", "mitm_shield", "network_scanner", "ui_shield",
        "api_shield", "cryptovault", "adaptive_defense",
    ],
    "aplicaciones_moviles": [
        "ui_shield", "sim_identity", "runtime_integrity", "clickjacking_guard",
        "api_shield", "cryptovault", "adaptive_defense",
    ],
    "otros": [
        "network_scanner", "sqli_shield", "cryptovault", "ransom_sentinel",
        "adaptive_defense",
    ],
}

# Matriz base de confianza motor × tipo de amenaza (0-1)
CONFIDENCE_MATRIX: Dict[str, Dict[str, float]] = {
    "credential_stuffing": {
        "ato_analyzer": 0.92, "api_shield": 0.85, "bec_shield": 0.72,
        "phishing_shield": 0.68, "sqli_shield": 0.55, "ui_shield": 0.40,
        "sim_identity": 0.75, "iot_guard": 0.30, "mitm_shield": 0.45,
        "network_scanner": 0.35, "ransom_sentinel": 0.20,
    },
    "api_attack": {
        "api_shield": 0.95, "sqli_shield": 0.82, "ato_analyzer": 0.70,
        "mitm_shield": 0.65, "iot_guard": 0.50, "network_scanner": 0.55,
        "bec_shield": 0.45, "ui_shield": 0.40,
    },
    "ransomware": {
        "ransom_sentinel": 0.96, "adaptive_defense": 0.90, "network_scanner": 0.60,
        "iot_guard": 0.45, "cryptovault": 0.70, "bec_shield": 0.25,
    },
    "lateral_movement": {
        "network_scanner": 0.88, "mitm_shield": 0.80, "iot_guard": 0.72,
        "adaptive_defense": 0.85, "api_shield": 0.50, "ato_analyzer": 0.45,
    },
    "privilege_escalation": {
        "ato_analyzer": 0.85, "runtime_integrity": 0.82, "adaptive_defense": 0.88,
        "sim_identity": 0.70, "sqli_shield": 0.55, "network_scanner": 0.50,
    },
    "exfiltration": {
        "mitm_shield": 0.85, "network_scanner": 0.82, "api_shield": 0.75,
        "bec_shield": 0.70, "adaptive_defense": 0.80, "iot_guard": 0.55,
    },
    "zero_day": {
        "adaptive_defense": 0.90, "runtime_integrity": 0.78, "ransom_sentinel": 0.72,
        "network_scanner": 0.65, "ui_shield": 0.60, "sqli_shield": 0.55,
    },
    "phishing": {
        "phishing_shield": 0.94, "bec_shield": 0.88, "ato_analyzer": 0.75,
        "api_shield": 0.40, "sim_identity": 0.50,
    },
    "mobile_threat": {
        "ui_shield": 0.93, "clickjacking_guard": 0.88, "sim_identity": 0.85,
        "runtime_integrity": 0.82, "api_shield": 0.55, "ato_analyzer": 0.45,
    },
    "iot_anomaly": {
        "iot_guard": 0.94, "mitm_shield": 0.80, "network_scanner": 0.75,
        "api_shield": 0.45, "adaptive_defense": 0.70,
    },
    "generic": {
        "adaptive_defense": 0.75, "network_scanner": 0.60, "cryptovault": 0.55,
        "api_shield": 0.50, "ato_analyzer": 0.50,
    },
}

THREAT_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "credential_stuffing": (
        "credential", "stuffing", "brute", "login", "ato", "account takeover",
        "password spray", "fuerza bruta", "credencial",
    ),
    "api_attack": ("api", "endpoint", "rest", "graphql", "rate limit", "abuse api"),
    "ransomware": ("ransom", "cryptolocker", "encrypt", "cifrado masivo"),
    "lateral_movement": ("lateral", "pivot", "movimiento lateral", "spread", "propag"),
    "privilege_escalation": ("privilege", "escalad", "elevation", "root", "admin exploit"),
    "exfiltration": ("exfil", "data leak", "filtración", "extracción de datos"),
    "zero_day": ("zero-day", "zero day", "0-day", "desconocido", "sin firma"),
    "phishing": ("phishing", "spear", "correo malicioso", "bec", "fraude"),
    "mobile_threat": ("overlay", "clickjack", "sim swap", "móvil", "mobile", "ui shield"),
    "iot_anomaly": ("iot", "telemetr", "gps", "sensor", "dispositivo iot"),
}


def _ensure_dirs() -> None:
    os.makedirs(ASPE_DIR, exist_ok=True)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _load_state() -> Dict[str, Any]:
    _ensure_dirs()
    if not os.path.exists(STATE_FILE):
        return {
            "sector_key": None,
            "module_states": {},
            "active_incidents": [],
            "dynamic_activations": [],
            "confidence_level": NO_DATA,
            "last_orchestration": None,
        }
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {"module_states": {}, "active_incidents": [], "dynamic_activations": []}


def _save_state(state: Dict[str, Any]) -> None:
    _ensure_dirs()
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)


def _append_action(record: Dict[str, Any]) -> None:
    _ensure_dirs()
    record.setdefault("timestamp", _now())
    with open(ACTIONS_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    try:
        from services.defense_evidence_registry import record_defense_event
        record_defense_event(
            phase="respond",
            action=record.get("event") or "aspe_orchestration",
            motor="adaptive_sector_protection_engine",
            outcome="success",
            finding_id=record.get("finding_id"),
            threat_type=record.get("threat_type"),
            evidence={
                "activated": record.get("activated"),
                "evidence_factor": record.get("evidence_factor"),
            },
            user_email=record.get("user_email"),
            detail=str(record.get("activated", ""))[:300],
        )
    except Exception:
        pass


def _read_actions(limit: int = 60) -> List[Dict[str, Any]]:
    if not os.path.exists(ACTIONS_FILE):
        return []
    rows: List[Dict[str, Any]] = []
    try:
        with open(ACTIONS_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except Exception as exc:
        logger.debug("ASPE read actions: %s", exc)
    return rows[-limit:]


def _resolve_sector(user_email: Optional[str] = None) -> str:
    from services.sector_shield_service import resolve_sector_for_user
    return resolve_sector_for_user(user_email)


def _priority_modules_for_sector(sector_key: str, user_email: Optional[str] = None) -> List[str]:
    key = sector_key
    if key == "otros":
        try:
            from services.universal_compatibility_engine import uce
            return uce.recommend_modules_for_otros_sector(user_email)
        except Exception:
            return ["network_scanner", "cryptovault", "sqli_shield", "ransom_sentinel", "adaptive_defense"]
    return list(SECTOR_PRIORITY.get(key, SECTOR_PRIORITY["fintech"]))


def classify_threat_type(finding: Optional[dict] = None) -> str:
    if not finding:
        return "generic"
    motor = str(finding.get("motor") or finding.get("source") or "").lower()
    motor_map = {
        "scan_open_ports": "api_attack",
        "network_ndr": "iot_anomaly",
        "network_inventory": "iot_anomaly",
        "arp": "lateral_movement",
        "mitm": "exfiltration",
        "ransom": "ransomware",
        "bec": "phishing",
        "ato": "credential_stuffing",
        "phishing": "phishing",
        "api_shield": "api_attack",
        "iot": "iot_anomaly",
        "sqli": "api_attack",
        "ui_shield": "mobile_threat",
        "sim": "mobile_threat",
    }
    for key, threat_type in motor_map.items():
        if key in motor:
            return threat_type
    explicit = str(finding.get("threat_type") or finding.get("tipo") or "").lower()
    if explicit in THREAT_KEYWORDS:
        return explicit
    blob = " ".join(
        str(finding.get(k) or "")
        for k in ("tipo", "threat_type", "nombre", "descripcion", "description", "id", "categoria", "title")
    ).lower()
    details = finding.get("details") or {}
    if isinstance(details, dict):
        blob += " " + " ".join(str(v) for v in details.values())
    for threat_type, keywords in THREAT_KEYWORDS.items():
        if any(kw in blob for kw in keywords):
            return threat_type
    severity = str(finding.get("severidad") or finding.get("severity") or "").lower()
    if "ransom" in blob or "ransom" in severity:
        return "ransomware"
    return "generic"


def _evidence_factor(finding: Optional[dict]) -> float:
    if not finding:
        return 0.85
    factor = 0.55
    if finding.get("verified") or finding.get("evidence"):
        factor += 0.25
    details = finding.get("details") or {}
    if isinstance(details, dict) and (details.get("verified") or details.get("evidence")):
        factor += 0.15
    if finding.get("confianza") in ("Alta", "HIGH", "high", "ALTA"):
        factor += 0.10
    if finding.get("evidencia") and isinstance(finding.get("evidencia"), dict):
        factor += 0.05
    return min(1.0, factor)


def compute_module_confidence(
    module_id: str,
    threat_type: str,
    sector_key: str,
    finding: Optional[dict] = None,
) -> float:
    matrix_row = CONFIDENCE_MATRIX.get(threat_type) or CONFIDENCE_MATRIX["generic"]
    base = matrix_row.get(module_id, matrix_row.get("adaptive_defense", 0.35))
    score = base * _evidence_factor(finding)
    priority = _priority_modules_for_sector(sector_key)
    mod_sector = PROTECTION_MODULES.get(module_id, {}).get("sector")
    if module_id in priority:
        score = min(1.0, score + 0.08)
    elif mod_sector and mod_sector == sector_key:
        score = min(1.0, score + 0.05)
    return round(score, 3)


def _telemetry_sufficient(module_id: str, finding: Optional[dict]) -> Tuple[bool, str]:
    """Evita invocar motores sectoriales sin telemetría/evidencia real verificable."""
    finding = finding or {}
    evidencia = finding.get("evidencia") or finding.get("details") or {}
    if not isinstance(evidencia, dict):
        evidencia = {}

    if module_id == "iot_guard":
        telem = evidencia.get("telemetry") if isinstance(evidencia.get("telemetry"), dict) else evidencia
        coord = telem.get("current_coord") or {}
        if coord.get("lat") or coord.get("lon"):
            return True, ""
        if telem.get("engine_rpm") or telem.get("speed") or telem.get("is_signed_by_hardware"):
            return True, ""
        if finding.get("verified") or finding.get("mac"):
            return True, ""
        return False, "Sin telemetría IoT real — motor en standby"

    if module_id in ("bec_shield", "phishing_shield"):
        if finding.get("verified") or evidencia.get("body") or evidencia.get("amount"):
            return True, ""
        return False, "Sin evidencia de comunicación/email — motor en standby"

    if module_id == "ato_analyzer":
        loc = evidencia.get("location") or {}
        if loc.get("lat") or loc.get("lon") or evidencia.get("typing_speed"):
            return True, ""
        if finding.get("verified"):
            return True, ""
        return False, "Sin telemetría de sesión ATO — motor en standby"

    if module_id == "mitm_shield":
        if finding.get("verified") or evidencia.get("dst") or evidencia.get("protocol"):
            return True, ""
        return False, "Sin metadatos TLS de conexión — motor en standby"

    if module_id in ("sim_identity", "runtime_integrity", "ui_shield"):
        if finding.get("verified") or len(evidencia) >= 2:
            return True, ""
        return False, "Sin telemetría móvil/runtime — motor en standby"

    return True, ""


def _invoke_protection_module(module_id: str, finding: Optional[dict] = None) -> Dict[str, Any]:
    """Ejecuta un motor real existente — sin simulación."""
    spec = PROTECTION_MODULES.get(module_id)
    if not spec:
        return {"status": "error", "message": f"Módulo desconocido: {module_id}"}

    sufficient, skip_reason = _telemetry_sufficient(module_id, finding)
    if not sufficient:
        return {
            "status": "standby",
            "module": module_id,
            "result": {"note": skip_reason, "skipped": "insufficient_telemetry"},
            "elapsed_sec": 0,
        }

    started = time.time()
    try:
        if spec.get("service") == "network_scanner":
            from services.network_scanner import network_scanner
            nodes = network_scanner.get_cached_nodes() or []
            if not nodes:
                network_scanner.scan_network()
                nodes = network_scanner.get_cached_nodes() or []
            return {
                "status": "done",
                "module": module_id,
                "result": {"nodes": len(nodes), "source": "network_scanner"},
                "elapsed_sec": round(time.time() - started, 2),
            }

        if spec.get("service") == "cryptovault":
            from services.novus_security_integration import novus_security
            vault = novus_security.vault
            active = vault is not None and getattr(vault, "llave_aes", None) is not None
            return {
                "status": "done",
                "module": module_id,
                "result": {"vault_active": active, "tls": vault.get_tls_status() if vault else NO_DATA},
                "elapsed_sec": round(time.time() - started, 2),
            }

        if spec.get("service") == "adaptive_defense":
            return {
                "status": "standby",
                "module": module_id,
                "result": {"note": "Adaptive Defense se activa vía remediation_orchestrator"},
                "elapsed_sec": 0,
            }

        from services.novus_security_integration import novus_security
        engine = novus_security.security_engine
        method_name = spec.get("method")
        if not method_name or not hasattr(engine, method_name):
            return {"status": "error", "message": f"Método no disponible: {method_name}"}

        method = getattr(engine, method_name)
        fid = str((finding or {}).get("id") or "ASPE-INCIDENT")
        ip = str((finding or {}).get("ip") or (finding or {}).get("source_ip") or "127.0.0.1")
        evidencia = (finding or {}).get("evidencia") or (finding or {}).get("details") or {}
        if not isinstance(evidencia, dict):
            evidencia = {"raw": str(evidencia)[:300]}

        if module_id == "bec_shield":
            result = method(
                {
                    "subject": finding.get("nombre") or fid,
                    "from": ip,
                    "sender": ip,
                    "sender_display_name": evidencia.get("sender_display_name") or finding.get("nombre") or fid,
                },
                {"amount": evidencia.get("amount", 0), "account": evidencia.get("account", fid)},
            )
        elif module_id == "ato_analyzer":
            browser = evidencia.get("browser") or {
                "user_agent": finding.get("fuente", "NOVUS"),
                "os": evidencia.get("os", "unknown"),
                "resolution": evidencia.get("resolution", "unknown"),
                "cpu_cores": evidencia.get("cpu_cores", 0),
            }
            result = method(
                fid,
                {
                    "ip": ip,
                    "current_location": evidencia.get("location") or {"lat": 0, "lon": 0},
                    "browser_data": browser,
                    "typing_speed": evidencia.get("typing_speed", 0),
                },
                evidencia.get("baseline") or {"last_location": None, "avg_typing_speed": 0},
            )
        elif module_id == "phishing_shield":
            result = method(
                {
                    "from": ip,
                    "sender": evidencia.get("sender") or ip,
                    "subject": finding.get("nombre") or fid,
                },
                str(finding.get("descripcion") or evidencia.get("body") or ""),
            )
        elif module_id == "api_shield":
            result = method(ip, evidencia.get("path") or f"/api/{fid}")
        elif module_id == "iot_guard":
            hist = evidencia.get("baseline") or evidencia.get("historical") or {}
            telem = evidencia.get("telemetry") if isinstance(evidencia.get("telemetry"), dict) else evidencia
            result = method(
                finding.get("mac") or fid,
                {
                    "current_coord": telem.get("current_coord") or {"lat": 0, "lon": 0},
                    "engine_rpm": telem.get("engine_rpm", 0),
                    "speed": telem.get("speed", 0),
                    "is_signed_by_hardware": telem.get("is_signed_by_hardware", False),
                    **{k: v for k, v in telem.items() if k not in ("current_coord",)},
                },
                {
                    "last_coord": hist.get("last_coord") or telem.get("last_coord") or {"lat": 0, "lon": 0},
                    "last_time": hist.get("last_time") or telem.get("last_time") or time.time(),
                    "in_signal_zone": hist.get("in_signal_zone", False),
                },
            )
        elif module_id == "mitm_shield":
            result = method({
                "src": ip,
                "dst": evidencia.get("dst") or "remote",
                "protocol": evidencia.get("protocol") or "tls",
            })
        elif module_id == "ui_shield":
            result = method({
                "window": fid,
                "overlay_detected": bool(evidencia.get("overlay_detected")),
                "evidence": evidencia,
            })
        elif module_id == "clickjacking_guard":
            result = method(
                {"target": fid},
                evidencia.get("headers") or {"x-requested-with": finding.get("fuente", "NOVUS")},
            )
        elif module_id == "sim_identity":
            result = method(
                {"device_id": evidencia.get("device_id") or fid},
                evidencia.get("session") or {"user": "session"},
            )
        elif module_id == "runtime_integrity":
            result = method({
                "app": evidencia.get("app") or "novus_host",
                "checksum": evidencia.get("checksum") or fid,
            })
        elif module_id == "sqli_shield":
            payload = str(
                finding.get("descripcion") or finding.get("nombre") or evidencia.get("payload") or ""
            )
            result = method(payload[:200], evidencia.get("context") or "NOVUS_CONTEXT")
        elif module_id == "ransom_sentinel":
            result = method({
                "path": evidencia.get("path") or fid,
                "operations": evidencia,
            })
        else:
            result = method(fid, {})

        return {
            "status": "done",
            "module": module_id,
            "result": result if isinstance(result, dict) else {"response": str(result)[:500]},
            "elapsed_sec": round(time.time() - started, 2),
        }
    except Exception as exc:
        logger.error(f"ASPE invoke {module_id}: {exc}", exc_info=True)
        return {
            "status": "failed",
            "module": module_id,
            "message": str(exc),
            "elapsed_sec": round(time.time() - started, 2),
        }


def initialize_sector_protection(user_email: Optional[str] = None) -> Dict[str, Any]:
    """Configura protecciones activas y standby al registro/login."""
    from services.universal_compatibility_engine import uce

    sector_key = _resolve_sector(user_email)
    infra = uce.detect_infrastructure(user_email=user_email, persist=True)
    priority = _priority_modules_for_sector(sector_key, user_email)

    module_states: Dict[str, Dict[str, Any]] = {}
    for mid, spec in PROTECTION_MODULES.items():
        if mid in priority:
            mode = "active"
        else:
            mode = "standby"
        module_states[mid] = {
            "mode": mode,
            "label": spec["label"],
            "sector": spec.get("sector"),
            "since": _now(),
        }

    state = _load_state()
    state.update({
        "sector_key": sector_key,
        "module_states": module_states,
        "infrastructure_snapshot": {
            "technologies": infra.get("technologies") or [],
            "count": infra.get("technologies_count", 0),
            "detected_at": infra.get("detected_at"),
        },
        "priority_modules": priority,
        "confidence_level": "Alta" if infra.get("technologies_count", 0) >= 2 else "Media",
        "last_orchestration": _now(),
        "initialized_by": user_email,
    })
    _save_state(state)

    _append_action({
        "event": "sector_init",
        "sector_key": sector_key,
        "active_modules": priority,
        "standby_count": sum(1 for m in module_states.values() if m["mode"] == "standby"),
        "infrastructure": infra.get("technologies") or [],
        "user_email": user_email,
    })

    return {
        "status": "success",
        "sector_key": sector_key,
        "active_modules": priority,
        "standby_modules": [m for m, s in module_states.items() if s["mode"] == "standby"],
        "infrastructure": infra,
        "confidence_level": state["confidence_level"],
    }


def bootstrap_sector_baselines() -> Dict[str, Any]:
    """
    Al arranque: define perfiles activos/standby para todos los sectores PyME.
    Los motores no prioritarios permanecen en standby para apoyo cruzado.
    """
    from services.universal_compatibility_engine import uce

    infra = uce.get_infrastructure_panel()
    baselines: Dict[str, Any] = {}
    all_standby: set = set()

    for sector_key, priority in SECTOR_PRIORITY.items():
        standby = [mid for mid in PROTECTION_MODULES if mid not in priority]
        all_standby.update(standby)
        baselines[sector_key] = {
            "active_modules": priority,
            "standby_modules": standby,
            "threat_focus": _sector_threat_focus(sector_key),
        }

    state = _load_state()
    state["sector_baselines"] = baselines
    state["bootstrapped_at"] = _now()
    state["infrastructure_snapshot"] = {
        "technologies": infra.get("technologies") or [],
        "count": infra.get("technologies_count", 0),
    }
    _save_state(state)

    try:
        from services.defense_coordinator import defense_coordinator

        for sector_key, profile in baselines.items():
            defense_coordinator.record_detection(
                "adaptive_sector_protection_engine",
                "sector_baseline_boot",
                profile,
                phase="prevent",
                outcome="success",
                threat_type=profile.get("threat_focus"),
                detail=f"ASPE baseline {sector_key}: {len(profile['active_modules'])} activos",
                confidence="Alta",
            )
    except Exception as exc:
        logger.debug("ASPE bootstrap registry: %s", exc)

    return {
        "status": "success",
        "sectors": baselines,
        "standby_pool_size": len(all_standby),
    }


def _sector_threat_focus(sector_key: str) -> str:
    focus = {
        "fintech": "credential_stuffing",
        "logistica": "iot_anomaly",
        "aplicaciones_moviles": "mobile_threat",
        "otros": "generic",
    }
    return focus.get(sector_key, "generic")


def evaluate_incident(
    finding: dict,
    user_email: Optional[str] = None,
    source: str = "aspe",
) -> Dict[str, Any]:
    """
    Evalúa evidencia y activa temporalmente módulos de otro sector si aportan mejor cobertura.
    """
    sector_key = _resolve_sector(user_email)
    threat_type = classify_threat_type(finding)
    finding_id = str(finding.get("id") or f"INC-{int(time.time())}")
    evidence_factor = _evidence_factor(finding)

    state = _load_state()
    if not state.get("module_states"):
        initialize_sector_protection(user_email)
        state = _load_state()

    priority = _priority_modules_for_sector(sector_key, user_email)
    scores: List[Dict[str, Any]] = []

    for mid in PROTECTION_MODULES:
        conf = compute_module_confidence(mid, threat_type, sector_key, finding)
        scores.append({
            "module_id": mid,
            "label": PROTECTION_MODULES[mid]["label"],
            "confidence": conf,
            "sector": PROTECTION_MODULES[mid].get("sector"),
            "is_priority": mid in priority,
        })

    scores.sort(key=lambda x: x["confidence"], reverse=True)

    dynamic_candidates = [
        s for s in scores
        if s["confidence"] >= CONFIDENCE_THRESHOLD
        and evidence_factor >= EVIDENCE_MIN_FOR_DYNAMIC
        and not s["is_priority"]
        and s["module_id"] not in ("adaptive_defense", "cryptovault")
    ][:MAX_DYNAMIC_MODULES]

    activated: List[Dict[str, Any]] = []
    for cand in dynamic_candidates:
        mid = cand["module_id"]
        exec_result = _invoke_protection_module(mid, finding)
        activation = {
            "module_id": mid,
            "label": cand["label"],
            "confidence": cand["confidence"],
            "threat_type": threat_type,
            "reason": (
                f"Matriz de confianza: {cand['confidence']:.0%} para {threat_type} "
                f"(sector cliente: {sector_key}, evidencia: {evidence_factor:.0%})"
            ),
            "cross_sector": PROTECTION_MODULES[mid].get("sector") != sector_key,
            "execution": exec_result,
            "activated_at": _now(),
            "finding_id": finding_id,
        }
        activated.append(activation)

        ms = state.setdefault("module_states", {}).setdefault(mid, {})
        ms["mode"] = "dynamic_active"
        ms["dynamic_since"] = _now()
        ms["dynamic_reason"] = activation["reason"]
        ms["dynamic_finding"] = finding_id

    if activated:
        state.setdefault("dynamic_activations", []).extend(activated)
        state.setdefault("active_incidents", []).append({
            "finding_id": finding_id,
            "threat_type": threat_type,
            "started_at": _now(),
            "modules": [a["module_id"] for a in activated],
            "source": source,
        })
        state["confidence_level"] = f"{max(a['confidence'] for a in activated):.0%}"
        state["last_orchestration"] = _now()
        _save_state(state)

        _append_action({
            "event": "dynamic_activation",
            "finding_id": finding_id,
            "threat_type": threat_type,
            "sector_key": sector_key,
            "activated": activated,
            "evidence_factor": evidence_factor,
            "user_email": user_email,
            "source": source,
        })

    # Ejecutar módulos prioritarios activos del sector (verificación ligera)
    priority_ran = []
    for mid in priority[:3]:
        if mid in ("adaptive_defense",):
            continue
        if state.get("module_states", {}).get(mid, {}).get("mode") == "active":
            pr = _invoke_protection_module(mid, finding)
            priority_ran.append({"module_id": mid, "execution": pr})

    result = {
        "status": "success" if activated or priority_ran else "no_action",
        "threat_type": threat_type,
        "sector_key": sector_key,
        "confidence_matrix_top": scores[:6],
        "dynamic_activated": activated,
        "priority_executed": priority_ran,
        "finding_id": finding_id,
    }

    try:
        from services.defense_coordinator import defense_coordinator

        defense_coordinator.record_detection(
            "adaptive_sector_protection_engine",
            "incident_evaluated",
            {
                "finding_id": finding_id,
                "threat_type": threat_type,
                "evidence_factor": evidence_factor,
                "dynamic_count": len(activated),
                "priority_count": len(priority_ran),
                "source": source,
                "verified": evidence_factor >= EVIDENCE_MIN_FOR_DYNAMIC or bool(priority_ran),
            },
            phase="detect" if result["status"] == "no_action" else "respond",
            outcome=result["status"],
            threat_type=threat_type,
            finding_id=finding_id,
            detail=f"ASPE {result['status']}: {threat_type} sector={sector_key}",
            confidence=f"{evidence_factor:.0%}",
            user_email=user_email,
        )
        if activated or (result["status"] == "no_action" and evidence_factor >= EVIDENCE_MIN_FOR_DYNAMIC):
            defense_coordinator.notify_kernel_incident(
                "adaptive_sector_protection_engine",
                "ASPE_INCIDENT",
                f"Evaluación {finding_id}: {threat_type} — {result['status']}",
                incident_id=finding_id,
                severity="high" if activated else "medium",
                evidence={"dynamic": [a.get("module_id") for a in activated]},
            )
    except Exception as exc:
        logger.debug("ASPE evaluate registry: %s", exc)

    return result


def release_incident(finding_id: str, resolved: bool = True) -> Dict[str, Any]:
    """Devuelve módulos dinámicos a standby cuando el incidente termina."""
    state = _load_state()
    released = []
    now = datetime.now()

    for act in list(state.get("dynamic_activations") or []):
        if act.get("finding_id") != finding_id:
            continue
        mid = act.get("module_id")
        ms = state.get("module_states", {}).get(mid, {})
        if ms.get("mode") == "dynamic_active":
            ms["mode"] = "standby"
            ms.pop("dynamic_since", None)
            ms.pop("dynamic_reason", None)
            ms.pop("dynamic_finding", None)
            released.append(mid)

    state["dynamic_activations"] = [
        a for a in (state.get("dynamic_activations") or [])
        if a.get("finding_id") != finding_id
    ]
    state["active_incidents"] = [
        i for i in (state.get("active_incidents") or [])
        if i.get("finding_id") != finding_id
    ]

    # TTL fallback para activaciones antiguas
    for mid, ms in (state.get("module_states") or {}).items():
        if ms.get("mode") != "dynamic_active":
            continue
        since_str = ms.get("dynamic_since")
        if since_str:
            try:
                since = datetime.strptime(since_str, "%Y-%m-%d %H:%M:%S")
                if (now - since) > timedelta(minutes=DYNAMIC_TTL_MINUTES):
                    ms["mode"] = "standby"
                    ms.pop("dynamic_since", None)
                    released.append(mid)
            except Exception:
                pass

    _save_state(state)

    if released:
        _append_action({
            "event": "release_standby",
            "finding_id": finding_id,
            "released_modules": released,
            "resolved": resolved,
        })

    return {"status": "success", "released": released, "finding_id": finding_id}


def get_sector_protection_panel(user_email: Optional[str] = None) -> Dict[str, Any]:
    """Panel unificado UCE + ASPE para dashboard e intel."""
    from services.performance_cache import get_or_compute, invalidate
    from core.config import Config

    return get_or_compute(
        f"aspe_panel:{user_email or '_'}",
        Config.PANEL_CACHE_TTL,
        lambda: _build_sector_protection_panel(user_email),
    )


def _build_sector_protection_panel(user_email: Optional[str] = None) -> Dict[str, Any]:
    from services.universal_compatibility_engine import uce
    from services.adaptive_defense_engine import adaptive_defense

    state = _load_state()
    if not state.get("module_states"):
        initialize_sector_protection(user_email)
        state = _load_state()

    sector_key = state.get("sector_key") or _resolve_sector(user_email)
    infra = uce.get_infrastructure_panel(user_email)
    module_states = state.get("module_states") or {}

    active = []
    standby = []
    dynamic = []
    for mid, ms in module_states.items():
        spec = PROTECTION_MODULES.get(mid, {})
        entry = {
            "id": mid,
            "label": ms.get("label") or spec.get("label", mid),
            "mode": ms.get("mode"),
            "sector": spec.get("sector"),
        }
        if ms.get("dynamic_reason"):
            entry["reason"] = ms.get("dynamic_reason")
        mode = ms.get("mode")
        if mode == "active":
            active.append(entry)
        elif mode == "dynamic_active":
            dynamic.append(entry)
        else:
            standby.append(entry)

    actions = _read_actions(30)
    motor_log = [
        a for a in actions
        if a.get("event") in ("dynamic_activation", "release_standby", "sector_init")
    ]

    ade = {}
    try:
        ade = adaptive_defense.get_adaptive_defense_panel(user_email)
    except Exception:
        ade = {"estado_actual": explain("adaptive_defense_idle")}

    return {
        "motor": "Adaptive Sector Protection Engine",
        "sector_key": sector_key,
        "sector_label": _sector_label(sector_key),
        "confidence_level": state.get("confidence_level") or (
            "Alta" if len(active) >= 1 else explain("sector_confidence_pending")
        ),
        "protecciones_activas": active,
        "protecciones_standby": standby,
        "protecciones_dinamicas": dynamic,
        "active_incidents": state.get("active_incidents") or [],
        "infrastructure": {
            "technologies": infra.get("technologies") or [],
            "count": infra.get("technologies_count", 0),
            "detected_at": infra.get("detected_at"),
            "items": infra.get("detected_items") or [],
        },
        "adaptive_defense": {
            "estado": ade.get("estado_actual"),
            "contenciones": ade.get("contenciones_activas", 0),
        },
        "motor_activations": [
            {
                "event": a.get("event"),
                "fecha": a.get("timestamp"),
                "motores": [
                    x.get("label") or x.get("module_id")
                    for x in (a.get("activated") or [])
                ] or a.get("active_modules"),
                "motivo": (
                    (a.get("activated") or [{}])[0].get("reason")
                    if a.get("activated") else "Inicialización sectorial"
                ),
                "threat_type": a.get("threat_type"),
                "duracion": a.get("elapsed_sec"),
                "resultado": a.get("event"),
                "riesgo_reducido": len(a.get("activated") or []) if a.get("event") == "dynamic_activation" else 0,
            }
            for a in reversed(motor_log[-15:])
        ],
        "last_orchestration": state.get("last_orchestration"),
    }


def _sector_label(sector_key: str) -> str:
    from services.sector_profile_service import get_sector_profile
    return get_sector_profile(sector_key).get("label", sector_key)


def generate_audit_report(user_email: Optional[str] = None) -> Dict[str, Any]:
    """Informe de auditoría UCE + ASPE."""
    from services.universal_compatibility_engine import uce

    panel = get_sector_protection_panel(user_email)
    uce_audit = uce.generate_compatibility_audit(user_email)
    actions = _read_actions(100)
    dynamic_events = [a for a in actions if a.get("event") == "dynamic_activation"]

    return {
        "generated_at": _now(),
        "tecnologias_detectadas": uce_audit.get("tecnologias_detectadas") or [],
        "sector_detectado": panel.get("sector_key"),
        "sector_label": panel.get("sector_label"),
        "protecciones_activas": panel.get("protecciones_activas") or [],
        "protecciones_standby": panel.get("protecciones_standby") or [],
        "protecciones_dinamicas": panel.get("protecciones_dinamicas") or [],
        "motores_utilizados_pruebas": [
            {
                "motor": (a.get("activated") or [{}])[0].get("label"),
                "threat": a.get("threat_type"),
                "fecha": a.get("timestamp"),
            }
            for a in dynamic_events
        ],
        "compatibilidad_lograda": uce_audit.get("compatibilidad_lograda_pct"),
        "fortalezas": uce_audit.get("fortalezas") or [],
        "limitaciones": uce_audit.get("limitaciones") or [],
        "oportunidades_mejora": uce_audit.get("oportunidades") or [],
        "confidence_level": panel.get("confidence_level"),
        "adaptive_defense": panel.get("adaptive_defense"),
    }


def answer_kernel_query(question: str, user_email: Optional[str] = None) -> Optional[str]:
    q = (question or "").lower()
    triggers = (
        "qué motores", "que motores", "protegiéndome", "protegiendome",
        "protecciones en espera", "protecciones activas", "standby",
        "por qué activaste", "porque activaste", "por qué utilizaste",
        "porque utilizaste", "mobile shield", "fintech shield",
        "aspe", "sector protection", "protección sectorial", "proteccion sectorial",
        "uce", "infraestructura detectada", "qué escudo", "que escudo",
    )
    if not any(t in q for t in triggers):
        return None

    panel = get_sector_protection_panel(user_email)

    if "espera" in q or "standby" in q:
        standby = panel.get("protecciones_standby") or []
        if not standby:
            return "No hay módulos en standby — todos los motores asignados están activos o en uso dinámico."
        lines = [f"Módulos en standby inteligente ({len(standby)}):"]
        for s in standby[:10]:
            lines.append(f"• {s.get('label')} — preparado, sin consumo activo")
        return "\n".join(lines)

    if "mobile shield" in q or "ui shield" in q:
        dynamic = panel.get("protecciones_dinamicas") or []
        ui_dyn = [d for d in dynamic if d.get("id") in ("ui_shield", "clickjacking_guard")]
        if ui_dyn:
            return f"Mobile/UI Shield activado dinámicamente: {ui_dyn[0].get('reason', NO_DATA)}"
        active = [a for a in (panel.get("protecciones_activas") or []) if a.get("id") == "ui_shield"]
        if active:
            return f"UI Shield (Mobile Shield) está activo como protección prioritaria del sector {panel.get('sector_label')}."
        return (
            "UI Shield no está activo ahora. Permanece en standby hasta que ASPE detecte "
            "amenaza móvil (overlay, clickjacking, SIM) con confianza suficiente."
        )

    if "fintech" in q or "bec" in q:
        dynamic = panel.get("protecciones_dinamicas") or []
        fin_dyn = [d for d in dynamic if d.get("sector") == "fintech" or d.get("id") == "bec_shield"]
        if fin_dyn:
            return f"Escudo Fintech activado temporalmente: {fin_dyn[0].get('reason', NO_DATA)}"
        return (
            f"Sector actual: {panel.get('sector_label')}. "
            "Los motores Fintech permanecen en standby salvo activación cruzada por ASPE."
        )

    if "infraestructura" in q or "uce" in q:
        infra = panel.get("infrastructure") or {}
        techs = infra.get("technologies") or []
        if not techs:
            return "UCE aún no ha detectado tecnologías adicionales. Ejecute un escaneo de seguridad NOVUS."
        return f"Infraestructura detectada ({infra.get('count', 0)}): {', '.join(techs[:12])}."

    active = panel.get("protecciones_activas") or []
    dynamic = panel.get("protecciones_dinamicas") or []
    lines = [
        f"Sector: {panel.get('sector_label')} ({panel.get('sector_key')})",
        f"Nivel de confianza ASPE: {panel.get('confidence_level')}",
        f"Protecciones activas ({len(active)}):",
    ]
    for a in active[:8]:
        lines.append(f"  • {a.get('label')}")
    if dynamic:
        lines.append(f"Activadas dinámicamente ({len(dynamic)}):")
        for d in dynamic:
            lines.append(f"  • {d.get('label')}: {d.get('reason', '')[:120]}")
    lines.append(f"Adaptive Defense: {panel.get('adaptive_defense', {}).get('estado', NO_DATA)}")
    return "\n".join(lines)


class AdaptiveSectorProtectionEngine:
    initialize_sector_protection = staticmethod(initialize_sector_protection)
    evaluate_incident = staticmethod(evaluate_incident)
    release_incident = staticmethod(release_incident)
    get_sector_protection_panel = staticmethod(get_sector_protection_panel)
    generate_audit_report = staticmethod(generate_audit_report)
    answer_kernel_query = staticmethod(answer_kernel_query)
    classify_threat_type = staticmethod(classify_threat_type)
    compute_module_confidence = staticmethod(compute_module_confidence)


aspe = AdaptiveSectorProtectionEngine()
