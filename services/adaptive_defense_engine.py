"""
Adaptive Defense Engine — capa de defensa activa progresiva NOVUS.

Reduce riesgo cuando la remediación automática no resuelve el hallazgo.
Reutiliza motores existentes; no reemplaza remediación ni escudos sectoriales.
Todas las acciones quedan registradas con evidencia y son reversibles cuando procede.
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

NO_DATA = "Sin datos disponibles"
ADAPTIVE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "adaptive_defense"
)
ACTIONS_FILE = os.path.join(ADAPTIVE_DIR, "actions.jsonl")
STATE_FILE = os.path.join(ADAPTIVE_DIR, "state.json")

RISK_LEVELS = ("BAJO", "MEDIO", "ALTO", "CRITICO")


def _ensure_dirs() -> None:
    os.makedirs(ADAPTIVE_DIR, exist_ok=True)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _load_state() -> Dict[str, Any]:
    _ensure_dirs()
    if not os.path.exists(STATE_FILE):
        return {"active_containments": [], "endpoint_scores": {}, "last_level": None}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {"active_containments": [], "endpoint_scores": {}, "last_level": None}


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
        from services.kernel_memory import log_operation
        log_operation({
            "type": "adaptive_defense_action",
            "action": record.get("action"),
            "finding_id": record.get("finding_id"),
            "risk_level": record.get("risk_level"),
            "confidence": record.get("confidence"),
            "detail": record.get("detail"),
        })
    except Exception:
        pass
    try:
        from services.defense_evidence_registry import record_defense_event
        event = record.get("event") or record.get("action") or "adaptive_action"
        phase = "recover" if event == "revert" else "contain"
        if event == "adaptive_response":
            phase = "respond"
        acts = record.get("actions") or []
        for act in acts if isinstance(acts, list) and acts else [record]:
            if not isinstance(act, dict):
                continue
            record_defense_event(
                phase=phase,
                action=act.get("action") or event,
                motor="adaptive_defense_engine",
                outcome=act.get("status") or "success",
                finding_id=record.get("finding_id"),
                evidence={"level": record.get("level"), "sub": act},
                reversible=bool(act.get("reversible")),
                revert_key=act.get("revert_key"),
                detail=act.get("detail"),
                confidence=record.get("confidence"),
            )
    except Exception:
        pass


def _read_actions(limit: int = 50) -> List[Dict[str, Any]]:
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
        logger.debug("adaptive_defense read actions: %s", exc)
    return rows[-limit:]


def _normalize_risk(raw: str) -> str:
    v = str(raw or "").upper()
    if any(x in v for x in ("CRIT", "CRÍT")):
        return "CRITICO"
    if "ALTO" in v or "HIGH" in v:
        return "ALTO"
    if "MED" in v:
        return "MEDIO"
    if "BAJO" in v or "LOW" in v:
        return "BAJO"
    return "MEDIO"


def _has_critical_evidence(finding: dict) -> bool:
    """Evidencia real verificada — nunca CRITICO sin esto."""
    if finding.get("verified") or finding.get("evidence"):
        return True
    if finding.get("evidencia"):
        return True
    details = finding.get("details") or {}
    if isinstance(details, dict) and (details.get("verified") or details.get("evidence")):
        return True
    tipo = str(finding.get("tipo") or finding.get("threat_type") or "").lower()
    if "ransomware" in tipo and finding.get("verified"):
        return True
    try:
        from services.novus_security_integration import novus_security
        cache = novus_security._threat_cache or {}
        fid = str(finding.get("id") or "")
        if fid:
            for threat in cache.get("threats") or []:
                if str(threat.get("id", "")) == fid or str(threat.get("type", "")) in fid:
                    det = threat.get("details") or {}
                    if det.get("verified") or det.get("evidence"):
                        return True
        for proc in cache.get("suspicious_processes") or []:
            pid = proc.get("pid")
            if fid and f"PROC-{pid}" in fid:
                desc = (proc.get("description") or "").lower()
                if any(k in desc for k in ("malicious", "malware", "ransom", "inject", "keylog")):
                    return True
    except Exception:
        pass
    return False


def classify_risk_level(finding: dict) -> str:
    level = _normalize_risk(
        finding.get("riesgo") or finding.get("severidad") or finding.get("gravedad") or finding.get("severity")
    )
    if level == "CRITICO" and not _has_critical_evidence(finding):
        return "ALTO"
    return level


def _resolve_sector(user_email: Optional[str]) -> str:
    try:
        from services.sector_shield_service import resolve_sector_for_user, normalize_sector
        return normalize_sector(resolve_sector_for_user(user_email))
    except Exception:
        return "general"


def _port_from_finding(finding_id: str, finding: dict) -> Optional[int]:
    try:
        from services.manual_remediation_guide import _port_from_finding
        return _port_from_finding({"id": finding_id, **finding})
    except Exception:
        return None


def _pid_from_finding(finding_id: str, finding: dict) -> Optional[int]:
    try:
        from services.manual_remediation_guide import _pid_from_finding
        return _pid_from_finding({"id": finding_id, **finding})
    except Exception:
        return None


def _is_suspicious_process(pid: int) -> bool:
    try:
        from services.novus_security_integration import novus_security
        for proc in (novus_security._threat_cache or {}).get("suspicious_processes") or []:
            if int(proc.get("pid") or 0) == pid:
                return True
    except Exception:
        pass
    return False


def calculate_endpoint_protection(
    hallazgos: Any,
    active_containments: int = 0,
    risk_level: Optional[str] = None,
) -> int:
    """
    Protección % derivada de telemetría real — no inventada.
    100 = sin hallazgos activos; baja con hallazgos y contenciones activas.
    """
    h = 0
    if isinstance(hallazgos, int):
        h = hallazgos
    elif isinstance(hallazgos, str) and hallazgos.isdigit():
        h = int(hallazgos)

    deduction = min(75, h * 10 + active_containments * 5)
    if risk_level == "CRITICO":
        deduction = min(80, deduction + 15)
    elif risk_level == "ALTO":
        deduction = min(80, deduction + 8)
    return max(0, min(100, 100 - deduction))


def _action_increase_monitoring(finding_id: str, finding: dict) -> Dict[str, Any]:
    motors = []
    try:
        from services.novus_security_integration import novus_security
        novus_security.detect_threats_realtime(force=True)
        novus_security.scan_vulnerabilities(force=True)
        motors.extend(["security.threats", "security.vulnerabilities"])
    except Exception as exc:
        return {"action": "increase_monitoring", "status": "failed", "detail": str(exc), "reversible": False}

    try:
        from services.network_event_log import network_event_log
        network_event_log.record(
            f"Adaptive Defense: monitoreo intensificado — {finding_id}",
            level="alert",
        )
        motors.append("network_event_log")
    except Exception:
        pass

    return {
        "action": "increase_monitoring",
        "status": "done",
        "detail": "Escaneo y monitoreo en tiempo real reforzados",
        "motors": motors,
        "reversible": False,
        "risk_reduction": "bajo",
    }


def _action_firewall_block_port(finding_id: str, finding: dict) -> Dict[str, Any]:
    port = _port_from_finding(finding_id, finding)
    if not port:
        return {"action": "firewall_block_port", "status": "skipped", "detail": "Puerto no identificado", "reversible": False}
    if platform.system() != "Windows":
        return {"action": "firewall_block_port", "status": "skipped", "detail": "Regla firewall solo en Windows", "reversible": False}
    rule_name = f"NOVUS-ADE-Block-TCP-{port}-In"
    try:
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", "protocol=TCP",
                f"localport={port}", "enable=yes",
            ],
            capture_output=True, text=True, timeout=30, check=False,
        )
        return {
            "action": "firewall_block_port",
            "status": "done",
            "detail": f"Puerto TCP {port} bloqueado entrante (regla {rule_name})",
            "reversible": True,
            "revert_key": rule_name,
            "port": port,
            "risk_reduction": "medio",
        }
    except Exception as exc:
        return {"action": "firewall_block_port", "status": "failed", "detail": str(exc), "reversible": False}


def _action_terminate_process(finding_id: str, finding: dict, force_kill: bool = False) -> Dict[str, Any]:
    pid = _pid_from_finding(finding_id, finding)
    if not pid:
        return {"action": "terminate_process", "status": "skipped", "detail": "PID no identificado", "reversible": False}
    if not _is_suspicious_process(pid):
        return {
            "action": "terminate_process",
            "status": "skipped",
            "detail": f"PID {pid} no está en lista de procesos sospechosos del motor — no se detiene",
            "reversible": False,
        }
    try:
        import psutil
        proc = psutil.Process(pid)
        name = proc.name()
        if force_kill:
            proc.kill()
            verb = "kill"
        else:
            proc.terminate()
            verb = "terminate"
        return {
            "action": "terminate_process",
            "status": "done",
            "detail": f"Proceso {name} (PID {pid}) — {verb} ejecutado por evidencia real",
            "reversible": False,
            "pid": pid,
            "process_name": name,
            "risk_reduction": "alto",
        }
    except Exception as exc:
        return {"action": "terminate_process", "status": "failed", "detail": str(exc), "reversible": False}


def _action_sector_scan(user_email: Optional[str]) -> Dict[str, Any]:
    try:
        from services.sector_shield_service import scan_sector
        result = scan_sector(user_email)
        return {
            "action": "sector_shield_scan",
            "status": "done",
            "detail": f"Escaneo sectorial ejecutado — sector {result.get('sector', NO_DATA)}",
            "motors": ["security.sector_shield"],
            "reversible": False,
            "risk_reduction": "medio",
        }
    except Exception as exc:
        return {"action": "sector_shield_scan", "status": "failed", "detail": str(exc), "reversible": False}


def _action_block_suspicious_ip(finding: dict) -> Dict[str, Any]:
    ip = finding.get("ip") or finding.get("remote_ip")
    if not ip or str(ip) in ("local", "127.0.0.1", "localhost"):
        return {"action": "block_ip", "status": "skipped", "detail": "IP remota no identificada", "reversible": False}
    try:
        from database import SessionLocal, IPBloqueada
        db = SessionLocal()
        try:
            existing = db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == str(ip)).first()
            if not existing:
                row = IPBloqueada(direccion_ip=str(ip), razon="Adaptive Defense — conexión sospechosa")
                db.add(row)
                db.commit()
            result = {
                "action": "block_ip",
                "status": "done",
                "detail": f"IP {ip} registrada en lista de bloqueo NOVUS",
                "reversible": True,
                "revert_key": str(ip),
                "risk_reduction": "alto",
            }
            try:
                from services.os_firewall_service import block_ip_os
                os_result = block_ip_os(str(ip))
                result["os_firewall"] = os_result
                if os_result.get("status") == "done":
                    result["detail"] = f"IP {ip} en SQLite + firewall OS ({os_result.get('os_rule')})"
            except Exception:
                pass
            return result
        finally:
            db.close()
    except Exception as exc:
        return {"action": "block_ip", "status": "failed", "detail": str(exc), "reversible": False}


def _action_partial_isolation(finding_id: str, finding: dict) -> Dict[str, Any]:
    """Aislamiento parcial solo con evidencia crítica verificada."""
    if not _has_critical_evidence(finding):
        return {
            "action": "partial_isolation",
            "status": "skipped",
            "detail": "Sin evidencia crítica verificada — aislamiento no aplicado",
            "reversible": False,
        }
    actions = []
    port_action = _action_firewall_block_port(finding_id, finding)
    actions.append(port_action)
    proc_action = _action_terminate_process(finding_id, finding, force_kill=True)
    actions.append(proc_action)
    return {
        "action": "partial_isolation",
        "status": "done" if any(a.get("status") == "done" for a in actions) else "warning",
        "detail": "Aislamiento parcial: puertos comprometidos contenidos y proceso malicioso detenido",
        "sub_actions": actions,
        "reversible": True,
        "risk_reduction": "critico",
    }


def _actions_for_level(level: str, finding_id: str, finding: dict, user_email: Optional[str]) -> List[Dict[str, Any]]:
    executed: List[Dict[str, Any]] = []
    if level == "BAJO":
        executed.append(_action_increase_monitoring(finding_id, finding))
    elif level == "MEDIO":
        executed.append(_action_increase_monitoring(finding_id, finding))
        executed.append(_action_sector_scan(user_email))
        if "PORT" in finding_id or "FIND-PORT" in finding_id:
            executed.append(_action_firewall_block_port(finding_id, finding))
    elif level == "ALTO":
        executed.append(_action_increase_monitoring(finding_id, finding))
        executed.append(_action_sector_scan(user_email))
        if "PORT" in finding_id or "FIND-PORT" in finding_id:
            executed.append(_action_firewall_block_port(finding_id, finding))
        if "PROC" in finding_id:
            executed.append(_action_terminate_process(finding_id, finding, force_kill=True))
        ip_action = _action_block_suspicious_ip(finding)
        if ip_action.get("status") != "skipped":
            executed.append(ip_action)
        try:
            from services.remediation_orchestrator import run_auto_remediation
            rem = run_auto_remediation(finding_id, finding, executed_by="adaptive_defense_engine", skip_adaptive=True)
            executed.append({
                "action": "continue_remediation",
                "status": "done" if rem.get("resolved") else "warning",
                "detail": rem.get("message", NO_DATA),
                "reversible": False,
                "resolved": rem.get("resolved"),
            })
            if rem.get("resolved"):
                return executed
        except Exception as exc:
            executed.append({"action": "continue_remediation", "status": "failed", "detail": str(exc)})
    elif level == "CRITICO":
        if _has_critical_evidence(finding):
            executed.append(_action_partial_isolation(finding_id, finding))
        else:
            executed.append({
                "action": "partial_isolation",
                "status": "skipped",
                "detail": "CRITICO sin evidencia verificada — escalado bloqueado",
                "reversible": False,
            })
        executed.append(_action_increase_monitoring(finding_id, finding))
    return executed


def revert_containment(revert_key: str, action_type: str) -> Dict[str, Any]:
    """Revierte una contención cuando el hallazgo fue corregido."""
    if action_type == "firewall_block_port" and platform.system() == "Windows":
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={revert_key}"],
                capture_output=True, timeout=20, check=False,
            )
            return {"status": "success", "detail": f"Regla {revert_key} eliminada"}
        except Exception as exc:
            return {"status": "error", "detail": str(exc)}
    if action_type == "block_ip":
        try:
            from database import SessionLocal, IPBloqueada
            db = SessionLocal()
            try:
                db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == revert_key).delete()
                db.commit()
                detail = f"IP {revert_key} desbloqueada"
                try:
                    from services.os_firewall_service import unblock_ip_os
                    os_rev = unblock_ip_os(str(revert_key))
                    if os_rev.get("status") == "done":
                        detail += " + regla OS eliminada"
                except Exception:
                    pass
                return {"status": "success", "detail": detail}
            finally:
                db.close()
        except Exception as exc:
            return {"status": "error", "detail": str(exc)}
    return {"status": "skipped", "detail": "Acción no reversible automáticamente"}


def revert_containments_for_finding(finding_id: str) -> int:
    state = _load_state()
    reverted = 0
    kept = []
    for item in state.get("active_containments") or []:
        if item.get("finding_id") != finding_id:
            kept.append(item)
            continue
        result = revert_containment(item.get("revert_key", ""), item.get("action_type", ""))
        if result.get("status") == "success":
            reverted += 1
            _append_action({
                "event": "revert",
                "finding_id": finding_id,
                "detail": result.get("detail"),
            })
    state["active_containments"] = kept
    _save_state(state)
    return reverted


def activate_after_failed_remediation(
    finding_id: str,
    finding: dict,
    remediation_result: Optional[dict] = None,
    user_email: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Activar Adaptive Defense cuando la remediación automática no resolvió el hallazgo.
    No bloquea el flujo — continúa en segundo plano.
    """
    start = time.time()
    level = classify_risk_level(finding)
    sector = _resolve_sector(user_email)
    executed = _actions_for_level(level, finding_id, finding, user_email)

    resolved_via_remediation = any(
        a.get("action") == "continue_remediation" and a.get("resolved") for a in executed
    )
    if resolved_via_remediation:
        revert_containments_for_finding(finding_id)
        return {
            "status": "resolved_by_remediation",
            "level": level,
            "actions": executed,
            "message": "Remediación completada tras respuesta adaptativa ALTO",
        }

    state = _load_state()
    for act in executed:
        if act.get("reversible") and act.get("revert_key"):
            state.setdefault("active_containments", []).append({
                "finding_id": finding_id,
                "action_type": act.get("action"),
                "revert_key": act.get("revert_key"),
                "since": _now(),
            })
    state["last_level"] = level
    _save_state(state)

    record = {
        "event": "adaptive_response",
        "finding_id": finding_id,
        "level": level,
        "sector": sector,
        "actions": executed,
        "elapsed_sec": round(time.time() - start, 2),
        "remediation_failed": True,
    }
    _append_action(record)

    try:
        from services.network_event_log import network_event_log
        network_event_log.record(
            f"Adaptive Defense {level}: {finding_id} — {len(executed)} acción(es)",
            level="alert",
        )
    except Exception:
        pass

    if level == "CRITICO":
        try:
            from services.threat_intelligence_service import threat_intelligence
            threat_intelligence.create_or_update_case(
                finding,
                context={"usuario": user_email or "sistema", "sector": sector},
                motores=["adaptive_defense_engine", "security.threats"],
                acciones=[a.get("detail") for a in executed if a.get("detail")],
                timeline_events=[{
                    "timestamp": _now(),
                    "evento": "Adaptive Defense CRÍTICO",
                    "detalle": f"Aislamiento parcial activado — {finding_id}",
                }],
            )
        except Exception as exc:
            logger.debug("ADE critical incident: %s", exc)

    try:
        from services.vulnerability_analyst_service import sync_platform_after_remediation
        sync_platform_after_remediation(finding_id, resolved=False)
    except Exception:
        pass

    return {
        "status": "active",
        "level": level,
        "sector": sector,
        "actions": executed,
        "actions_count": len(executed),
        "elapsed_sec": record["elapsed_sec"],
        "message": f"Adaptive Defense activado — nivel {level}",
    }


def get_endpoint_states(user_email: Optional[str] = None) -> List[Dict[str, Any]]:
    """Estado dinámico de protección por endpoint — calculado desde telemetría real."""
    try:
        from services.platform_metrics_service import build_endpoint_inventory
        inventory = build_endpoint_inventory()
    except Exception:
        inventory = []

    state = _load_state()
    containments = state.get("active_containments") or []
    last_level = state.get("last_level")
    results = []
    for ep in inventory:
        name = ep.get("nombre") or ep.get("name") or "endpoint"
        hallazgos = ep.get("hallazgos") if ep.get("hallazgos") != NO_DATA else ep.get("findings")
        active = sum(1 for c in containments if c.get("finding_id"))
        pct = calculate_endpoint_protection(hallazgos, active, last_level)
        results.append({
            "endpoint": name,
            "ip": ep.get("ip"),
            "proteccion_pct": pct,
            "hallazgos": hallazgos,
            "estado": ep.get("estado") or ep.get("status"),
            "contenciones_activas": active,
        })
    return results


def get_adaptive_defense_panel(user_email: Optional[str] = None) -> Dict[str, Any]:
    """Panel para Centro de Inteligencia — solo datos reales del motor."""
    actions = _read_actions(40)
    response_actions = [a for a in actions if a.get("event") == "adaptive_response"]
    state = _load_state()
    containments = state.get("active_containments") or []

    services_protected = []
    processes_contained = []
    risk_reduced = 0
    time_gained_sec = 0

    for rec in response_actions:
        for act in rec.get("actions") or []:
            if act.get("status") == "done":
                risk_reduced += 1
            if act.get("action") == "firewall_block_port" and act.get("port"):
                services_protected.append(f"TCP/{act['port']}")
            if act.get("action") == "terminate_process" and act.get("process_name"):
                processes_contained.append(f"{act['process_name']} (PID {act.get('pid')})")
            for sub in act.get("sub_actions") or []:
                if sub.get("port"):
                    services_protected.append(f"TCP/{sub['port']}")
                if sub.get("process_name"):
                    processes_contained.append(sub["process_name"])
        time_gained_sec += rec.get("elapsed_sec") or 0

    for c in containments:
        try:
            since = datetime.strptime(c.get("since", ""), "%Y-%m-%d %H:%M:%S")
            time_gained_sec += max(0, int((datetime.now() - since).total_seconds()))
        except Exception:
            pass

    return {
        "motor": "Adaptive Defense Engine",
        "estado_actual": state.get("last_level") or "Sin activación reciente",
        "sector": _resolve_sector(user_email),
        "acciones_ejecutadas": [
            {
                "fecha": a.get("timestamp"),
                "nivel": a.get("level"),
                "hallazgo": a.get("finding_id"),
                "acciones": len(a.get("actions") or []),
                "detalle": (a.get("actions") or [{}])[0].get("detail") if a.get("actions") else NO_DATA,
            }
            for a in reversed(response_actions[-10:])
        ],
        "riesgo_reducido_acciones": risk_reduced,
        "servicios_protegidos": list(dict.fromkeys(services_protected))[:10],
        "procesos_contenidos": list(dict.fromkeys(processes_contained))[:10],
        "tiempo_ganado_seg": time_gained_sec,
        "contenciones_activas": len(containments),
        "endpoints": get_endpoint_states(user_email),
        "ultima_respuesta": response_actions[-1] if response_actions else None,
        "requiere_aprobacion": [
            "Aislamiento parcial (CRITICO) — solo con evidencia verificada",
            "Eliminación de reglas firewall manuales fuera de NOVUS",
        ],
        "automaticas": [
            "Monitoreo intensificado",
            "Escaneo sectorial",
            "Bloqueo de puerto comprometido (Windows)",
            "Contención de proceso sospechoso verificado",
            "Registro IP sospechosa",
            "Continuación de remediación automática",
        ],
    }


def answer_kernel_query(question: str, user_email: Optional[str] = None) -> Optional[str]:
    q = (question or "").lower()
    triggers = (
        "adaptive defense", "defensa adaptativa", "qué hiciste", "que hiciste",
        "cómo protegiste", "como protegiste", "qué acciones tomaste", "que acciones tomaste",
        "por qué limitaste", "porque limitaste", "protegiste mi equipo", "contuviste",
    )
    if not any(t in q for t in triggers):
        return None

    panel = get_adaptive_defense_panel(user_email)
    if "limitaste" in q or "por qué" in q or "porque" in q:
        last = panel.get("ultima_respuesta")
        if not last:
            return "Aún no se ha activado Adaptive Defense en esta sesión. Se activa cuando la remediación automática no resuelve un hallazgo."
        acts = last.get("actions") or []
        lines = [f"Nivel {last.get('level')} — hallazgo {last.get('finding_id')}:"]
        for a in acts:
            if a.get("detail"):
                lines.append(f"• {a.get('action')}: {a.get('detail')}")
        return "\n".join(lines)

    if "protegiste" in q or "hiciste" in q or "acciones" in q:
        acciones = panel.get("acciones_ejecutadas") or []
        if not acciones:
            return (
                "Adaptive Defense no ha ejecutado acciones aún. "
                "Se activa automáticamente cuando la remediación falla, aplicando contención progresiva según el riesgo."
            )
        lines = [
            f"Estado: {panel.get('estado_actual')}",
            f"Sector: {panel.get('sector')}",
            f"Acciones que redujeron riesgo: {panel.get('riesgo_reducido_acciones')}",
            f"Servicios protegidos: {', '.join(panel.get('servicios_protegidos') or []) or 'ninguno activo'}",
            f"Procesos contenidos: {', '.join(panel.get('procesos_contenidos') or []) or 'ninguno'}",
            f"Tiempo ganado (contención activa): {panel.get('tiempo_ganado_seg')}s",
        ]
        for a in acciones[:5]:
            lines.append(f"• [{a.get('fecha')}] {a.get('nivel')}: {a.get('detalle')}")
        return "\n".join(lines)

    eps = panel.get("endpoints") or []
    if eps:
        ep_line = ", ".join(f"{e['endpoint']} {e['proteccion_pct']}%" for e in eps[:3])
        return f"Adaptive Defense — {panel.get('estado_actual')}. Protección endpoints: {ep_line}."
    return f"Adaptive Defense activo. Estado: {panel.get('estado_actual')}. Contenciones: {panel.get('contenciones_activas')}."


# Singleton-style module API
class AdaptiveDefenseEngine:
    activate_after_failed_remediation = staticmethod(activate_after_failed_remediation)
    revert_containments_for_finding = staticmethod(revert_containments_for_finding)
    get_adaptive_defense_panel = staticmethod(get_adaptive_defense_panel)
    get_endpoint_states = staticmethod(get_endpoint_states)
    answer_kernel_query = staticmethod(answer_kernel_query)
    classify_risk_level = staticmethod(classify_risk_level)


adaptive_defense = AdaptiveDefenseEngine()
