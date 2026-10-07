"""
Orquestador central de Playbooks NOVUS.
Coordina motores existentes vía capability_registry — sin duplicar lógica ni crear SOAR paralelo.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from utils.logger import logger

LEARNING_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "playbook_learning")
LEARNING_FILE = os.path.join(LEARNING_DIR, "records.jsonl")

MAX_CHAIN_DEPTH = 5

# Pipelines → secuencia de capacidades del registry existente (orden importa)
ORCHESTRATION_PIPELINES: Dict[str, Dict[str, Any]] = {
    "device_unknown": {
        "label": "Dispositivo desconocido en red",
        "capabilities": [
            "network.radar",
            "network.ndr",
            "topology.view",
            "advanced_detector.ports",
            "connections.active",
            "advanced_detector.processes",
            "security.vulnerabilities",
            "security.threats",
            "threat_intelligence.center",
            "remediation.engine",
            "dashboard.metrics",
            "reports.manager",
        ],
    },
    "vuln_critical": {
        "label": "Vulnerabilidad crítica",
        "capabilities": [
            "security.vulnerabilities",
            "remediation.engine",
            "security.vulnerabilities",
            "incidents.manager",
            "threat_intelligence.center",
            "reports.manager",
            "playbooks.manager",
        ],
    },
    "email_suspicious": {
        "label": "Correo sospechoso",
        "capabilities": [
            "gmail.analyzer",
            "security.threats",
            "security.vault",
            "threat_intelligence.center",
            "siem.logs",
            "reports.manager",
        ],
    },
    "traffic_anomaly": {
        "label": "Tráfico anómalo",
        "capabilities": [
            "traffic.stats",
            "connections.active",
            "network.ndr",
            "advanced_detector.processes",
            "advanced_detector.ports",
            "security.threats",
            "remediation.engine",
            "dashboard.metrics",
        ],
    },
    "sector_full": {
        "label": "Respuesta sectorial completa",
        "capabilities": [
            "security.sector_shield",
            "security.threats",
            "security.vulnerabilities",
            "network.scanner",
            "threat_intelligence.center",
            "reports.manager",
            "dashboard.metrics",
        ],
    },
    "platform_close": {
        "label": "Cierre y sincronización de plataforma",
        "capabilities": [
            "dashboard.metrics",
            "security.vulnerabilities",
            "security.threats",
            "threat_intelligence.center",
            "reports.manager",
            "siem.logs",
        ],
    },
}

SECTOR_DEFAULT_PIPELINES = {
    "fintech": "sector_full",
    "logistica": "traffic_anomaly",
    "aplicaciones_moviles": "sector_full",
    "otros": "platform_close",
}

ORCHESTRATOR_PLAYBOOK_SPECS: Dict[str, Dict[str, Any]] = {
    "PB-ORCH-DEVICE": {
        "nombre": "Orquestador — Dispositivo desconocido",
        "trigger": "manual",
        "accion": "orchestrate_device",
        "prioridad": "Alta",
        "reglas_asociadas": ["pipeline:device_unknown"],
        "kernel_respuestas": ORCHESTRATION_PIPELINES["device_unknown"]["capabilities"],
        "automatizaciones_asociadas": ["PB-ORCH-CLOSE"],
    },
    "PB-ORCH-VULN": {
        "nombre": "Orquestador — Vulnerabilidad crítica",
        "trigger": "manual",
        "accion": "orchestrate_vuln",
        "prioridad": "Crítico",
        "reglas_asociadas": ["pipeline:vuln_critical"],
        "kernel_respuestas": ORCHESTRATION_PIPELINES["vuln_critical"]["capabilities"],
        "automatizaciones_asociadas": ["PB-ORCH-CLOSE"],
    },
    "PB-ORCH-EMAIL": {
        "nombre": "Orquestador — Correo sospechoso",
        "trigger": "manual",
        "accion": "orchestrate_email",
        "prioridad": "Alta",
        "reglas_asociadas": ["pipeline:email_suspicious"],
        "kernel_respuestas": ORCHESTRATION_PIPELINES["email_suspicious"]["capabilities"],
        "automatizaciones_asociadas": ["PB-ORCH-CLOSE"],
    },
    "PB-ORCH-TRAFFIC": {
        "nombre": "Orquestador — Tráfico anómalo",
        "trigger": "manual",
        "accion": "orchestrate_traffic",
        "prioridad": "Alta",
        "reglas_asociadas": ["pipeline:traffic_anomaly"],
        "kernel_respuestas": ORCHESTRATION_PIPELINES["traffic_anomaly"]["capabilities"],
        "automatizaciones_asociadas": ["PB-ORCH-CLOSE"],
    },
    "PB-ORCH-CLOSE": {
        "nombre": "Orquestador — Sincronizar plataforma",
        "trigger": "manual",
        "accion": "orchestrate_close",
        "prioridad": "Medio",
        "reglas_asociadas": ["pipeline:platform_close"],
        "kernel_respuestas": ORCHESTRATION_PIPELINES["platform_close"]["capabilities"],
    },
}


def ensure_orchestrator_playbooks() -> None:
    from services.playbook_service import create_playbook, get_playbook, update_playbook

    for pb_id, spec in ORCHESTRATOR_PLAYBOOK_SPECS.items():
        existing = get_playbook(pb_id)
        if existing:
            update_playbook(pb_id, spec)
        else:
            create_playbook({"id": pb_id, **spec, "estado": "Activo"})


def resolve_pipeline_id(playbook: Dict[str, Any], user_email: Optional[str] = None) -> Optional[str]:
    accion = (playbook.get("accion") or "").lower()
    mapping = {
        "orchestrate_device": "device_unknown",
        "orchestrate_vuln": "vuln_critical",
        "orchestrate_email": "email_suspicious",
        "orchestrate_traffic": "traffic_anomaly",
        "orchestrate_close": "platform_close",
        "orchestrate_full": "device_unknown",
    }
    if accion in mapping:
        return mapping[accion]

    for rule in playbook.get("reglas_asociadas") or []:
        if str(rule).startswith("pipeline:"):
            return str(rule).split(":", 1)[1].strip()

    pb_id = playbook.get("id", "")
    if pb_id.startswith("PB-SECTOR-"):
        try:
            from services.sector_shield_service import resolve_sector_for_user
            sector = resolve_sector_for_user(user_email)
            from services.sector_profile_service import normalize_sector
            key = normalize_sector(sector)
            return SECTOR_DEFAULT_PIPELINES.get(key, "platform_close")
        except Exception:
            return "platform_close"
    return None


def _phase_step(phase: str, detail: str = "", status: str = "running") -> Dict[str, Any]:
    return {
        "label": phase,
        "detail": detail,
        "status": status,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }


def run_capability_pipeline(
    capability_ids: List[str],
    user_email: Optional[str],
    steps: List[Dict[str, Any]],
    motors: List[str],
    executed: List[str],
    modified: List[str],
    not_modified: List[str],
    label: str = "Orquestación",
) -> Dict[str, Any]:
    """Ejecuta capacidades vía registry existente con recuperación ante errores."""
    if not capability_ids:
        return {"status": "success", "collected": {}, "capabilities_executed": []}

    unique_caps = list(dict.fromkeys(capability_ids))
    steps.append(_phase_step("Ejecutando", f"{label}: {len(unique_caps)} componente(s) NOVUS", "running"))

    collected: Dict[str, Any] = {}
    executed_caps: List[str] = []
    failed_caps: List[str] = []

    try:
        from services.ai_capability_registry import capability_registry
        motors.append("ai_capability_registry")
        result = capability_registry.execute(unique_caps, user_id=user_email, force_refresh=True)
        collected = result.get("_capability_raw") or {}
        executed_caps = result.get("capabilities_executed") or []
        failed_caps = result.get("capabilities_failed") or []
        for cap in executed_caps:
            executed.append(f"Motor: {cap}")
            modified.append(f"Datos consultados: {cap}")
        for cap in failed_caps:
            not_modified.append(f"Componente sin respuesta: {cap}")
        for mod in result.get("modules_queried") or []:
            motors.append(str(mod))
    except Exception as exc:
        steps[-1] = _phase_step("Ejecutando", f"{label} — error registry: {exc}", "failed")
        not_modified.append(f"Orquestación parcial: {exc}")
        return {"status": "warning", "collected": collected, "error": str(exc)}

    detail = f"{len(executed_caps)} OK, {len(failed_caps)} fallido(s)"
    steps[-1] = _phase_step("Ejecutando", f"{label} completada — {detail}", "done" if executed_caps else "warning")
    return {
        "status": "success" if executed_caps else "warning",
        "collected": collected,
        "capabilities_executed": executed_caps,
        "capabilities_failed": failed_caps,
    }


def run_orchestration_for_playbook(
    playbook: Dict[str, Any],
    user_email: Optional[str],
    steps: List[Dict[str, Any]],
    motors: List[str],
    executed: List[str],
    modified: List[str],
    not_modified: List[str],
) -> Dict[str, Any]:
    """Coordina pipeline + capacidades kernel_respuestas del playbook."""
    pipeline_id = resolve_pipeline_id(playbook, user_email)
    merged_caps: List[str] = list(playbook.get("kernel_respuestas") or [])

    if pipeline_id and pipeline_id in ORCHESTRATION_PIPELINES:
        pipe = ORCHESTRATION_PIPELINES[pipeline_id]
        steps.append(_phase_step("Analizando", f"Pipeline: {pipe['label']}", "done"))
        merged_caps = list(dict.fromkeys((pipe.get("capabilities") or []) + merged_caps))

    if not merged_caps:
        return {"status": "success", "collected": {}}

    return run_capability_pipeline(
        merged_caps, user_email, steps, motors, executed, modified, not_modified,
        label=ORCHESTRATION_PIPELINES.get(pipeline_id or "", {}).get("label", "Orquestación NOVUS"),
    )


def run_chained_playbooks(
    chain_ids: List[str],
    user_email: Optional[str],
    steps: List[Dict[str, Any]],
    motors: List[str],
    executed: List[str],
    modified: List[str],
    not_modified: List[str],
    depth: int = 0,
    visited: Optional[Set[str]] = None,
    parent_execution_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Encadena playbooks hijos (automatizaciones_asociadas) sin recursión infinita."""
    visited = visited or set()
    child_results: List[Dict[str, Any]] = []

    for raw_id in chain_ids or []:
        child_id = str(raw_id).strip()
        if not child_id.startswith("PB-"):
            continue
        if child_id in visited:
            not_modified.append(f"Cadena omitida (ciclo): {child_id}")
            continue
        if depth >= MAX_CHAIN_DEPTH:
            not_modified.append(f"Profundidad máxima alcanzada antes de {child_id}")
            break

        steps.append(_phase_step("Ejecutando", f"Encadenando playbook {child_id}", "running"))
        visited.add(child_id)

        from services.playbook_service import execute_playbook
        try:
            result = execute_playbook(
                child_id,
                user_email,
                _chain_depth=depth + 1,
                _visited=visited,
                _parent_execution_id=parent_execution_id,
            )
            child_results.append(result)
            status = result.get("status", "error")
            steps[-1] = _phase_step(
                "Ejecutando",
                f"Playbook encadenado {child_id}: {result.get('message', status)[:120]}",
                "done" if status == "success" else "failed",
            )
            executed.append(f"Playbook encadenado: {child_id}")
            if status == "success":
                modified.append(f"Cadena ejecutada: {child_id}")
            else:
                not_modified.append(f"Cadena falló: {child_id} — {result.get('message', '')}")
            for m in result.get("motors_used") or []:
                motors.append(m)
        except Exception as exc:
            steps[-1] = _phase_step("Ejecutando", f"Cadena {child_id}: {exc}", "failed")
            not_modified.append(f"Error en cadena {child_id}: {exc}")

    return child_results


def sync_platform_state(user_email: Optional[str], steps: List[Dict[str, Any]], motors: List[str]) -> None:
    """Refresca métricas canónicas e inteligencia con datos reales."""
    steps.append(_phase_step("Verificando", "Sincronizando Dashboard, Inteligencia e Historial", "running"))
    try:
        from services.platform_metrics_service import get_unified_security_payload
        payload = get_unified_security_payload()
        motors.append("platform_metrics_service")
        threats = payload.get("threats_count") or payload.get("total_threats")
        vulns = payload.get("vulnerabilities_count") or payload.get("active_vulnerabilities")
        steps[-1] = _phase_step(
            "Verificando",
            f"Plataforma sincronizada — amenazas: {threats}, vulns activas: {vulns}",
            "done",
        )
    except Exception as exc:
        steps[-1] = _phase_step("Verificando", f"Sincronización parcial: {exc}", "warning")

    try:
        from services.threat_intelligence_service import ThreatIntelligenceService
        ti = ThreatIntelligenceService()
        sync = ti.sync_from_real_sources(user_email=user_email)
        motors.append("threat_intelligence_service")
        steps.append(_phase_step(
            "Verificando",
            f"Centro Inteligencia: {sync.get('created', 0)} nuevos, {sync.get('updated', 0)} actualizados",
            "done",
        ))
    except Exception as exc:
        steps.append(_phase_step("Verificando", f"Sync inteligencia: {exc}", "warning"))


def save_playbook_learning(
    playbook: Dict[str, Any],
    execution_id: str,
    summary: Dict[str, Any],
    orchestration_result: Dict[str, Any],
    user_email: Optional[str],
    chain_results: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Persiste aprendizaje real para Kernel IA y Centro de Inteligencia."""
    os.makedirs(LEARNING_DIR, exist_ok=True)
    record = {
        "execution_id": execution_id,
        "playbook_id": playbook.get("id"),
        "playbook_nombre": playbook.get("nombre"),
        "usuario": user_email,
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "resultado": summary.get("estado"),
        "nivel_exito": summary.get("nivel_exito"),
        "duracion_seg": summary.get("duracion_seg"),
        "tiempo_ms": summary.get("duracion_ms"),
        "acciones": summary.get("executed_actions") or [],
        "motores": summary.get("motors") or [],
        "modificaciones": summary.get("modified") or [],
        "no_modificadas": summary.get("not_modified") or [],
        "causa": summary.get("causa") or summary.get("resultado_texto"),
        "error": summary.get("error"),
        "capabilities_executed": orchestration_result.get("capabilities_executed") or [],
        "chain_count": len(chain_results or []),
    }
    try:
        with open(LEARNING_FILE, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.debug("playbook learning file: %s", exc)

    try:
        from services.threat_intelligence_service import ThreatIntelligenceService
        ti = ThreatIntelligenceService()
        collected = orchestration_result.get("collected") or {}
        collected["playbook_execution"] = record
        ti.ingest_kernel_operation(
            message=f"Playbook {playbook.get('id')}: {summary.get('resultado_texto', '')[:200]}",
            plan_intent=f"playbook:{playbook.get('id')}",
            engines=summary.get("motors") or [],
            collected=collected,
            user_email=user_email,
            elapsed_sec=summary.get("duracion_seg"),
            decisions=summary.get("executed_actions") or [],
        )
    except Exception as exc:
        logger.debug("playbook TI learning: %s", exc)

    try:
        from services.kernel_memory import kernel_memory
        if user_email:
            kernel_memory.record_interaction(
                None,
                user_email,
                f"Playbook {playbook.get('id')} — {summary.get('nivel_exito')}",
                "playbook_orchestration",
                summary.get("motors") or [],
                "execution",
            )
    except Exception as exc:
        logger.debug("playbook kernel memory: %s", exc)


def is_orchestrator_action(accion: str) -> bool:
    return (accion or "").lower().startswith("orchestrate")
