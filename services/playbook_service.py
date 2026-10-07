"""
Playbook persistence and execution for NOVUS automation.
Uses SQLite (database.Playbook) as the single source of truth.
"""
import json
import os
import socket
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from database import SessionLocal, Playbook, PlaybookExecution, Log
from utils.logger import logger

JSON_PLAYBOOKS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "playbooks")
_migrated = False

PHASE_LABELS = ("Preparando", "Analizando", "Ejecutando", "Verificando", "Finalizado")


def _deliver_playbook_report_to_ceo(report: dict, user_email: Optional[str]) -> None:
    try:
        from services.email_delivery_service import deliver_report_to_ceo

        deliver_report_to_ceo(report, category="playbook", trigger_user_email=user_email)
    except Exception as exc:
        logger.debug("CEO playbook report: %s", exc)


def _json_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def _serialize_playbook(record: Playbook) -> Dict[str, Any]:
    return {
        "id": record.id,
        "nombre": record.nombre,
        "trigger": record.trigger,
        "accion": record.accion,
        "prioridad": record.prioridad,
        "estado": record.estado,
        "reglas_asociadas": _json_list(record.reglas_asociadas),
        "remediaciones_asociadas": _json_list(record.remediaciones_asociadas),
        "automatizaciones_asociadas": _json_list(record.automatizaciones_asociadas),
        "kernel_respuestas": _json_list(record.kernel_respuestas),
        "ejecuciones": record.ejecuciones or 0,
        "fecha_creacion": record.fecha_creacion,
        "fecha_actualizacion": record.fecha_actualizacion,
    }


def _serialize_execution(record: PlaybookExecution) -> Dict[str, Any]:
    return {
        "id": record.id,
        "playbook_id": record.playbook_id,
        "playbook_nombre": record.playbook_nombre,
        "usuario": record.usuario,
        "estado": record.estado,
        "nivel_exito": record.nivel_exito,
        "trigger_met": bool(record.trigger_met),
        "duracion_ms": record.duracion_ms or 0,
        "duracion_seg": round((record.duracion_ms or 0) / 1000, 2),
        "resultado": record.resultado,
        "acciones": _json_list(record.acciones_json),
        "motores": _json_list(record.motores_json),
        "report_id": record.report_id,
        "fecha": record.fecha,
    }


def _phase_step(phase: str, detail: str = "", status: str = "running") -> Dict[str, Any]:
    return {
        "label": phase,
        "detail": detail,
        "status": status,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }


def _ensure_migrated():
    global _migrated
    if _migrated:
        return
    if not os.path.isdir(JSON_PLAYBOOKS_DIR):
        _migrated = True
        return
    db = SessionLocal()
    try:
        existing = db.query(Playbook).count()
        if existing > 0:
            _migrated = True
            return
        for filename in os.listdir(JSON_PLAYBOOKS_DIR):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(JSON_PLAYBOOKS_DIR, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                pb_id = data.get("id") or filename.replace(".json", "")
                if db.query(Playbook).filter(Playbook.id == pb_id).first():
                    continue
                record = Playbook(
                    id=pb_id,
                    nombre=data.get("nombre", "Playbook"),
                    trigger=data.get("trigger", "manual"),
                    accion=data.get("accion", "log"),
                    prioridad=data.get("prioridad", "Medio"),
                    estado="Activo" if str(data.get("estado", "Activo")).lower() in ("activo", "active") else "Inactivo",
                    ejecuciones=int(data.get("ejecuciones") or 0),
                    fecha_creacion=data.get("fecha_creacion") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )
                db.add(record)
            except Exception as exc:
                logger.warning(f"Playbook migration skip {filename}: {exc}")
        db.commit()
    finally:
        db.close()
    _migrated = True


def _ensure_orchestrator_catalog():
    try:
        from services.playbook_orchestrator import ensure_orchestrator_playbooks
        ensure_orchestrator_playbooks()
    except Exception as exc:
        logger.debug("orchestrator catalog: %s", exc)


def list_playbooks(active_only: bool = False, sector_key: Optional[str] = None) -> List[Dict[str, Any]]:
    _ensure_migrated()
    _ensure_orchestrator_catalog()
    db = SessionLocal()
    try:
        query = db.query(Playbook).order_by(Playbook.fecha_creacion.desc())
        if active_only:
            query = query.filter(Playbook.estado == "Activo")
        items = [_serialize_playbook(r) for r in query.all()]
    finally:
        db.close()
    if sector_key:
        from services.sector_profile_service import filter_playbooks_for_sector
        return filter_playbooks_for_sector(items, sector_key)
    return items


def get_playbook(playbook_id: str) -> Optional[Dict[str, Any]]:
    _ensure_migrated()
    db = SessionLocal()
    try:
        record = db.query(Playbook).filter(Playbook.id == playbook_id).first()
        return _serialize_playbook(record) if record else None
    finally:
        db.close()


def list_executions(playbook_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    _ensure_migrated()
    db = SessionLocal()
    try:
        query = db.query(PlaybookExecution).order_by(PlaybookExecution.fecha.desc())
        if playbook_id:
            query = query.filter(PlaybookExecution.playbook_id == playbook_id)
        return [_serialize_execution(r) for r in query.limit(limit).all()]
    finally:
        db.close()


def get_execution(execution_id: str) -> Optional[Dict[str, Any]]:
    _ensure_migrated()
    db = SessionLocal()
    try:
        record = db.query(PlaybookExecution).filter(PlaybookExecution.id == execution_id).first()
        return _serialize_execution(record) if record else None
    finally:
        db.close()


def create_playbook(data: Dict[str, Any]) -> Dict[str, Any]:
    _ensure_migrated()
    db = SessionLocal()
    try:
        pb_id = data.get("id") or f"PB-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        record = Playbook(
            id=pb_id,
            nombre=data.get("nombre", "Nuevo Playbook"),
            trigger=data.get("trigger", "manual"),
            accion=data.get("accion", "log"),
            prioridad=data.get("prioridad", "Medio"),
            estado=data.get("estado", "Activo"),
            reglas_asociadas=json.dumps(data.get("reglas_asociadas") or []),
            remediaciones_asociadas=json.dumps(data.get("remediaciones_asociadas") or []),
            automatizaciones_asociadas=json.dumps(data.get("automatizaciones_asociadas") or []),
            kernel_respuestas=json.dumps(data.get("kernel_respuestas") or []),
            ejecuciones=0,
            fecha_creacion=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return _serialize_playbook(record)
    finally:
        db.close()


def update_playbook(playbook_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    _ensure_migrated()
    db = SessionLocal()
    try:
        record = db.query(Playbook).filter(Playbook.id == playbook_id).first()
        if not record:
            return None
        for field in ("nombre", "trigger", "accion", "prioridad", "estado"):
            if field in data and data[field] is not None:
                setattr(record, field, data[field])
        for field in ("reglas_asociadas", "remediaciones_asociadas", "automatizaciones_asociadas", "kernel_respuestas"):
            if field in data:
                setattr(record, field, json.dumps(data[field] or []))
        record.fecha_actualizacion = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.commit()
        db.refresh(record)
        return _serialize_playbook(record)
    finally:
        db.close()


def delete_playbook(playbook_id: str) -> bool:
    _ensure_migrated()
    db = SessionLocal()
    try:
        record = db.query(Playbook).filter(Playbook.id == playbook_id).first()
        if not record:
            return False
        db.delete(record)
        db.commit()
        return True
    finally:
        db.close()


def duplicate_playbook(playbook_id: str) -> Optional[Dict[str, Any]]:
    source = get_playbook(playbook_id)
    if not source:
        return None
    new_id = f"PB-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    return create_playbook({
        **source,
        "id": new_id,
        "nombre": f"{source['nombre']} (copia)",
        "ejecuciones": 0,
        "estado": source.get("estado", "Activo"),
    })


def toggle_playbook(playbook_id: str, active: Optional[bool] = None) -> Optional[Dict[str, Any]]:
    record = get_playbook(playbook_id)
    if not record:
        return None
    new_state = "Activo" if (active if active is not None else record["estado"] != "Activo") else "Inactivo"
    return update_playbook(playbook_id, {"estado": new_state})


def _evaluate_trigger(playbook: Dict[str, Any], steps: List[Dict[str, Any]]) -> Tuple[bool, str]:
    from services.novus_security_integration import novus_security
    import psutil

    trigger = playbook.get("trigger", "manual")
    if trigger == "manual":
        steps.append(_phase_step("Analizando", "Trigger manual — ejecución autorizada", "done"))
        return True, "Trigger manual"

    detail = ""
    trigger_met = True
    if trigger == "cpu_high":
        cpu = psutil.cpu_percent(interval=0.5)
        trigger_met = cpu > 80
        detail = f"CPU actual: {cpu:.1f}% (umbral > 80%)"
    elif trigger == "memory_high":
        mem = psutil.virtual_memory().percent
        trigger_met = mem > 80
        detail = f"Memoria actual: {mem:.1f}% (umbral > 80%)"
    elif trigger == "disk_low":
        from utils.host_data import get_disk_usage
        disk = get_disk_usage()
        trigger_met = disk.percent > 85
        detail = f"Disco usado: {disk.percent:.1f}% (umbral > 85%)"
    elif trigger in ("suspicious_conn", "port_scan"):
        threats = novus_security.detect_threats_realtime()
        count = len(threats.get("suspicious_processes") or [])
        trigger_met = count > 0
        detail = f"Procesos sospechosos detectados: {count} (requiere ≥ 1)"
    else:
        detail = f"Trigger '{trigger}' no reconocido — se tratará como no cumplido"
        trigger_met = False

    steps.append(_phase_step(
        "Analizando",
        detail,
        "done" if trigger_met else "warning",
    ))
    return trigger_met, detail


def _run_primary_action(
    playbook: Dict[str, Any],
    user_email: Optional[str],
    steps: List[Dict[str, Any]],
    motors: List[str],
    executed: List[str],
    modified: List[str],
    not_modified: List[str],
) -> Dict[str, Any]:
    from services.novus_security_integration import novus_security
    import psutil

    accion = playbook.get("accion", "log")
    motors.append("playbook_service")
    action_result: Dict[str, Any] = {"status": "success", "message": ""}

    if accion == "optimize_memory":
        motors.append("novus_security_integration.memory_optimize")
        action_result = novus_security.execute_automation("memory_optimize")
        executed.append("Optimización de memoria (limpieza temporal)")
        if action_result.get("status") == "success":
            modified.append("Archivos temporales del sistema")
        else:
            not_modified.append(f"Memoria: {action_result.get('message', 'sin cambios')}")

    elif accion == "kill_process":
        motors.append("novus_security_integration.process_terminate")
        target = None
        for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
            try:
                if (proc.info.get("cpu_percent") or 0) > 80:
                    target = proc.info
                    break
            except Exception:
                pass
        if target:
            action_result = novus_security.execute_automation(
                "process_terminate", {"pid": target["pid"]}
            )
            executed.append(f"Terminar proceso {target.get('name')} PID {target.get('pid')}")
            if action_result.get("status") == "success":
                modified.append(f"Proceso PID {target.get('pid')} terminado")
            else:
                not_modified.append(
                    f"No se pudo terminar PID {target.get('pid')}: {action_result.get('message', '')}"
                )
        else:
            action_result = {
                "status": "success",
                "message": "No hay procesos con CPU > 80% en este momento",
            }
            not_modified.append("Ningún proceso superó el umbral CPU > 80%")

    elif accion == "sector_shield_scan":
        from services.sector_shield_service import scan_sector
        motors.append("sector_shield_service")
        scan_result = scan_sector(user_email)
        action_result = {
            "status": scan_result.get("status", "success"),
            "message": scan_result.get("message", "Escaneo sectorial completado"),
        }
        executed.append("Escaneo sectorial NOVUS")
        steps.extend(scan_result.get("steps") or [])
        if scan_result.get("status") == "success":
            modified.append("Estado sectorial actualizado en escudo NOVUS")
        else:
            not_modified.append(scan_result.get("message", "Escaneo sectorial incompleto"))

    elif accion == "block_ip":
        motors.append("database.IPBloqueada")
        from database import IPBloqueada
        threats = novus_security.detect_threats_realtime()
        blocked_ips: List[str] = []
        db = SessionLocal()
        try:
            for proc in (threats.get("suspicious_processes") or [])[:5]:
                pid = proc.get("pid")
                if not pid:
                    continue
                try:
                    p = psutil.Process(pid)
                    for conn in p.connections(kind="inet"):
                        rip = getattr(conn.raddr, "ip", None) if conn.raddr else None
                        if not rip or rip.startswith("127.") or rip.startswith("0."):
                            continue
                        existing = db.query(IPBloqueada).filter(
                            IPBloqueada.direccion_ip == rip
                        ).first()
                        if not existing:
                            db.add(IPBloqueada(
                                direccion_ip=rip,
                                razon=f"Playbook {playbook.get('id')}: proceso sospechoso {proc.get('name')}",
                            ))
                            blocked_ips.append(rip)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            db.commit()
        finally:
            db.close()
        if blocked_ips:
            action_result = {
                "status": "success",
                "message": f"IP(s) registradas en lista de bloqueo: {', '.join(blocked_ips)}",
            }
            executed.append(f"Bloqueo de IP: {', '.join(blocked_ips)}")
            modified.extend(blocked_ips)
        else:
            action_result = {
                "status": "warning",
                "message": (
                    "No se encontraron IPs remotas bloqueables en procesos sospechosos actuales. "
                    "Verifique que existan conexiones salientes activas asociadas a amenazas."
                ),
            }
            not_modified.append("Sin IPs remotas bloqueables en el escaneo actual")

    elif accion == "alert":
        motors.append("novus_security_integration.threat_registry")
        novus_security._register_runtime_threat(
            "playbook_alert",
            "playbook_service",
            "MEDIUM",
            {"playbook": playbook.get("id"), "nombre": playbook.get("nombre")},
        )
        action_result = {"status": "success", "message": "Alerta registrada en motor de amenazas NOVUS"}
        executed.append("Registro de alerta en Threat Registry")
        modified.append("Alerta runtime persistida en base de datos")

    elif accion == "log":
        motors.append("database.Log")
        action_result = {"status": "success", "message": "Evento registrado en log de automatización"}
        executed.append("Registro en log del sistema")
        modified.append("Entrada de auditoría en logs NOVUS")

    elif str(accion).lower().startswith("orchestrate"):
        from services.playbook_orchestrator import run_orchestration_for_playbook
        orch = run_orchestration_for_playbook(
            playbook, user_email, steps, motors, executed, modified, not_modified,
        )
        action_result = {
            "status": orch.get("status", "success"),
            "message": f"Orquestación NOVUS — {len(orch.get('capabilities_executed') or [])} componente(s) coordinados",
            "orchestration": orch,
        }

    else:
        action_result = {
            "status": "error",
            "message": f"Acción '{accion}' no está implementada en el motor de playbooks",
        }
        not_modified.append(f"Acción desconocida: {accion}")

    steps.append(_phase_step(
        "Ejecutando",
        action_result.get("message", accion),
        "done" if action_result.get("status") == "success" else "failed",
    ))
    return action_result


def _run_associated_remediations(
    finding_ids: List[str],
    user_email: Optional[str],
    steps: List[Dict[str, Any]],
    motors: List[str],
    executed: List[str],
    modified: List[str],
    not_modified: List[str],
) -> None:
    if not finding_ids:
        return
    from services.remediation_engine import remediate_vulnerability

    motors.append("remediation_orchestrator")
    for fid in finding_ids:
        fid = str(fid).strip()
        if not fid:
            continue
        try:
            result = remediate_vulnerability(fid, executed_by=user_email)
            status = result.get("status", "error")
            msg = result.get("message") or result.get("error") or "Sin detalle"
            steps.append(_phase_step(
                "Ejecutando",
                f"Remediación {fid}: {msg}",
                "done" if status == "success" else "failed",
            ))
            executed.append(f"Remediación automática {fid}")
            if status == "success":
                modified.append(f"Hallazgo {fid} remediado")
            else:
                not_modified.append(f"Hallazgo {fid}: {msg}")
            for s in result.get("steps") or []:
                steps.append(s)
        except Exception as exc:
            steps.append(_phase_step("Ejecutando", f"Remediación {fid} falló: {exc}", "failed"))
            not_modified.append(f"Remediación {fid}: {exc}")


def _run_associated_rules(
    rule_ids: List[str],
    steps: List[Dict[str, Any]],
    motors: List[str],
    executed: List[str],
) -> None:
    if not rule_ids:
        return
    from services.novus_security_integration import novus_security

    motors.append("novus_security_integration")
    for rule_id in rule_ids:
        rule_id = str(rule_id).strip().upper()
        if not rule_id:
            continue
        try:
            if "THREAT" in rule_id or "MEM" in rule_id:
                data = novus_security.detect_threats_realtime()
                count = len(data.get("suspicious_processes") or []) + len(data.get("threats") or [])
                detail = f"Regla {rule_id}: {count} indicador(es) de amenaza en vivo"
            elif "CPU" in rule_id:
                import psutil
                detail = f"Regla {rule_id}: CPU {psutil.cpu_percent(interval=0.3):.1f}%"
            else:
                detail = f"Regla {rule_id}: evaluada contra telemetría NOVUS"
            steps.append(_phase_step("Analizando", detail, "done"))
            executed.append(f"Evaluación regla {rule_id}")
        except Exception as exc:
            steps.append(_phase_step("Analizando", f"Regla {rule_id}: {exc}", "failed"))


def _run_kernel_capabilities(
    cap_ids: List[str],
    user_email: Optional[str],
    steps: List[Dict[str, Any]],
    motors: List[str],
    executed: List[str],
    modified: List[str],
    not_modified: List[str],
) -> None:
    if not cap_ids:
        return
    try:
        from services.ai_capability_registry import capability_registry
        motors.append("ai_capability_registry")
        result = capability_registry.execute(cap_ids, user_id=user_email)
        executed_caps = result.get("capabilities_executed") or []
        failed_caps = result.get("capabilities_failed") or []
        for cap in executed_caps:
            executed.append(f"Capacidad Kernel: {cap}")
            modified.append(f"Motor {cap} consultado")
        for cap in failed_caps:
            not_modified.append(f"Capacidad Kernel {cap} no disponible o falló")
        steps.append(_phase_step(
            "Ejecutando",
            f"Kernel IA: {len(executed_caps)} capacidad(es) OK, {len(failed_caps)} fallida(s)",
            "done" if executed_caps else "warning",
        ))
    except Exception as exc:
        steps.append(_phase_step("Ejecutando", f"Kernel IA: {exc}", "failed"))
        not_modified.append(f"Capacidades Kernel: {exc}")


def _compute_success_level(
    action_result: Dict[str, Any],
    modified: List[str],
    not_modified: List[str],
    trigger_met: bool,
) -> str:
    if not trigger_met:
        return "Nulo"
    if action_result.get("status") == "error":
        return "Bajo"
    if modified and not not_modified:
        return "Alto"
    if modified and not_modified:
        return "Medio"
    if action_result.get("status") == "success":
        return "Medio"
    return "Bajo"


def _build_playbook_report(
    playbook: Dict[str, Any],
    execution_id: str,
    steps: List[Dict[str, Any]],
    summary: Dict[str, Any],
    user_email: Optional[str],
) -> Dict[str, Any]:
    now = datetime.now()
    report_id = f"PB-RPT-{now.strftime('%Y%m%d%H%M%S')}"
    hostname = socket.gethostname()
    tech = {
        "tipo_vulnerabilidad": "Ejecución de Playbook",
        "que_ocurrio": summary.get("resultado_texto", ""),
        "descripcion_tecnica": (
            f"Playbook {playbook.get('id')} — trigger {playbook.get('trigger')}, "
            f"acción {playbook.get('accion')}, prioridad {playbook.get('prioridad')}"
        ),
        "descripcion_sencilla": summary.get("resultado_texto", ""),
        "evidencias": [
            f"[{s.get('timestamp')}] {s.get('label')}: {s.get('detail', '')}"
            for s in steps
        ],
        "acciones_automaticas": summary.get("executed_actions") or [],
        "acciones_no_realizadas": summary.get("not_modified") or [],
        "modificaciones_realizadas": summary.get("modified") or [],
        "motores_utilizados": summary.get("motors") or [],
        "nivel_confianza": summary.get("nivel_exito", "Medio"),
        "motor": ", ".join(summary.get("motors") or ["playbook_service"]),
        "origen": f"Ejecución manual/automática por {user_email or 'sistema NOVUS'}",
        "riesgo_sistema": playbook.get("prioridad", "Medio"),
        "consecuencias": summary.get("resultado_texto", ""),
        "linea_tiempo": [
            {"hora": s.get("timestamp"), "evento": f"{s.get('label')}: {s.get('detail', '')}"}
            for s in steps
        ],
        "recomendaciones": [
            "Revise el historial de ejecución en Automatización NOVUS.",
            "Valide en Vulnerabilidades/Incidentes si los hallazgos asociados cambiaron de estado.",
        ],
        "observaciones": (
            f"Duración: {summary.get('duracion_seg', 0)}s. "
            f"Nivel de éxito: {summary.get('nivel_exito')}. "
            f"ID ejecución: {execution_id}."
        ),
    }
    estado = "Completado" if summary.get("estado") == "exitoso" else summary.get("estado", "Completado")
    return {
        "id": report_id,
        "finding_id": playbook.get("id"),
        "tipo": "Playbook",
        "fecha": now.strftime("%Y-%m-%d %H:%M:%S"),
        "severidad": playbook.get("prioridad", "Medio"),
        "estado": estado,
        "equipo_afectado": hostname,
        "tiempo_resolucion": f"{summary.get('duracion_seg', 0)}s",
        "resumen_ejecutivo": summary.get("resultado_texto", ""),
        "technical": tech,
        "conclusiones": summary.get("resultado_texto", ""),
        "remediation_log": steps,
        "playbook_execution_id": execution_id,
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
    }


def _persist_execution(
    execution_id: str,
    playbook: Dict[str, Any],
    user_email: Optional[str],
    summary: Dict[str, Any],
    report_id: Optional[str],
) -> None:
    db = SessionLocal()
    try:
        record = PlaybookExecution(
            id=execution_id,
            playbook_id=playbook["id"],
            playbook_nombre=playbook.get("nombre", ""),
            usuario=user_email,
            estado=summary.get("estado", "exitoso"),
            nivel_exito=summary.get("nivel_exito", "Medio"),
            trigger_met=bool(summary.get("trigger_met")),
            duracion_ms=int(summary.get("duracion_ms") or 0),
            resultado=summary.get("resultado_texto", ""),
            acciones_json=json.dumps(summary.get("executed_actions") or [], ensure_ascii=False),
            motores_json=json.dumps(summary.get("motors") or [], ensure_ascii=False),
            report_id=report_id,
            fecha=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        db.add(record)
        db.add(Log(
            evento="playbook_execution",
            detalle=(
                f"{playbook['id']} | {summary.get('estado')} | "
                f"{summary.get('nivel_exito')} | {summary.get('duracion_seg')}s | "
                f"{summary.get('resultado_texto', '')[:500]}"
            ),
            fecha=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ))
        db.commit()
    finally:
        db.close()


def _increment_executions(playbook_id: str):
    db = SessionLocal()
    try:
        record = db.query(Playbook).filter(Playbook.id == playbook_id).first()
        if record:
            record.ejecuciones = (record.ejecuciones or 0) + 1
            record.fecha_actualizacion = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            db.commit()
    finally:
        db.close()


def execute_playbook(
    playbook_id: str,
    user_email: Optional[str] = None,
    *,
    _chain_depth: int = 0,
    _visited: Optional[Set[str]] = None,
    _parent_execution_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Ejecuta un playbook completo con orquestación, cadenas, auditoría e informe."""
    from services.playbook_orchestrator import (
        MAX_CHAIN_DEPTH,
        is_orchestrator_action,
        run_chained_playbooks,
        run_orchestration_for_playbook,
        save_playbook_learning,
        sync_platform_state,
    )

    visited: Set[str] = set(_visited or [])
    if playbook_id in visited and _chain_depth > 0:
        return {
            "status": "error",
            "message": f"Ciclo detectado en cadena de playbooks: {playbook_id}",
            "error_detail": "CHAIN_CYCLE",
            "steps": [],
        }
    visited.add(playbook_id)

    started = time.time()
    execution_id = f"PBX-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"

    playbook = get_playbook(playbook_id)
    if not playbook:
        return {
            "status": "error",
            "message": f"Playbook '{playbook_id}' no existe en la base de datos NOVUS",
            "steps": [],
            "error_detail": "PLAYBOOK_NOT_FOUND",
        }
    if playbook.get("estado") != "Activo":
        return {
            "status": "error",
            "message": f"El playbook '{playbook.get('nombre')}' está inactivo. Actívelo antes de ejecutar.",
            "steps": [],
            "error_detail": "PLAYBOOK_INACTIVE",
        }

    steps: List[Dict[str, Any]] = []
    motors: List[str] = []
    executed: List[str] = []
    modified: List[str] = []
    not_modified: List[str] = []

    steps.append(_phase_step(
        "Preparando",
        f"Cargando playbook «{playbook.get('nombre')}» ({playbook_id})",
        "done",
    ))

    trigger_met, trigger_detail = _evaluate_trigger(playbook, steps)

    if playbook.get("trigger") != "manual" and not trigger_met:
        duracion_ms = int((time.time() - started) * 1000)
        resultado = (
            f"Trigger no cumplido: {trigger_detail}. "
            "No se ejecutaron acciones para evitar respuesta innecesaria."
        )
        summary = {
            "estado": "sin_accion",
            "nivel_exito": "Nulo",
            "trigger_met": False,
            "duracion_ms": duracion_ms,
            "duracion_seg": round(duracion_ms / 1000, 2),
            "resultado_texto": resultado,
            "executed_actions": [],
            "motors": motors,
            "modified": [],
            "not_modified": [resultado],
        }
        steps.append(_phase_step("Finalizado", resultado, "warning"))
        report = _build_playbook_report(playbook, execution_id, steps, summary, user_email)
        from services.security_report_service import save_report
        save_report(report)
        try:
            from services.report_pdf_service import generate_pdf
            generate_pdf(report)
        except Exception as pdf_exc:
            logger.debug("playbook pdf (sin acción): %s", pdf_exc)
        _deliver_playbook_report_to_ceo(report, user_email)
        _persist_execution(execution_id, playbook, user_email, summary, report["id"])
        return {
            "status": "success",
            "message": resultado,
            "trigger_met": False,
            "steps": steps,
            "playbook_id": playbook_id,
            "execution_id": execution_id,
            "report_id": report["id"],
            "duration_seconds": summary["duracion_seg"],
            "success_level": "Nulo",
            "motors_used": motors,
        }

    _run_associated_rules(playbook.get("reglas_asociadas") or [], steps, motors, executed)

    action_result = _run_primary_action(
        playbook, user_email, steps, motors, executed, modified, not_modified
    )
    orchestration_result: Dict[str, Any] = action_result.get("orchestration") or {}

    if not is_orchestrator_action(playbook.get("accion", "")):
        orchestration_result = run_orchestration_for_playbook(
            playbook, user_email, steps, motors, executed, modified, not_modified,
        )

    _run_associated_remediations(
        playbook.get("remediaciones_asociadas") or [],
        user_email,
        steps,
        motors,
        executed,
        modified,
        not_modified,
    )

    kernel_caps = [
        c for c in (playbook.get("kernel_respuestas") or [])
        if c not in (orchestration_result.get("capabilities_executed") or [])
    ]
    if kernel_caps and not is_orchestrator_action(playbook.get("accion", "")):
        _run_kernel_capabilities(
            kernel_caps,
            user_email,
            steps,
            motors,
            executed,
            modified,
            not_modified,
        )

    chain_ids = [
        x for x in (playbook.get("automatizaciones_asociadas") or [])
        if str(x).strip().startswith("PB-")
    ]
    chain_results: List[Dict[str, Any]] = []
    if chain_ids and _chain_depth < MAX_CHAIN_DEPTH:
        chain_results = run_chained_playbooks(
            chain_ids,
            user_email,
            steps,
            motors,
            executed,
            modified,
            not_modified,
            depth=_chain_depth,
            visited=visited,
            parent_execution_id=execution_id,
        )

    if _chain_depth == 0:
        sync_platform_state(user_email, steps, motors)

    steps.append(_phase_step("Verificando", "Comprobando resultados de acciones ejecutadas", "running"))
    verify_detail = (
        f"{len(modified)} modificación(es), {len(not_modified)} sin cambio o pendiente(s)"
    )
    steps[-1] = _phase_step("Verificando", verify_detail, "done")

    duracion_ms = int((time.time() - started) * 1000)
    duracion_seg = round(duracion_ms / 1000, 2)
    nivel_exito = _compute_success_level(action_result, modified, not_modified, trigger_met)

    if action_result.get("status") == "error":
        estado = "error"
        resultado = action_result.get("message") or "La acción principal del playbook falló"
        causa = action_result.get("message") or "Acción principal falló"
    elif not_modified and not modified:
        estado = "parcial"
        resultado = action_result.get("message") or "Playbook completado sin modificaciones en el sistema"
        causa = None
    else:
        estado = "exitoso"
        resultado = action_result.get("message") or "Playbook ejecutado correctamente"
        causa = None

    if chain_results:
        executed.append(f"{len(chain_results)} playbook(s) encadenado(s)")

    steps.append(_phase_step(
        "Finalizado",
        f"{resultado} — Tiempo: {duracion_seg}s — Éxito: {nivel_exito}",
        "done" if estado == "exitoso" else "warning" if estado == "parcial" else "failed",
    ))

    summary = {
        "estado": estado,
        "nivel_exito": nivel_exito,
        "trigger_met": trigger_met,
        "duracion_ms": duracion_ms,
        "duracion_seg": duracion_seg,
        "resultado_texto": resultado,
        "executed_actions": executed,
        "motors": list(dict.fromkeys(motors)),
        "modified": modified,
        "not_modified": not_modified,
        "causa": causa,
        "error": causa if estado == "error" else None,
    }

    report = _build_playbook_report(playbook, execution_id, steps, summary, user_email)
    from services.security_report_service import save_report
    save_report(report)
    try:
        from services.report_pdf_service import generate_pdf
        generate_pdf(report)
    except Exception as pdf_exc:
        logger.warning("playbook pdf: %s", pdf_exc)

    _deliver_playbook_report_to_ceo(report, user_email)
    _persist_execution(execution_id, playbook, user_email, summary, report["id"])
    if _chain_depth == 0:
        save_playbook_learning(
            playbook, execution_id, summary, orchestration_result, user_email, chain_results,
        )
    _increment_executions(playbook_id)

    try:
        from services.network_event_log import network_event_log
        network_event_log.record(
            f"Playbook {playbook_id} ejecutado — {estado} — {duracion_seg}s — {nivel_exito}",
            level="info" if estado == "exitoso" else "alert",
        )
    except Exception:
        pass

    return {
        "status": "success" if estado != "error" else "error",
        "message": resultado,
        "trigger_met": trigger_met,
        "steps": steps,
        "playbook_id": playbook_id,
        "execution_id": execution_id,
        "report_id": report["id"],
        "duration_seconds": duracion_seg,
        "success_level": nivel_exito,
        "motors_used": summary["motors"],
        "executed_actions": executed,
        "modified": modified,
        "not_modified": not_modified,
        "error_detail": action_result.get("message") if estado == "error" else None,
        "chain_results": [{"playbook_id": c.get("playbook_id"), "status": c.get("status")} for c in chain_results],
        "orchestration_components": orchestration_result.get("capabilities_executed") or [],
    }
