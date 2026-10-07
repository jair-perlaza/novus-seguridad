"""
Orquestador de remediación — agota estrategias automáticas antes de guía manual.
"""
from __future__ import annotations

import os
import platform
import subprocess
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil

from services.manual_remediation_guide import build_manual_guide
from services.security_report_service import (
    ensure_report_for_finding,
    get_report_by_finding,
    update_report_status,
)
from utils.logger import logger

NO_DATA = "Sin datos disponibles"


def _step(label, status="done", detail="", error=None):
    return {
        "label": label,
        "status": status,
        "detail": detail,
        "error": error,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }


def _port_from_id(vulnerability_id: str, finding: dict) -> Optional[int]:
    from services.manual_remediation_guide import _port_from_finding
    return _port_from_finding({"id": vulnerability_id, **finding})


def _pid_from_id(vulnerability_id: str, finding: dict) -> Optional[int]:
    from services.manual_remediation_guide import _pid_from_finding
    return _pid_from_finding({"id": vulnerability_id, **finding})


def _verify(vulnerability_id: str, finding: dict) -> dict:
    from services.vulnerability_analyst_service import verify_finding_absent
    return verify_finding_absent(vulnerability_id, finding, force_fresh=True)


def _strategy_terminate_port_owner(vulnerability_id: str, finding: dict) -> Tuple[List[dict], str]:
    steps = []
    port = _port_from_id(vulnerability_id, finding)
    if not port:
        return steps, "Puerto no identificado"
    steps.append(_step(f"Estrategia: terminar proceso dueño del puerto {port}", "running"))
    terminated = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port == port and conn.status == "LISTEN" and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    name = proc.name()
                    proc.terminate()
                    proc.wait(timeout=5)
                    terminated.append(f"{name} (PID {conn.pid})")
                except psutil.NoSuchProcess:
                    terminated.append(f"PID {conn.pid} ya no existe")
                except psutil.AccessDenied as exc:
                    steps[-1] = _step(steps[-1]["label"], "failed", error=str(exc),
                                       detail="Permisos insuficientes para terminar el proceso.")
                    return steps, str(exc)
    except (psutil.AccessDenied, psutil.Error) as exc:
        steps[-1] = _step(steps[-1]["label"], "failed", error=str(exc))
        return steps, str(exc)
    detail = f"Procesos terminados: {', '.join(terminated)}" if terminated else "Ningún proceso identificado en LISTEN"
    steps[-1] = _step(steps[-1]["label"], "done", detail)
    return steps, ""


def _strategy_kill_port_owner(vulnerability_id: str, finding: dict) -> Tuple[List[dict], str]:
    steps = []
    port = _port_from_id(vulnerability_id, finding)
    if not port:
        return steps, "Puerto no identificado"
    steps.append(_step(f"Estrategia: forzar cierre (kill) puerto {port}", "running"))
    killed = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port == port and conn.status == "LISTEN" and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    name = proc.name()
                    proc.kill()
                    killed.append(f"{name} (PID {conn.pid})")
                except psutil.NoSuchProcess:
                    pass
                except psutil.AccessDenied as exc:
                    steps[-1] = _step(steps[-1]["label"], "failed", error=str(exc))
                    return steps, str(exc)
    except (psutil.AccessDenied, psutil.Error) as exc:
        steps[-1] = _step(steps[-1]["label"], "failed", error=str(exc))
        return steps, str(exc)
    steps[-1] = _step(steps[-1]["label"], "done",
                       f"Kill enviado: {', '.join(killed)}" if killed else "Sin proceso para kill")
    return steps, ""


def _strategy_firewall_block_port(vulnerability_id: str, finding: dict) -> Tuple[List[dict], str]:
    steps = []
    if platform.system() != "Windows":
        steps.append(_step("Estrategia: regla firewall", "done", "Omitida — solo Windows soporta netsh advfirewall"))
        return steps, "Plataforma no Windows"
    port = _port_from_id(vulnerability_id, finding)
    if not port:
        return steps, "Puerto no identificado"
    rule_name = f"NOVUS-Block-TCP-{port}-In"
    steps.append(_step(f"Estrategia: regla firewall bloqueando TCP {port} entrante", "running"))
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            capture_output=True, timeout=10,
        )
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", "protocol=TCP",
                f"localport={port}", "enable=yes",
            ],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            steps[-1] = _step(steps[-1]["label"], "done", f"Regla '{rule_name}' creada.")
        else:
            err = result.stderr or result.stdout or "Error netsh"
            steps[-1] = _step(steps[-1]["label"], "failed", detail=err)
            return steps, err
    except Exception as exc:
        steps[-1] = _step(steps[-1]["label"], "failed", error=str(exc))
        return steps, str(exc)
    return steps, ""


def _strategy_stop_windows_service(vulnerability_id: str, finding: dict) -> Tuple[List[dict], str]:
    steps = []
    if platform.system() != "Windows":
        return steps, "Solo Windows"
    port = _port_from_id(vulnerability_id, finding)
    from services.manual_remediation_guide import _port_owner_details, _windows_service_for_pid
    owners = _port_owner_details(port) if port else []
    if not owners:
        steps.append(_step("Estrategia: detener servicio Windows", "done", "Sin servicio identificado para el puerto"))
        return steps, "Sin servicio"
    svc = owners[0].get("nombre_servicio")
    if not svc or svc == "N/A":
        pid = owners[0].get("pid")
        svc = _windows_service_for_pid(pid) if pid else None
    if not svc:
        steps.append(_step("Estrategia: detener servicio Windows", "done", "Nombre de servicio no disponible"))
        return steps, "Servicio no identificado"
    steps.append(_step(f"Estrategia: detener servicio '{svc}'", "running"))
    try:
        result = subprocess.run(["sc", "stop", svc], capture_output=True, text=True, timeout=30)
        out = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0 or "STOP_PENDING" in out:
            steps[-1] = _step(steps[-1]["label"], "done", f"Servicio '{svc}' detenido.")
        else:
            steps[-1] = _step(steps[-1]["label"], "failed", detail=out.strip()[:300])
            return steps, out.strip()
    except Exception as exc:
        steps[-1] = _step(steps[-1]["label"], "failed", error=str(exc))
        return steps, str(exc)
    return steps, ""


def _strategy_terminate_process(vulnerability_id: str, finding: dict) -> Tuple[List[dict], str]:
    steps = []
    pid = _pid_from_id(vulnerability_id, finding)
    if not pid:
        return steps, "PID no identificado"
    steps.append(_step(f"Estrategia: terminate PID {pid}", "running"))
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.terminate()
        proc.wait(timeout=5)
        steps[-1] = _step(steps[-1]["label"], "done", f"Proceso {name} (PID {pid}) terminado.")
    except psutil.NoSuchProcess:
        steps[-1] = _step(steps[-1]["label"], "done", "Proceso ya no existe.")
    except psutil.AccessDenied as exc:
        steps[-1] = _step(steps[-1]["label"], "failed", error=str(exc))
        return steps, str(exc)
    except Exception as exc:
        steps[-1] = _step(steps[-1]["label"], "failed", error=str(exc))
        return steps, str(exc)
    return steps, ""


def _strategy_kill_process(vulnerability_id: str, finding: dict) -> Tuple[List[dict], str]:
    steps = []
    pid = _pid_from_id(vulnerability_id, finding)
    if not pid:
        return steps, "PID no identificado"
    steps.append(_step(f"Estrategia: kill forzado PID {pid}", "running"))
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.kill()
        steps[-1] = _step(steps[-1]["label"], "done", f"Kill enviado a {name} (PID {pid}).")
    except psutil.NoSuchProcess:
        steps[-1] = _step(steps[-1]["label"], "done", "Proceso ya no existe.")
    except psutil.AccessDenied as exc:
        steps[-1] = _step(steps[-1]["label"], "failed", error=str(exc))
        return steps, str(exc)
    except Exception as exc:
        steps[-1] = _step(steps[-1]["label"], "failed", error=str(exc))
        return steps, str(exc)
    return steps, ""


def _strategy_enable_firewall(vulnerability_id: str, finding: dict) -> Tuple[List[dict], str]:
    steps = []
    if platform.system() != "Windows":
        return steps, "Solo Windows"
    steps.append(_step("Estrategia: activar firewall Windows (netsh)", "running"))
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            steps[-1] = _step(steps[-1]["label"], "done", "Firewall activado en todos los perfiles.")
        else:
            err = result.stderr or result.stdout
            steps[-1] = _step(steps[-1]["label"], "failed", detail=err)
            return steps, err
    except Exception as exc:
        steps[-1] = _step(steps[-1]["label"], "failed", error=str(exc))
        return steps, str(exc)
    return steps, ""


def _strategy_restrict_file_permissions(vulnerability_id: str, finding: dict) -> Tuple[List[dict], str]:
    steps = []
    ev = finding.get("evidencia") or {}
    path = ev.get("archivo") or finding.get("file")
    if not path or not os.path.exists(str(path)):
        return steps, "Archivo no encontrado"
    if platform.system() == "Windows":
        steps.append(_step("Estrategia: permisos de archivo", "done",
                           "En Windows los permisos requieren icacls manual — ver guía."))
        return steps, "ACL Windows requiere intervención manual"
    steps.append(_step(f"Estrategia: chmod restrictivo en {path}", "running"))
    try:
        os.chmod(str(path), 0o640)
        steps[-1] = _step(steps[-1]["label"], "done", f"Permisos cambiados a 640 en {path}")
    except Exception as exc:
        steps[-1] = _step(steps[-1]["label"], "failed", error=str(exc))
        return steps, str(exc)
    return steps, ""


def _select_strategies(vulnerability_id: str, finding: dict) -> List[Tuple[str, Callable]]:
    fid = vulnerability_id
    tipo = finding.get("tipo") or ""

    if "FIND-PORT-" in fid or "PORT-" in fid:
        return [
            ("terminate_port_owner", _strategy_terminate_port_owner),
            ("kill_port_owner", _strategy_kill_port_owner),
            ("firewall_block_inbound", _strategy_firewall_block_port),
            ("stop_windows_service", _strategy_stop_windows_service),
        ]
    if "FIND-PROC-" in fid or fid.startswith("PROC-"):
        return [
            ("terminate_process", _strategy_terminate_process),
            ("kill_process", _strategy_kill_process),
        ]
    if tipo == "firewall_disabled" or "firewall" in str(finding.get("nombre") or "").lower():
        return [("enable_firewall", _strategy_enable_firewall)]
    if tipo == "file_permissions":
        ev = finding.get("evidencia") or {}
        if ev.get("archivo"):
            return [("restrict_permissions", _strategy_restrict_file_permissions)]
    ev = finding.get("evidencia") or {}
    if ev.get("archivo"):
        return [("restrict_permissions", _strategy_restrict_file_permissions)]
    return []


def run_auto_remediation(vulnerability_id: str, finding: dict, executed_by: Optional[str] = None, skip_adaptive: bool = False) -> dict:
    """
    Ejecuta todas las estrategias automáticas compatibles hasta resolver o agotar opciones.
    """
    from services.vulnerability_analyst_service import (
        record_remediation,
        sync_platform_after_remediation,
    )

    start = time.time()
    all_steps: List[dict] = []
    strategies_attempted: List[dict] = []
    failure_reasons: List[str] = []

    all_steps.append(_step("Análisis de vulnerabilidad", "done", f"ID: {vulnerability_id}"))
    strategies = _select_strategies(vulnerability_id, finding)
    all_steps.append(_step(
        "Estrategias automáticas identificadas", "done",
        f"{len(strategies)} método(s) disponible(s): " + ", ".join(s[0] for s in strategies),
    ))

    resolved = False
    verification = {}
    last_method = "remediation_orchestrator"

    for strategy_id, strategy_fn in strategies:
        strat_steps, err = strategy_fn(vulnerability_id, finding)
        all_steps.extend(strat_steps)
        status = "failed" if err and strat_steps and strat_steps[-1].get("status") == "failed" else "executed"
        strategies_attempted.append({
            "id": strategy_id,
            "status": status,
            "error": err or None,
        })
        if err and status == "failed":
            failure_reasons.append(f"{strategy_id}: {err}")

        all_steps.append(_step("Verificación post-estrategia", "running"))
        verification = _verify(vulnerability_id, finding)
        last_method = strategy_id
        if verification.get("resolved"):
            all_steps[-1] = _step("Verificación post-estrategia", "done", verification.get("detail"))
            resolved = True
            break
        all_steps[-1] = _step("Verificación post-estrategia", "warning", verification.get("detail"))
        failure_reasons.append(f"Tras {strategy_id}: {verification.get('detail')}")
        time.sleep(0.5)

    manual_guide = None
    if not resolved:
        manual_guide = build_manual_guide(finding, strategies_attempted, failure_reasons)
        all_steps.append(_step(
            "Estrategias automáticas agotadas",
            "warning",
            manual_guide.get("titulo", "Requiere intervención manual."),
        ))

    if resolved:
        final_status = "RESUELTA"
        message = (
            f"Estado: RESUELTA — {verification.get('verified_at')}. "
            f"Última estrategia exitosa: {last_method}. "
            f"Motor: {verification.get('motor')}."
        )
    else:
        final_status = "Requiere remediación manual"
        message = manual_guide.get("titulo") if manual_guide else "No fue posible corregir automáticamente."

    record_remediation(vulnerability_id, executed_by, last_method, verification, all_steps)
    sync_platform_after_remediation(vulnerability_id, resolved)

    report = get_report_by_finding(vulnerability_id)
    if not report:
        report = ensure_report_for_finding(vulnerability_id, finding)
    elapsed = f"{round(time.time() - start, 1)}s"
    if report:
        update_report_status(
            report["id"], final_status, remediation_log=all_steps,
            tiempo_resolucion=elapsed, verification=verification,
        )

    all_steps.append(_step(
        "Remediación completada" if resolved else "Remediación manual requerida",
        "done" if resolved else "warning",
        message,
    ))

    aspe_result = None
    if not resolved:
        try:
            from services.adaptive_sector_protection_engine import aspe
            aspe_result = aspe.evaluate_incident(
                finding,
                user_email=executed_by if executed_by and "@" in str(executed_by) else None,
                source="remediation_orchestrator",
            )
            if aspe_result.get("dynamic_activated"):
                all_steps.append(_step(
                    "Adaptive Sector Protection Engine",
                    "done",
                    f"Activación cruzada: {len(aspe_result['dynamic_activated'])} módulo(s) — {aspe_result.get('threat_type')}",
                ))
        except Exception as exc:
            logger.debug("ASPE evaluate incident: %s", exc)

    ade_result = None
    if not resolved and not skip_adaptive:
        try:
            from services.adaptive_defense_engine import adaptive_defense
            ade_result = adaptive_defense.activate_after_failed_remediation(
                vulnerability_id,
                finding,
                remediation_result={"resolved": resolved, "strategies_attempted": strategies_attempted},
                user_email=executed_by if executed_by and "@" in str(executed_by) else None,
            )
            all_steps.append(_step(
                "Adaptive Defense Engine",
                "done" if ade_result.get("status") in ("active", "resolved_by_remediation") else "warning",
                ade_result.get("message", NO_DATA),
            ))
        except Exception as exc:
            logger.error("Adaptive Defense activation: %s", exc, exc_info=True)
            all_steps.append(_step("Adaptive Defense Engine", "failed", str(exc)))

    try:
        from services.defense_evidence_registry import record_defense_event
        record_defense_event(
            phase="recover" if resolved else "respond",
            action="auto_remediation",
            motor="remediation_orchestrator",
            outcome="success" if resolved else "manual_required",
            finding_id=vulnerability_id,
            evidence={"verification": verification, "strategies": strategies_attempted},
            detail=message,
        )
    except Exception:
        pass

    return {
        "status": "success" if resolved else "manual_required",
        "steps": all_steps,
        "report_id": report["id"] if report else None,
        "final_status": final_status,
        "resolved": resolved,
        "verification": verification,
        "verification_status": (
            "SUCCESS" if resolved else ("FAILED" if verification else "NOT_VERIFIED")
        ),
        "elapsed": elapsed,
        "message": message,
        "strategies_attempted": strategies_attempted,
        "manual_guide": manual_guide,
        "requires_manual": not resolved,
        "auto_exhausted": not resolved and len(strategies) > 0,
        "adaptive_defense": ade_result,
        "aspe": aspe_result,
    }


def verify_manual_remediation(vulnerability_id: str, finding: dict, executed_by: Optional[str] = None) -> dict:
    """Verificación final tras remediación manual del usuario."""
    from services.vulnerability_analyst_service import (
        record_remediation,
        sync_platform_after_remediation,
    )

    steps = [_step("Verificación final post-remediación manual", "running")]
    verification = _verify(vulnerability_id, finding)
    resolved = verification.get("resolved", False)

    if resolved:
        steps[-1] = _step("Verificación final post-remediación manual", "done", verification.get("detail"))
        message = f"RESUELTA — confirmado por {verification.get('motor')} el {verification.get('verified_at')}"
        final_status = "RESUELTA"
    else:
        steps[-1] = _step("Verificación final post-remediación manual", "warning", verification.get("detail"))
        message = f"La vulnerabilidad persiste: {verification.get('detail')}"
        final_status = "Requiere remediación manual"

    record_remediation(
        vulnerability_id, executed_by,
        "manual_remediation.verify",
        verification, steps,
    )
    sync_platform_after_remediation(vulnerability_id, resolved)

    return {
        "status": "success" if resolved else "still_present",
        "resolved": resolved,
        "verification": verification,
        "message": message,
        "final_status": final_status,
        "steps": steps,
    }
