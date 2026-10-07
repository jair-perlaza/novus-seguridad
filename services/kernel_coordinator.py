"""
Coordinador del Kernel IA — ejecuta tareas, muestra progreso en vivo, decide acciones.

Flujo: Comprender → Pensar → Planificar → Ejecutar → Esperar → Correlacionar → Decidir → Explicar → Responder
"""
from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from services.ai_orchestrator import kernel_orchestrator
from services.kernel_agents.registry import AGENT_REGISTRY, get_agent
from services.kernel_memory import kernel_memory
from services.kernel_planner import ExecutionPlan
from services.kernel_engine_orchestrator import kernel_engine_orchestrator
from services.kernel_session_context import kernel_session_context
from services.kernel_task_planner import KernelTask, build_task_list, tasks_to_dict
from services.soc_report_builder import build_soc_report
from utils.logger import logger


def _auto_remediation_allowed() -> bool:
    try:
        from services.config_service import auto_remediation_enabled
        return auto_remediation_enabled()
    except Exception:
        return False


class OperationState:
    """Estado en vivo de una operación del Kernel."""

    def __init__(self, operation_id: str, message: str, session_id: str):
        self.operation_id = operation_id
        self.message = message
        self.session_id = session_id
        self.status = "planning"
        self.tasks: List[KernelTask] = []
        self.current_task_id = 0
        self.live_message = "Inicializando..."
        self.live_log: List[str] = []
        self.started_at = datetime.now().isoformat()
        self.finished_at: Optional[str] = None
        self.scan_id: Optional[str] = None
        self.result: Optional[Dict[str, Any]] = None
        self.collected: Dict[str, Any] = {}
        self.decisions: List[str] = []
        self.confirm_required = False
        self.confirm_token: Optional[str] = None
        self.confirm_payload: Optional[dict] = None
        self.performance_level: int = 2
        self.performance_label: str = ""
        self.eta_message: str = ""
        self.target_seconds_min: float = 5.0
        self.target_seconds_max: float = 15.0
        self.live_feed: List[Dict[str, Any]] = []
        self.last_finding: str = ""
        self._seen_findings: set = set()
        self._feed_seq: int = 0


IMMEDIATE_ACK = (
    "Entendido.\n\n"
    "Voy a iniciar el análisis.\n"
    "Preparando motores...\n"
    "No cierre esta ventana.\n"
    "Le iré mostrando los hallazgos conforme aparezcan."
)


class KernelCoordinator:
    """Coordina agentes especializados y expone progreso en tiempo real."""

    def __init__(self):
        self._ops: Dict[str, OperationState] = {}
        self._lock = threading.Lock()

    def get_status(self, operation_id: str) -> Optional[Dict[str, Any]]:
        op = self._ops.get(operation_id)
        if not op:
            return None
        progress = 0
        if op.tasks:
            done = sum(1 for t in op.tasks if t.status in ("completed", "skipped"))
            progress = int(done / len(op.tasks) * 100)
        try:
            started_dt = datetime.fromisoformat(op.started_at)
            elapsed_sec = (datetime.now() - started_dt).total_seconds()
        except Exception:
            elapsed_sec = 0.0
        eta_remaining = max(0.0, op.target_seconds_max - elapsed_sec)
        current_task = next((t for t in op.tasks if t.status == "running"), None)
        next_task = next((t for t in op.tasks if t.status == "pending"), None)
        out = {
            "operation_id": op.operation_id,
            "status": op.status,
            "live_message": op.live_message,
            "live_log": op.live_log[-30:],
            "tasks": tasks_to_dict(op.tasks),
            "current_task_id": op.current_task_id,
            "progress_pct": progress,
            "scan_id": op.scan_id,
            "started_at": op.started_at,
            "finished_at": op.finished_at,
            "decisions": op.decisions,
            "performance_level": op.performance_level,
            "performance_label": op.performance_label,
            "eta_message": op.eta_message,
            "target_seconds_min": op.target_seconds_min,
            "target_seconds_max": op.target_seconds_max,
            "current_motor": (current_task.label if current_task else op.live_message) or "—",
            "next_motor": (next_task.label if next_task else "Finalizando informe") or "—",
            "last_finding": op.last_finding or "Sin hallazgos aún",
            "elapsed_sec": round(elapsed_sec, 1),
            "eta_remaining_sec": round(eta_remaining, 1),
            "live_feed": op.live_feed[-40:],
        }
        if op.status == "completed" and op.result:
            out["has_result"] = True
        return out

    def get_result(self, operation_id: str) -> Optional[Dict[str, Any]]:
        op = self._ops.get(operation_id)
        if not op or op.status != "completed":
            return None
        return op.result

    def start_operation(
        self,
        session_id: str,
        message: str,
        plan: ExecutionPlan,
        intent_data: dict,
        user_id: Optional[int],
        user_email: Optional[str],
        user_prefs: dict,
    ) -> Dict[str, Any]:
        """Inicia operación async — NO responde con informe; solo estado de trabajo."""
        operation_id = str(uuid.uuid4())[:12]
        tasks = build_task_list(plan, message)
        op = OperationState(operation_id, message, session_id)
        op.tasks = tasks
        op.status = "running"
        op.performance_level = plan.performance_level
        op.performance_label = plan.performance_label
        op.eta_message = plan.eta_message or f"Estimado {plan.target_seconds_min:.0f}–{plan.target_seconds_max:.0f}s"
        op.target_seconds_min = plan.target_seconds_min
        op.target_seconds_max = plan.target_seconds_max
        op.live_message = "Inicializando..." if tasks else "Preparando motores..."

        with self._lock:
            self._ops[operation_id] = op

        thread = threading.Thread(
            target=self._run_operation,
            args=(operation_id, plan, intent_data, user_id, user_email, user_prefs),
            daemon=True,
            name=f"kernel-op-{operation_id}",
        )
        thread.start()

        return {
            "working": True,
            "defer_reply": True,
            "operation_id": operation_id,
            "tasks": tasks_to_dict(tasks),
            "live_message": op.live_message,
            "agent_mode": True,
            "request_type": plan.request_type,
            "performance_level": plan.performance_level,
            "performance_label": plan.performance_label,
            "eta_message": op.eta_message,
            "target_seconds_min": plan.target_seconds_min,
            "target_seconds_max": plan.target_seconds_max,
            "plan": {"goal": plan.goal, "intent": plan.intent_id},
            "reply": None,
            "immediate_ack": IMMEDIATE_ACK,
            "actions": [{"label": "Ver progreso", "type": "operation", "operation_id": operation_id}],
        }

    def _feed(self, op: OperationState, kind: str, text: str):
        """Publica actualización en vivo para el chat progresivo (UI)."""
        op._feed_seq += 1
        entry = {
            "id": op._feed_seq,
            "kind": kind,
            "text": text,
            "ts": datetime.now().strftime("%H:%M:%S"),
        }
        op.live_feed.append(entry)
        if kind == "finding":
            op.last_finding = text

    def _scan_collected_findings(self, op: OperationState, collected: dict):
        """Detecta hallazgos reales en datos ya recolectados — sin inventar."""
        sec = collected.get("security") or {}
        for sp in (sec.get("suspicious_processes") or [])[:5]:
            pid = sp.get("pid")
            name = sp.get("name") or "proceso"
            fid = f"proc-{pid}-{name}"
            if fid in op._seen_findings:
                continue
            op._seen_findings.add(fid)
            self._feed(
                op, "finding",
                f"Encontré un proceso poco habitual: {name}. Lo estoy verificando.",
            )
        vulns = collected.get("vulnerabilities") or []
        if isinstance(vulns, list):
            for i, v in enumerate(vulns[:3]):
                vid = v.get("id") if isinstance(v, dict) else str(v)
                key = f"vuln-{vid}-{i}"
                if key in op._seen_findings:
                    continue
                op._seen_findings.add(key)
                title = v.get("title", v.get("name", str(v)[:60])) if isinstance(v, dict) else str(v)[:60]
                self._feed(op, "finding", f"Hallazgo de vulnerabilidad: {title}")

    def _log(self, op: OperationState, msg: str):
        op.live_message = msg
        op.live_log.append(f"{datetime.now().strftime('%H:%M:%S')} — {msg}")
        if msg and not msg.startswith("Inicializando"):
            self._feed(op, "status", msg)

    def _run_operation(
        self,
        operation_id: str,
        plan: ExecutionPlan,
        intent_data: dict,
        user_id: Optional[int],
        user_email: Optional[str],
        user_prefs: dict,
    ):
        op = self._ops.get(operation_id)
        if not op:
            return
        started = datetime.now()
        steps_log: List[str] = []
        collected: Dict[str, Any] = {"capabilities_executed": [], "capabilities_failed": [], "gaps": []}
        actions_executed: List[dict] = []

        try:
            # Deep Scan workflow — solo escaneo integral (perfil full)
            if (
                plan.workflow_profile == "full"
                or plan.intent_id in ("deep_scan", "full_computer_analysis")
            ) and plan.request_type == "action" and not plan.inline_action:
                self._run_deep_scan_workflow(op, plan, session_id=op.session_id, user_id=user_id)
                if op.result:
                    self._finalize_op(op, plan, intent_data, user_id, user_email, started, op.result)
                return

            # Inline actions (gmail, report)
            if plan.inline_action:
                from services.kernel_operator import kernel_operator
                for t in op.tasks:
                    t.status = "running"
                    op.current_task_id = t.task_id
                    self._log(op, t.label)
                result = kernel_operator._execute_inline(plan.inline_action, op.message, user_id)
                result["agent_mode"] = True
                result["operation_id"] = operation_id
                result["performance_level"] = plan.performance_level
                op.result = result
                op.status = "completed"
                op.finished_at = datetime.now().isoformat()
                for t in op.tasks:
                    t.status = "completed"
                self._finalize_op(op, plan, intent_data, user_id, user_email, started, result)
                return

            # Ejecución vía orquestador central Fase 1
            self._log(op, "Preparando motores...")
            for task in op.tasks:
                if task.capability or task.action:
                    task.status = "running"
                    op.current_task_id = task.task_id
            collected = kernel_engine_orchestrator.execute_plan(
                plan, op.session_id, user_id
            )
            op.collected = collected
            actions_executed = list(collected.pop("orchestrator_actions", []) or [])

            exec_caps = set(collected.get("capabilities_executed") or [])
            for task in op.tasks:
                if task.capability:
                    if task.capability in exec_caps:
                        task.status = "completed"
                        task.result_summary = "OK"
                        self._feed(op, "progress", f"✓ {task.label.rstrip('.')}.")
                    elif task.status == "running":
                        task.status = "failed"
            self._scan_collected_findings(op, collected)
            steps_log.extend(plan.internal_plan or [])

            # Tareas milestone (sin motor propio)
            for task in op.tasks:
                if not task.capability and not task.action and task.status == "pending":
                    task.status = "completed"

            op.status = "correlating"
            self._log(op, "Correlacionando resultados...")
            steps_log.append("Correlacionando resultados")

            # Decisiones sobre amenazas
            op.status = "deciding"
            decisions, confirm, confirm_data = self._apply_decisions(collected, op.session_id, user_id)
            op.decisions = decisions

            op.status = "reporting"
            self._log(op, "Generando informe...")
            report = build_soc_report(
                intent=intent_data,
                data=collected,
                message=op.message,
                actions_executed=actions_executed,
                started_at=started,
                timeline=steps_log,
            )

            decision_text = self._build_decision_narrative(plan, op, decisions, collected)
            reply_parts = [decision_text]
            if decisions:
                reply_parts.append("\n".join(f"▸ {d}" for d in decisions))
            reply_parts.append(report["reply"])
            full_reply = "\n\n".join(reply_parts)

            result = {
                "request_type": plan.request_type,
                "reply": full_reply,
                "actions": report.get("actions", []),
                "confirm_required": confirm,
                "confirm_token": confirm_data.get("token") if confirm_data else None,
                "engines_executed": collected.get("capabilities_executed", []),
                "risk_level": report.get("risk_level"),
                "soc_report": True,
                "agent_mode": True,
                "operation_id": operation_id,
                "performance_level": plan.performance_level,
                "elapsed_sec": round((datetime.now() - started).total_seconds(), 2),
                "cache_hits": collected.get("cache_hits") or 0,
                "decisions": decisions,
                "data_snapshot": report.get("data_snapshot"),
            }

            if confirm and confirm_data:
                from services.ai_kernel import ai_kernel
                session = ai_kernel._get_session(op.session_id)
                session["pending_confirm"] = confirm_data

            for t in op.tasks:
                if t.status == "running":
                    t.status = "completed"
            self._log(op, "Finalizado.")
            op.result = result
            op.status = "completed"
            op.finished_at = datetime.now().isoformat()
            self._finalize_op(op, plan, intent_data, user_id, user_email, started, result)

        except Exception as exc:
            logger.error(f"Operation {operation_id} failed: {exc}", exc_info=True)
            op.status = "error"
            op.live_message = f"Error: {exc}"
            op.result = {
                "reply": f"Error en operación del Kernel: {exc}",
                "agent_mode": True,
                "operation_id": operation_id,
            }
            op.finished_at = datetime.now().isoformat()

    def _run_deep_scan_workflow(
        self,
        op: OperationState,
        plan: ExecutionPlan,
        session_id: str,
        user_id: Optional[int],
    ):
        from services.deep_scan_engine import deep_scan_engine

        profile = plan.workflow_profile or "full"
        modules = plan.workflow_modules or []

        self._log(op, "Inicializando análisis...")
        op.live_message = plan.eta_message or op.live_message
        scan_id = deep_scan_engine.start_scan(
            session_id, user_id, profile=profile, query=op.message, modules_loaded=modules,
        )
        op.scan_id = scan_id

        # Mapear fases deep scan → tareas visuales
        task_idx = 0
        deadline = time.time() + 600
        last_phase = ""
        last_threats = 0

        while time.time() < deadline:
            st = deep_scan_engine.get_status(scan_id)
            if not st:
                break
            state = st.get("status")
            phase = st.get("phase") or ""
            phase_label = st.get("phase_label") or phase
            stats = st.get("stats") or {}
            threats = int(stats.get("threats_found") or 0)
            if threats > last_threats:
                last_threats = threats
                self._feed(op, "finding", f"Detectadas {threats} amenaza(s) durante el escaneo.")

            if phase_label and phase_label != last_phase:
                last_phase = phase_label
                self._feed(op, "progress", f"✓ {phase_label}")
                # Avanzar tareas según progreso
                while task_idx < len(op.tasks) - 1:
                    op.tasks[task_idx].status = "completed"
                    task_idx += 1
                if task_idx < len(op.tasks):
                    op.tasks[task_idx].status = "running"
                    op.current_task_id = op.tasks[task_idx].task_id
                    self._log(op, op.tasks[task_idx].label if op.tasks[task_idx].label else phase_label)
                else:
                    self._log(op, phase_label)

            if state == "completed":
                report = deep_scan_engine.get_report(scan_id)
                if report:
                    for t in op.tasks:
                        if t.status != "completed":
                            t.status = "completed"
                    self._log(op, "Escaneo finalizado.")

                    # Decisiones post-escaneo
                    findings = report.get("findings") or []
                    decisions = []
                    confirm = False
                    confirm_data = None
                    if findings:
                        decisions.append(f"Encontré {len(findings)} hallazgo(s) durante el análisis.")
                        for f in findings[:3]:
                            decisions.append(
                                f"  • [{f.get('risk', '?').upper()}] {f.get('title', f.get('name', 'Hallazgo'))}"
                            )
                        if _auto_remediation_allowed():
                            decisions.append("Política activa: iniciando mitigación automática de hallazgos de bajo impacto...")
                        else:
                            decisions.append(
                                "Política de seguridad: acciones que afectan procesos/archivos requieren su confirmación."
                            )
                            if findings:
                                import uuid as _uuid
                                token = str(_uuid.uuid4())[:8]
                                confirm = True
                                confirm_data = {
                                    "token": token,
                                    "label": f"Remediar hallazgos detectados ({len(findings)})",
                                    "action": "clean_threats_batch",
                                    "payload": {
                                        "threats": [
                                            {
                                                "id": f.get("id", f"FIND-{i}"),
                                                "nombre": f.get("title", f.get("name")),
                                                "descripcion": f.get("reason", f.get("description", "")),
                                            }
                                            for i, f in enumerate(findings[:10])
                                        ]
                                    },
                                }
                    else:
                        decisions.append("No se detectaron amenazas críticas en este ciclo de análisis.")

                    narrative = "═══ ANÁLISIS COMPLETADO ═══\n\n" + "\n".join(decisions)
                    text = report.get("text_report", "")
                    op.collected = {
                        "findings": findings,
                        "deep_scan": report,
                        "risk_level": report.get("risk_level"),
                    }
                    op.result = {
                        "request_type": "action",
                        "profile": profile,
                        "reply": narrative + "\n\n" + text,
                        "scan_id": scan_id,
                        "task_completed": True,
                        "soc_workflow": True,
                        "soc_report": True,
                        "engines_executed": report.get("engines_used", []),
                        "risk_level": report.get("risk_level"),
                        "decisions": decisions,
                        "confirm_required": confirm,
                        "confirm_token": confirm_data.get("token") if confirm_data else None,
                        "ndci_offer": True,
                        "actions": [
                            {
                                "label": "Crear Caso de Estudio",
                                "type": "ndci_create",
                                "scan_id": scan_id,
                                "operation_id": op.operation_id,
                            },
                            {"label": "XDR", "type": "navigate", "url": "/amenazas"},
                            {"label": "Vulnerabilidades", "type": "navigate", "url": "/vulnerabilidades"},
                            {"label": "Casos de Estudio", "type": "navigate", "url": "/casos-estudio"},
                        ],
                    }
                    if confirm and confirm_data:
                        from services.ai_kernel import ai_kernel
                        ai_kernel._get_session(session_id)["pending_confirm"] = confirm_data
                return
            if state == "error":
                self._log(op, f"Error en escaneo: {st.get('error', 'desconocido')}")
                op.result = {"reply": f"Error en Deep Scan: {st.get('error')}", "scan_id": scan_id}
                return
            time.sleep(1.0)

        op.result = {"reply": "Tiempo de espera agotado para el escaneo.", "scan_id": scan_id}

    def _apply_decisions(
        self,
        collected: dict,
        session_id: str,
        user_id: Optional[int],
    ) -> tuple:
        """Evalúa amenazas y aplica política — actuar o pedir confirmación."""
        decisions: List[str] = []
        sec = collected.get("security") or {}
        sus = sec.get("suspicious_processes") or []
        vulns = collected.get("vulnerabilities") or []
        threat_count = sec.get("threat_count") or 0

        if not sus and not threat_count and not vulns:
            return decisions, False, None

        if sus or threat_count:
            decisions.append(f"Encontré {len(sus) or threat_count} indicador(es) de amenaza.")
            try:
                from services.forensic_pcap_capture_service import maybe_kernel_high_criticality_pcap

                maybe_kernel_high_criticality_pcap(
                    threat_count=int(threat_count or 0),
                    suspicious=sus,
                    detail="kernel_coordinator",
                )
            except Exception as exc:
                logger.debug("kernel pcap trigger: %s", exc)
            if _auto_remediation_allowed() and sus:
                decisions.append(f"Aislando/analizando proceso sospechoso: {sus[0].get('name', '?')}...")
                try:
                    from services.remediation_engine import remediate_vulnerability
                    pid = sus[0].get("pid")
                    rid = f"PROC-{pid}" if pid else None
                    if rid:
                        r = remediate_vulnerability(rid)
                        decisions.append(f"Mitigación automática: {r.get('message', 'ejecutada')}")
                except Exception as exc:
                    decisions.append(f"Mitigación automática no disponible: {exc}")
                return decisions, False, None

            decisions.append(
                "La política exige confirmación antes de eliminar procesos o modificar archivos."
            )
            import uuid as _uuid
            token = str(_uuid.uuid4())[:8]
            threats = []
            for sp in sus[:5]:
                threats.append({
                    "id": f"PROC-{sp.get('pid')}",
                    "nombre": sp.get("name"),
                    "descripcion": sp.get("description", sp.get("command_line", "")),
                })
            confirm_data = {
                "token": token,
                "label": "Mitigar amenazas detectadas",
                "action": "clean_threats_batch",
                "payload": {"threats": threats},
            }
            return decisions, bool(threats), confirm_data

        return decisions, False, None

    def _build_decision_narrative(self, plan: ExecutionPlan, op: OperationState, decisions: List[str], collected: dict) -> str:
        agents_used = sorted({t.agent_id for t in op.tasks if t.status == "completed"})
        completed = sum(1 for t in op.tasks if t.status == "completed")
        lines = [
            f"Análisis SOC — {plan.goal}",
            f"Motores: {', '.join(agents_used) or 'SOC'} | Tareas: {completed}/{len(op.tasks)}",
        ]
        if plan.missing_capabilities:
            lines.append("Limitaciones detectadas:")
            for m in plan.missing_capabilities[:3]:
                lines.append(f"  • {m}")
        return "\n".join(lines)

    def _finalize_op(
        self,
        op: OperationState,
        plan: ExecutionPlan,
        intent_data: dict,
        user_id: Optional[int],
        user_email: Optional[str],
        started: datetime,
        result: dict,
    ):
        engines = result.get("engines_executed") or []
        anomalies: List[str] = []
        snap = result.get("data_snapshot") or {}
        if snap.get("vuln_count"):
            anomalies.append(f"{snap['vuln_count']} vulnerabilidad(es)/hallazgo(s)")
        if snap.get("threat_count"):
            anomalies.append(f"{snap['threat_count']} amenaza(s) XDR")
        report_summary = (result.get("reply") or "")[:500]
        kernel_session_context.update_after_operation(
            session_id=op.session_id,
            operation_id=op.operation_id,
            intent_id=plan.intent_id,
            engines=[str(e) for e in engines],
            risk_level=result.get("risk_level") or "",
            anomalies=anomalies or None,
            report_summary=report_summary,
            scan_profile=plan.workflow_profile,
            actions=[a.get("label", "") for a in (result.get("actions") or []) if a.get("label")],
        )
        try:
            from services.threat_intelligence_service import threat_intelligence
            threat_intelligence.ingest_kernel_operation(
                message=op.message,
                plan_intent=plan.intent_id,
                engines=[str(e) for e in engines],
                collected=op.collected or {},
                user_email=user_email,
                elapsed_sec=result.get("elapsed_sec"),
                decisions=op.decisions,
            )
        except Exception as ti_exc:
            logger.warning(f"ThreatIntel kernel ingest: {ti_exc}")
        kernel_memory.record_interaction(
            user_id, user_email, op.message, plan.intent_id,
            [str(e) for e in engines], plan.request_type, plan.workflow_profile,
        )
        kernel_memory.log_operation({
            "operation_id": op.operation_id,
            "message": op.message[:200],
            "intent": plan.intent_id,
            "tasks": len(op.tasks),
            "decisions": op.decisions,
            "elapsed_sec": round((datetime.now() - started).total_seconds(), 2),
        })


kernel_coordinator = KernelCoordinator()
