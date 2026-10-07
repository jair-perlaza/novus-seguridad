"""
Kernel Agent — Cerebro central de NOVUS — Fase 1.

Comprender → Planificar → Orquestar → Correlacionar → Explicar
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from services.ai_orchestrator import kernel_orchestrator
from services.kernel_coordinator import kernel_coordinator
from services.kernel_engine_orchestrator import kernel_engine_orchestrator
from services.kernel_intent_interpreter import interpret_intent
from services.kernel_memory import kernel_memory
from services.kernel_planner import ExecutionPlan, build_plan, GREETING
from services.kernel_session_context import kernel_session_context
from services.soc_report_builder import build_soc_report
from utils.logger import logger


class KernelAgent:
    """Cerebro operativo Fase 1 — intención, plan, orquestación, contexto."""

    def process(
        self,
        session_id: str,
        message: str,
        user_id: Optional[int] = None,
        user_email: Optional[str] = None,
        context: Optional[dict] = None,
        history: Optional[List[dict]] = None,
    ) -> Dict[str, Any]:
        operation_id = str(uuid.uuid4())[:12]
        user_prefs = kernel_memory.get_preferences(user_id, user_email)
        ctx = dict(context or {})
        if user_email and not ctx.get("sector_key"):
            from services.sector_profile_service import get_kernel_context_for_user
            ctx.update(get_kernel_context_for_user(user_email))
        # Contexto interno Adaptive Profile Engine (señales, no dump de baseline al cliente)
        if user_email:
            try:
                from services.adaptive_profile_engine import kernel_adaptive_context

                ctx.update(kernel_adaptive_context(user_email))
            except Exception as ape_exc:
                logger.debug("kernel adaptive context: %s", ape_exc)
        history = history or []

        if GREETING.match(message.strip()):
            plan = build_plan(message, context=ctx, user_prefs=user_prefs, session_id=session_id, history=history)
            sector_ctx = {k: ctx[k] for k in ("sector_key", "sector_label", "kernel_priorities") if k in ctx}
            reply = self._greeting_response(user_prefs, sector_ctx)
            result = {
                "reply": reply,
                "request_type": "greeting",
                "agent_mode": True,
                "confirm_required": False,
                "operation_id": operation_id,
                "performance_level": plan.performance_level,
                "actions": [],
            }
            kernel_memory.record_interaction(user_id, user_email, message, "greeting", [], "greeting")
            hint = kernel_memory.personalization_hint(user_id, user_email)
            if hint:
                result["personalization"] = hint
            return result

        # Kernel IA Enterprise V2.0 — capa modular aditiva (no reemplaza motores)
        try:
            from services.kernel_enterprise_v2 import kernel_enterprise_v2

            v2_reply = kernel_enterprise_v2.answer_kernel_query(
                message,
                user_email=user_email,
                user_role=(ctx or {}).get("user_role"),
                context=ctx,
            )
            if v2_reply is not None:
                kernel_memory.record_interaction(
                    user_id, user_email, message, "kernel_enterprise_v2", ["kernel.enterprise.v2"], "query"
                )
                return {
                    "reply": v2_reply,
                    "request_type": "query",
                    "agent_mode": True,
                    "confirm_required": False,
                    "operation_id": operation_id,
                    "engines_executed": ["kernel.enterprise.v2"],
                    "data_source": "kernel_enterprise_v2",
                    "actions": [
                        {"label": "Estado Enterprise V2", "type": "api", "url": "/api/ai/enterprise/v2/status"}
                    ],
                }
        except Exception as ke_v2_exc:
            logger.debug("Kernel Enterprise V2 query: %s", ke_v2_exc)

        # Swarm Defense Engine — inteligencia de enjambre (capa aditiva)
        try:
            from services.swarm_defense import swarm_defense_engine

            swarm_reply = swarm_defense_engine.answer_kernel_query(
                message, user_email=user_email, context=ctx
            )
            if swarm_reply is not None:
                kernel_memory.record_interaction(
                    user_id, user_email, message, "swarm_defense", ["swarm.defense.engine"], "query"
                )
                return {
                    "reply": swarm_reply,
                    "request_type": "query",
                    "agent_mode": True,
                    "confirm_required": False,
                    "operation_id": operation_id,
                    "engines_executed": ["swarm.defense.engine"],
                    "data_source": "swarm_defense_engine",
                    "actions": [
                        {"label": "Estado Swarm Defense", "type": "api", "url": "/api/swarm-defense/status"}
                    ],
                }
        except Exception as swarm_exc:
            logger.debug("Swarm Defense kernel query: %s", swarm_exc)

        # Consultas NDCI — casos de estudio permanentes (solo Super Administrador)
        try:
            from services.rbac_service import can_access_module_by_email
            if user_email and can_access_module_by_email(user_email, "casos_estudio"):
                from services.ndci_service import ndci_service
                ndci_reply = ndci_service.answer_kernel_query(message)
                if ndci_reply is not None:
                    kernel_memory.record_interaction(
                        user_id, user_email, message, "ndci", ["ndci.case_intelligence"], "query"
                    )
                    return {
                        "reply": ndci_reply,
                        "request_type": "query",
                        "agent_mode": True,
                        "confirm_required": False,
                        "operation_id": operation_id,
                        "engines_executed": ["ndci.case_intelligence"],
                        "data_source": "ndci_service",
                        "actions": [{"label": "Casos de Estudio", "type": "navigate", "url": "/casos-estudio"}],
                    }
        except Exception as ndci_exc:
            logger.debug("NDCI kernel query: %s", ndci_exc)

        # Consultas Centro de Inteligencia — cerebro operativo
        try:
            from services.threat_intelligence_service import threat_intelligence
            intel_reply = threat_intelligence.answer_kernel_query(message, user_email=user_email)
            if intel_reply is not None:
                kernel_memory.record_interaction(
                    user_id, user_email, message, "inteligencia", ["threat_intelligence.center"], "query"
                )
                return {
                    "reply": intel_reply,
                    "request_type": "query",
                    "agent_mode": True,
                    "confirm_required": False,
                    "operation_id": operation_id,
                    "engines_executed": ["threat_intelligence.center"],
                    "data_source": "intel_operational_service",
                    "actions": [{"label": "Abrir Inteligencia", "type": "navigate", "url": "/inteligencia"}],
                }
        except Exception as intel_exc:
            logger.debug("Intel kernel query: %s", intel_exc)

        # Consultas ASPE / UCE — protección sectorial adaptativa
        try:
            from services.adaptive_sector_protection_engine import aspe
            aspe_reply = aspe.answer_kernel_query(message, user_email=user_email)
            if aspe_reply is not None:
                kernel_memory.record_interaction(
                    user_id, user_email, message, "aspe", ["aspe.sector_protection", "uce.compatibility"], "query"
                )
                return {
                    "reply": aspe_reply,
                    "request_type": "query",
                    "agent_mode": True,
                    "confirm_required": False,
                    "operation_id": operation_id,
                    "engines_executed": ["aspe.sector_protection", "uce.compatibility"],
                    "data_source": "adaptive_sector_protection_engine",
                    "actions": [{"label": "Abrir Dashboard", "type": "navigate", "url": "/"}],
                }
        except Exception as aspe_exc:
            logger.debug("ASPE kernel query: %s", aspe_exc)

        # Consultas Adaptive Defense Engine
        try:
            from services.adaptive_defense_engine import adaptive_defense
            ade_reply = adaptive_defense.answer_kernel_query(message, user_email=user_email)
            if ade_reply is not None:
                kernel_memory.record_interaction(
                    user_id, user_email, message, "adaptive_defense", ["adaptive.defense"], "query"
                )
                return {
                    "reply": ade_reply,
                    "request_type": "query",
                    "agent_mode": True,
                    "confirm_required": False,
                    "operation_id": operation_id,
                    "engines_executed": ["adaptive.defense"],
                    "data_source": "adaptive_defense_engine",
                    "actions": [{"label": "Abrir Inteligencia", "type": "navigate", "url": "/inteligencia"}],
                }
        except Exception as ade_exc:
            logger.debug("Adaptive Defense kernel query: %s", ade_exc)

        # Consultas Configuración — estado activo del sistema
        try:
            from services.config_service import answer_kernel_query as config_kernel_query
            cfg_reply = config_kernel_query(message)
            if cfg_reply is not None:
                kernel_memory.record_interaction(
                    user_id, user_email, message, "config", ["config.service"], "query"
                )
                return {
                    "reply": cfg_reply,
                    "request_type": "query",
                    "agent_mode": True,
                    "confirm_required": False,
                    "operation_id": operation_id,
                    "engines_executed": ["config.service"],
                    "data_source": "config_service",
                    "actions": [{"label": "Abrir Configuración", "type": "navigate", "url": "/configuracion"}],
                }
        except Exception as cfg_exc:
            logger.debug("Config kernel query: %s", cfg_exc)

        # Consultas Reportes — generación y consultas empresariales
        try:
            from services.enterprise_report_service import answer_kernel_query as reports_kernel_query
            rep_reply = reports_kernel_query(message, user_email=user_email)
            if rep_reply is not None:
                kernel_memory.record_interaction(
                    user_id, user_email, message, "reports", ["reports.enterprise"], "query"
                )
                return {
                    "reply": rep_reply,
                    "request_type": "query",
                    "agent_mode": True,
                    "confirm_required": False,
                    "operation_id": operation_id,
                    "engines_executed": ["reports.enterprise"],
                    "data_source": "enterprise_report_service",
                    "actions": [{"label": "Abrir Reportes", "type": "navigate", "url": "/reportes"}],
                }
        except Exception as rep_exc:
            logger.debug("Reports kernel query: %s", rep_exc)

        # Consultas Topology — exclusivamente datos del mapa de red
        try:
            from services.topology_service import answer_kernel_query as topology_kernel_query
            topo_reply = topology_kernel_query(message)
            if topo_reply is not None:
                kernel_memory.record_interaction(
                    user_id, user_email, message, "topology", ["network.topology"], "query"
                )
                return {
                    "reply": topo_reply,
                    "request_type": "query",
                    "agent_mode": True,
                    "confirm_required": False,
                    "operation_id": operation_id,
                    "engines_executed": ["network.topology"],
                    "data_source": "topology_service",
                    "actions": [{"label": "Abrir Topology", "type": "navigate", "url": "/topology"}],
                }
        except Exception as topo_exc:
            logger.debug("Topology kernel query: %s", topo_exc)

        # Sensor Red+Endpoint Enterprise — solo análisis
        try:
            msg_l = (message or "").lower()
            if any(
                k in msg_l
                for k in (
                    "endpoint enterprise",
                    "yara",
                    "rootkit",
                    "análisis de memoria",
                    "analisis de memoria",
                    "risk score endpoint",
                    "edr",
                )
            ):
                from services.endpoint_enterprise.kernel_insights import answer_kernel_query as eep_kernel

                eep_reply = eep_kernel(message)
                if eep_reply:
                    kernel_memory.record_interaction(
                        user_id, user_email, message, "endpoint_enterprise", ["endpoint.enterprise"], "query"
                    )
                    return {
                        "reply": eep_reply,
                        "request_type": "query",
                        "agent_mode": True,
                        "confirm_required": False,
                        "operation_id": operation_id,
                        "engines_executed": ["endpoint.enterprise"],
                        "data_source": "endpoint_enterprise",
                        "actions": [{"label": "Abrir Endpoint", "type": "navigate", "url": "/endpoint"}],
                    }
        except Exception as eep_exc:
            logger.debug("Endpoint Enterprise kernel query: %s", eep_exc)

        # WSAE — solo análisis
        try:
            msg_l = (message or "").lower()
            if any(
                k in msg_l
                for k in (
                    "wsae",
                    "mfa",
                    "totp",
                    "oauth",
                    "oidc",
                    "csrf api",
                    "web security",
                    "autenticación enterprise",
                    "autenticacion enterprise",
                )
            ):
                from services.web_security_auth_enterprise.kernel_insights import answer_kernel_query as wsae_kernel

                wsae_reply = wsae_kernel(message)
                if wsae_reply:
                    kernel_memory.record_interaction(
                        user_id, user_email, message, "web_security_auth_enterprise", ["wsae"], "query"
                    )
                    return {
                        "reply": wsae_reply,
                        "request_type": "query",
                        "agent_mode": True,
                        "confirm_required": False,
                        "operation_id": operation_id,
                        "engines_executed": ["web_security_auth_enterprise"],
                        "data_source": "web_security_auth_enterprise",
                        "actions": [{"label": "Login", "type": "navigate", "url": "/login"}],
                    }
        except Exception as wsae_exc:
            logger.debug("WSAE kernel query: %s", wsae_exc)

        # BTDE — solo análisis
        try:
            msg_l = (message or "").lower()
            if any(
                k in msg_l
                for k in (
                    "btde",
                    "behavioral threat",
                    "comportamental",
                    "anomalía comportamental",
                    "anomalia comportamental",
                    "threat detection engine",
                    "zero-day",
                    "zeroday",
                )
            ):
                from services.behavioral_threat_detection.kernel_insights import answer_kernel_query as btde_kernel

                btde_reply = btde_kernel(message)
                if btde_reply:
                    kernel_memory.record_interaction(
                        user_id, user_email, message, "behavioral_threat_detection", ["btde"], "query"
                    )
                    return {
                        "reply": btde_reply,
                        "request_type": "query",
                        "agent_mode": True,
                        "confirm_required": False,
                        "operation_id": operation_id,
                        "engines_executed": ["behavioral_threat_detection"],
                        "data_source": "behavioral_threat_detection",
                        "actions": [{"label": "Abrir Centro de Defensa", "type": "navigate", "url": "/centro-defensa"}],
                    }
        except Exception as btde_exc:
            logger.debug("BTDE kernel query: %s", btde_exc)

        # Sensor Red+Endpoint Enterprise sensor red — solo análisis
        try:
            msg_l = (message or "").lower()
            if any(
                k in msg_l
                for k in (
                    "sensor de red",
                    "inventario de red",
                    "rogue dhcp",
                    "dns cache",
                    "network endpoint",
                    "anomalías de red",
                    "anomalias de red",
                )
            ):
                from services.network_endpoint_enterprise.kernel_insights import answer_kernel_query as nee_kernel

                nee_reply = nee_kernel(message)
                if nee_reply:
                    kernel_memory.record_interaction(
                        user_id, user_email, message, "network_endpoint_enterprise", ["network.endpoint.enterprise"], "query"
                    )
                    return {
                        "reply": nee_reply,
                        "request_type": "query",
                        "agent_mode": True,
                        "confirm_required": False,
                        "operation_id": operation_id,
                        "engines_executed": ["network.endpoint.enterprise"],
                        "data_source": "network_endpoint_enterprise",
                        "actions": [{"label": "Abrir Network", "type": "navigate", "url": "/network"}],
                    }
        except Exception as nee_exc:
            logger.debug("NEE kernel query: %s", nee_exc)

        # Motor de inferencia de eventos — analyze-only
        try:
            msg_l = (message or "").lower()
            if any(
                k in msg_l
                for k in (
                    "kernel event",
                    "motor de eventos",
                    "inferencia del kernel",
                    "calculated_risk",
                    "recommend_isolate",
                    "aprendizaje del kernel",
                    "feedback del kernel",
                )
            ):
                from services.ai_kernel_event_engine.kernel_insights import answer_kernel_query as event_kernel

                event_reply = event_kernel(message)
                if event_reply:
                    kernel_memory.record_interaction(
                        user_id, user_email, message, "ai_kernel_event_engine", ["ai.kernel.event"], "query"
                    )
                    return {
                        "reply": event_reply,
                        "request_type": "query",
                        "agent_mode": True,
                        "confirm_required": False,
                        "operation_id": operation_id,
                        "engines_executed": ["ai.kernel.event"],
                        "data_source": "ai_kernel_event_engine",
                        "actions": [{"label": "Abrir Network", "type": "navigate", "url": "/network"}],
                    }
        except Exception as event_exc:
            logger.debug("AI kernel event query: %s", event_exc)

        # Kernel Core — saludo, escaneo YARA, aislamiento recomendado, aprendizaje
        try:
            msg_l = (message or "").lower().strip()
            core_triggers = (
                "escanea",
                "scan ",
                "falso positivo",
                "autorizar equipo",
                "genera regla yara",
                "kernel core",
            )
            if msg_l in ("hola", "buenas", "hey", "que tal") or any(t in msg_l for t in core_triggers):
                from services.ai_kernel_core.request_router import process_user_request

                core = process_user_request(message, context_data=ctx)
                if core.get("response"):
                    kernel_memory.record_interaction(
                        user_id, user_email, message, "ai_kernel_core", ["ai.kernel.core"], "query"
                    )
                    return {
                        "reply": core.get("response"),
                        "request_type": core.get("type", "query").lower(),
                        "agent_mode": True,
                        "confirm_required": False,
                        "operation_id": operation_id,
                        "engines_executed": ["ai.kernel.core"],
                        "data_source": "ai_kernel_core",
                        "executes_actions": core.get("executes_actions", False),
                        "core_data": core.get("data"),
                    }
        except Exception as core_exc:
            logger.debug("AI kernel core query: %s", core_exc)

        # Consultas NDR — exclusivamente datos del módulo Network (no Dashboard)
        try:
            from services.network_ndr_service import answer_kernel_query
            ndr_reply = answer_kernel_query(message)
            if ndr_reply is not None:
                kernel_memory.record_interaction(
                    user_id, user_email, message, "network_ndr", ["network.ndr"], "query"
                )
                return {
                    "reply": ndr_reply,
                    "request_type": "query",
                    "agent_mode": True,
                    "confirm_required": False,
                    "operation_id": operation_id,
                    "engines_executed": ["network.ndr"],
                    "data_source": "network_ndr_service",
                    "actions": [{"label": "Abrir Network", "type": "navigate", "url": "/network"}],
                }
        except Exception as ndr_exc:
            logger.debug("NDR kernel query: %s", ndr_exc)

        # Consultas de vulnerabilidades — exclusivamente motor de vulnerabilidades
        try:
            from services.vulnerability_analyst_service import answer_kernel_query as vuln_kernel_query
            vuln_reply = vuln_kernel_query(message)
            if vuln_reply is not None:
                kernel_memory.record_interaction(
                    user_id, user_email, message, "vulnerabilities", ["security.vulnerabilities"], "query"
                )
                return {
                    "reply": vuln_reply,
                    "request_type": "query",
                    "agent_mode": True,
                    "confirm_required": False,
                    "operation_id": operation_id,
                    "engines_executed": ["security.vulnerabilities"],
                    "data_source": "vulnerability_analyst_service",
                    "actions": [{"label": "Abrir Vulnerabilidades", "type": "navigate", "url": "/vulnerabilidades"}],
                }
        except Exception as vuln_exc:
            logger.debug("Vulnerability kernel query: %s", vuln_exc)

        # Amenazas runtime — motor central de seguridad
        try:
            from services.novus_security_integration import novus_security
            sec_reply = novus_security.answer_kernel_query(message, user_email=user_email)
            if sec_reply is not None:
                kernel_memory.record_interaction(
                    user_id, user_email, message, "security_runtime", ["security.threats"], "query"
                )
                return {
                    "reply": sec_reply,
                    "request_type": "query",
                    "agent_mode": True,
                    "confirm_required": False,
                    "operation_id": operation_id,
                    "engines_executed": ["security.threats", "novus_security_integration"],
                    "data_source": "novus_security_integration",
                    "actions": [{"label": "Centro de Inteligencia", "type": "navigate", "url": "/inteligencia"}],
                }
        except Exception as sec_exc:
            logger.debug("Security runtime kernel query: %s", sec_exc)

        plan = build_plan(message, context=ctx, user_prefs=user_prefs, session_id=session_id, history=history)

        base_intent = kernel_orchestrator.analyze_intent(message)
        session_ctx = kernel_session_context.enrich_from_history(session_id, history)
        intent_data = interpret_intent(message, base_intent, session_ctx, history)
        intent_data["primary_intent"] = plan.intent_id
        intent_data["primary_label"] = plan.intent_label
        if plan.capabilities:
            intent_data["capabilities"] = plan.capabilities

        logger.info(
            f"KernelAgent Fase1: intent={plan.intent_id} scenario={plan.scenario_id} "
            f"conf={plan.intent_confidence}% caps={len(plan.capabilities)} "
            f"plan_steps={len(plan.internal_plan)}"
        )

        if plan.skip_engines:
            sector_ctx = {k: ctx[k] for k in ("sector_key", "sector_label", "kernel_priorities") if k in ctx}
            reply = self._greeting_response(user_prefs, sector_ctx)
            return {"reply": reply, "request_type": "greeting", "agent_mode": True, "operation_id": operation_id}

        if plan.sync_fast_path and plan.performance_level == 1 and not plan.workflow_profile:
            return self._quick_query_response(
                session_id, message, plan, intent_data, user_id, user_email, operation_id
            )

        return kernel_coordinator.start_operation(
            session_id=session_id,
            message=message,
            plan=plan,
            intent_data=intent_data,
            user_id=user_id,
            user_email=user_email,
            user_prefs=user_prefs,
        )

    def _quick_query_response(
        self,
        session_id: str,
        message: str,
        plan: ExecutionPlan,
        intent_data: dict,
        user_id: Optional[int],
        user_email: Optional[str],
        operation_id: str,
    ) -> Dict[str, Any]:
        started = datetime.now()
        caps = plan.quick_capabilities or plan.capabilities[:3] or ["system.metrics"]
        if user_email:
            from services.sector_profile_service import get_kernel_context_for_user
            sector_ctx = get_kernel_context_for_user(user_email)
            intent_data["sector_label"] = sector_ctx.get("sector_label")
            intent_data["sector_key"] = sector_ctx.get("sector_key")
        collected = kernel_engine_orchestrator.execute_plan(
            plan, session_id, user_id, capabilities_override=caps
        )
        report = build_soc_report(
            intent=intent_data,
            data=collected,
            message=message,
            actions_executed=collected.get("orchestrator_actions") or [],
            started_at=started,
            timeline=plan.internal_plan or [f"Consulta rápida — {', '.join(caps)}"],
        )
        elapsed = round((datetime.now() - started).total_seconds(), 2)
        kernel_session_context.update_after_operation(
            session_id, operation_id, plan.intent_id,
            collected.get("capabilities_executed") or caps,
            report.get("risk_level", ""),
            report_summary=report.get("reply", "")[:500],
        )
        kernel_memory.record_interaction(
            user_id, user_email, message, plan.intent_id,
            collected.get("capabilities_executed") or caps, "query",
        )
        header = f"⚡ Consulta rápida ({elapsed}s)"
        if collected.get("cache_hits"):
            header += f" — {collected['cache_hits']} dato(s) desde caché"
        return {
            "reply": f"{header}\n\n{report['reply']}",
            "request_type": "query",
            "agent_mode": True,
            "performance_level": 1,
            "elapsed_sec": elapsed,
            "confirm_required": False,
            "operation_id": operation_id,
            "engines_executed": collected.get("capabilities_executed") or caps,
            "risk_level": report.get("risk_level"),
            "actions": report.get("actions", []),
        }

    def _greeting_response(self, prefs: dict, sector_ctx: Optional[dict] = None) -> str:
        from services.ai_kernel_brain.kernel_prompt import get_kernel_brain

        brain = get_kernel_brain()
        saludo = brain.get_time_based_greeting()
        total = prefs.get("total_interactions", 0)
        freq = prefs.get("frequent_intents") or []
        sector_label = (sector_ctx or {}).get("sector_label") or prefs.get("sector_label") or "SOC"
        priorities = (sector_ctx or {}).get("kernel_priorities") or []
        lines = [
            f"{saludo}. Analista SOC/XDR NOVUS — sector {sector_label}.",
            "",
            "Indíqueme qué desea analizar; adaptaré motores y prioridades a su perfil sectorial.",
            "Ejecuto motores reales y reporto solo evidencia verificada.",
        ]
        if priorities:
            lines.append(f"Prioridades activas: {', '.join(priorities[:4])}.")
        if total > 0:
            lines.append(f"\n({total} interacciones previas registradas.)")
        if freq:
            lines.append(f"Suele consultar: {', '.join(freq[:3])}.")
        return "\n".join(lines)


kernel_agent = KernelAgent()
