"""
Orquestador central de motores — Fase 1 Kernel IA.

Decide qué motores ejecutar, en qué orden, en paralelo o omitidos.
Reutiliza ai_orchestrator.collect_capabilities y capability_registry.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from services.ai_orchestrator import kernel_orchestrator
from services.kernel_performance_planner import partition_parallel
from services.kernel_planner import ExecutionPlan
from services.kernel_session_context import kernel_session_context
from utils.logger import logger


class KernelEngineOrchestrator:
    """Orquestación central — sin duplicar motores."""

    def execute_plan(
        self,
        plan: ExecutionPlan,
        session_id: str,
        user_id: Optional[int],
        capabilities_override: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        caps = list(capabilities_override or plan.capabilities or [])
        force = plan.force_refresh_policy

        # Omitir motores recientes si la política lo permite
        filtered = []
        skipped = []
        for cap in caps:
            if kernel_session_context.should_skip_engine(session_id, cap, force):
                skipped.append(cap)
            else:
                filtered.append(cap)
        if skipped:
            logger.info(f"Orquestador: reutilizando caché para {len(skipped)} motor(es): {skipped[:5]}")

        if not filtered and skipped:
            filtered = skipped  # si todos en caché, ejecutar lectura cache anyway

        groups = plan.parallel_groups if plan.parallel_groups else (
            partition_parallel(filtered) if filtered else []
        )
        if not groups and filtered:
            groups = [filtered]

        collected: Dict[str, Any] = {
            "capabilities_executed": [],
            "capabilities_failed": [],
            "modules_queried": [],
            "gaps": [],
            "cache_hits": 0,
            "engines_skipped_cache": skipped,
        }

        actions_log: List[dict] = []

        # Acciones orquestadas primero (side effects)
        for action_name in plan.orchestrator_actions or []:
            ar = kernel_orchestrator.execute_action(action_name, session_id, user_id=user_id)
            actions_log.append(ar)

        for group in groups:
            if not group:
                continue
            active = [c for c in group if c in filtered or c in caps]
            if not active:
                continue
            part = kernel_orchestrator.collect_capabilities(
                active,
                user_id=user_id,
                force_refresh=force,
                parallel_groups=partition_parallel(active) if len(active) > 1 else None,
                cache_ttl_sec=plan.cache_ttl_sec,
            )
            for k, v in part.items():
                if k in ("capabilities_executed", "capabilities_failed", "modules_queried", "gaps", "cache_hits", "_capability_raw"):
                    if isinstance(v, list) and isinstance(collected.get(k), list):
                        collected[k] = list(dict.fromkeys((collected.get(k) or []) + v))
                    elif k == "cache_hits":
                        collected[k] = (collected.get(k) or 0) + (v or 0)
                    else:
                        collected[k] = v
                elif not str(k).startswith("_"):
                    collected[k] = v

        kernel_session_context.record_engines(
            session_id, collected.get("capabilities_executed") or filtered
        )
        collected["orchestrator_actions"] = actions_log
        return collected


kernel_engine_orchestrator = KernelEngineOrchestrator()
