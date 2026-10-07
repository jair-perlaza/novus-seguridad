"""
Swarm Defense Engine — inteligencia de enjambre para NOVUS.
Capa aditiva: colabora sobre telemetría real; no reemplaza motores.
"""
from __future__ import annotations

import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.swarm_defense.collaborators import collaborator_catalog, run_collaborators
from services.swarm_defense.correlation import correlate
from services.swarm_defense.event_bus import (
    TOPIC_ANOMALY,
    TOPIC_CORRELATED,
    swarm_event_bus,
)
from services.swarm_defense.indicators import correlation_keys, extract_indicators
from services.swarm_defense.learning import record_confirmed_incident
from services.swarm_defense.response_policy import (
    APPROVAL_REQUIRED,
    AUTO_ALLOWED,
    LIMITATIONS,
    apply_auto_responses,
    execute_swarm_action,
)
from utils.logger import logger

_TRIGGER = re.compile(
    r"\b(swarm\s*defense|enjambre|swarm\s*engine|inteligencia\s+de\s+enjambre|"
    r"correlaci[oó]n\s+swarm|defensa\s+enjambre)\b",
    re.I,
)

_processing_lock = threading.Lock()
_recent_correlations: List[Dict[str, Any]] = []
_MAX_CORR = 100
_seen_keys: Dict[str, float] = {}
_DEDUP_SECONDS = 45.0
_reentrancy = threading.local()
_obs_metrics: Dict[str, float] = {
    "events_processed": 0,
    "response_time_ms_sum": 0.0,
    "coordinated_decisions": 0,
}


def _in_swarm() -> bool:
    return bool(getattr(_reentrancy, "depth", 0))


def _enter_swarm() -> None:
    _reentrancy.depth = getattr(_reentrancy, "depth", 0) + 1


def _leave_swarm() -> None:
    _reentrancy.depth = max(0, getattr(_reentrancy, "depth", 0) - 1)


class SwarmDefenseEngine:
    VERSION = "1.2.0-enterprise-mesh"

    def __init__(self) -> None:
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        swarm_event_bus.subscribe(TOPIC_ANOMALY, self._on_anomaly)
        self._started = True
        logger.info("Swarm Defense Engine started (bus topic=%s)", TOPIC_ANOMALY)

    def status(self) -> Dict[str, Any]:
        self.start()
        processed = int(_obs_metrics.get("events_processed") or 0)
        avg_ms = None
        if processed > 0:
            avg_ms = round(float(_obs_metrics.get("response_time_ms_sum") or 0) / processed, 2)
        bus_health = swarm_event_bus.health()
        from services.swarm_defense.collective_memory import memory_stats
        from services.swarm_defense.learning import learning_stats

        mesh = None
        try:
            from services.swarm_defense.mesh import mesh_status as _mesh_status

            mesh = _mesh_status()
        except Exception as exc:
            mesh = {"ok": False, "implemented": False, "error": str(exc)[:120]}

        return {
            "ok": True,
            "engine": "swarm_defense_engine",
            "version": self.VERSION,
            "replaces_existing_engines": False,
            "evidence_policy": "real_telemetry_only",
            "bus_topics": swarm_event_bus.topics(),
            "bus_health": bus_health,
            "mesh": mesh,
            "collaborators": collaborator_catalog(),
            "auto_actions": sorted(AUTO_ALLOWED),
            "approval_actions": sorted(APPROVAL_REQUIRED),
            "limitations": list(LIMITATIONS),
            "recent_events": len(swarm_event_bus.recent(200)),
            "recent_correlations": len(_recent_correlations),
            "observability": {
                "motors_active": len(collaborator_catalog()),
                "events_processed": processed,
                "coordinated_decisions": int(_obs_metrics.get("coordinated_decisions") or 0),
                "avg_response_ms": avg_ms,
                "memory": memory_stats(),
                "learning": learning_stats(),
                "mesh_peers_connected": (mesh or {}).get("peers_connected"),
            },
            "kernel_policy": {
                "executes_actions": False,
                "final_decision_owner": "swarm_defense_engine",
            },
            "wired_containment": {
                "block_domain": True,
                "isolate_host": True,
                "revoke_sessions": True,
                "block_ip": True,
                "kill_process": True,
            },
        }

    def observability(self) -> Dict[str, Any]:
        """Panel técnico — solo métricas reales."""
        st = self.status()
        mesh = st.get("mesh") or {}
        return {
            "ok": True,
            "motors_active": st["observability"]["motors_active"],
            "collaborators": [c["module_id"] for c in st["collaborators"]],
            "events_processed": st["observability"]["events_processed"],
            "coordinated_decisions": st["observability"]["coordinated_decisions"],
            "avg_response_ms": st["observability"]["avg_response_ms"],
            "bus": st["bus_health"],
            "mesh": {
                "peers_connected": mesh.get("peers_connected"),
                "trusted_peers": mesh.get("trusted_peers"),
                "outbound": (mesh.get("sync") or {}).get("outbound_events"),
                "inbound": (mesh.get("sync") or {}).get("inbound_events"),
                "ioc_counts": (mesh.get("sync") or {}).get("ioc_counts"),
                "crypto_ok": (mesh.get("node") or {}).get("crypto_ok"),
                "health": mesh.get("health"),
                "node_id": (mesh.get("node") or {}).get("node_id"),
            },
            "correlations_buffered": st["recent_correlations"],
            "memory": st["observability"]["memory"],
            "learning": st["observability"]["learning"],
            "health": "ok" if st["ok"] else "degraded",
        }

    def notify_detection(self, event_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Entrada desde defense_coordinator — publica en el bus."""
        self.start()
        if not event_payload:
            return None
        if _in_swarm():
            return None
        motor = str(event_payload.get("motor") or "")
        evidence = event_payload.get("evidence") if isinstance(event_payload.get("evidence"), dict) else {}
        if motor == "swarm_defense_engine" or evidence.get("swarm"):
            return None

        payload = dict(event_payload)
        payload["_swarm_started_at"] = datetime.now(timezone.utc).isoformat()
        return swarm_event_bus.publish(TOPIC_ANOMALY, payload)

    def _on_anomaly(self, bus_event: Dict[str, Any]) -> None:
        payload = bus_event.get("payload") or {}
        try:
            result = self.process_event(payload)
            if result:
                swarm_event_bus.publish(TOPIC_CORRELATED, result)
        except Exception as exc:
            logger.debug("swarm process_event: %s", exc)

    def process_event(self, event_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        indicators = extract_indicators(event_payload)
        keys = correlation_keys(indicators, event_payload)
        now = datetime.now(timezone.utc).timestamp()

        with _processing_lock:
            for k in keys:
                last = _seen_keys.get(k)
                if last and (now - last) < _DEDUP_SECONDS:
                    return {
                        "deduplicated": True,
                        "key": k,
                        "message": "Evento duplicado en ventana Swarm — no se re-procesa",
                        "policy": "real_evidence_only",
                    }
            for k in keys:
                _seen_keys[k] = now
            stale = [k for k, t in _seen_keys.items() if now - t > 600]
            for k in stale:
                _seen_keys.pop(k, None)

        _enter_swarm()
        try:
            t0 = datetime.now(timezone.utc)
            contributions = run_collaborators(event_payload, indicators)
            correlation = correlate(event_payload, indicators, contributions)
            # Memoria colectiva → reincidencia
            from services.swarm_defense.collective_memory import (
                lookup_similar,
                remember_incident,
                resolve_memory_tenant_id,
            )
            from services.swarm_defense.priority import compute_priority

            # P0-1: collective_memory operativa solo con tenant inequívoco (deny-by-default).
            memory_tenant_id = resolve_memory_tenant_id(event_payload)
            memory_hit = lookup_similar(
                indicators=indicators,
                category=(correlation.get("classification") or {}).get("category"),
                tenant_id=memory_tenant_id,
                origin_event=event_payload,
            )
            priority = compute_priority(
                classification=correlation.get("classification") or {},
                confidence=correlation.get("confidence") or {},
                indicators=indicators,
                origin_event=event_payload,
                memory_hit=memory_hit,
            )
            correlation["memory"] = memory_hit
            correlation["priority"] = priority
            correlation["bus_event_ref"] = event_payload.get("finding_id")
            correlation["origin"] = {
                "motor": event_payload.get("motor"),
                "action": event_payload.get("action"),
                "phase": event_payload.get("phase"),
                "threat_type": event_payload.get("threat_type"),
                "finding_id": event_payload.get("finding_id"),
            }
            correlation["processed_at"] = datetime.now(timezone.utc).isoformat()
            correlation["kernel_role"] = {
                "executes_actions": False,
                "analyzes": True,
                "correlates": True,
                "prioritizes": True,
                "explains": True,
                "proposes": True,
                "final_decision_owner": "swarm_defense_engine",
            }

            # Solo responder tras contexto: require sufficient_evidence OR at least 1 module
            conf = correlation.get("confidence") or {}
            if conf.get("level") == "insufficient_evidence":
                correlation["auto_responses"] = [
                    {
                        "ok": False,
                        "status": "deferred",
                        "message": "Swarm espera más contexto de colaboradores antes de responder",
                    }
                ]
            else:
                auto_results = apply_auto_responses(correlation, event_payload)
                correlation["auto_responses"] = auto_results

                if correlation.get("sufficient_evidence"):
                    path = record_confirmed_incident(
                        correlation,
                        event_payload,
                        source="swarm_auto",
                        response_results=auto_results,
                    )
                    correlation["learning_path"] = path
                    remember_incident(
                        correlation=correlation,
                        origin_event=event_payload,
                        priority=priority,
                        tenant_id=memory_tenant_id,
                    )

            elapsed_ms = (datetime.now(timezone.utc) - t0).total_seconds() * 1000.0
            correlation["response_time_ms"] = round(elapsed_ms, 2)

            with _processing_lock:
                _recent_correlations.append(correlation)
                if len(_recent_correlations) > _MAX_CORR:
                    del _recent_correlations[0 : len(_recent_correlations) - _MAX_CORR]
                _obs_metrics["events_processed"] = _obs_metrics.get("events_processed", 0) + 1
                _obs_metrics["response_time_ms_sum"] = _obs_metrics.get("response_time_ms_sum", 0) + elapsed_ms
                if correlation.get("auto_responses"):
                    _obs_metrics["coordinated_decisions"] = _obs_metrics.get("coordinated_decisions", 0) + 1

            try:
                from services.swarm_defense.event_bus import TOPIC_PRIORITY, swarm_event_bus

                swarm_event_bus.publish(TOPIC_PRIORITY, {"priority": priority, "finding_id": event_payload.get("finding_id")})
            except Exception:
                pass

            # Mesh colonia: propagar intel real a peers (no reenviar intel remota)
            evidence = event_payload.get("evidence") if isinstance(event_payload.get("evidence"), dict) else {}
            if (
                correlation.get("sufficient_evidence")
                and event_payload.get("motor") != "swarm_mesh"
                and not evidence.get("swarm_mesh_remote")
            ):
                try:
                    from services.swarm_defense.mesh.propagator import propagate_to_peers

                    mesh_result = propagate_to_peers(
                        correlation=correlation,
                        origin_event=event_payload,
                        indicators=indicators,
                    )
                    correlation["mesh_propagate"] = {
                        "ok": mesh_result.get("ok"),
                        "sent": mesh_result.get("sent"),
                        "peers_targeted": mesh_result.get("peers_targeted"),
                    }
                except Exception as mesh_exc:
                    correlation["mesh_propagate"] = {"ok": False, "error": str(mesh_exc)[:120]}

            return correlation
        finally:
            _leave_swarm()

    def recent_correlations(self, limit: int = 20) -> List[Dict[str, Any]]:
        with _processing_lock:
            return list(_recent_correlations[-limit:])

    def execute_action(
        self,
        action_id: str,
        *,
        correlation: Optional[Dict[str, Any]] = None,
        origin_event: Optional[Dict[str, Any]] = None,
        user_email: Optional[str] = None,
        confirmed: bool = False,
        reason: str = "",
        params: Optional[dict] = None,
    ) -> Dict[str, Any]:
        corr = correlation or (self.recent_correlations(1)[-1] if self.recent_correlations(1) else {})
        origin = origin_event or corr.get("origin") or {}
        _enter_swarm()
        try:
            return execute_swarm_action(
                action_id,
                correlation=corr,
                origin_event=origin,
                user_email=user_email,
                confirmed=confirmed,
                reason=reason,
                params=params,
            )
        finally:
            _leave_swarm()

    def answer_kernel_query(
        self,
        message: str,
        user_email: Optional[str] = None,
        context: Optional[dict] = None,
    ) -> Optional[str]:
        text = (message or "").strip()
        if not text or not _TRIGGER.search(text):
            return None
        st = self.status()
        lines = [
            "## Swarm Defense Engine",
            "Inteligencia de enjambre activa. No reemplaza motores existentes.",
            "Política: solo telemetría y evidencia real.",
            "**Kernel IA no ejecuta acciones** — solo analiza/prioriza/explica/propone. Decisión final: Swarm.",
            "",
            f"- Colaboradores: **{len(st['collaborators'])}**",
            f"- Acciones auto: {', '.join(st['auto_actions'])}",
            f"- Requieren aprobación: {', '.join(st['approval_actions'])}",
            f"- Eventos procesados: {st['observability']['events_processed']}",
            f"- Tiempo medio respuesta (ms): {st['observability']['avg_response_ms']}",
            "",
            "### Módulos participantes",
        ]
        for c in st["collaborators"]:
            lines.append(f"- **{c['label']}**: {', '.join(c['contributes'])}")
        recent = self.recent_correlations(3)
        lines.append("")
        lines.append("### Últimas correlaciones")
        if not recent:
            lines.append(
                "Sin correlaciones recientes (aún no hay eventos de detección publicados al bus)."
            )
        else:
            for corr in recent:
                conf = corr.get("confidence") or {}
                cls = corr.get("classification") or {}
                lines.append(
                    f"- categoría=`{cls.get('category')}` confianza=`{conf.get('level')}` "
                    f"módulos={cls.get('supporting_modules')} "
                    f"{'(deduplicado)' if corr.get('deduplicated') else ''}"
                )
        lines.append("")
        lines.append("### Limitaciones actuales")
        for lim in st["limitations"]:
            lines.append(f"- {lim}")
        lines.append("")
        lines.append("API: `GET /api/swarm-defense/status`")
        return "\n".join(lines)


swarm_defense_engine = SwarmDefenseEngine()


def notify_detection(event_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Hook público para defense_coordinator."""
    try:
        return swarm_defense_engine.notify_detection(event_payload)
    except Exception as exc:
        logger.debug("swarm notify_detection: %s", exc)
        return None
