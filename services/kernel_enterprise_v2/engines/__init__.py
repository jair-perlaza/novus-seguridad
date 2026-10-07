"""
Engines Kernel IA Enterprise V2.0 — coordinación modular sobre datos reales.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from services.kernel_enterprise_v2.base import BaseEngine
from services.kernel_enterprise_v2.registry import PackRegistry


class ReasoningEngine(BaseEngine):
    engine_id = "reasoning"
    label = "Reasoning Engine"
    version = "1.0.0"

    def run(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Correlaciona módulos solo con hechos recolectados — sin inferencias inventadas."""
        query = str(request.get("query") or "")
        registry: PackRegistry = request["registry"]
        packs = registry.match_knowledge(query, limit=6)
        correlations: List[Dict[str, Any]] = []
        gaps: List[str] = []
        for pack in packs:
            ev = pack.collect_evidence(query, request.get("context"))
            correlations.append(
                {
                    "pack_id": pack.pack_id,
                    "label": pack.label,
                    "found": ev.found,
                    "sources": ev.sources,
                    "fact_count": len(ev.facts),
                    "gaps": ev.gaps,
                }
            )
            if not ev.found:
                gaps.extend(ev.gaps)
        modules = [
            "centro_defensa",
            "network",
            "xdr",
            "ndr",
            "mail_shield",
            "web_shield",
            "endpoint",
            "reportes",
            "forense",
            "compliance",
            "casos_estudio",
            "historial",
            "inventario",
            "topology",
            "escudos_sectoriales",
        ]
        return {
            "engine": self.engine_id,
            "query": query,
            "correlated_packs": correlations,
            "module_surface": modules,
            "gaps": gaps[:20],
            "policy": "Solo hechos de Knowledge Packs / motores. Sin simulaciones.",
            "sufficient_evidence": any(c["found"] for c in correlations),
        }


class AutomationEngine(BaseEngine):
    engine_id = "automation"
    label = "Automation Engine"
    version = "1.0.0"

    def run(self, request: Dict[str, Any]) -> Dict[str, Any]:
        registry: PackRegistry = request["registry"]
        action_id = request.get("action_id")
        if not action_id:
            # Listar acciones de automatización cableadas
            actions = [a for a in registry.list_actions(category="automation") if a.get("wired")]
            return {
                "engine": self.engine_id,
                "mode": "catalog",
                "wired_automation_actions": actions,
                "note": "Ejecución requiere action_id + RBAC + confirmación + auditoría",
            }
        pack = registry.get_action(action_id)
        if not pack:
            return {
                "engine": self.engine_id,
                "ok": False,
                "status": "error",
                "message": f"Action pack no encontrado: {action_id}",
            }
        result = pack.execute(
            user_email=request.get("user_email"),
            user_role=request.get("user_role"),
            params=request.get("params") or {},
            confirmed=bool(request.get("confirmed")),
            reason=str(request.get("reason") or ""),
        )
        return {"engine": self.engine_id, **result.to_dict()}


class LearningEngine(BaseEngine):
    engine_id = "learning"
    label = "Learning Engine"
    version = "1.0.0"

    def run(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Aprendizaje verificable — solo lee stores existentes (kernel_memory, audits)."""
        facts: List[Dict[str, Any]] = []
        gaps: List[str] = []
        try:
            from services.kernel_memory import kernel_memory

            prefs = kernel_memory.get_preferences(
                request.get("user_id"), request.get("user_email")
            )
            facts.append({"source": "kernel_memory.preferences", "data": prefs})
        except Exception as exc:
            gaps.append(f"kernel_memory: {exc}")
        try:
            from services.kernel_enterprise_v2.audit import recent_audits

            facts.append({"source": "kernel_enterprise_v2.audit", "data": recent_audits(20)})
        except Exception as exc:
            gaps.append(f"audit: {exc}")
        try:
            from services.defense_evidence_registry import list_recent_events

            facts.append({"source": "defense_evidence_registry", "data": list_recent_events(15)})
        except Exception as exc:
            try:
                from services.defense_evidence_registry import recent_events

                facts.append({"source": "defense_evidence_registry", "data": recent_events(15)})
            except Exception as exc2:
                gaps.append(f"defense_evidence_registry: {exc}; {exc2}")
        return {
            "engine": self.engine_id,
            "verifiable": True,
            "never_lose_knowledge": "persistencia append-only + kernel_memory",
            "facts": facts,
            "gaps": gaps,
            "policy": "Sin modelos externos ni datos inventados",
        }


class ComplianceEngine(BaseEngine):
    engine_id = "compliance"
    label = "Compliance Engine"
    version = "1.0.0"

    def run(self, request: Dict[str, Any]) -> Dict[str, Any]:
        registry: PackRegistry = request["registry"]
        pack = registry.get_knowledge("gov.compliance") or registry.get_knowledge("compliance.iso27001")
        if pack:
            ev = pack.collect_evidence(str(request.get("query") or "cumplimiento"), request.get("context"))
            return {"engine": self.engine_id, "evidence": ev.to_dict()}
        return {
            "engine": self.engine_id,
            "found": False,
            "gaps": ["Knowledge pack de cumplimiento no registrado"],
        }


class ForensicEngine(BaseEngine):
    engine_id = "forensic"
    label = "Forensic Engine"
    version = "1.0.0"

    def run(self, request: Dict[str, Any]) -> Dict[str, Any]:
        registry: PackRegistry = request["registry"]
        pack = registry.get_knowledge("forensic.digital")
        if pack:
            ev = pack.collect_evidence(str(request.get("query") or "forense"), request.get("context"))
            return {"engine": self.engine_id, "evidence": ev.to_dict()}
        return {"engine": self.engine_id, "found": False, "gaps": ["Pack forense no registrado"]}


class DeviceControlEngine(BaseEngine):
    engine_id = "device_control"
    label = "Device Control Engine"
    version = "1.0.0"

    def run(self, request: Dict[str, Any]) -> Dict[str, Any]:
        registry: PackRegistry = request["registry"]
        pack = registry.get_knowledge("sec.endpoint")
        actions = registry.list_actions(category="scan", wired_only=True)
        device_actions = [a for a in actions if "endpoint" in a["action_id"] or "device" in a["action_id"] or "usb" in a["action_id"]]
        ev = pack.collect_evidence(str(request.get("query") or "endpoint"), request.get("context")) if pack else None
        return {
            "engine": self.engine_id,
            "evidence": ev.to_dict() if ev else None,
            "available_wired_actions": device_actions,
            "policy": "Control de dispositivos solo vía Action Packs autorizados",
        }


class NetworkIntelligenceEngine(BaseEngine):
    engine_id = "network_intelligence"
    label = "Network Intelligence Engine"
    version = "1.0.0"

    def run(self, request: Dict[str, Any]) -> Dict[str, Any]:
        registry: PackRegistry = request["registry"]
        pack = registry.get_knowledge("net.networks") or registry.get_knowledge("sec.ndr")
        ev = pack.collect_evidence(str(request.get("query") or "red"), request.get("context")) if pack else None
        return {
            "engine": self.engine_id,
            "evidence": ev.to_dict() if ev else {"found": False, "gaps": ["Sin pack de red"]},
        }


class EnterpriseAssistantEngine(BaseEngine):
    engine_id = "enterprise_assistant"
    label = "Enterprise Assistant Engine"
    version = "1.0.0"

    def run(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Asistente: resume arquitectura + evidencia match; nunca inventa respuestas técnicas."""
        registry: PackRegistry = request["registry"]
        query = str(request.get("query") or "")
        knowledge = [p.meta() for p in registry.match_knowledge(query, limit=5)]
        actions = [a.meta() for a in registry.match_actions(query, limit=5)]
        summary = registry.summary()
        return {
            "engine": self.engine_id,
            "architecture": summary,
            "matched_knowledge": knowledge,
            "matched_actions": actions,
            "guidance": (
                "Use Knowledge Packs para consultar evidencia y Action Packs para ejecutar "
                "solo con permisos. Si no hay evidencia, Kernel lo declara explícitamente."
            ),
        }


def register_all_engines(registry: PackRegistry) -> int:
    engines = [
        ReasoningEngine(),
        AutomationEngine(),
        LearningEngine(),
        ComplianceEngine(),
        ForensicEngine(),
        DeviceControlEngine(),
        NetworkIntelligenceEngine(),
        EnterpriseAssistantEngine(),
    ]
    for eng in engines:
        registry.register_engine(eng)
    return len(engines)
