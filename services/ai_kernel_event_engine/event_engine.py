"""Motor de inferencia de eventos — recomendaciones only."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from services.ai_kernel_event_engine.knowledge_adapter import get_knowledge_adapter
from services.ai_kernel_event_engine.system_context import NOVUSAISystemContext
from utils.logger import logger

_engine: Optional["NOVUSAIKernelEngine"] = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _map_device_type(raw: str) -> str:
    mapping = {
        "CELULAR": "Celular",
        "TABLET": "Tablet",
        "PORTATIL": "Laptop",
        "PORTÁTIL": "Laptop",
        "COMPUTADOR": "PC",
        "DISPOSITIVO_LINUX_UNIX": "Otro",
        "DESCONOCIDO": "Otro",
    }
    key = (raw or "").upper()
    return mapping.get(key, raw or "Otro")


class NOVUSAIKernelEngine:
    """
    Capa 2: inferencia sobre eventos de red/radar/endpoint.
    No ejecuta aislamiento ni firewall — delega recomendación al flujo AIE/Swarm.
    """

    def __init__(self, defense_controller_ref=None):
        self.system_context = NOVUSAISystemContext.SYSTEM_INSTRUCTIONS
        self.adapter = get_knowledge_adapter()
        self.defense_controller = defense_controller_ref

    def analyze_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        mac = (payload.get("mac") or "").upper()
        ip = payload.get("ip") or "NO DISPONIBLE"
        device_type = _map_device_type(payload.get("device_type") or "Otro")
        attack_count = int(payload.get("attack_count") or 0)
        details = payload.get("details") or payload.get("message") or ""

        if self.adapter.is_whitelisted(mac):
            return {
                "timestamp": _utc_now(),
                "event_type": event_type,
                "mac": mac,
                "ip": ip,
                "device_type": device_type,
                "calculated_risk": 0,
                "risk_modifier_applied": self.adapter.get_risk_modifier(mac),
                "recommended_action": "ALLOW",
                "recommendation": "ALLOW",
                "executes_actions": False,
                "action_executed_autonomously": False,
                "reasons": ["Activo con excepción aprendida por retroalimentación admin"],
                "verified": True,
                "invented": False,
            }

        risk_modifier = self.adapter.get_risk_modifier(mac)
        base_risk = 0.0
        reasons = []

        et = (event_type or "").upper()
        if et == "ANOMALOUS_PROCESS":
            base_risk += 60
            reasons.append(
                f"Comportamiento de proceso sospechoso observable ({details or 'sin detalle'}) — no confirma malware"
            )
        elif et == "OFFICE_SUSPICIOUS_CHILD":
            base_risk += 45
            reasons.append(
                f"Office inició hijo sospechoso ({details or 'sin detalle'}) — señal BTDE, no incidente automático"
            )
        elif et == "PROCESS_MASQUERADING":
            base_risk += 50
            reasons.append(
                f"Posible suplantación de proceso ({details or 'sin detalle'}) — heurística de ruta"
            )
        elif et == "UNRECOGNIZED_SUBNET_CONNECT":
            base_risk += 40
            reasons.append(f"Dispositivo {device_type} en subred no habitual")
        elif et == "DEVICE_ATTACK_ACCUMULATION":
            base_risk += min(80, attack_count * 15)
            reasons.append(f"Dispositivo acumula {attack_count} señales de ataque registradas")

        if attack_count > 0 and et != "DEVICE_ATTACK_ACCUMULATION":
            base_risk += min(40, attack_count * 20)
            reasons.append(f"Historial: {attack_count} señales previas en inventario AIE")

        final_risk = round(base_risk * risk_modifier, 1)

        if final_risk >= 70:
            recommendation = "RECOMMEND_ISOLATE"
        elif final_risk >= 40:
            recommendation = "RECOMMEND_MONITOR"
        else:
            recommendation = "ALLOW"

        result = {
            "timestamp": _utc_now(),
            "event_type": et,
            "mac": mac,
            "ip": ip,
            "device_type": device_type,
            "calculated_risk": final_risk,
            "risk_modifier_applied": risk_modifier,
            "recommended_action": recommendation,
            "recommendation": recommendation,
            "executes_actions": False,
            "action_executed_autonomously": False,
            "reasons": reasons,
            "verified": bool(mac or ip != "NO DISPONIBLE"),
            "invented": False,
        }

        if recommendation == "RECOMMEND_ISOLATE" and self.defense_controller and mac:
            iso = self.defense_controller.isolate_device(mac, admin_request=False)
            result["isolation_recommendation"] = iso
            result["note"] = (
                "Aislamiento recomendado — use POST /api/network/assets/<mac>/action action=isolate "
                "o aprobación Swarm"
            )

        return result


def get_ai_kernel_engine() -> NOVUSAIKernelEngine:
    global _engine
    if _engine is None:
        try:
            from services.network_device_defense.defense_controller import get_defense_controller

            dc = get_defense_controller()
        except Exception:
            dc = None
        _engine = NOVUSAIKernelEngine(defense_controller_ref=dc)
    return _engine


def analyze_security_event(event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """API funcional del motor — recomendación only."""
    try:
        return get_ai_kernel_engine().analyze_event(event_type, payload)
    except Exception as exc:
        logger.debug("analyze_security_event: %s", exc)
        return {
            "timestamp": _utc_now(),
            "event_type": event_type,
            "recommended_action": "ALLOW",
            "recommendation": "ALLOW",
            "executes_actions": False,
            "action_executed_autonomously": False,
            "error": str(exc)[:160],
            "verified": False,
            "invented": False,
        }
