"""Router de peticiones del Kernel Core — delega a motores canónicos."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from services.ai_kernel_core.audit_log import log_audit
from services.ai_kernel_core.system_prompt_factory import NOVUSSystemPromptFactory
from utils.logger import logger

_engine: Optional["NOVUSAIKernelCoreEngine"] = None

_GREETINGS = frozenset(
    {
        "hola",
        "buenas",
        "que tal",
        "hey",
        "iniciar",
        "buenos dias",
        "buenas tardes",
        "buenas noches",
    }
)


class NOVUSAIKernelCoreEngine:
    """
    Controlador principal — conecta UI/chat con motores existentes.
    NOVUSNetworkEnforcer (iptables/netsh) no integrado.
    """

    def process_user_request(
        self,
        user_input: str,
        context_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        user_input_lower = (user_input or "").lower().strip()
        context_data = context_data or {}

        if user_input_lower in _GREETINGS:
            greeting = NOVUSSystemPromptFactory.get_time_greeting()
            resp = (
                f"{greeting}. IA Kernel de NOVUS activa. "
                "Indique qué área desea analizar; ejecuto motores reales y reporto evidencia verificada."
            )
            entry = log_audit("GREETING", {"input": user_input, "executes_actions": False})
            return {
                "type": "GREETING",
                "response": resp,
                "executes_actions": False,
                "audit_id": entry.get("timestamp"),
                "verified": True,
                "invented": False,
            }

        if any(term in user_input_lower for term in ("escanea", "analiza", "revisa carpeta", "escaneo", "scan")):
            path_match = re.search(r'[\'"]?([a-zA-Z]:\\[^\'"]+|/[^\'"]+)[\'"]?', user_input or "")
            target_path = path_match.group(1) if path_match else context_data.get("target_path", ".")
            from services.endpoint_enterprise.yara_engine import reload_engine, scan_directory

            reload_engine()
            scan_result = scan_directory(target_path, max_files=int(context_data.get("max_files") or 50))
            log_audit("FILE_SCAN", {**scan_result, "executes_actions": False})
            count = scan_result.get("matches_count") or 0
            if count > 0:
                resp = (
                    f"Escaneo YARA completado en '{target_path}': "
                    f"{scan_result.get('files_scanned', 0)} archivos, {count} coincidencia(s) heurística(s). "
                    "Correlacionar con BTDE antes de contención."
                )
            else:
                resp = (
                    f"Escaneo finalizado en '{target_path}'. "
                    f"Archivos analizados: {scan_result.get('files_scanned', 0)}. "
                    f"Estado motor: {scan_result.get('status')}."
                )
            return {
                "type": "SCAN_RESULT",
                "response": resp,
                "data": scan_result,
                "executes_actions": False,
                "verified": scan_result.get("verified", False),
                "invented": False,
            }

        if any(term in user_input_lower for term in ("aisla", "bloquea", "corta acceso", "isolate")):
            mac = context_data.get("mac", "")
            ip = context_data.get("ip", "")
            from services.network_device_defense.defense_controller import get_defense_controller

            admin = bool(context_data.get("admin_request"))
            iso = get_defense_controller().isolate_device(mac, admin_request=admin)
            log_audit(
                "ISOLATION_REQUEST",
                {"mac": mac, "ip": ip, "result": iso, "executes_actions": iso.get("executes_actions", False)},
            )
            if admin and iso.get("executes_actions"):
                resp = iso.get("message") or "Acción administrativa AIE aplicada."
            else:
                resp = (
                    iso.get("message")
                    or "Se recomienda aislamiento en inventario AIE — requiere acción admin o Swarm."
                )
            return {
                "type": "ENFORCEMENT_RECOMMENDATION" if not admin else "ENFORCEMENT_ACTION",
                "response": resp,
                "data": iso,
                "success": iso.get("status") in ("SUCCESS", "RECOMMENDATION"),
                "executes_actions": bool(iso.get("executes_actions")),
                "executes_network_block": False,
                "verified": True,
                "invented": False,
            }

        if "falso positivo" in user_input_lower or "autorizar equipo" in user_input_lower:
            mac = context_data.get("mac", "")
            reason = user_input
            from services.ai_kernel_event_engine.knowledge_adapter import get_knowledge_adapter

            learn = get_knowledge_adapter().learn_from_feedback(
                mac,
                original_verdict="unknown",
                admin_action="OVERRIDE_UNBLOCK",
                reason=reason,
            )
            log_audit("LEARNING_OVERRIDE", {**learn, "mac": mac})
            resp = f"Aprendizaje registrado para {mac.upper() or 'NO DISPONIBLE'}. Umbral ajustado."
            return {
                "type": "LEARNING_UPDATED",
                "response": resp,
                "data": learn,
                "executes_actions": False,
                "verified": True,
                "invented": False,
            }

        if "genera regla yara" in user_input_lower or "generate yara" in user_input_lower:
            from services.endpoint_enterprise.yara_engine import generate_yara_rule_draft

            draft = generate_yara_rule_draft(
                "KeyloggingPattern",
                ["GetAsyncKeyState", "SetWindowsHookEx"],
            )
            log_audit("YARA_DRAFT_GENERATED", {"executes_actions": False})
            return {
                "type": "YARA_DRAFT",
                "response": "Borrador YARA generado — requiere revisión humana antes de despliegue en rules/.",
                "data": {"rule_draft": draft},
                "executes_actions": False,
                "verified": True,
                "invented": False,
            }

        system_prompt = NOVUSSystemPromptFactory.build_system_prompt()
        resp = (
            f"Consulta recibida: '{user_input[:120]}'. "
            "Para análisis con motores reales use kernel_operator (escaneo, red, procesos). "
            "executes_actions=false por defecto."
        )
        log_audit("GENERAL_QUERY", {"input": user_input[:200], "executes_actions": False})
        return {
            "type": "GENERAL_KNOWLEDGE",
            "response": resp,
            "prompt_used_excerpt": system_prompt[:400],
            "module_status": NOVUSSystemPromptFactory.module_status(),
            "executes_actions": False,
            "verified": True,
            "invented": False,
        }


def get_kernel_core_engine() -> NOVUSAIKernelCoreEngine:
    global _engine
    if _engine is None:
        _engine = NOVUSAIKernelCoreEngine()
    return _engine


def process_user_request(user_input: str, context_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    try:
        return get_kernel_core_engine().process_user_request(user_input, context_data)
    except Exception as exc:
        logger.debug("process_user_request: %s", exc)
        return {
            "type": "ERROR",
            "response": str(exc)[:200],
            "executes_actions": False,
            "verified": False,
            "invented": False,
        }
