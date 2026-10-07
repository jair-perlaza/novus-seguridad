"""Núcleo unificado del IA Kernel — facade sobre motores existentes (4 capas)."""
from services.ai_kernel_core.request_router import (
    NOVUSAIKernelCoreEngine,
    get_kernel_core_engine,
    process_user_request,
)
from services.ai_kernel_core.system_prompt_factory import NOVUSSystemPromptFactory
from services.ai_kernel_core.action_payload import (
    ActionPayload,
    execute_action_payload,
    infer_intent_from_text,
    validate_action_payload,
)
from services.ai_kernel_core.ws_kernel_bridge import process_kernel_ws_message

__all__ = [
    "NOVUSSystemPromptFactory",
    "NOVUSAIKernelCoreEngine",
    "get_kernel_core_engine",
    "process_user_request",
    "ActionPayload",
    "execute_action_payload",
    "infer_intent_from_text",
    "validate_action_payload",
    "process_kernel_ws_message",
]
