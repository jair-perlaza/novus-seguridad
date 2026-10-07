"""Paquete de agentes especializados del Kernel IA."""
from services.kernel_agents.registry import AGENT_REGISTRY, get_agent, agent_for_capability

__all__ = ["AGENT_REGISTRY", "get_agent", "agent_for_capability"]
