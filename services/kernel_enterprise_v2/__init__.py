"""
Kernel IA Enterprise V2.0 — arquitectura modular e ilimitada.
Capa aditiva: no modifica ni reemplaza motores / AIKernel / capability_registry.
"""
from services.kernel_enterprise_v2.orchestrator import kernel_enterprise_v2
from services.kernel_enterprise_v2.registry import ensure_bootstrapped, pack_registry

__all__ = ["kernel_enterprise_v2", "pack_registry", "ensure_bootstrapped"]
