"""Limitaciones Ring-0 / capacidades no afirmadas."""

LIMITATIONS = [
    {
        "capability": "SSDT / IDT / kernel hooks",
        "status": "not_implemented",
        "audit_mark": "NO IMPLEMENTADO",
        "reason": (
            "Leer/comparar SSDT requiere código en Ring-0 (driver firmado EV). "
            "Python en user-mode no puede demostrar integridad del SSDT de forma fiable."
        ),
        "enterprise_alternative": (
            "Driver minifilter/EDR firmado o Microsoft Defender for Endpoint / ETW kernel providers "
            "con telemetría correlacionada vía Swarm."
        ),
    },
    {
        "capability": "Rootkit kernel propio",
        "status": "not_implemented",
        "audit_mark": "NO IMPLEMENTADO",
        "reason": "Criterio oficial exige motor kernel propio; esta Fase 1 es híbrida user-mode.",
        "enterprise_alternative": "Cross-view + hooks user-mode + ETW + correlación multi-indicador (implementado).",
    },
    {
        "capability": "DKOM unlink avanzado",
        "status": "partial_user_mode",
        "audit_mark": "PARCIAL",
        "reason": "Cross-view puede fallar si el rootkit oculta el proceso a todas las APIs user-mode.",
        "enterprise_alternative": "ETW kernel + driver + cross-view.",
    },
]
