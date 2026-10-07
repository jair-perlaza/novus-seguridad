"""Limitaciones honestas del BTDE — no inflar Zero-day / ML."""
from __future__ import annotations

LIMITATIONS = [
    {
        "capability": "Zero-day detector dedicado",
        "status": "delegated",
        "audit_mark": "DELEGADO A ZDDE",
        "reason": (
            "BTDE detecta desviaciones comportamentales verificables; "
            "no es el detector dedicado de amenaza desconocida/zero-day candidato."
        ),
        "enterprise_alternative": (
            "Zero-Day Detection Engine Enterprise (ZDDE): correlación multicapa "
            "BTDE+Swarm+Endpoint+Red+APE+Forense+Kernel; candidato ≠ CVE confirmado."
        ),
    },
    {
        "capability": "Clasificador ML malware desconocido",
        "status": "not_implemented",
        "audit_mark": "NO IMPLEMENTADO",
        "reason": "Sin modelo ML entrenado/validado en este motor.",
        "enterprise_alternative": "Heurística comportamental + baseline + correlación.",
    },
    {
        "capability": "ETW/AMSI script-block completo",
        "status": "partial",
        "audit_mark": "PARCIAL",
        "reason": "Análisis de cmdline/procesos en user-mode; sin suscripción AMSI kernel.",
        "enterprise_alternative": "PowerShell logging / Sysmon / EDR provider.",
    },
]
