#!/usr/bin/env python3
"""Limitaciones honestas ZDDE — no afirmar detección universal de zero-day."""
from __future__ import annotations

LIMITATIONS = [
    {
        "capability": "Detección garantizada de todo zero-day CVE",
        "status": "not_claimed",
        "audit_mark": "NO AFIRMADO",
        "reason": (
            "ZDDE clasifica candidatos a amenaza desconocida por correlación multicapa "
            "de comportamiento real. No garantiza cobertura de todos los zero-day."
        ),
    },
    {
        "capability": "Antivirus / firmas como método principal",
        "status": "not_implemented_by_design",
        "audit_mark": "NO UTILIZADO COMO MÉTODO PRINCIPAL",
        "reason": "Detección basada en correlación comportamental + contexto multi-motor.",
    },
    {
        "capability": "Clasificador ML entrenado",
        "status": "not_implemented",
        "audit_mark": "NO IMPLEMENTADO",
        "reason": "Sin modelo ML; pesos fijos explicables.",
    },
    {
        "capability": "Respuesta destructiva automática",
        "status": "not_implemented_by_design",
        "audit_mark": "PROHIBIDO",
        "reason": "Solo propone / notifica / eleva; acciones destructivas requieren aprobación.",
    },
]

CLASSIFICATION = {
    "EVIDENCIA_INSUFICIENTE": "Evidencia insuficiente — no se afirma amenaza desconocida ni zero-day.",
    "ANOMALIA_CORRELACIONADA": "Anomalía comportamental correlacionada (no zero-day).",
    "CANDIDATO_AMENAZA_DESCONOCIDA": (
        "Candidato a amenaza desconocida (comportamiento multi-capa sin firma). "
        "No equivale a confirmación CVE zero-day."
    ),
}
