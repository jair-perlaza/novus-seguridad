"""Explicaciones Kernel IA basadas únicamente en evidencia del hallazgo."""
from __future__ import annotations

from typing import Any, Dict, List


def explain_threat(finding: Dict[str, Any]) -> Dict[str, Any]:
    motor = finding.get("motor") or finding.get("engine") or "motor NOVUS"
    title = finding.get("title") or finding.get("name") or finding.get("id") or "Hallazgo"
    risk = finding.get("risk") or finding.get("severity") or "info"
    evidence = finding.get("evidence") or finding.get("reason") or finding.get("description") or ""
    technique = finding.get("technique") or finding.get("category") or ""
    verified = finding.get("verified", True)

    summary = (
        f"Se registró «{title}» con severidad/riesgo «{risk}». "
        f"Mecanismo: {motor}."
    )
    if technique:
        summary += f" Técnica/categoría: {technique}."
    if not verified:
        summary += " (Sin bandera verified — tratar como informativo.)"

    recommendations: List[str] = []
    if str(risk).lower() in ("high", "critical", "alto", "critico"):
        recommendations.append("Validar en XDR/Centro de Defensa y conservar evidencia antes de contener.")
    elif str(risk).lower() in ("medium", "medio"):
        recommendations.append("Correlacionar con telemetría de red y endpoint en el mismo intervalo.")
    else:
        recommendations.append("Monitorear; no elevar sin nueva evidencia.")

    return {
        "summary": summary,
        "why_detected": str(evidence)[:800] if evidence else "Evidencia no adjunta en el objeto hallazgo.",
        "mechanism": motor,
        "risk_level": risk,
        "recommendations": recommendations,
        "priorities": [
            "1. Confirmar evidencia en registro de defensa / informe MDR.",
            "2. Aplicar remediación manual o playbook si el operador lo autoriza.",
        ],
        "disclaimer": "Explicación generada solo desde campos del hallazgo; no se inventan IOCs.",
    }
