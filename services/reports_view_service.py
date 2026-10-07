"""
Vista canónica de informes almacenados — solo lectura del JSON persistido.
Proyección ejecutiva vía report_presentation_service (sin volcar estructuras internas).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from services.report_presentation_service import build_executive_presentation

NO_EVIDENCE = "Sin evidencia verificable."


def build_detail_view(report: dict, *, include_technical: bool = False) -> Dict[str, Any]:
    """Construye narrativa profesional para UI; coherente con export PDF."""
    if not report or not report.get("id"):
        raise ValueError("Informe inválido o sin identificador")

    presentation = build_executive_presentation(report)
    exec_block = presentation.get("executive") or {}

    priority = exec_block.get("prioridad") or exec_block.get("nivel_riesgo") or "—"

    out: Dict[str, Any] = {
        "id": report["id"],
        "fecha": f"{exec_block.get('fecha', '—')} {exec_block.get('hora', '—')}".strip(),
        "tipo": presentation.get("tipo") or "Informe de seguridad",
        "severidad": exec_block.get("nivel_riesgo") or "—",
        "estado": exec_block.get("estado_general") or report.get("estado") or "—",
        "equipo": exec_block.get("equipo") or NO_EVIDENCE,
        "prioridad": priority,
        "title": presentation.get("title"),
        "presentation": presentation,
        "sections": _legacy_sections_from_presentation(presentation),
        "pdf_url": f"/api/reports/{report['id']}/export?format=pdf",
        "source": "stored_report",
    }

    if include_technical:
        from services.report_presentation_service import serialize_technical_audit

        out["technical_audit_json"] = serialize_technical_audit(report)

    return out


def _legacy_sections_from_presentation(presentation: dict) -> List[Dict[str, Any]]:
    """Secciones mínimas por compatibilidad; la UI principal usa `presentation`."""
    sections: List[Dict[str, Any]] = []
    exec_block = presentation.get("executive") or {}
    sections.append({
        "title": "Resumen ejecutivo",
        "body": exec_block.get("resumen") or NO_EVIDENCE,
        "items": [],
    })
    kernel = presentation.get("kernel_analysis") or {}
    if kernel.get("que_encontro"):
        body = "\n".join(
            x for x in (
                kernel.get("que_significa"),
                "Riesgos: " + "; ".join(kernel.get("riesgos") or []),
            ) if x
        )
        sections.append({
            "title": kernel.get("titulo") or "Análisis del Kernel IA",
            "body": kernel.get("que_encontro") + ("\n\n" + body if body else ""),
            "items": kernel.get("acciones_recomendadas") or [],
        })
    return sections
