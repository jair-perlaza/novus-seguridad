"""PDF profesional para expedientes NDCI — informe nivel consultora."""
from __future__ import annotations

import json
import os
from typing import Any, Dict

from services.ndci_service import NDCI_DIR

LOGO_TEXT = "NOVUS — Digital Case Intelligence"


def _safe(text: Any) -> str:
    if text is None:
        return ""
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


def _section(pdf, title: str, body: str):
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(pdf.epw, 7, _safe(title), ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(pdf.epw, 5, _safe(body or "—"))
    pdf.ln(2)


def generate_ndci_pdf(expediente: dict) -> str:
    os.makedirs(NDCI_DIR, exist_ok=True)
    case_id = (expediente.get("identificacion") or {}).get("id") or "NDCI-DRAFT"
    out_path = os.path.join(NDCI_DIR, f"{case_id}.pdf")
    try:
        from fpdf import FPDF
    except ImportError:
        html_path = out_path.replace(".pdf", ".html")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(f"<html><body><h1>{case_id}</h1><pre>{json.dumps(expediente, indent=2, default=str)}</pre></body></html>")
        return html_path

    pdf = FPDF()
    pdf.set_margins(18, 18, 18)
    pdf.set_auto_page_break(auto=True, margin=18)

    # 1. Portada
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 22)
    pdf.ln(35)
    pdf.cell(pdf.epw, 12, _safe(LOGO_TEXT), ln=True, align="C")
    pdf.set_font("Helvetica", "", 14)
    pdf.cell(pdf.epw, 10, _safe("Expediente Técnico de Ciberseguridad"), ln=True, align="C")
    pdf.ln(15)
    iden = expediente.get("identificacion") or {}
    pdf.set_font("Helvetica", "", 11)
    for line in (
        f"ID: {iden.get('id')}",
        f"Fecha: {iden.get('fecha')} {iden.get('hora')}",
        f"Cliente: {iden.get('usuario')} / {iden.get('empresa')}",
        f"Sector: {iden.get('sector')}",
        f"NOVUS v{iden.get('novus_version')}",
        f"Kernel: {iden.get('kernel_version')}",
        f"Riesgo: {expediente.get('nivel_riesgo')}",
    ):
        pdf.cell(pdf.epw, 8, _safe(line), ln=True, align="C")

    # Índice
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(pdf.epw, 10, "Índice", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for i, item in enumerate((
        "1. Resumen Ejecutivo", "2. Inventario Completo", "3. Topología",
        "4. Cronología", "5. Análisis de Red", "6. Análisis de Seguridad",
        "7. Amenazas", "8. Adaptive Defense", "9. Kernel IA",
        "10. Predicción", "11. Simulaciones", "12. Cumplimiento",
        "13. Comparación Histórica", "14. Aprendizaje", "15. Recomendaciones y Métricas",
    ), 1):
        pdf.cell(pdf.epw, 6, item, ln=True)

    pdf.add_page()
    res = expediente.get("resumen_ejecutivo_detallado") or {}
    _section(pdf, "1. Resumen Ejecutivo",
        f"Objetivo: {res.get('objetivo')}\n"
        f"Infraestructura: {res.get('infraestructura')}\n"
        f"Nivel de seguridad: {res.get('nivel_seguridad')}\n"
        f"Conclusión: {res.get('conclusion_ejecutiva')}\n"
        f"Hallazgos: {'; '.join(res.get('principales_hallazgos') or [])}")

    inv = expediente.get("inventario_completo") or []
    inv_lines = [
        f"{r.get('nombre')} | {r.get('tipo')} | {r.get('ip')} | {r.get('mac')} | "
        f"{r.get('sistema_operativo')} | {r.get('nivel_riesgo')} | {r.get('confianza')}"
        for r in inv[:25]
    ]
    _section(pdf, "2. Inventario Completo", "\n".join(inv_lines) or "Sin dispositivos en inventario.")

    topo = expediente.get("topologia") or {}
    _section(pdf, "3. Topología",
        f"Nodos: {topo.get('nodes_count')}\n"
        f"Conexiones: {len(topo.get('connections') or [])}\n"
        f"Organización: {topo.get('organizacion') or (topo.get('digital_twin') or {}).get('communication_model')}")

    pdf.add_page()
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(pdf.epw, 7, "4. Cronología", ln=True)
    pdf.set_font("Helvetica", "", 8)
    for step in expediente.get("timeline") or []:
        pdf.multi_cell(pdf.epw, 4, _safe(
            f"{step.get('timestamp')} | {step.get('evento')}: {(step.get('detalle') or '')[:180]}"
        ))

    analisis = expediente.get("analisis_red") or {}
    _section(pdf, "5. Análisis de Red",
        f"Arquitectura: {analisis.get('arquitectura')}\n"
        f"Gateway: {analisis.get('gateway')}\n"
        f"Flujo: {analisis.get('flujo_comunicacion')}\n"
        f"Mayor tráfico: {analisis.get('dispositivo_mayor_trafico')}\n"
        f"Protocolos: {', '.join(analisis.get('protocolos_observados') or [])}")

    asec = expediente.get("analisis_seguridad") or expediente.get("seguridad") or {}
    vuln_lines = [
        f"[{v.get('id')}] {v.get('nombre')} — {v.get('impacto')}"
        for v in (asec.get("vulnerabilidades") or [])[:15]
    ]
    _section(pdf, "6. Análisis de Seguridad", "\n".join(vuln_lines) or "Sin vulnerabilidades activas.")

    threats = expediente.get("amenazas") or {}
    t_lines = []
    for cat, items in threats.items():
        if cat.startswith("_"):
            continue
        t_lines.append(f"{cat}: {len(items)} evidencia(s)" if items else f"{cat}: sin evidencia")
    for cat, msg in (threats.get("_sin_evidencia") or {}).items():
        t_lines.append(f"{cat}: {msg}")
    _section(pdf, "7. Amenazas", "\n".join(t_lines))

    ade = expediente.get("adaptive_defense") or {}
    ade_detail = ade.get("detalle") or {}
    _section(pdf, "8. Adaptive Defense",
        f"Estado: {ade.get('estado')}\nContenciones: {ade.get('contenciones')}\n"
        f"Acciones: {json.dumps(ade.get('acciones') or [], default=str)[:500]}")

    k = expediente.get("kernel_ia") or {}
    _section(pdf, "9. Kernel IA — Análisis Profesional",
        f"Qué encontró:\n" + "\n".join(k.get("que_encontro") or []) + "\n\n"
        f"Impacto:\n" + "\n".join(k.get("impacto") or []) + "\n\n"
        f"Si no se corrige: {k.get('si_no_se_corrige')}\n\n"
        f"Recomendaciones:\n" + "\n".join(k.get("recomendaciones") or []))

    pred = expediente.get("prediccion") or {}
    pred_lines = []
    for key, h in (pred.get("horizontes") or {}).items():
        pred_lines.append(f"{key}: {h.get('riesgo_estimado_pct')}% ({h.get('nivel')})")
    _section(pdf, "10. Predicción", "\n".join(pred_lines))

    sims = expediente.get("simulaciones") or []
    sim_text = "\n".join(
        f"{s.get('escenario')}: {s.get('respuesta_esperada')}" for s in sims[:4]
    )
    _section(pdf, "11. Simulaciones", sim_text)

    comp = expediente.get("cumplimiento") or {}
    _section(pdf, "12. Cumplimiento",
        f"{comp.get('disclaimer')}\nBrechas: {'; '.join(comp.get('brechas_identificadas') or [])}")

    hist = expediente.get("comparacion_historica") or {}
    _section(pdf, "13. Comparación Histórica",
        f"Caso anterior: {hist.get('caso_anterior')}\n"
        f"Nuevos: {hist.get('dispositivos_nuevos')}\n"
        f"Desaparecidos: {hist.get('dispositivos_desaparecidos')}")

    aprend = expediente.get("aprendizaje") or {}
    _section(pdf, "14. Aprendizaje",
        "NOVUS: " + "; ".join(aprend.get("novus_aprendio") or []) + "\n"
        "Kernel: " + "; ".join((aprend.get("kernel_aprendio") or [])[:3]))

    rec = expediente.get("recomendaciones") or {}
    rec_text = []
    for level in ("criticas", "altas", "medias", "bajas"):
        for r in rec.get(level) or []:
            rec_text.append(f"[{level.upper()}] {r.get('motivo', r)}")
    met = expediente.get("metricas") or {}
    _section(pdf, "15. Recomendaciones y Métricas",
        "\n".join(rec_text) + f"\n\nCPU: {met.get('cpu_pct')}% RAM: {met.get('ram_pct')}% "
        f"Tiempo: {met.get('tiempo_analisis_sec')}s Dispositivos: {met.get('dispositivos')}")

    pdf.output(out_path)
    return out_path
