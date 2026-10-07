"""Render HTML profesional para informes MDR del Centro de Defensa."""
from __future__ import annotations

import html
import json
from typing import Any, Dict, List


def _esc(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, (dict, list)):
        return html.escape(json.dumps(val, ensure_ascii=False, indent=2)[:12000])
    return html.escape(str(val))


def _render_list(items: List[Any]) -> str:
    if not items:
        return '<p class="muted">Sin registros en telemetría para esta sección.</p>'
    rows = []
    for it in items[:80]:
        if isinstance(it, dict):
            title = it.get("title") or it.get("name") or it.get("ip") or it.get("path") or it.get("id") or "—"
            risk = it.get("risk") or it.get("severity") or ""
            detail = it.get("description") or it.get("reason") or it.get("message") or ""
            rows.append(
                f'<div class="item"><strong>{_esc(title)}</strong>'
                f'{f" <span class=\"tag\">{_esc(risk)}</span>" if risk else ""}'
                f'<div class="detail">{_esc(detail)[:500]}</div></div>'
            )
        else:
            rows.append(f'<div class="item">{_esc(it)}</div>')
    return "".join(rows)


def _render_content(content: Any) -> str:
    if content is None:
        return '<p class="muted">No aplica.</p>'
    if isinstance(content, dict):
        lines = "".join(
            f'<div class="kv"><span>{_esc(k)}</span><strong>{_esc(v)}</strong></div>'
            for k, v in content.items()
            if v is not None and v != "" and v != []
        )
        return lines or '<p class="muted">Sin datos.</p>'
    if isinstance(content, list):
        return _render_list(content)
    return f"<p>{_esc(content)}</p>"


def ensure_defense_report(report: Dict[str, Any]) -> Dict[str, Any]:
    tech = report.get("technical") or {}
    dr = tech.get("defense_report")
    if dr:
        return dr
    from services.manual_defense_report_builder import build_defense_report_payload

    mech_id = report.get("finding_id") or ""
    motors = tech.get("motores_utilizados") or []
    for m in reversed(motors):
        if m and m != "manual_defense_center":
            mech_id = m
            break
    result = {
        "status": "completed",
        "analyzed": (tech.get("estadisticas") or {}).get("files_analyzed"),
        "findings": tech.get("hallazgos") or [],
        "evidence": tech.get("evidencias") or [],
        "recommendations": tech.get("recomendaciones") or [],
        "limitations": tech.get("limitaciones") or [],
        "auto_actions": tech.get("acciones_automaticas") or [],
        "duration_sec": tech.get("duracion_segundos"),
        "raw_summary": {"stats": tech.get("estadisticas") or {}},
        "timestamp": tech.get("fecha_deteccion"),
    }
    category = "equipo"
    for prefix, cat in (("net_", "red"), ("web_", "web"), ("mail_", "correo"), ("cloud_", "cloud")):
        if str(mech_id).startswith(prefix):
            category = cat
            break
    title = (tech.get("tipo_vulnerabilidad") or "").replace("Análisis manual — ", "") or str(mech_id)
    return build_defense_report_payload(
        mechanism_id=str(mech_id),
        mechanism_title=title,
        category=category,
        result=result,
        user_email=tech.get("operador"),
    )


def render_manual_defense_report_html(report: Dict[str, Any]) -> str:
    tech = report.get("technical") or {}
    dr = ensure_defense_report(report)
    sections = dr.get("sections") or []
    kernel = dr.get("kernel_analysis") or {}
    not_found = dr.get("not_found_verified") or []
    limitations = dr.get("limitations") or []

    sec_html = ""
    for sec in sections:
        note = sec.get("note")
        sec_html += f"""
        <section class="block">
            <h2>{_esc(sec.get("title"))}</h2>
            {f'<p class="note">{_esc(note)}</p>' if note else ''}
            {_render_content(sec.get("content"))}
        </section>"""

    nf_html = ""
    if not_found:
        nf_html = "<ul>" + "".join(f"<li>{_esc(x.get('label'))}</li>" for x in not_found) + "</ul>"
    else:
        nf_html = '<p class="muted">No hay amenazas verificadas sin hallazgo, o el mecanismo no declaró controles específicos.</p>'

    lim_html = ""
    if limitations:
        lim_html = "<ul>" + "".join(f"<li>{_esc(x)}</li>" for x in limitations) + "</ul>"

    k_found = kernel.get("risks_found") or []
    k_found_html = _render_list(k_found) if k_found else '<p class="muted">Sin riesgos destacados en hallazgos.</p>'

    k_nf = kernel.get("risks_not_found_verified") or []
    k_nf_html = (
        "<ul>" + "".join(f"<li>{_esc(x.get('label'))}</li>" for x in k_nf) + "</ul>"
        if k_nf
        else "<p class=\"muted\">—</p>"
    )

    recs = kernel.get("recommendations") or []
    prios = kernel.get("priorities") or []

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{_esc(report.get("id"))} — NOVUS Centro de Defensa</title>
<style>
body {{ font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; background: #f1f5f9; color: #0f172a; }}
.cover {{ background: linear-gradient(135deg, #4338ca, #5d5fef); color: #fff; padding: 48px 32px; }}
.cover h1 {{ margin: 0 0 8px; font-size: 28px; }}
.cover .meta {{ opacity: 0.92; font-size: 14px; line-height: 1.6; }}
.wrap {{ max-width: 920px; margin: 0 auto; padding: 32px 20px 48px; }}
.block {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px 22px; margin-bottom: 16px; }}
.block h2 {{ margin: 0 0 12px; font-size: 16px; color: #4338ca; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; }}
.kv {{ display: grid; grid-template-columns: 180px 1fr; gap: 8px; font-size: 13px; padding: 4px 0; border-bottom: 1px solid #f1f5f9; }}
.kv span {{ color: #64748b; }}
.item {{ padding: 10px 0; border-bottom: 1px solid #f1f5f9; font-size: 13px; }}
.item .detail {{ color: #475569; font-size: 12px; margin-top: 4px; }}
.tag {{ background: #fef3c7; color: #92400e; font-size: 10px; padding: 2px 6px; border-radius: 4px; margin-left: 6px; }}
.muted {{ color: #64748b; font-size: 13px; }}
.note {{ font-size: 12px; color: #64748b; font-style: italic; }}
.kernel {{ border-left: 4px solid #5d5fef; }}
.footer {{ text-align: center; font-size: 11px; color: #94a3b8; margin-top: 24px; }}
@media print {{ body {{ background: #fff; }} .block {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<div class="cover">
  <h1>Informe de defensa — {_esc(dr.get("mechanism_title") or report.get("tipo"))}</h1>
  <div class="meta">
    <div>ID: <strong>{_esc(report.get("id"))}</strong></div>
    <div>Equipo: {_esc(report.get("equipo_afectado"))} · {_esc(report.get("fecha"))}</div>
    <div>Severidad: {_esc(report.get("severidad"))} · Estado: {_esc(report.get("estado"))}</div>
    <div>Categoría: {_esc(dr.get("category_label"))}</div>
  </div>
</div>
<div class="wrap">
  <section class="block">
    <h2>Resumen ejecutivo</h2>
    <p>{_esc(dr.get("executive_summary") or report.get("resumen_ejecutivo"))}</p>
  </section>
  {sec_html}
  <section class="block">
    <h2>No se encontró (amenazas verificadas)</h2>
    <p class="note">Solo se listan controles ejecutados en este análisis sin indicadores en telemetría.</p>
    {nf_html}
  </section>
  <section class="block">
    <h2>Limitaciones del análisis</h2>
    {lim_html or '<p class="muted">Sin limitaciones adicionales registradas.</p>'}
  </section>
  <section class="block kernel">
    <h2>Análisis Kernel IA (síntesis verificable)</h2>
    <p>{_esc(kernel.get("summary"))}</p>
    <h3 style="font-size:14px;margin-top:16px;color:#334155">Riesgos encontrados</h3>
    {k_found_html}
    <h3 style="font-size:14px;margin-top:16px;color:#334155">Riesgos no encontrados (verificados)</h3>
    {k_nf_html}
    <h3 style="font-size:14px;margin-top:16px;color:#334155">Recomendaciones</h3>
    <ul>{"".join(f"<li>{_esc(r)}</li>" for r in recs) or '<li class="muted">—</li>'}</ul>
    <h3 style="font-size:14px;margin-top:16px;color:#334155">Prioridades</h3>
    <ol>{"".join(f"<li>{_esc(p)}</li>" for p in prios)}</ol>
    <p class="note">{_esc(kernel.get("disclaimer"))}</p>
  </section>
  <section class="block">
    <h2>Conclusión</h2>
    <p>{_esc(dr.get("conclusion") or report.get("conclusiones"))}</p>
  </section>
  <div class="footer">NOVUS Security Platform — informe basado en telemetría real del mecanismo ejecutado.</div>
</div>
</body>
</html>"""
