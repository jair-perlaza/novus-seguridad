#!/usr/bin/env python3
"""Validación módulo Reportes reconstruido — 100 ciclos (misma lógica que botones UI)."""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "reports_rebuild_audit_20260721")
sys.path.insert(0, ROOT)

QA_EMAIL = "novus.qa.jul2026@example.com"
QA_PASS = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
CYCLES = int(os.environ.get("NOVUS_REPORTS_CYCLES", "100"))


def _login(client) -> bool:
    with client.session_transaction() as sess:
        sess.clear()
    r = client.get("/login")
    if r.status_code != 200:
        return False
    html = r.get_data(as_text=True)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if not m:
        return False
    r = client.post(
        "/login",
        data={"email": QA_EMAIL, "password": QA_PASS, "csrf_token": m.group(1)},
        follow_redirects=True,
    )
    return r.status_code in (200, 302)


def _dom_checks(html: str) -> list[str]:
    fails = []
    if "NovusRemediation.showReportDetail" in html:
        fails.append("legacy NovusRemediation en reportes")
    if "novus-btn-details" in html:
        fails.append("novus-btn-details presente")
    if html.count('id="novus-remediation-overlay"') > 0:
        fails.append("modal remediación incluido en reportes")
    if "export?format=html" in html or "export?format=csv" in html:
        fails.append("exportaciones HTML/CSV en UI")
    if 'id="novus-report-detail-overlay"' not in html:
        fails.append("falta panel detalle reportes")
    if "NovusReports.openDetail" not in html and "novus-report-action-details" not in html:
        fails.append("faltan botones reconstruidos")
    return fails


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    from main import app
    from services.security_report_service import get_report, list_reports
    from services.reports_view_service import build_detail_view
    from services.report_pdf_service import export_report
    from services.module_kernel_context import build_consult_prompt

    client = app.test_client()
    if not _login(client):
        print("FAIL login")
        return 1

    page = client.get("/reportes")
    html = page.get_data(as_text=True)
    dom_fails = _dom_checks(html)

    reports = list_reports(limit=200)
    if not reports:
        print("FAIL no hay informes almacenados")
        return 1

    ok_detail = 0
    ok_pdf = 0
    ok_kernel = 0
    failures = list(dom_fails)

    for i in range(CYCLES):
        rid = reports[i % len(reports)]["id"]
        report = get_report(rid)
        if not report:
            failures.append(f"cycle {i+1} missing report {rid}")
            continue
        try:
            view = build_detail_view(report)
            if view.get("sections"):
                ok_detail += 1
            else:
                failures.append(f"cycle {i+1} empty sections {rid}")
        except Exception as exc:
            failures.append(f"cycle {i+1} detail {rid}: {exc}")

        try:
            path = export_report(report, "pdf")
            if os.path.isfile(path) and os.path.getsize(path) > 200:
                ok_pdf += 1
            else:
                failures.append(f"cycle {i+1} pdf file {rid}")
        except Exception as exc:
            failures.append(f"cycle {i+1} pdf {rid}: {exc}")

        try:
            consult = build_consult_prompt("reportes", QA_EMAIL, {"report_id": rid, "read_only": True})
            ctx = consult.get("context") or {}
            brief = ctx.get("report_executive_brief")
            if brief and str(brief.get("report_id")) == str(rid) and consult.get("prompt"):
                ok_kernel += 1
            else:
                failures.append(f"cycle {i+1} kernel context {rid}")
        except Exception as exc:
            failures.append(f"cycle {i+1} kernel {rid}: {exc}")

    # Humo HTTP: un informe vía API (misma ruta que Ver Detalles en UI)
    smoke_rid = reports[0]["id"]
    smoke = client.get(f"/api/reports/{smoke_rid}/detail-view")
    smoke_json = smoke.get_json(silent=True) or {}
    http_smoke = smoke.status_code == 200 and smoke_json.get("status") == "success"
    if not http_smoke:
        failures.append(f"http_smoke detail-view {smoke_rid} status={smoke_json.get('status')}")

    summary = {
        "detail_ok": ok_detail,
        "pdf_ok": ok_pdf,
        "kernel_ok": ok_kernel,
        "required": CYCLES,
        "reports_pool": len(reports),
        "http_smoke_detail_view": http_smoke,
    }
    passed = (
        ok_detail == CYCLES
        and ok_pdf == CYCLES
        and ok_kernel == CYCLES
        and not dom_fails
    )

    md = [
        "# Reconstrucción módulo Reportes — auditoría",
        "",
        f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Arquitectura nueva",
        "",
        "- UI: `NovusReports` (`static/js/novus-reports-module.js`) + `reports_detail_panel.html`",
        "- Sin modal de remediación en `/reportes` (include `global_search_only.html`)",
        "- `GET /api/reports/<id>/detail-view` → `reports_view_service.build_detail_view` (JSON persistido)",
        "- PDF: `export_report(report)` sobre el mismo objeto persistido",
        "- Kernel IA: `build_consult_prompt` con `selected_report` únicamente (`read_only`)",
        "",
        "## Acciones por informe (UI)",
        "",
        "1. Ver Detalles → fetch detail-view + panel dedicado",
        "2. Descargar PDF → export del informe abierto / almacenado",
        "3. Consultar Kernel IA → module-consult con `report_id`",
        "",
        "## Eliminado",
        "",
        "- Botones HTML, JSON, CSV, Excel en tabla",
        "- `NovusRemediation` / generador / sincronizar vía modal de remediación",
        "- Centro de reportes AJAX con export CSV embebido",
        "",
        "## Pruebas (100 ciclos)",
        "",
        f"- Ver Detalles (vista canónica): **{ok_detail}/{CYCLES}**",
        f"- Descargar PDF (export persistido): **{ok_pdf}/{CYCLES}**",
        f"- Consultar Kernel IA (contexto informe): **{ok_kernel}/{CYCLES}**",
        f"- Humo HTTP detail-view: **{'OK' if http_smoke else 'FAIL'}**",
        f"- Pool informes: **{len(reports)}**",
        "",
        "## Resultado",
        "",
        f"**{'PASS' if passed else 'FAIL'}**",
        "",
    ]
    if failures[:15]:
        md.append("### Fallos (muestra)\n")
        for f in failures[:15]:
            md.append(f"- {f}")

    with open(os.path.join(OUT, "rebuild_audit.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    with open(os.path.join(OUT, "rebuild_results.json"), "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "pass": passed, "failures": failures[:50]}, fh, indent=2)

    print("PASS" if passed else "FAIL", summary)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
