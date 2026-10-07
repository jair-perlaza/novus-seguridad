#!/usr/bin/env python3
"""
Auditoría forense Reportes — 50 ciclos generate/export + validación DOM del modal.
Demuestra ausencia de novus-btn-details y un único overlay de remediación.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "reports_forensic_audit_20260721")
sys.path.insert(0, ROOT)

QA_EMAIL = "novus.qa.jul2026@example.com"
QA_PASS = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
CYCLES = int(os.environ.get("NOVUS_FORENSIC_CYCLES", "50"))


def _login(client) -> bool:
    """Sesión real vía POST /login con token CSRF (compatible con SESSION_PROTECTION strong)."""
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
    if r.status_code not in (200, 302):
        return False
    for _ in range(5):
        probe = client.get("/api/reports/center")
        data = probe.get_json(silent=True) or {}
        if probe.status_code == 200 and data.get("status") == "success":
            return True
        time.sleep(1.5)
    return False


def _dom_forensics(html: str) -> dict:
    overlay_count = len(re.findall(r'id="novus-remediation-overlay"', html))
    download_ids = len(re.findall(r'id="novus-btn-download"', html))
    details_ref = "novus-btn-details" in html
    confirm_destroy = "footer.innerHTML" in html and "novus-btn-view-report" in html
    return {
        "overlay_count": overlay_count,
        "download_button_ids": download_ids,
        "references_novus_btn_details": details_ref,
        "confirm_replaces_report_footer_via_innerHTML": confirm_destroy,
    }


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    from main import app

    client = app.test_client()
    if not _login(client):
        print("FAIL login")
        return 1

    page = client.get("/reportes")
    html = page.get_data(as_text=True)
    dom = _dom_forensics(html)
    js_snippet = ""
    rem_path = os.path.join(ROOT, "templates", "partials", "remediation_modal.html")
    with open(rem_path, encoding="utf-8") as fh:
        rem_html = fh.read()
    confirm_innerhtml_footer = bool(
        re.search(
            r"footer\.innerHTML\s*=\s*`[\s\S]*novus-btn-view-report",
            rem_html,
        )
    )
    dom["confirm_replaces_report_footer_via_innerHTML"] = confirm_innerhtml_footer

    results = {
        "started_at": datetime.now().isoformat(),
        "dom_reportes": dom,
        "cycles": [],
        "failures": [],
    }

    if dom["overlay_count"] != 1:
        results["failures"].append(f"overlay_count={dom['overlay_count']} expected 1")
    if dom["download_button_ids"] != 1:
        results["failures"].append(f"download_ids={dom['download_button_ids']} expected 1")
    if dom["references_novus_btn_details"]:
        results["failures"].append("novus-btn-details still in /reportes HTML")
    if confirm_innerhtml_footer:
        results["failures"].append("confirm() still destroys report footer via innerHTML")

    ok_gen = 0
    ok_pdf = 0
    ok_xlsx = 0
    ok_csv = 0
    ok_get = 0

    for i in range(CYCLES):
        t0 = time.perf_counter()
        cycle = {"i": i + 1}
        gen = client.post(
            "/api/reports/generate",
            json={"sections": ["general", "red"]},
            content_type="application/json",
        )
        cycle["generate_status"] = gen.status_code
        data = gen.get_json(silent=True) or {}
        rid = data.get("report_id")
        if data.get("status") == "recovering" or data.get("login_required"):
            results["failures"].append(
                f"cycle {i+1} auth/recovery masked response (ref={data.get('reference')})"
            )
        elif gen.status_code == 200 and data.get("status") == "success" and rid:
            ok_gen += 1
            cycle["report_id"] = rid
            for fmt, key in (("pdf", "ok_pdf"), ("xlsx", "ok_xlsx"), ("csv", "ok_csv")):
                ex = client.get(f"/api/reports/{rid}/export?format={fmt}")
                cycle[f"export_{fmt}"] = ex.status_code
                if ex.status_code == 200 and ex.data:
                    if fmt == "pdf":
                        ok_pdf += 1
                    elif fmt == "xlsx":
                        ok_xlsx += 1
                    elif fmt == "csv":
                        ok_csv += 1
            det = client.get(f"/api/reports/{rid}")
            cycle["get_detail"] = det.status_code
            if det.status_code == 200 and (det.get_json(silent=True) or {}).get("report"):
                ok_get += 1
        else:
            detail = data.get("message") or data.get("status") or gen.status_code
            results["failures"].append(f"cycle {i+1} generate failed status={gen.status_code} detail={detail}")
        cycle["ms"] = round((time.perf_counter() - t0) * 1000, 1)
        results["cycles"].append(cycle)

    summary = {
        "generate_ok": ok_gen,
        "pdf_ok": ok_pdf,
        "xlsx_ok": ok_xlsx,
        "csv_ok": ok_csv,
        "detail_ok": ok_get,
        "required": CYCLES,
    }
    results["summary"] = summary

    if ok_gen < CYCLES:
        results["failures"].append(f"generate {ok_gen}/{CYCLES}")
    if ok_pdf < CYCLES:
        results["failures"].append(f"pdf {ok_pdf}/{CYCLES}")
    if ok_xlsx < CYCLES:
        results["failures"].append(f"xlsx {ok_xlsx}/{CYCLES}")
    if ok_csv < CYCLES:
        results["failures"].append(f"csv {ok_csv}/{CYCLES}")
    if ok_get < CYCLES:
        results["failures"].append(f"detail {ok_get}/{CYCLES}")

    root_cause = {
        "primary": "Referencia JS a id inexistente `novus-btn-details` en verDetalle (reportes.html)",
        "secondary": "confirm() reemplazaba `.novus-modal-footer` con innerHTML eliminando botones durante peticiones async",
        "tertiary": "Doble include de remediation_modal en incidentes.html (IDs duplicados en otras rutas)",
        "file": "templates/reportes.html, templates/partials/remediation_modal.html",
        "function": "verDetalle / NovusRemediation.confirm / NovusRemediation._setReportButtons",
        "variable_null": "document.getElementById('novus-btn-details') === null",
        "fix": "showReportDetail(); footer report-actions persistente; confirm en #novus-footer-confirm-actions",
    }
    results["root_cause"] = root_cause
    results["pass"] = len(results["failures"]) == 0

    json_path = os.path.join(OUT, "forensic_results.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)

    md = [
        "# Auditoría forense — Módulo Reportes",
        "",
        f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Causa raíz",
        "",
        f"- **Primaria:** {root_cause['primary']}",
        f"- **Secundaria (race):** {root_cause['secondary']}",
        f"- **Terciaria:** {root_cause['tertiary']}",
        "",
        "## Evidencia técnica",
        "",
        f"- Variable null: `{root_cause['variable_null']}`",
        f"- Archivo: `{root_cause['file']}`",
        f"- Funciones: `{root_cause['function']}`",
        "",
        "## Solución implementada",
        "",
        f"- {root_cause['fix']}",
        "",
        "## Pruebas ({0} ciclos)".format(CYCLES),
        "",
        f"- Generate: **{ok_gen}/{CYCLES}**",
        f"- PDF: **{ok_pdf}/{CYCLES}**",
        f"- Excel: **{ok_xlsx}/{CYCLES}**",
        f"- CSV: **{ok_csv}/{CYCLES}**",
        f"- GET detalle: **{ok_get}/{CYCLES}**",
        "",
        "## DOM /reportes",
        "",
        f"- Overlays remediación: **{dom['overlay_count']}** (esperado 1)",
        f"- Botones download id: **{dom['download_button_ids']}** (esperado 1)",
        f"- Referencia novus-btn-details: **{dom['references_novus_btn_details']}**",
        f"- confirm destruye footer report: **{confirm_innerhtml_footer}** (esperado False)",
        "",
        "## Resultado",
        "",
        f"**{'PASS' if results['pass'] else 'FAIL'}**",
        "",
    ]
    if results["failures"]:
        md.append("Fallos:\n")
        for f in results["failures"]:
            md.append(f"- {f}")

    md_path = os.path.join(OUT, "forensic_audit.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))

    print("PASS" if results["pass"] else "FAIL", summary, "failures", len(results["failures"]))
    print("Wrote", md_path)
    return 0 if results["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
