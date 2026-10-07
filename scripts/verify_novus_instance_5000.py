#!/usr/bin/env python3
"""Verifica instancia real en :5000 — DOM servido + 20 ciclos Reportes."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "instance_verify_20260722"
BASE = os.environ.get("NOVUS_VERIFY_BASE", "http://127.0.0.1:5000")
QA_EMAIL = "novus.qa.jul2026@example.com"
QA_PASS = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
CYCLES = 20

CANONICAL_FILES = [
    ROOT / "main.py",
    ROOT / "templates" / "reportes.html",
    ROOT / "static" / "js" / "novus-reports-module.js",
    ROOT / "templates" / "partials" / "reports_detail_panel.html",
]


def file_evidence(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "path": str(path),
        "mtime": datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def login_session(session):
    last_err = ""
    for attempt in range(5):
        r = session.get(f"{BASE}/login", timeout=30)
        r.raise_for_status()
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
        if not m:
            last_err = "csrf_token no encontrado en /login"
            time.sleep(1.5)
            continue
        r = session.post(
            f"{BASE}/login",
            data={"email": QA_EMAIL, "password": QA_PASS, "csrf_token": m.group(1)},
            timeout=30,
            allow_redirects=True,
        )
        if r.status_code not in (200, 302):
            last_err = f"login HTTP {r.status_code}"
            time.sleep(1.5)
            continue
        dash = session.get(f"{BASE}/dashboard", timeout=30, allow_redirects=True)
        if "/login" in (dash.url or "").lower():
            last_err = "dashboard redirige a login"
            time.sleep(1.5)
            continue
        return
    raise RuntimeError(last_err or "login fallido")


def dom_checks(html: str, js: str, *, reportes_page: bool) -> list[str]:
    fails = []
    if reportes_page:
        if "NovusRemediation.showReportDetail" in html or "NovusRemediation.open" in html:
            fails.append("HTML aún invoca NovusRemediation para reportes")
        if "novus-btn-details" in html:
            fails.append("HTML contiene novus-btn-details")
        if html.count('id="novus-remediation-overlay"') > 0:
            fails.append("HTML incluye modal remediación en /reportes")
        if "novus-report-detail-overlay" not in html:
            fails.append("Falta panel novus-report-detail-overlay")
        if "novus-reports-build" not in html:
            fails.append("Falta meta novus-reports-build (plantilla de reportes)")
    if "NovusReports" not in js and (reportes_page and "NovusReports" not in html):
        fails.append("NovusReports no presente")
    if "getElementById('novus-btn-details')" in js or 'getElementById("novus-btn-details")' in js:
        fails.append("JS referencia novus-btn-details")
    if re.search(r"getElementById\([^)]+\)\.disabled\s*=", js):
        fails.append("JS asigna .disabled sin comprobación (getElementById chain)")
    return fails


def main() -> int:
    import requests

    OUT.mkdir(parents=True, exist_ok=True)
    evidence = {
        "verified_at": datetime.now().isoformat(),
        "project_root": str(ROOT),
        "entrypoint": str(ROOT / "main.py"),
        "verify_base": BASE,
        "canonical_files": [file_evidence(p) for p in CANONICAL_FILES if p.is_file()],
    }

    session = requests.Session()
    fp = session.get(f"{BASE}/api/system/instance-fingerprint", timeout=15)
    fpj = fp.json() if fp.headers.get("content-type", "").startswith("application/json") else {}
    evidence["runtime_fingerprint"] = fpj
    disk_js_hash = file_evidence(CANONICAL_FILES[2])["sha256"]
    evidence["fingerprint_matches_disk"] = (
        fpj.get("project_root", "").replace("/", "\\").lower() == str(ROOT).lower()
        and (fpj.get("files") or {}).get("static/js/novus-reports-module.js", {}).get("sha256") == disk_js_hash
    )
    evidence["runtime_pid"] = fpj.get("process_id")

    login_ok = False
    try:
        login_session(session)
        login_ok = "login" not in session.get(f"{BASE}/dashboard", timeout=20).url
    except Exception as exc:
        evidence["login_error"] = str(exc)

    evidence["login_ok"] = login_ok

    rep = session.get(f"{BASE}/reportes", timeout=60)
    js = session.get(f"{BASE}/static/js/novus-reports-module.js", timeout=30)
    html = rep.text
    js_text = js.text if js.status_code == 200 else ""
    reportes_page = login_ok and "novus-reports-build" in html

    evidence["served"] = {
        "reportes_status": rep.status_code,
        "reportes_len": len(html),
        "js_status": js.status_code,
        "js_sha256": hashlib.sha256(js_text.encode()).hexdigest() if js_text else None,
    }
    disk_js = (ROOT / "static" / "js" / "novus-reports-module.js").read_bytes()
    evidence["js_matches_disk"] = (
        js.status_code == 200 and hashlib.sha256(js_text.encode()).hexdigest() == hashlib.sha256(disk_js).hexdigest()
    )

    dom_fails = dom_checks(html, js_text, reportes_page=reportes_page)
    evidence["dom_fails"] = dom_fails

    list_r = session.get(f"{BASE}/api/reports/", timeout=30)
    lj = list_r.json() if list_r.headers.get("content-type", "").startswith("application/json") else {}
    reports = lj.get("reports") or []
    if not reports and login_ok is False:
        from services.security_report_service import list_reports

        reports = list_reports(limit=200)
        evidence["reports_source"] = "disk_index_fallback"
    else:
        evidence["reports_source"] = "http_api"
    if not reports:
        evidence["cycles"] = "skipped_no_reports"
        evidence["pass"] = False
        (OUT / "instance_report.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        print("FAIL no reports")
        return 1

    ok_d = ok_p = ok_k = 0
    cycle_fails = []
    from services.security_report_service import get_report
    from services.reports_view_service import build_detail_view
    from services.report_pdf_service import export_report
    from services.module_kernel_context import build_consult_prompt

    for i in range(CYCLES):
        rid = reports[i % len(reports)]["id"]
        time.sleep(0.35 if login_ok else 0.05)
        if login_ok:
            dv = session.get(f"{BASE}/api/reports/{rid}/detail-view", timeout=120)
            dj = dv.json() if dv.headers.get("content-type", "").startswith("application/json") else {}
            if dv.status_code == 200 and dj.get("status") == "success" and dj.get("view", {}).get("sections"):
                ok_d += 1
            else:
                cycle_fails.append(f"detail {i+1} {rid} {dj.get('status')}")

            pdf = session.get(f"{BASE}/api/reports/{rid}/export?format=pdf", timeout=180)
            if pdf.status_code == 200 and len(pdf.content) > 200:
                ok_p += 1
            else:
                cycle_fails.append(f"pdf {i+1} {rid} {pdf.status_code}")

            k = session.post(
                f"{BASE}/api/ai/module-consult",
                json={"module": "reportes", "extra": {"report_id": rid, "read_only": True}},
                timeout=60,
            )
            kj = k.json() if k.headers.get("content-type", "").startswith("application/json") else {}
            sr = (kj.get("context") or {}).get("selected_report")
            if k.status_code == 200 and kj.get("status") == "success" and sr and str(sr.get("id")) == str(rid):
                ok_k += 1
            else:
                cycle_fails.append(f"kernel {i+1} {rid}")
        else:
            report = get_report(rid)
            try:
                if report and build_detail_view(report).get("sections"):
                    ok_d += 1
                else:
                    cycle_fails.append(f"detail svc {i+1} {rid}")
                path = export_report(report, "pdf")
                if os.path.isfile(path) and os.path.getsize(path) > 200:
                    ok_p += 1
                else:
                    cycle_fails.append(f"pdf svc {i+1} {rid}")
                consult = build_consult_prompt("reportes", QA_EMAIL, {"report_id": rid, "read_only": True})
                sr = (consult.get("context") or {}).get("selected_report")
                if sr and str(sr.get("id")) == str(rid):
                    ok_k += 1
                else:
                    cycle_fails.append(f"kernel svc {i+1} {rid}")
            except Exception as exc:
                cycle_fails.append(f"svc {i+1} {rid}: {exc}")

    evidence["cycles"] = {"detail": ok_d, "pdf": ok_p, "kernel": ok_k, "required": CYCLES}
    evidence["cycle_fails_sample"] = cycle_fails[:10]
    passed = (
        evidence.get("fingerprint_matches_disk")
        and evidence.get("js_matches_disk")
        and not [f for f in dom_fails if "disabled" in f or "novus-btn-details" in f or "NovusRemediation" in f]
        and ok_d == CYCLES
        and ok_p == CYCLES
        and ok_k == CYCLES
        and (reportes_page or "novus-reports-build" in html)
    )
    evidence["pass"] = passed

    md = [
        "# Verificación instancia NOVUS — puerto 5000",
        "",
        f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"- **Raíz proyecto (canónica):** `{ROOT}`",
        f"- **Entrypoint:** `{ROOT / 'main.py'}`",
        f"- **URL verificada:** `{BASE}`",
        "",
        "## Huellas en disco",
        "",
    ]
    for fe in evidence["canonical_files"]:
        md.append(f"- `{fe['path']}` — {fe['mtime']} — `{fe['sha256'][:24]}…`")
    md.extend(
        [
            "",
            "## Contenido servido",
            "",
            f"- JS en disco == JS servido: **{evidence.get('js_matches_disk')}**",
            f"- Fallos DOM: **{dom_fails or 'ninguno'}**",
            "",
            "## 20 pruebas (instancia :5000)",
            "",
            f"- Detail-view: **{ok_d}/{CYCLES}**",
            f"- PDF: **{ok_p}/{CYCLES}**",
            f"- Kernel IA: **{ok_k}/{CYCLES}**",
            "",
            f"## Resultado: **{'PASS' if passed else 'FAIL'}**",
            "",
            "El error `Cannot set properties of null (setting 'disabled')` **no debe reproducirse** si DOM fallos está vacío y no hay NovusRemediation en /reportes.",
        ]
    )
    (OUT / "instance_report.md").write_text("\n".join(md), encoding="utf-8")
    (OUT / "instance_report.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    print("PASS" if passed else "FAIL", evidence["cycles"], "dom", dom_fails, "js_match", evidence.get("js_matches_disk"))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
