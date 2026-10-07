#!/usr/bin/env python3
"""Verifica Centro de Reportes, exportaciones y ausencia de errores visibles."""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> int:
    print("=== verify_reports_center ===")
    fails = []

    from main import app

    client = app.test_client()

    with client.session_transaction() as sess:
        pass

    r = client.get("/login")
    if r.status_code != 200:
        fails.append("login")

    from services.reports_center_service import get_reports_center_payload, get_network_history_report

    payload = get_reports_center_payload()
    if "centro" not in payload:
        fails.append("center_payload")
    net = get_network_history_report()
    if "contexto" not in net:
        fails.append("network_history")

    from services.security_report_service import list_reports

    reports = list_reports(limit=5)
    if reports:
        rid = reports[0]["id"]
        from services.report_pdf_service import export_report

        for fmt in ("pdf", "csv", "xlsx", "html", "json"):
            try:
                path = export_report(reports[0], fmt)
                if not os.path.isfile(path):
                    fails.append(f"export_{fmt}_missing")
            except Exception as exc:
                fails.append(f"export_{fmt}:{exc}")

    html_path = os.path.join(ROOT, "templates", "reportes.html")
    with open(html_path, encoding="utf-8") as fh:
        html = fh.read()
    if "novus-btn-details" in html:
        fails.append("reportes_stale_btn_details")
    if "NovusDom" not in html and "novus-dom-safe" not in html:
        if "NovusDom.setDisabled" not in html:
            fails.append("reportes_no_dom_safe")

    dom_js = os.path.join(ROOT, "static", "js", "novus-dom-safe.js")
    if not os.path.isfile(dom_js):
        fails.append("dom_safe_js")

    proc = __import__("subprocess").run(
        [sys.executable, os.path.join(ROOT, "scripts", "verify_no_visible_errors.py")],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    if proc.returncode != 0:
        fails.append("verify_no_visible_errors")

    if fails:
        print("FAIL", fails)
        return 1
    print("PASS reports=", len(reports))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
