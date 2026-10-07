#!/usr/bin/env py -3
"""
Auditoría de presentación de informes: la vista ejecutiva no debe filtrar JSON/campos internos.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from services.security_report_service import list_reports, get_report
from services.reports_view_service import build_detail_view
from services.report_presentation_service import (
    build_executive_presentation,
    audit_presentation_leaks,
)
from services.report_pdf_service import generate_presentation_pdf


def _audit_view_text(view: dict) -> list[str]:
    fails = []
    pres = view.get("presentation") or {}
    reason = audit_presentation_leaks(pres)
    if reason:
        fails.append(f"presentation leak pattern: {reason}")
    if view.get("technical_audit_json"):
        fails.append("technical_audit_json present in default view (must be admin-only)")
    return fails


def main() -> int:
    reports = list_reports(limit=80)
    tested = 0
    failures: list[str] = []
    samples: list[str] = []

    type_keys = set()
    for entry in reports:
        rid = entry.get("id")
        if not rid:
            continue
        report = get_report(rid)
        if not report:
            continue
        type_keys.add(report.get("report_type") or report.get("tipo") or "SEC")
        tested += 1
        try:
            view = build_detail_view(report, include_technical=False)
            failures.extend(f"{rid}: {f}" for f in _audit_view_text(view))
            pres = build_executive_presentation(report)
            if not pres.get("executive"):
                failures.append(f"{rid}: missing executive block")
            pdf_path = generate_presentation_pdf(report)
            if not os.path.isfile(pdf_path):
                failures.append(f"{rid}: PDF not created")
            else:
                if pdf_path.endswith(".pdf"):
                    with open(pdf_path, "rb") as fh:
                        raw = fh.read().decode("latin-1", errors="ignore").lower()
                    for token in (
                        "learning_summary",
                        "trust_factors",
                        "classification_reason",
                        "confidence_score",
                        "admin_action",
                    ):
                        if token in raw:
                            failures.append(f"{rid}: PDF contains internal token {token}")
            if len(samples) < 5:
                samples.append(rid)
        except Exception as exc:
            failures.append(f"{rid}: exception {exc}")

    out_dir = os.path.join(ROOT, "data", "report_presentation_audit_20260722")
    os.makedirs(out_dir, exist_ok=True)
    report_md = os.path.join(out_dir, "audit_report.md")
    with open(report_md, "w", encoding="utf-8") as fh:
        fh.write("# Auditoría presentación informes NOVUS\n\n")
        fh.write(f"- Fecha: {datetime.now().isoformat()}\n")
        fh.write(f"- Informes probados: **{tested}**\n")
        fh.write(f"- Tipos vistos: {', '.join(sorted(type_keys)) or '—'}\n")
        fh.write(f"- Muestras: {', '.join(samples) or '—'}\n\n")
        if failures:
            fh.write("## Fallos\n\n")
            for f in failures[:100]:
                fh.write(f"- {f}\n")
        else:
            fh.write("## Resultado\n\n**PASS** — Sin fugas detectadas en vista ejecutiva ni PDF (muestra).\n")

    print(f"Tested: {tested}, failures: {len(failures)}")
    print(f"Report: {report_md}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
