"""Pruebas reales de exportación PDF e informes MDR."""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from services.security_report_service import get_report, list_reports
from services.report_pdf_service import generate_pdf, export_report
from utils.pdf_text import normalize_pdf_text


def main():
    results = {"pdf_ok": [], "pdf_fail": [], "html_fallback": []}
    reports = [r for r in list_reports() if str(r.get("id", "")).startswith("MDR-")][:5]
    if not reports:
        rid = "MDR-20260720123602-host_scan_full"
        one = get_report(rid)
        if one:
            reports = [one]
    for meta in reports:
        rid = meta["id"] if isinstance(meta, dict) and "id" in meta else meta.get("id")
        report = get_report(rid) if isinstance(meta, dict) and "technical" not in meta else meta
        if not report:
            continue
        try:
            path = generate_pdf(report)
            ext = os.path.splitext(path)[1].lower()
            ok = os.path.isfile(path) and os.path.getsize(path) > 100
            if ext == ".html":
                results["html_fallback"].append(rid)
            elif ok:
                results["pdf_ok"].append(rid)
            else:
                results["pdf_fail"].append({"id": rid, "reason": "empty file"})
        except Exception as exc:
            results["pdf_fail"].append({"id": rid, "reason": str(exc)})

    sample = "Protección crítica — informe · ñáéíóú € 🛡"
    norm = normalize_pdf_text(sample)
    assert "?" not in norm or "Protecci" in norm

    out = os.path.join(ROOT, "data", "export_audit", "verify_export_results.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(json.dumps(results, indent=2))
    return 0 if not results["pdf_fail"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
