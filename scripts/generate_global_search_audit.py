#!/usr/bin/env py -3
"""Auditoría del buscador global NOVUS + humo API."""
from __future__ import annotations

import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

OUT_DIR = os.path.join(ROOT, "data", "global_search_audit_20260722")


def main() -> int:
    from services.global_search_kernel_service import build_audit_report, run_global_search
    from services.global_search_index import get_static_index

    os.makedirs(OUT_DIR, exist_ok=True)
    t0 = time.perf_counter()
    sample = run_global_search("vulnerabilidad", limit=10, user_email="audit@novus.local", sector="logistica")
    elapsed = (time.perf_counter() - t0) * 1000
    audit = build_audit_report()
    audit["smoke_query"] = "vulnerabilidad"
    audit["smoke_results"] = sample.get("count", 0)
    audit["smoke_timing_ms"] = sample.get("timing_ms", elapsed)
    audit["smoke_kernel_intent"] = (sample.get("kernel") or {}).get("intent")

    forbidden_ui = [
        "Escribe para buscar",
        "Atajos:",
        "navegar",
        "novus-search-footer",
        "novus-search-hint",
    ]
    html_paths = [
        os.path.join(ROOT, "templates", "partials", "global_search.html"),
        os.path.join(ROOT, "templates", "partials", "global_search_only.html"),
    ]
    ui_ok = True
    ui_notes = []
    for path in html_paths:
        text = open(path, encoding="utf-8").read()
        for token in forbidden_ui:
            if token in text:
                ui_ok = False
                ui_notes.append(f"{os.path.basename(path)} contiene «{token}»")

    md = os.path.join(OUT_DIR, "global_search_audit.md")
    with open(md, "w", encoding="utf-8") as fh:
        fh.write("# Auditoría — Buscador global NOVUS\n\n")
        fh.write("## Datos indexados (estático)\n\n")
        fh.write(f"- Ítems catálogo: **{audit['static_index'].get('static_items')}**\n")
        fh.write(f"- Categorías: {', '.join(audit['static_index'].get('categories') or [])}\n")
        fh.write(f"- Informes (estimado): **{audit['static_index'].get('reports_indexed_estimate')}**\n\n")
        fh.write("## Fuentes dinámicas consultadas\n\n")
        for k, v in (audit.get("dynamic_sources") or {}).items():
            fh.write(f"- {k}: **{v}**\n")
        fh.write("\n## Kernel IA (buscador)\n\n")
        for line in audit.get("kernel_capabilities") or []:
            fh.write(f"- {line}\n")
        fh.write("\n## Aprendizaje persistente\n\n")
        for k, v in (audit.get("learning") or {}).items():
            fh.write(f"- {k}: **{v}**\n")
        fh.write("\n## Métricas de humo\n\n")
        fh.write(f"- Consulta: `{audit['smoke_query']}`\n")
        fh.write(f"- Resultados: **{audit['smoke_results']}**\n")
        fh.write(f"- Tiempo: **{audit['smoke_timing_ms']} ms**\n")
        fh.write(f"- Intención Kernel: `{audit['smoke_kernel_intent']}`\n\n")
        fh.write("## Limitaciones\n\n")
        for line in audit.get("limitations") or []:
            fh.write(f"- {line}\n")
        fh.write("\n## UI (sin paneles de ayuda)\n\n")
        fh.write(f"- Estado: **{'PASS' if ui_ok else 'FAIL'}**\n")
        for n in ui_notes:
            fh.write(f"- {n}\n")

    with open(os.path.join(OUT_DIR, "audit.json"), "w", encoding="utf-8") as fh:
        json.dump({"audit": audit, "ui_ok": ui_ok, "ui_notes": ui_notes}, fh, indent=2, ensure_ascii=False)

    print("UI:", "PASS" if ui_ok else "FAIL")
    print("Smoke results:", audit["smoke_results"])
    print("Report:", md)
    return 0 if ui_ok and audit["smoke_results"] > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
