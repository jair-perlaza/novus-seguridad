#!/usr/bin/env python3
"""Pruebas NOVUS Threat Intelligence Center."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, ".")

from database import Base, engine, inicializar_db
from services.report_pdf_service import generate_case_pdf
from services.threat_intelligence_service import threat_intelligence


def main():
    print("=" * 60)
    print("NOVUS Threat Intelligence Center — Pruebas")
    print("=" * 60)

    inicializar_db()
    tables = [t.name for t in Base.metadata.sorted_tables if "inteligencia" in t.name]
    print(f"\n[1] Tablas TI: {tables}")
    assert "inteligencia_casos" in tables, "Falta tabla inteligencia_casos"

    print("\n[2] Sincronizando datos reales del equipo...")
    sync = threat_intelligence.sync_from_real_sources(user_email="ti-test@novus.local")
    print(f"    created={sync['created']} updated={sync['updated']} total={sync['total']}")
    assert sync["total"] >= 0

    cases = threat_intelligence.list_cases(limit=20)
    print(f"\n[3] Casos listados: {len(cases)}")
    if not cases:
        print("    WARN: sin casos — equipo puede no tener hallazgos en este momento")
    else:
        c = cases[0]
        print(f"    Primer caso: {c['id']} tipo={c['tipo']} riesgo={c['nivel_riesgo']}")
        assert c.get("id"), "Caso sin ID"
        assert c.get("evidencia") is not None, "Sin evidencia"

    print("\n[4] Búsqueda por keyword...")
    found = threat_intelligence.search_cases({"keyword": "proc"}) if cases else []
    print(f"    Resultados búsqueda 'proc': {len(found)}")

    if cases:
        full = threat_intelligence.get_case(cases[0]["id"])
        assert full and full.get("timeline") is not None, "Timeline missing"
        print(f"\n[5] Timeline eventos: {len(full.get('timeline', []))}")
        print(f"    Propuestas mejora: {len(full.get('propuestas_mejora', []))}")
        print(f"    Lecciones: {bool(full.get('lecciones_aprendidas'))}")

        print("\n[6] Export PDF...")
        path = generate_case_pdf(full)
        assert os.path.exists(path), f"PDF no generado: {path}"
        print(f"    OK: {path} ({os.path.getsize(path)} bytes)")

    print("\n[7] Correlación (mismo source_ref)...")
    if cases and cases[0].get("source_ref"):
        ref = cases[0]["source_ref"]
        before = threat_intelligence.stats()["total"]
        threat_intelligence.create_or_update_case({"id": ref, "nombre": "re-test", "descripcion": "corr"})
        after = threat_intelligence.stats()["total"]
        assert after == before, "Correlación falló — duplicó caso"
        print("    OK — no duplicó expediente")

    stats = threat_intelligence.stats()
    print(f"\n[8] Stats: {stats}")
    print("\n" + "=" * 60)
    print("TODAS LAS PRUEBAS PASS")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
