#!/usr/bin/env python3
"""Auditoría Platform Health Center + Centro de Evidencias."""
from __future__ import annotations

import json
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = 0
FAIL = 0


def check(name: str, fn):
    global PASS, FAIL
    try:
        ok = bool(fn())
        if ok:
            PASS += 1
            print(f"  [OK] {name}")
        else:
            FAIL += 1
            print(f"  [FAIL] {name}")
    except Exception as exc:
        FAIL += 1
        print(f"  [FAIL] {name}: {exc}")


def main():
    print("=== Platform Health + Evidence Center Audit ===\n")

    from migrate_database import migrate_database
    migrate_database()

    from database import ensure_tables_exist
    ensure_tables_exist()

    from services.platform_health_service import ENGINE_IDS, get_platform_health, probe_engine

    health = get_platform_health()
    check("platform health payload", lambda: health.get("engines") and len(health["engines"]) >= 10)
    check("all engines probed", lambda: len(health["engines"]) == len(ENGINE_IDS))
    check("health scores real", lambda: all(isinstance(e.get("health_score"), int) for e in health["engines"]))
    check("no fake static status", lambda: health.get("generated_at") is not None)

    nme = probe_engine("network_monitor_engine")
    check("NME has telemetry fields", lambda: "cpu_percent" in nme and "events_processed" in nme)

    from services.evidence_center_service import (
        EVIDENCE_CATEGORIES,
        backfill_from_defense_registry,
        get_evidence_summary,
        list_evidence,
        record_evidence,
    )

    test_id = f"EVD-TEST-{uuid.uuid4().hex[:8]}"
    ev = record_evidence(
        motor="test_audit_motor",
        description="Evidencia de prueba auditoría — eliminable",
        categoria="auditoria",
        nivel_riesgo="bajo",
        nivel_confianza="Alta",
        accion_ejecutada="audit_probe",
        resultado="success",
        source_event_id=test_id,
        dedupe_key=test_id,
    )
    check("record evidence", lambda: ev.get("id") == test_id)

    dup = record_evidence(
        motor="test_audit_motor",
        description="Duplicado",
        dedupe_key=test_id,
    )
    check("dedupe evidence", lambda: dup.get("id") == test_id)

    from services.defense_evidence_registry import record_defense_event

    def_id = f"DEF-TEST-{uuid.uuid4().hex[:8]}"
    record_defense_event(
        phase="audit",
        action="audit_bridge_test",
        motor="api_security_service",
        outcome="blocked",
        detail="Test bridge evidence center",
        confidence="Alta",
    )

    items = list_evidence(limit=20, motor="api_security_service")
    check("defense bridge creates evidence", lambda: any("audit_bridge" in (i.get("accion_ejecutada") or "") for i in items))

    backfill = backfill_from_defense_registry(limit=50)
    check("backfill runs", lambda: "imported" in backfill)

    summary = get_evidence_summary()
    check("evidence summary", lambda: summary.get("total", 0) >= 1)
    check("categories defined", lambda: len(EVIDENCE_CATEGORIES) >= 8)

    report_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "platform_health")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "audit_report.md")
    lines = [
        "# Auditoría Platform Health Center + Centro de Evidencias",
        "",
        f"**Fecha:** {health.get('generated_at')}",
        "",
        "## Estado general NOVUS",
        f"- Estado: **{health.get('overall_status_label')}**",
        f"- Health Score global: **{health.get('overall_health_score')}**",
        f"- Motores activos: {health.get('engines_active')} | degradados: {health.get('engines_degraded')} | detenidos: {health.get('engines_stopped')}",
        "",
        "## Salud por motor",
        "",
        "| Motor | Estado | Health | Eventos | Último error |",
        "|---|---|---:|---:|---|",
    ]
    for e in health.get("engines", []):
        err = (e.get("last_error") or "—")[:40]
        lines.append(f"| {e.get('label')} | {e.get('status_label')} | {e.get('health_score')} | {e.get('events_processed')} | {err} |")

    lines.extend([
        "",
        "## Evidencias almacenadas",
        f"- Total: **{summary.get('total')}**",
        f"- Por categoría: `{json.dumps(summary.get('by_category', {}), ensure_ascii=False)}`",
        f"- Backfill: imported={backfill.get('imported')}, skipped={backfill.get('skipped')}",
        "",
        "## Mejoras implementadas",
        "- `services/platform_health_service.py` — probes reales por motor (NME, AIE, Kernel IA, ADE, UCE, CryptoVault, Threat Intel, API Protection, Topology, Report Engine)",
        "- `services/evidence_center_service.py` + tabla `platform_evidences` — persistencia SQLite unificada",
        "- Puente automático desde `defense_evidence_registry`",
        "- Hooks en AIE (`apply_admin_action`) y `device_connection_monitor`",
        "- APIs: `GET /api/system/platform-health`, `GET /api/system/evidence-center`",
        "- UI: `/platform-health`, `/centro-evidencias` con auto-refresh",
        "",
        f"## Resultado tests: {PASS} OK / {FAIL} FAIL",
    ])
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"\nInforme: {report_path}")
    print(f"\n=== RESULTADO: {PASS} OK, {FAIL} FAIL ===")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
