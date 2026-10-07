#!/usr/bin/env python3
"""Genera informe de auditoría de arquitectura de datos empresarial."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT_DIR = os.path.join(ROOT, "data", "enterprise_data_audit")


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    from core.enterprise_databases.bootstrap import initialize_enterprise_databases
    from core.enterprise_databases.engines import (
        AuditSessionLocal,
        ClientsSessionLocal,
        EvidenceSessionLocal,
        HistorySessionLocal,
        KernelSessionLocal,
        SecurityEventsSessionLocal,
        StudyCasesSessionLocal,
    )
    from core.enterprise_databases.schema import (
        AnonymizedStudyCase,
        AuditLogRecord,
        ClientUserRecord,
        EnterpriseRecord,
        EvidenceRecord,
        HistoryAnalysisSession,
        KernelPatternRecord,
        NetworkProfileRecord,
        SecurityEventRecord,
        SupportAccessTokenRecord,
    )
    from services.enterprise_data_service import get_architecture_status

    initialize_enterprise_databases()
    arch = get_architecture_status()

    def count(session_factory, model):
        db = session_factory()
        try:
            return db.query(model).count()
        finally:
            db.close()

    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "bases_creadas": arch,
        "conteos_reales": {
            "clients_enterprises": count(ClientsSessionLocal, EnterpriseRecord),
            "clients_users": count(ClientsSessionLocal, ClientUserRecord),
            "security_events": count(SecurityEventsSessionLocal, SecurityEventRecord),
            "history_network_profiles": count(HistorySessionLocal, NetworkProfileRecord),
            "history_sessions": count(HistorySessionLocal, HistoryAnalysisSession),
            "kernel_patterns": count(KernelSessionLocal, KernelPatternRecord),
            "evidence_records": count(EvidenceSessionLocal, EvidenceRecord),
            "study_cases_anonymized": count(StudyCasesSessionLocal, AnonymizedStudyCase),
            "audit_log": count(AuditSessionLocal, AuditLogRecord),
            "support_tokens": count(AuditSessionLocal, SupportAccessTokenRecord),
        },
        "relaciones": [
            "security_events.legacy_ref → monolito / evidence_records.id",
            "evidence_records.related_event_id → security_events.id",
            "history.network_profiles.scope_id → data/network_security_history/",
            "kernel_* ← build_kernel_network_insights (solo si sufficient_data)",
            "study_cases ← save_anonymized_study_case (sin PII)",
        ],
        "permisos": {
            "tenant_isolation": "resolve_tenant_id + enterprise_access_control",
            "support": "SupportAccessTokenRecord + POST validate",
            "creator_center": "ROLE_NOVUS_CREATOR / NOVUS_CREATOR_EMAIL",
        },
        "cifrado": {
            "ndci_expedientes": "CryptoVault AES-GCM",
            "audit_logs_legacy": "CryptoVault opcional en registrar_log_seguridad",
            "domain_sqlite": "Aislamiento por archivo en data/databases/",
        },
        "validacion_mezcla_clientes": (
            "Bases físicamente separadas; tenant_id en eventos/evidencia/histórico; "
            "casos de estudio sin campos email/empresa/usuario."
        ),
    }

    json_path = os.path.join(OUT_DIR, "enterprise_data_audit.json")
    md_path = os.path.join(OUT_DIR, "enterprise_data_audit.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    lines = [
        "# Informe auditoría — Arquitectura de datos empresarial NOVUS",
        "",
        f"Generado: {report['generated_at']}",
        "",
        "## Bases de datos",
    ]
    for k, v in arch.get("domains", {}).items():
        lines.append(f"- **{k}** ({v.get('label')}): `{v.get('path')}` — existe={v.get('exists')}")
    lines.extend(["", "## Conteos (datos reales)", ""])
    for k, v in report["conteos_reales"].items():
        lines.append(f"- {k}: **{v}**")
    lines.extend(["", "## Validación", "", report["validacion_mezcla_clientes"], ""])
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print("Wrote", json_path)
    print("Wrote", md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
