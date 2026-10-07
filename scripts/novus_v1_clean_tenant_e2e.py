#!/usr/bin/env python3
"""Prueba E2E tenant limpio — verifica ausencia de datos QA/simulados en MVP."""
from __future__ import annotations

import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_release_candidate" / "NOVUS_V1_CLEAN_TENANT_E2E.json"

QA_MARKERS = (
    "QA-NOVUS-2026",
    "novus.qa.jul2026@example.com",
    "TEST-PORT-9999",
    "DB-VULN",
    "simulated",
    "placeholder",
    "demo",
    "fixture",
)

CONTAMINATION_PATHS = (
    "192.0.2.",
    "198.51.100.",
    "203.0.113.",
)


def _scan_blob(obj) -> list:
    hits = []
    text = json.dumps(obj, ensure_ascii=False, default=str).lower()
    for marker in QA_MARKERS:
        if marker.lower() in text:
            hits.append(marker)
    for prefix in CONTAMINATION_PATHS:
        if prefix in text:
            hits.append(prefix)
    return sorted(set(hits))


def main() -> int:
    from werkzeug.security import generate_password_hash
    from database import SessionLocal, Usuario, TenantMonitoringScope, inicializar_db, ensure_tables_exist
    from services.tenant_scope_service import resolve_tenant_id
    from services.security_report_service import list_reports
    from services.evidence_center_service import list_evidence
    from services.login_session_audit_service import list_login_sessions
    from services.platform_metrics_service import get_platform_counters, get_unified_security_payload
    from services.network_snapshot_service import read_nodes_api, read_ndr_api

    inicializar_db()
    ensure_tables_exist()

    tenant_id = f"CLIENT-{uuid.uuid4().hex[:10].upper()}"
    email = f"cliente.{tenant_id.lower()}@novus-client.test"
    password = "NovusClient2026!"

    db = SessionLocal()
    try:
        db.add(Usuario(
            email=email,
            hashed_password=generate_password_hash(password),
            is_active=True,
            nit_pyme=tenant_id,
            sector="fintech",
            role="admin",
        ))
        db.add(TenantMonitoringScope(
            tenant_id=tenant_id,
            monitoring_enabled=True,
            monitoring_mode="platform_node",
            node_id="local",
            configured_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            updated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        ))
        db.commit()
        user = db.query(Usuario).filter(Usuario.email == email).first()
        resolved = resolve_tenant_id(user)
    finally:
        db.close()

    checks = []
    tenant_payloads = {
        "reports": list_reports(limit=50, tenant_id=tenant_id),
        "evidence": list_evidence(limit=50, tenant_id=tenant_id),
        "sessions": list_login_sessions(limit=20, tenant_id=tenant_id),
        "counters": get_platform_counters(tenant_id=tenant_id),
        "security": get_unified_security_payload(tenant_id=tenant_id),
    }
    platform_payloads = {
        "nodes": read_nodes_api(trigger_discovery=False),
        "ndr": read_ndr_api(trigger_discovery=False),
    }

    for name, data in tenant_payloads.items():
        hits = _scan_blob(data)
        checks.append({
            "module": name,
            "scope": "tenant",
            "verdict": "PASS" if not hits else "FAIL",
            "contamination": hits,
        })

    for name, data in platform_payloads.items():
        hits = [m for m in _scan_blob(data) if m in QA_MARKERS]
        checks.append({
            "module": name,
            "scope": "platform_network",
            "verdict": "PASS" if not hits else "FAIL",
            "contamination": hits,
        })

    checks.append({
        "module": "tenant_resolution",
        "verdict": "PASS" if resolved == tenant_id else "FAIL",
        "resolved": resolved,
    })

    overall = "VERIFIED" if all(c["verdict"] == "PASS" for c in checks) else "FAIL"
    report = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tenant_id": tenant_id,
        "email": email,
        "checks": checks,
        "overall": overall,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"overall": overall, "tenant_id": tenant_id}, indent=2))
    return 0 if overall == "VERIFIED" else 1


if __name__ == "__main__":
    sys.exit(main())
