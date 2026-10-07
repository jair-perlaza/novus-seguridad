"""Verificación HTTP del Centro de Defensa Manual."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = os.environ.get("NOVUS_BASE_URL", "http://127.0.0.1:5000")
EMAIL = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
PASSWORD = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")


def main():
    from services.manual_defense_catalog import build_catalog, audit_capabilities, get_mechanism
    from services.manual_defense_service import execute_mechanism, build_kernel_consult

    cat = build_catalog(None)
    assert len(cat) >= 50, len(cat)
    audit = audit_capabilities(None)
    assert audit["total"] == len(cat)

    # Sync: procesos (rápido)
    ex = execute_mechanism("host_scan_processes", {}, user_id=1, user_email=EMAIL)
    assert ex.get("status") == "ok", ex
    assert "result" in ex

    k = build_kernel_consult("host_scan_processes", EMAIL)
    assert k.get("mechanism_structured"), k.keys()

    # Mail debe estar unavailable sin OAuth
    mail = execute_mechanism("mail_scan_mailbox", {}, user_id=1, user_email=EMAIL)
    assert mail.get("status") in ("unavailable", "ok"), mail

    cloud = execute_mechanism("sector_cloud", {}, user_email=EMAIL)
    assert cloud.get("status") == "unavailable", cloud

    from database import ensure_tables_exist, ManualDefenseRun, SessionLocal

    ensure_tables_exist()
    db = SessionLocal()
    try:
        db.query(ManualDefenseRun).limit(1).all()
    finally:
        db.close()

    out = {
        "catalog_count": len(cat),
        "audit": audit,
        "sample_execute": ex.get("result", {}).get("status"),
        "kernel_has_structured": bool(k.get("mechanism_structured")),
    }
    dest = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "manual_defense_center", "verify_local.json")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
    print("PASS", dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
