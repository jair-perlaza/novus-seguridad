#!/usr/bin/env python3
"""Completa evidencia de validación tras interrupción por timeout."""
import json
import re
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_real_operation_audit"
BASE = "http://127.0.0.1:5000"
TEST_TAG = "TEST-VALIDATION-20260818T005204Z"


def main():
    from database import SessionLocal, Log, Alerta, NetworkDeviceInventory, PlatformEvidence
    from services.encrypted_backup_service import verify_backup, restore_encrypted_backup

    db = SessionLocal()
    try:
        rec = {
            "log": db.query(Log).filter(Log.evento == TEST_TAG).count(),
            "alert": db.query(Alerta).filter(Alerta.titulo == TEST_TAG).count(),
            "asset": db.query(NetworkDeviceInventory).filter(NetworkDeviceInventory.hostname == TEST_TAG).count(),
            "evidence": db.query(PlatformEvidence).filter(PlatformEvidence.source_event_id == TEST_TAG).count(),
        }
    finally:
        db.close()

    bak = ROOT / "data/encrypted_backups/backup_20260817_195239_validation_20260818T005204Z.novusbak.json"
    bv = verify_backup(str(bak))
    br = restore_encrypted_backup(str(bak), actor="validation")

    def login(email, pw):
        s = requests.Session()
        r = s.get(f"{BASE}/login", timeout=90)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
        s.post(f"{BASE}/login", data={"email": email, "password": pw, "csrf_token": csrf.group(1) if csrf else ""}, timeout=90)
        return s

    qa = login("novus.qa.jul2026@example.com", "NovusQA2026!")
    cl = login("operaciones@novapay-fintech.co", "NovaPay#Fintech2026")
    tenant = {}
    for ep in ["/api/network/nodes", "/api/dashboard/live", "/api/security/summary", "/api/security/alerts", "/api/system/evidence-center", "/api/reports/list"]:
        try:
            qb = qa.get(BASE + ep, timeout=120).json()
            cb = cl.get(BASE + ep, timeout=120).json()
            tenant[ep] = {
                "qa_status": qb.get("status"),
                "client_status": cb.get("status"),
                "qa_items": len(qb.get("nodes") or qb.get("alerts") or qb.get("reports") or []),
                "client_items": len(cb.get("nodes") or cb.get("alerts") or cb.get("reports") or []),
            }
        except Exception as exc:
            tenant[ep] = {"error": str(exc)[:120]}

    baseline_path = ROOT / "data/behavioral_threat_detection/baseline_cache.json"
    bl = json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.is_file() else {}
    test_proc = f"{TEST_TAG}-PROC"
    learning = {
        "test_proc_in_baseline": test_proc in (bl.get("proc_names") or []),
        "warm_cycles": bl.get("warm_cycles"),
        "ml": False,
    }

    report = {
        "test_tag": TEST_TAG,
        "persistence_after_restart": rec,
        "persistence_verdict": "VERIFICADO" if all(rec.values()) else "NO VERIFICADO",
        "backup_verdict": "BACKUP VERIFICADO" if bv.get("ok") and br.get("ok") else "BACKUP NO VERIFICADO",
        "backup_verify": bv,
        "backup_restore_ok": br.get("ok"),
        "tenant": tenant,
        "learning": learning,
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return report


if __name__ == "__main__":
    main()
