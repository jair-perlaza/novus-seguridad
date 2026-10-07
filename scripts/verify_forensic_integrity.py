#!/usr/bin/env python3
"""Pruebas reales del sistema forense de integridad NOVUS."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> int:
    fails = []
    print("=== verify_forensic_integrity ===")

    from services.forensic_evidence_keys import ensure_forensic_signing_key
    from services import forensic_evidence_integrity_service as fev

    ensure_forensic_signing_key()

    row = fev.seal_evidence(
        source_id="VERIFY-TEST-001",
        source_type="verify_script",
        motor="verify_forensic_integrity",
        evidence_type="test_seal",
        payload={"verified": True, "purpose": "integrity_test"},
        user_email="verify@novus.local",
        tenant_id="verify-tenant",
        equipment="script",
    )
    if not row or not row.get("content_hash_sha256"):
        fails.append("seal")

    vr = fev.verify_single(row["forensic_id"])
    if not vr.get("ok"):
        fails.append("verify_single")

    full = fev.run_full_verifier()
    if full.get("total", 0) < 1:
        fails.append("full_verifier_empty")

    # Tamper test on isolated copy
    if os.path.isfile(fev.RECORDS_FILE):
        tmp = tempfile.mkdtemp()
        try:
            copy_path = os.path.join(tmp, "records.jsonl")
            shutil.copy(fev.RECORDS_FILE, copy_path)
            with open(copy_path, "r+", encoding="utf-8") as fh:
                lines = fh.readlines()
                if lines:
                    lines[0] = lines[0].replace("a", "A", 1)
                    fh.seek(0)
                    fh.writelines(lines)
                    fh.truncate()
            tampered = fev.run_full_verifier(ledger_path=copy_path)
            if tampered.get("compromised", 0) < 1 and tampered.get("chain_breaks", 0) < 1:
                fails.append("tamper_not_detected")
            else:
                print("tamper_detected ok", tampered.get("compromised"), tampered.get("chain_breaks"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    mig = fev.migrate_defense_registry_batch(max_lines=50)
    print("migration_batch", mig)

    try:
        from core.app import create_app

        app = create_app("development")
        rules = {r.rule for r in app.url_map.iter_rules()}
        for route in ("/api/forensic-evidence/verify-all", "/verificador-evidencias"):
            if route not in rules:
                fails.append(f"route:{route}")
    except Exception as exc:
        fails.append(f"app:{exc}")

    if fails:
        print("FAIL", fails)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
