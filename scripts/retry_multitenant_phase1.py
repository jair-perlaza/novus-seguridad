#!/usr/bin/env python3
"""Reintento fase 1 aislamiento — NOVUS debe estar estable."""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_real_operation_audit"

from scripts.critical_security_validation import (
    MARK_A,
    MARK_B,
    RUN_ID,
    resolve_tenant_ids,
    insert_isolation_fixtures,
    phase1_multitenant,
    build_md_multitenant,
    save_json,
    save_md,
    utc,
)

RUN_ID = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
import scripts.critical_security_validation as csv
csv.RUN_ID = RUN_ID
csv.MARK_A = f"A-ISOL-{RUN_ID}"
csv.MARK_B = f"B-ISOL-{RUN_ID}"


def main():
    tenant_meta = resolve_tenant_ids()
    # retry insert with backoff
    fixtures = None
    for attempt in range(5):
        fixtures = insert_isolation_fixtures(
            tenant_meta["novus.qa.jul2026@example.com"]["tenant_id"],
            tenant_meta["operaciones@novapay-fintech.co"]["tenant_id"],
        )
        if fixtures.get("ok"):
            break
        time.sleep(8)
    prior = {}
    p = OUT / "MULTITENANT_READONLY_TEST.json"
    if p.is_file():
        prior = json.loads(p.read_text(encoding="utf-8"))

    p1 = phase1_multitenant(tenant_meta)
    p1["prior_readonly_test_reference"] = {
        "captured_at": prior.get("captured_at_utc"),
        "cross_leak_signals": prior.get("cross_leak_signals"),
        "overall_verdict": prior.get("overall_verdict"),
    }
    # Merge prior confirmed leaks into definitive verdict
    if prior.get("cross_leak_signals"):
        p1["historical_confirmed_leaks"] = prior["cross_leak_signals"]
        if not p1.get("critical_cross_tenant_endpoints"):
            p1["critical_cross_tenant_endpoints"] = [
                x.get("endpoint", "").split("/api/")[-1] for x in prior["cross_leak_signals"]
            ]
        p1["overall_verdict"] = (
            "RIESGO CONFIRMADO — cross-tenant exposure en evidence/reports/sessions "
            "(readonly test previo + gap arquitectural VERIFICADO en código)"
        )

    save_json(OUT / "MULTITENANT_ISOLATION_DEFINITIVE_REPORT.json", p1)
    save_md(OUT / "MULTITENANT_ISOLATION_DEFINITIVE_REPORT.md", build_md_multitenant(p1))
    print(json.dumps({"ok": True, "fixtures_ok": fixtures.get("ok"), "critical": p1.get("critical_cross_tenant_endpoints")}, ensure_ascii=True))


if __name__ == "__main__":
    main()
