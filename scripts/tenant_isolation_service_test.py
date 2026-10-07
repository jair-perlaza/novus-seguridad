#!/usr/bin/env python3
"""Verificación aislamiento — capa servicio (sin HTTP agresivo)."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_real_operation_audit"
RUN = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
MA = f"A-SVC-{RUN}"
MB = f"B-SVC-{RUN}"


def main():
    from database import SessionLocal, Usuario, PlatformEvidence, LoginSessionAudit
    from services.tenant_scope_service import resolve_tenant_id
    from services.evidence_center_service import list_evidence, get_evidence_by_id
    from services.login_session_audit_service import list_login_sessions, get_login_session
    from services.security_report_service import list_reports, get_report, save_report, _migrate_legacy_index_once
    from services.behavioral_threat_detection.baseline import update_from_snapshot, get_baseline_view, save_baseline

    db = SessionLocal()
    ua = db.query(Usuario).filter(Usuario.email == "novus.qa.jul2026@example.com").first()
    ub = db.query(Usuario).filter(Usuario.email == "operaciones@novapay-fintech.co").first()
    ta, tb = resolve_tenant_id(ua), resolve_tenant_id(ub)
    db.close()

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    db = SessionLocal()
    db.add(PlatformEvidence(id=f"{MA}-EV", tenant_id=ta, fecha=ts[:10], hora="00:00:00", timestamp=ts, motor="network_snapshot_service", categoria="security", descripcion=MA, nivel_riesgo="info", evidence_json="{}"))
    db.add(PlatformEvidence(id=f"{MB}-EV", tenant_id=tb, fecha=ts[:10], hora="00:00:00", timestamp=ts, motor="network_snapshot_service", categoria="security", descripcion=MB, nivel_riesgo="info", evidence_json="{}"))
    db.add(LoginSessionAudit(id=f"{MA}-SES", tenant_id=ta, user_email=ua.email, login_at=ts, ip_address="10.0.0.1", session_id="s1", login_result="success"))
    db.add(LoginSessionAudit(id=f"{MB}-SES", tenant_id=tb, user_email=ub.email, login_at=ts, ip_address="10.0.0.2", session_id="s2", login_result="success"))
    db.commit()
    db.close()

    save_report({"id": f"REP-{MA}", "finding_id": f"{MA}-F", "tipo": "t", "fecha": ts, "severidad": "Informativo", "estado": "Abierto", "equipo_afectado": "h", "resumen_ejecutivo": MA, "technical": {"linea_tiempo": []}, "conclusiones": MA, "remediation_log": [], "generated_at": ts}, tenant_id=ta)
    save_report({"id": f"REP-{MB}", "finding_id": f"{MB}-F", "tipo": "t", "fecha": ts, "severidad": "Informativo", "estado": "Abierto", "equipo_afectado": "h", "resumen_ejecutivo": MB, "technical": {"linea_tiempo": []}, "conclusiones": MB, "remediation_log": [], "generated_at": ts}, tenant_id=tb)
    _migrate_legacy_index_once()

    update_from_snapshot({"processes": {"names": []}, "services": {"running": []}, "connections": {"remotes": ["1.2.3.4:443"]}}, tenant_id=ta)
    save_baseline(ta)
    update_from_snapshot({"processes": {"names": []}, "services": {"running": []}, "connections": {"remotes": ["5.6.7.8:443"]}}, tenant_id=tb)
    save_baseline(tb)

    tests = []
    def chk(name, ok):
        tests.append({"test": name, "verdict": "VERIFIED" if ok else "FAIL"})

    ev_a = {e["id"] for e in list_evidence(limit=200, tenant_id=ta)}
    ev_b = {e["id"] for e in list_evidence(limit=200, tenant_id=tb)}
    chk("A evidence no B", f"{MB}-EV" not in ev_a and f"{MA}-EV" in ev_a)
    chk("B evidence no A", f"{MA}-EV" not in ev_b and f"{MB}-EV" in ev_b)
    chk("A get B evidence blocked", get_evidence_by_id(f"{MB}-EV", tenant_id=ta) is None)
    chk("B get A evidence blocked", get_evidence_by_id(f"{MA}-EV", tenant_id=tb) is None)

    sa = {s["id"] for s in list_login_sessions(limit=200, tenant_id=ta)}
    sb = {s["id"] for s in list_login_sessions(limit=200, tenant_id=tb)}
    chk("A sessions no B", f"{MB}-SES" not in sa)
    chk("B sessions no A", f"{MA}-SES" not in sb)
    chk("A get B session blocked", get_login_session(f"{MB}-SES", tenant_id=ta) is None)
    chk("B get A session blocked", get_login_session(f"{MA}-SES", tenant_id=tb) is None)

    ra = {r["id"] for r in list_reports(limit=200, tenant_id=ta)}
    rb = {r["id"] for r in list_reports(limit=200, tenant_id=tb)}
    chk("A reports no B", f"REP-{MB}" not in ra and f"REP-{MA}" in ra)
    chk("B reports no A", f"REP-{MA}" not in rb and f"REP-{MB}" in rb)
    chk("A get B report blocked", get_report(f"REP-{MB}", tenant_id=ta) is None)
    chk("B get A report blocked", get_report(f"REP-{MA}", tenant_id=tb) is None)

    bla, blb = get_baseline_view(ta), get_baseline_view(tb)
    chk("baseline remotes isolated", "5.6.7.8:443" not in json.dumps(bla) and "1.2.3.4:443" not in json.dumps(blb))

    overall = "VERIFIED" if all(t["verdict"] == "VERIFIED" for t in tests) else "FAIL"
    report = {"run_id": RUN, "tests": tests, "overall": overall}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "TENANT_ISOLATION_SERVICE_TEST.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if overall == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
