#!/usr/bin/env python3
"""
Prueba negativa obligatoria — aislamiento multi-tenant post-fix.
A nunca lee B; B nunca lee A.
"""
from __future__ import annotations

import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_real_operation_audit"
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
CLIENT = ("operaciones@novapay-fintech.co", "NovaPay#Fintech2026")
RUN = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
MARK_A = f"A-FIX-{RUN}"
MARK_B = f"B-FIX-{RUN}"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def login(email: str, password: str) -> requests.Session:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=60)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    s.post(
        f"{BASE}/login",
        data={"email": email, "password": password, "csrf_token": csrf.group(1) if csrf else ""},
        timeout=60,
    )
    return s


def insert_fixtures(tenant_a: str, tenant_b: str) -> dict:
    from database import SessionLocal, PlatformEvidence, LoginSessionAudit
    from services.security_report_service import save_report

    ts = utc()
    db = SessionLocal()
    out = {"tenant_a": tenant_a, "tenant_b": tenant_b, "markers": {}}
    try:
        ev_a = PlatformEvidence(
            id=f"{MARK_A}-EVIDENCE-001",
            tenant_id=tenant_a,
            fecha=ts[:10],
            hora=ts[11:19],
            timestamp=ts,
            motor="network_snapshot_service",
            categoria="security",
            descripcion=f"Fix test exclusive A {MARK_A}",
            nivel_riesgo="info",
            source_event_id=MARK_A,
            evidence_json=json.dumps({"verified": True, "motor": "network_snapshot_service", "timestamp": ts}),
        )
        ev_b = PlatformEvidence(
            id=f"{MARK_B}-EVIDENCE-001",
            tenant_id=tenant_b,
            fecha=ts[:10],
            hora=ts[11:19],
            timestamp=ts,
            motor="network_snapshot_service",
            categoria="security",
            descripcion=f"Fix test exclusive B {MARK_B}",
            nivel_riesgo="info",
            source_event_id=MARK_B,
            evidence_json=json.dumps({"verified": True, "motor": "network_snapshot_service", "timestamp": ts}),
        )
        db.add(ev_a)
        db.add(ev_b)
        sa = LoginSessionAudit(
            id=f"{MARK_A}-SESSION-001",
            tenant_id=tenant_a,
            user_email=QA[0],
            login_at=ts,
            ip_address="10.91.155.110",
            session_id=f"sess-{MARK_A}",
            login_result="success",
            security_status="verified",
        )
        sb = LoginSessionAudit(
            id=f"{MARK_B}-SESSION-001",
            tenant_id=tenant_b,
            user_email=CLIENT[0],
            login_at=ts,
            ip_address="10.91.155.111",
            session_id=f"sess-{MARK_B}",
            login_result="success",
            security_status="verified",
        )
        db.add(sa)
        db.add(sb)
        db.commit()
        out["markers"] = {
            "evidence_a": ev_a.id,
            "evidence_b": ev_b.id,
            "session_a": sa.id,
            "session_b": sb.id,
        }
    except Exception as exc:
        db.rollback()
        out["error"] = str(exc)[:300]
    finally:
        db.close()

    ra = save_report(
        {
            "id": f"REP-{MARK_A}",
            "finding_id": f"{MARK_A}-FIND-001",
            "tipo": "Isolation fix test A",
            "fecha": ts,
            "severidad": "Informativo",
            "estado": "Abierto",
            "equipo_afectado": "test",
            "resumen_ejecutivo": MARK_A,
            "technical": {"fecha_deteccion": ts, "severidad": "Informativo", "estado": "Abierto", "linea_tiempo": []},
            "conclusiones": MARK_A,
            "remediation_log": [],
            "generated_at": ts,
        },
        tenant_id=tenant_a,
    )
    rb = save_report(
        {
            "id": f"REP-{MARK_B}",
            "finding_id": f"{MARK_B}-FIND-001",
            "tipo": "Isolation fix test B",
            "fecha": ts,
            "severidad": "Informativo",
            "estado": "Abierto",
            "equipo_afectado": "test",
            "resumen_ejecutivo": MARK_B,
            "technical": {"fecha_deteccion": ts, "severidad": "Informativo", "estado": "Abierto", "linea_tiempo": []},
            "conclusiones": MARK_B,
            "remediation_log": [],
            "generated_at": ts,
        },
        tenant_id=tenant_b,
    )
    out["markers"]["report_a"] = ra["id"]
    out["markers"]["report_b"] = rb["id"]
    return out


def _blob(body) -> str:
    return json.dumps(body, ensure_ascii=False) if body is not None else ""


def run_negative_tests() -> dict:
    from database import SessionLocal, Usuario
    from services.tenant_scope_service import resolve_tenant_id
    from services.behavioral_threat_detection.baseline import get_baseline_view, update_from_snapshot, save_baseline

    db = SessionLocal()
    try:
        ua = db.query(Usuario).filter(Usuario.email == QA[0]).first()
        ub = db.query(Usuario).filter(Usuario.email == CLIENT[0]).first()
        tid_a = resolve_tenant_id(ua)
        tid_b = resolve_tenant_id(ub)
    finally:
        db.close()

    fixtures = insert_fixtures(tid_a, tid_b)

    # Baseline A — marcar remotes exclusivos
    snap_a = {
        "processes": {"names": [f"{MARK_A}-proc"]},
        "services": {"running": [f"{MARK_A}-svc"]},
        "connections": {"remotes": [f"10.99.1.1:443"]},
    }
    snap_b = {
        "processes": {"names": [f"{MARK_B}-proc"]},
        "services": {"running": [f"{MARK_B}-svc"]},
        "connections": {"remotes": [f"10.99.2.2:443"]},
    }
    update_from_snapshot(snap_a, tenant_id=tid_a)
    save_baseline(tid_a)
    update_from_snapshot(snap_b, tenant_id=tid_b)
    save_baseline(tid_b)
    bl_a = get_baseline_view(tid_a)
    bl_b = get_baseline_view(tid_b)

    qa = login(QA[0], QA[1])
    cl = login(CLIENT[0], CLIENT[1])
    m = fixtures["markers"]

    tests = []

    def check(label: str, sess: requests.Session, ep: str, foreign_id: str, own_id: str, list_key: str):
        list_r = sess.get(BASE + ep, timeout=60)
        list_body = list_r.json() if list_r.headers.get("content-type", "").startswith("application/json") else {}
        list_blob = _blob(list_body)
        direct_r = sess.get(f"{BASE}{ep}?id={foreign_id}" if "login-sessions" in ep else f"{BASE}{ep.replace('/list','')}/{foreign_id}", timeout=60)
        if "login-sessions" in ep:
            direct_r = sess.get(f"{BASE}/api/system/login-sessions?id={foreign_id}", timeout=60)
        elif "evidence" in ep:
            direct_r = list_r  # no direct evidence id endpoint; use list only
        elif "reports" in ep:
            direct_r = sess.get(f"{BASE}/api/reports/{foreign_id}", timeout=60)

        direct_body = direct_r.json() if direct_r.headers.get("content-type", "").startswith("application/json") else {}
        foreign_in_list = foreign_id in list_blob
        own_in_list = own_id in list_blob
        direct_foreign = direct_r.status_code == 200 and direct_body.get("status") == "success" and foreign_id in _blob(direct_body)
        passed = not foreign_in_list and not direct_foreign
        tests.append(
            {
                "test": label,
                "endpoint": ep,
                "foreign_in_list": foreign_in_list,
                "own_in_list": own_in_list,
                "direct_foreign_http": direct_r.status_code,
                "direct_foreign_leaked": direct_foreign,
                "verdict": "VERIFIED" if passed else "FAIL",
            }
        )

    check("A list evidence no B", qa, "/api/system/evidence-center", m["evidence_b"], m["evidence_a"], "evidence")
    check("B list evidence no A", cl, "/api/system/evidence-center", m["evidence_a"], m["evidence_b"], "evidence")
    check("A sessions no B", qa, "/api/system/login-sessions", m["session_b"], m["session_a"], "sessions")
    check("B sessions no A", cl, "/api/system/login-sessions", m["session_a"], m["session_b"], "sessions")
    check("A direct session B blocked", qa, "/api/system/login-sessions", m["session_b"], m["session_a"], "sessions")
    check("B direct session A blocked", cl, "/api/system/login-sessions", m["session_a"], m["session_b"], "sessions")
    check("A reports no B", qa, "/api/reports/list", m["report_b"], m["report_a"], "reports")
    check("B reports no A", cl, "/api/reports/list", m["report_a"], m["report_b"], "reports")

    dr_a = qa.get(f"{BASE}/api/reports/{m['report_b']}", timeout=60)
    dr_b = cl.get(f"{BASE}/api/reports/{m['report_a']}", timeout=60)
    tests.append(
        {
            "test": "A direct report B blocked",
            "direct_http": dr_a.status_code,
            "verdict": "VERIFIED" if dr_a.status_code in (403, 404) or dr_a.json().get("status") != "success" else "FAIL",
        }
    )
    tests.append(
        {
            "test": "B direct report A blocked",
            "direct_http": dr_b.status_code,
            "verdict": "VERIFIED" if dr_b.status_code in (403, 404) or dr_b.json().get("status") != "success" else "FAIL",
        }
    )

    b_remotes_b_in_a = "10.99.2.2:443" in json.dumps(bl_a)
    b_remotes_a_in_b = "10.99.1.1:443" in json.dumps(bl_b)
    tests.append(
        {
            "test": "baseline tenant isolation remotes",
            "tenant_a_view": bl_a,
            "tenant_b_view": bl_b,
            "b_remote_visible_to_a": b_remotes_b_in_a,
            "a_remote_visible_to_b": b_remotes_a_in_b,
            "verdict": "VERIFIED" if not b_remotes_b_in_a and not b_remotes_a_in_b else "FAIL",
        }
    )

    all_pass = all(t.get("verdict") == "VERIFIED" for t in tests)
    report = {
        "run_id": RUN,
        "captured_at_utc": utc(),
        "fixtures": fixtures,
        "tests": tests,
        "overall": "VERIFIED" if all_pass else "FAIL",
    }
    save = OUT / "TENANT_ISOLATION_NEGATIVE_TEST.json"
    save.parent.mkdir(parents=True, exist_ok=True)
    save.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def main() -> int:
    migrate = ROOT / "migrate_database.py"
    import subprocess

    subprocess.run([sys.executable, str(migrate)], cwd=str(ROOT), check=False)
    report = run_negative_tests()
    print(json.dumps({"overall": report["overall"], "tests": len(report["tests"])}, ensure_ascii=True))
    return 0 if report["overall"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
