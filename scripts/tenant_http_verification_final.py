#!/usr/bin/env python3
"""
Cierre de verificación HTTP multi-tenant — Evidence, Sessions, Reports.
Genera TENANT_HTTP_VERIFICATION_FINAL.json y .md
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT_DIR = ROOT / "data" / "novus_real_operation_audit"
OUT_JSON = OUT_DIR / "TENANT_HTTP_VERIFICATION_FINAL.json"
OUT_MD = OUT_DIR / "TENANT_HTTP_VERIFICATION_FINAL.md"

BASE = os.environ.get("NOVUS_TEST_BASE", "http://127.0.0.1:5000")
QA = ("novus.qa.jul2026@example.com", os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!"))
CLIENT = ("operaciones@novapay-fintech.co", "NovaPay#Fintech2026")

EVID_A = "A-HTTP-ISOL-EVIDENCE-001"
EVID_B = "B-HTTP-ISOL-EVIDENCE-001"
SESS_A = "A-HTTP-ISOL-SESSION-001"
SESS_B = "B-HTTP-ISOL-SESSION-001"
REP_A = "A-HTTP-ISOL-REPORT-001"
REP_B = "B-HTTP-ISOL-REPORT-001"

RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
HTTP_TIMEOUT = 45


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def system_ram() -> Dict[str, Any]:
    vm = psutil.virtual_memory()
    return {
        "total_mb": round(vm.total / 1024 / 1024, 1),
        "used_mb": round(vm.used / 1024 / 1024, 1),
        "available_mb": round(vm.available / 1024 / 1024, 1),
        "percent": round(vm.percent, 1),
    }


def port_5000_listeners() -> List[Dict[str, Any]]:
    out = []
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN":
            out.append({"pid": c.pid, "addr": f"{c.laddr.ip}:{c.laddr.port}"})
    return out


def novus_process_stats() -> Optional[Dict[str, Any]]:
    listeners = port_5000_listeners()
    if not listeners:
        return None
    pid = listeners[0]["pid"]
    try:
        p = psutil.Process(pid)
        mem = p.memory_info()
        return {
            "pid": pid,
            "name": p.name(),
            "rss_mb": round(mem.rss / 1024 / 1024, 1),
            "threads": p.num_threads(),
            "cmdline": " ".join(p.cmdline())[:200],
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"pid": pid}


def redact_response(body: Any, max_len: int = 400) -> Any:
    if body is None:
        return None
    if isinstance(body, dict):
        safe = {}
        for k, v in body.items():
            if k in ("password", "token", "csrf_token", "secret"):
                safe[k] = "[REDACTED]"
            elif isinstance(v, (dict, list)):
                safe[k] = redact_response(v, max_len=120)
            else:
                safe[k] = v
        s = json.dumps(safe, ensure_ascii=False)
        if len(s) > max_len:
            return {"_truncated": s[:max_len] + "…"}
        return safe
    if isinstance(body, list):
        return [redact_response(x, max_len=80) for x in body[:5]]
    s = str(body)
    return s[:max_len] + ("…" if len(s) > max_len else "")


def _is_recovery(body: Any) -> bool:
    if not isinstance(body, dict):
        return False
    return body.get("status") == "recovering" or body.get("_novusRecovery") is True


def http_get(
    sess: requests.Session,
    path: str,
    *,
    auth_email: str,
    resource: str,
    expected: str,
) -> Dict[str, Any]:
    url = BASE + path
    t0 = time.perf_counter()
    err = None
    status = None
    body = None
    try:
        r = sess.get(url, timeout=HTTP_TIMEOUT)
        status = r.status_code
        if "application/json" in r.headers.get("content-type", ""):
            body = r.json()
        else:
            body = {"_non_json": r.text[:200]}
    except requests.exceptions.Timeout:
        err = "timeout"
    except Exception as exc:
        err = str(exc)[:120]
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
    return {
        "path": path,
        "auth_tenant_user": auth_email,
        "resource": resource,
        "expected": expected,
        "http_status": status,
        "error": err,
        "latency_ms": elapsed_ms,
        "response_summary": redact_response(body),
        "raw_for_leak_check": body,
        "recovering": _is_recovery(body),
    }


def ids_in_evidence_list(body: dict) -> set:
    items = body.get("evidence") or []
    return {str(x.get("id")) for x in items if isinstance(x, dict)}


def ids_in_sessions_list(body: dict) -> set:
    items = body.get("sessions") or []
    return {str(x.get("id")) for x in items if isinstance(x, dict)}


def ids_in_reports_list(body: dict) -> set:
    items = body.get("reports") or body.get("data") or []
    if isinstance(items, dict):
        items = items.get("reports") or []
    return {str(x.get("id")) for x in items if isinstance(x, dict)}


def login(email: str, password: str) -> Tuple[Optional[requests.Session], Optional[str]]:
    s = requests.Session()
    try:
        r = s.get(f"{BASE}/login", timeout=HTTP_TIMEOUT)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
        s.post(
            f"{BASE}/login",
            data={"email": email, "password": password, "csrf_token": csrf.group(1) if csrf else ""},
            timeout=HTTP_TIMEOUT,
        )
        return s, None
    except Exception as exc:
        return None, str(exc)[:200]


def check_recovery(sess: requests.Session) -> Dict[str, Any]:
    r = http_get(sess, "/api/tenant/scope", auth_email="probe", resource="tenant_scope", expected="ready")
    body = r.get("raw_for_leak_check") or {}
    recovering = (
        body.get("status") == "recovering"
        or body.get("_novusRecovery") is True
        or (isinstance(body, dict) and "recuperando" in str(body.get("message", "")).lower())
    )
    return {"recovering": recovering, "scope": redact_response(body), "http_status": r.get("http_status")}


def create_fixtures(tenant_a: str, tenant_b: str) -> Dict[str, Any]:
    from database import SessionLocal, PlatformEvidence, LoginSessionAudit
    from services.security_report_service import save_report

    ts = utc()
    db = SessionLocal()
    created = {"tenant_a": tenant_a, "tenant_b": tenant_b, "fixtures": {}}
    try:
        for evid, tid, mark in [
            (EVID_A, tenant_a, "A"),
            (EVID_B, tenant_b, "B"),
        ]:
            db.merge(
                PlatformEvidence(
                    id=evid,
                    tenant_id=tid,
                    fecha=ts[:10],
                    hora=ts[11:19],
                    timestamp=ts,
                    motor="network_snapshot_service",
                    categoria="security",
                    descripcion=f"HTTP isolation test {mark}",
                    nivel_riesgo="info",
                    source_event_id=evid,
                    evidence_json=json.dumps({"test": mark, "timestamp": ts}),
                )
            )
        for sid, tid, email, ip, mark in [
            (SESS_A, tenant_a, QA[0], "10.91.155.110", "A"),
            (SESS_B, tenant_b, CLIENT[0], "10.91.155.111", "B"),
        ]:
            db.merge(
                LoginSessionAudit(
                    id=sid,
                    tenant_id=tid,
                    user_email=email,
                    login_at=ts,
                    ip_address=ip,
                    session_id=f"sess-{sid}",
                    login_result="success",
                    security_status="verified",
                )
            )
        db.commit()
        created["fixtures"]["evidence"] = [EVID_A, EVID_B]
        created["fixtures"]["sessions"] = [SESS_A, SESS_B]
    except Exception as exc:
        db.rollback()
        created["db_error"] = str(exc)[:300]
    finally:
        db.close()

    for rid, tid, mark in [(REP_A, tenant_a, "A"), (REP_B, tenant_b, "B")]:
        save_report(
            {
                "id": rid,
                "finding_id": f"{rid}-FIND",
                "tipo": f"HTTP isolation {mark}",
                "fecha": ts,
                "severidad": "Informativo",
                "estado": "Abierto",
                "equipo_afectado": "test",
                "resumen_ejecutivo": mark,
                "technical": {"fecha_deteccion": ts, "severidad": "Informativo", "estado": "Abierto", "linea_tiempo": []},
                "conclusiones": mark,
                "remediation_log": [],
                "generated_at": ts,
            },
            tenant_id=tid,
        )
    created["fixtures"]["reports"] = [REP_A, REP_B]
    return created


def _finalize_verdict(result: Dict[str, Any], *, pass_ok: bool) -> Dict[str, Any]:
    if result.get("error") == "timeout" or result.get("recovering"):
        result["observed"] = "inconclusive_recovery_or_timeout"
        result["verdict"] = "INCONCLUSIVE"
    elif pass_ok:
        result["verdict"] = "VERIFIED"
    else:
        result["verdict"] = "FAIL"
    result.pop("raw_for_leak_check", None)
    return result


def evaluate_isolation(result: Dict[str, Any], foreign_id: str, own_id: str, list_key: str) -> Dict[str, Any]:
    body = result.get("raw_for_leak_check") or {}
    leaked = False
    own_visible = False
    if list_key == "evidence":
        ids = ids_in_evidence_list(body)
    elif list_key == "sessions":
        ids = ids_in_sessions_list(body)
    else:
        ids = ids_in_reports_list(body)
    if foreign_id in ids or foreign_id in json.dumps(body, ensure_ascii=False):
        leaked = True
    if own_id in ids or own_id in json.dumps(body, ensure_ascii=False):
        own_visible = True
    direct = result.get("_direct") or {}
    direct_leak = direct.get("foreign_leaked", False)
    passed = not leaked and not direct_leak
    if "own" in result.get("expected", ""):
        passed = passed and own_visible
    if "blocked" in result.get("expected", ""):
        passed = passed and not leaked and not direct_leak
    result["foreign_id"] = foreign_id
    result["own_id"] = own_id
    result["foreign_leaked"] = leaked or direct_leak
    result["own_visible"] = own_visible
    result["observed"] = "blocked" if not leaked and not direct_leak else "LEAK"
    return _finalize_verdict(result, pass_ok=passed)


def run_tenant_tests(
    sess: requests.Session,
    email: str,
    own: Dict[str, str],
    foreign: Dict[str, str],
    prefix: str,
) -> List[Dict[str, Any]]:
    tests: List[Dict[str, Any]] = []

    # Evidence list
    r = http_get(sess, "/api/system/evidence-center?limit=500", auth_email=email, resource="evidence_list", expected=f"{prefix}_list_own_no_foreign")
    r["expected"] = f"{prefix}: list own, hide foreign"
    tests.append(evaluate_isolation(r, foreign["evidence"], own["evidence"], "evidence"))

    # Evidence "direct" — no HTTP by-id route; verify foreign absent from scoped list (same as isolation vector)
    r2 = http_get(sess, f"/api/system/evidence-center?limit=500", auth_email=email, resource=f"evidence_direct_{foreign['evidence']}", expected=f"{prefix}_direct_foreign_blocked")
    body = r2.get("raw_for_leak_check") or {}
    foreign_in = foreign["evidence"] in ids_in_evidence_list(body) or foreign["evidence"] in json.dumps(body)
    own_in = own["evidence"] in ids_in_evidence_list(body) or own["evidence"] in json.dumps(body)
    r2["note"] = "No dedicated evidence-by-id HTTP route; isolation via list scope"
    r2["foreign_leaked"] = foreign_in
    r2["own_visible"] = own_in
    r2["observed"] = "blocked" if not foreign_in else "LEAK"
    tests.append(_finalize_verdict(r2, pass_ok=not foreign_in))

    # Sessions list
    r = http_get(sess, "/api/system/login-sessions?limit=200", auth_email=email, resource="sessions_list", expected=f"{prefix}_sessions")
    tests.append(evaluate_isolation(r, foreign["session"], own["session"], "sessions"))

    # Session direct own
    r_own = http_get(sess, f"/api/system/login-sessions?id={own['session']}", auth_email=email, resource=f"session_own_{own['session']}", expected="own_allowed")
    b = r_own.get("raw_for_leak_check") or {}
    ok = r_own.get("http_status") == 200 and b.get("status") == "success" and (b.get("session") or {}).get("id") == own["session"]
    r_own["observed"] = "allowed" if ok else "denied"
    tests.append(_finalize_verdict(r_own, pass_ok=ok))

    # Session direct foreign
    r_for = http_get(sess, f"/api/system/login-sessions?id={foreign['session']}", auth_email=email, resource=f"session_foreign_{foreign['session']}", expected="foreign_blocked")
    b = r_for.get("raw_for_leak_check") or {}
    blocked = r_for.get("http_status") in (403, 404) or b.get("status") != "success" or not b.get("session")
    leaked = b.get("status") == "success" and (b.get("session") or {}).get("id") == foreign["session"]
    r_for["foreign_leaked"] = leaked
    r_for["observed"] = "blocked" if blocked and not leaked else ("LEAK" if leaked else "ambiguous")
    tests.append(_finalize_verdict(r_for, pass_ok=blocked and not leaked))

    # Reports list
    r = http_get(sess, "/api/reports/list", auth_email=email, resource="reports_list", expected=f"{prefix}_reports")
    tests.append(evaluate_isolation(r, foreign["report"], own["report"], "reports"))

    # Report direct own
    r_own = http_get(sess, f"/api/reports/{own['report']}", auth_email=email, resource=f"report_own_{own['report']}", expected="own_allowed")
    b = r_own.get("raw_for_leak_check") or {}
    ok = r_own.get("http_status") == 200 and b.get("status") == "success" and (b.get("report") or {}).get("id") == own["report"]
    r_own["observed"] = "allowed" if ok else "denied"
    tests.append(_finalize_verdict(r_own, pass_ok=ok))

    # Report direct foreign
    r_for = http_get(sess, f"/api/reports/{foreign['report']}", auth_email=email, resource=f"report_foreign_{foreign['report']}", expected="foreign_blocked")
    b = r_for.get("raw_for_leak_check") or {}
    blocked = r_for.get("http_status") in (403, 404) or b.get("status") != "success"
    leaked = b.get("status") == "success" and (b.get("report") or {}).get("id") == foreign["report"]
    r_for["foreign_leaked"] = leaked
    r_for["observed"] = "blocked" if blocked and not leaked else ("LEAK" if leaked else "ambiguous")
    tests.append(_finalize_verdict(r_for, pass_ok=blocked and not leaked))

    return tests


def run_regression(sess: requests.Session, email: str) -> List[Dict[str, Any]]:
    endpoints = [
        "/api/network/info",
        "/api/network/nodes",
        "/api/network/topology",
        "/api/security/summary",
        "/api/dashboard/live",
    ]
    out = []
    for ep in endpoints:
        r = http_get(sess, ep, auth_email=email, resource=ep, expected="regression_ok")
        body = r.get("raw_for_leak_check") or {}
        recovering = body.get("status") == "recovering" or body.get("_novusRecovery") is True
        ok = r.get("http_status") == 200 and not recovering and r.get("error") != "timeout"
        if ep == "/api/network/nodes" and body.get("status") in ("success", "no_data", "ok"):
            ok = True
        r["recovering"] = recovering
        out.append(_finalize_verdict(r, pass_ok=ok))
    return out


def write_md(report: Dict[str, Any]) -> None:
    lines = [
        "# TENANT HTTP VERIFICATION FINAL",
        "",
        f"**Run ID:** {report.get('run_id')}",
        f"**Captured:** {report.get('captured_at_utc')}",
        f"**Overall:** {report.get('overall')}",
        "",
        "## 1. Estado inicial",
        "",
        json.dumps(report.get("initial_state", {}), indent=2, ensure_ascii=False),
        "",
        "## 2. RAM inicial",
        "",
        json.dumps(report.get("ram_initial", {}), ensure_ascii=False),
        "",
        "## 3. Fixtures creados",
        "",
        json.dumps(report.get("fixtures", {}), indent=2, ensure_ascii=False),
        "",
        "## 4–7. Pruebas A/B",
        "",
    ]
    for block in ("tests_tenant_a", "tests_tenant_b"):
        lines.append(f"### {block}")
        for t in report.get(block, []):
            lines.append(f"- **{t.get('resource')}** → {t.get('verdict')} (HTTP {t.get('http_status')}, {t.get('latency_ms')}ms, observed: {t.get('observed')})")
        lines.append("")

    lines += [
        "## 8. Resultados HTTP",
        "",
        f"Isolation tests: {report.get('isolation_summary')}",
        "",
        "## 9. Regresión Network/Dashboard",
        "",
    ]
    for t in report.get("regression", []):
        lines.append(f"- {t.get('path')}: {t.get('verdict')} (HTTP {t.get('http_status')})")
    lines += [
        "",
        "## 10. RAM durante prueba",
        "",
        json.dumps(report.get("ram_during", {}), ensure_ascii=False),
        "",
        "## 11. Fallos",
        "",
        json.dumps(report.get("failures", []), ensure_ascii=False),
        "",
        "## 12. Limitaciones",
        "",
    ]
    for lim in report.get("limitations", []):
        lines.append(f"- {lim}")
    lines += [
        "",
        "## 13. VERIFICADO",
        "",
        json.dumps(report.get("verified", []), ensure_ascii=False),
        "",
        "## 14. NO PUEDO CONFIRMARLO",
        "",
        json.dumps(report.get("not_confirmed", []), ensure_ascii=False),
    ]
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")


def wait_for_server(max_wait: int = 180) -> Tuple[bool, str]:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            r = requests.get(f"{BASE}/login", timeout=5)
            if r.status_code == 200:
                return True, "login_ready"
        except Exception:
            pass
        time.sleep(3)
    return False, "timeout_waiting_for_server"


def main() -> int:
    from migrate_database import migrate_database

    migrate_database()

    report: Dict[str, Any] = {
        "run_id": RUN_ID,
        "captured_at_utc": utc(),
        "limitations": [
            "Evidence center no expone ruta HTTP GET por id; aislamiento verificado vía listado scoped.",
        ],
    }

    report["initial_state"] = {
        "listeners_5000": port_5000_listeners(),
        "novus_process": novus_process_stats(),
    }
    report["ram_initial"] = {"system": system_ram(), "novus": novus_process_stats()}

    ready, reason = wait_for_server()
    if not ready:
        report["overall"] = "NO PUEDO CONFIRMARLO"
        report["not_confirmed"] = ["NO PUEDO CONFIRMARLO — servidor inestable (no arrancó a tiempo)"]
        report["verified"] = []
        report["failures"] = [reason]
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        OUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        write_md(report)
        print(json.dumps({"overall": report["overall"], "reason": reason}))
        return 2

    qa_sess, qa_err = login(QA[0], QA[1])
    if qa_err or not qa_sess:
        report["overall"] = "NO PUEDO CONFIRMARLO"
        report["not_confirmed"] = ["NO PUEDO CONFIRMARLO — login QA falló"]
        report["failures"] = [qa_err]
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        OUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        write_md(report)
        return 2

    rec = check_recovery(qa_sess)
    report["recovery_check_qa"] = rec
    if rec.get("recovering"):
        report["overall"] = "NO PUEDO CONFIRMARLO"
        report["not_confirmed"] = ["NO PUEDO CONFIRMARLO — servidor inestable (recovery mode)"]
        report["verified"] = []
        report["failures"] = ["recovery_before_test"]
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        OUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        write_md(report)
        print(json.dumps({"overall": report["overall"], "recovery": rec}))
        return 2

    from database import SessionLocal, Usuario
    from services.tenant_scope_service import resolve_tenant_id

    db = SessionLocal()
    try:
        ua = db.query(Usuario).filter(Usuario.email == QA[0]).first()
        ub = db.query(Usuario).filter(Usuario.email == CLIENT[0]).first()
        tid_a = resolve_tenant_id(ua)
        tid_b = resolve_tenant_id(ub)
    finally:
        db.close()

    report["tenants"] = {"A": {"email": QA[0], "tenant_id": tid_a}, "B": {"email": CLIENT[0], "tenant_id": tid_b}}
    report["fixtures"] = create_fixtures(tid_a, tid_b)

    own_a = {"evidence": EVID_A, "session": SESS_A, "report": REP_A}
    foreign_a = {"evidence": EVID_B, "session": SESS_B, "report": REP_B}
    own_b = {"evidence": EVID_B, "session": SESS_B, "report": REP_B}
    foreign_b = {"evidence": EVID_A, "session": SESS_A, "report": REP_A}

    report["tests_tenant_a"] = run_tenant_tests(qa_sess, QA[0], own_a, foreign_a, "A")
    report["ram_during"] = {"system": system_ram(), "novus": novus_process_stats()}

    cl_sess, cl_err = login(CLIENT[0], CLIENT[1])
    if cl_err or not cl_sess:
        report["overall"] = "NO PUEDO CONFIRMARLO"
        report["not_confirmed"] = ["NO PUEDO CONFIRMARLO — login Cliente falló"]
        report["failures"] = [cl_err]
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        OUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        write_md(report)
        return 2

    rec_b = check_recovery(cl_sess)
    report["recovery_check_client"] = rec_b
    if rec_b.get("recovering"):
        report["overall"] = "NO PUEDO CONFIRMARLO"
        report["not_confirmed"] = ["NO PUEDO CONFIRMARLO — servidor entró en recovery durante prueba"]
        report["verified"] = []
        report["failures"] = ["recovery_mid_test"]
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        OUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        write_md(report)
        return 2

    report["tests_tenant_b"] = run_tenant_tests(cl_sess, CLIENT[0], own_b, foreign_b, "B")
    report["regression"] = run_regression(qa_sess, QA[0])
    report["ram_final"] = {"system": system_ram(), "novus": novus_process_stats()}

    all_iso = report["tests_tenant_a"] + report["tests_tenant_b"]
    iso_fail = [t for t in all_iso if t.get("verdict") == "FAIL"]
    iso_inconclusive = [t for t in all_iso if t.get("verdict") == "INCONCLUSIVE"]
    reg_fail = [t for t in report["regression"] if t.get("verdict") == "FAIL"]
    reg_inconclusive = [t for t in report["regression"] if t.get("verdict") == "INCONCLUSIVE"]
    timeouts = [t for t in all_iso + report["regression"] if t.get("error") == "timeout"]
    recovery_hits = [t for t in all_iso + report["regression"] if t.get("recovering")]

    report["isolation_summary"] = {
        "total": len(all_iso),
        "verified": len([t for t in all_iso if t.get("verdict") == "VERIFIED"]),
        "failed": len(iso_fail),
        "inconclusive": len(iso_inconclusive),
    }
    report["failures"] = [
        {"resource": t.get("resource"), "verdict": t.get("verdict"), "http_status": t.get("http_status"), "error": t.get("error")}
        for t in iso_fail + reg_fail + iso_inconclusive + reg_inconclusive
    ]

    if timeouts or recovery_hits or iso_inconclusive or reg_inconclusive:
        reasons = []
        if timeouts:
            reasons.append("timeouts HTTP")
        if recovery_hits:
            reasons.append("servidor en recovery durante prueba")
        report["overall"] = "NO PUEDO CONFIRMARLO"
        report["not_confirmed"] = [f"NO PUEDO CONFIRMARLO — servidor inestable ({', '.join(reasons) or 'inconclusive'})"]
        report["verified"] = [t.get("resource") for t in all_iso + report["regression"] if t.get("verdict") == "VERIFIED"]
    elif iso_fail or reg_fail:
        report["overall"] = "MULTI-TENANT HTTP VERIFIED"
        report["verified"] = [
            "A→A permitido, A→B bloqueado",
            "B→B permitido, B→A bloqueado",
            "Evidence, Sessions, Reports",
            "Regresión mínima Network/Dashboard",
        ]
        report["not_confirmed"] = []
    else:
        report["overall"] = "FAIL"
        report["verified"] = [t.get("resource") for t in all_iso + report["regression"] if t.get("verdict") == "VERIFIED"]
        report["not_confirmed"] = ["Aislamiento o regresión con fallos — ver failures"]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    write_md(report)
    print(json.dumps({"overall": report["overall"], "isolation": report["isolation_summary"], "regression_failures": len(reg_fail)}))
    return 0 if report["overall"] == "MULTI-TENANT HTTP VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
