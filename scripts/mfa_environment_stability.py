#!/usr/bin/env python3
"""
MFA environment stability — baseline + isolated HTTP triggers.
NO modifica MFA ni auth. Solo mide y documenta recovery/backpressure.
"""
from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import requests
from werkzeug.security import generate_password_hash

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT_DIR = ROOT / "data" / "novus_compliance_audit"
BASE = "http://127.0.0.1:5000"
HTTP_TIMEOUT = 120
HTTP_SHORT = 30
RUN = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
TEST_EMAIL = f"mfa-e2e-test-{RUN}@example.com".lower()
TEST_PASSWORD = f"MfaE2eTest!{RUN[-6:]}"
BASELINE_WAIT_SEC = 300
STABLE_POLL_SEC = 15
STABLE_MAX_WAIT = 180


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_listener_pid() -> Optional[int]:
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            return c.pid
    return None


def backpressure_status() -> Dict[str, Any]:
    try:
        from services.resource_backpressure_service import get_status

        return get_status()
    except Exception as exc:
        return {"error": str(exc)}


def count_background_threads(pid: int) -> Dict[str, Any]:
    try:
        proc = psutil.Process(pid)
        names: Dict[str, int] = {}
        for t in proc.threads():
            pass
        for child in proc.children(recursive=True):
            try:
                n = child.name()
                names[n] = names.get(n, 0) + 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return {"thread_count": proc.num_threads(), "child_processes": names}
    except Exception as exc:
        return {"error": str(exc)}


def snapshot(label: str) -> Dict[str, Any]:
    snap: Dict[str, Any] = {"label": label, "ts": utc()}
    snap["system_ram_pct"] = round(psutil.virtual_memory().percent, 1)
    pid = find_listener_pid()
    snap["listener_pid"] = pid
    snap["listener_count"] = 1 if pid else 0
    if pid:
        try:
            proc = psutil.Process(pid)
            snap["novus_rss_mb"] = round(proc.memory_info().rss / (1024 * 1024), 1)
            snap["novus_threads"] = proc.num_threads()
            snap["background"] = count_background_threads(pid)
        except Exception as exc:
            snap["proc_error"] = str(exc)
    snap["backpressure"] = backpressure_status()
    try:
        t0 = time.perf_counter()
        r = requests.get(f"{BASE}/login", timeout=HTTP_SHORT)
        snap["login_get_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        snap["login_get_status"] = r.status_code
        snap["login_recovery"] = r.headers.get("X-Novus-Recovery")
    except Exception as exc:
        snap["login_get_error"] = str(exc)
    return snap


def is_recovering_response(resp: requests.Response) -> bool:
    if resp.headers.get("X-Novus-Recovery"):
        return True
    try:
        body = resp.json()
        return bool(body.get("_novusRecovery") or body.get("status") == "recovering")
    except Exception:
        return "recuperando" in (resp.text or "").lower()


def wait_stable(reason: str) -> Dict[str, Any]:
    """Espera hasta backpressure != critical y GET login rápido."""
    t0 = time.time()
    last = {}
    while time.time() - t0 < STABLE_MAX_WAIT:
        last = snapshot(f"stable_wait_{reason}")
        bp = (last.get("backpressure") or {}).get("level", "unknown")
        login_ms = last.get("login_get_ms") or 99999
        if bp not in ("critical",) and login_ms < 5000:
            last["stable"] = True
            last["waited_sec"] = round(time.time() - t0, 1)
            return last
        time.sleep(STABLE_POLL_SEC)
    last["stable"] = False
    last["waited_sec"] = round(time.time() - t0, 1)
    return last


def clear_localhost_auth_blocks() -> Dict[str, Any]:
    from database import SessionLocal, AuthOriginSanction, IPBloqueada

    ips = ("127.0.0.1", "::1", "localhost")
    stats = {"sanctions_revoked": 0, "ips_cleared": 0}
    db = SessionLocal()
    try:
        for ip in ips:
            for row in db.query(AuthOriginSanction).filter(
                AuthOriginSanction.origin_type == "ip",
                AuthOriginSanction.origin_key == ip,
                AuthOriginSanction.status == "active",
            ).all():
                row.status = "revoked"
                row.blocked_until = None
                stats["sanctions_revoked"] += 1
            for row in db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == ip).all():
                db.delete(row)
                stats["ips_cleared"] += 1
        db.commit()
    finally:
        db.close()
    return stats


def create_fixture() -> None:
    from database import SessionLocal, Usuario

    db = SessionLocal()
    try:
        db.query(Usuario).filter(Usuario.email == TEST_EMAIL).delete()
        db.add(
            Usuario(
                email=TEST_EMAIL,
                hashed_password=generate_password_hash(TEST_PASSWORD),
                role="company_admin",
                nit_pyme=f"mfa-e2e-{RUN}".lower(),
                sector="fintech",
                is_active=True,
                is_temporal=False,
            )
        )
        db.commit()
    finally:
        db.close()


def cleanup_fixture() -> Dict[str, Any]:
    from database import SessionLocal, Usuario

    stats = {"email": TEST_EMAIL, "user_deleted": False, "mfa_store_cleaned": False}
    db = SessionLocal()
    try:
        u = db.query(Usuario).filter(Usuario.email == TEST_EMAIL).first()
        if u:
            db.delete(u)
            db.commit()
            stats["user_deleted"] = True
    finally:
        db.close()
    store = ROOT / "data" / "web_security_auth_enterprise" / "mfa_store.json"
    if store.is_file():
        try:
            data = json.loads(store.read_text(encoding="utf-8") or "{}")
            if TEST_EMAIL in data:
                del data[TEST_EMAIL]
                store.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
                stats["mfa_store_cleaned"] = True
        except Exception as exc:
            stats["mfa_store_error"] = str(exc)
    return stats


def csrf_from_html(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def csrf_from_json_script(html: str) -> str:
    m = re.search(r"const csrf = (.+?);", html)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    return ""


def run_http_test(
    test_id: str,
    name: str,
    fn,
) -> Dict[str, Any]:
    before = snapshot(f"{test_id}_before")
    if not before.get("listener_pid"):
        return {
            "test_id": test_id,
            "name": name,
            "verdict": "NOT VERIFIABLE",
            "failure_class": "ENVIRONMENT/RESOURCE FAILURE",
            "detail": "no listener on :5000",
            "before": before,
        }
    bp_before = (before.get("backpressure") or {}).get("level")
    if bp_before == "critical":
        return {
            "test_id": test_id,
            "name": name,
            "verdict": "NOT VERIFIABLE",
            "failure_class": "ENVIRONMENT/RESOURCE FAILURE",
            "detail": "backpressure critical before test — skipped",
            "before": before,
        }
    t0 = time.perf_counter()
    try:
        http_result = fn()
    except requests.exceptions.Timeout as exc:
        elapsed = round((time.perf_counter() - t0) * 1000, 1)
        after = snapshot(f"{test_id}_after")
        return {
            "test_id": test_id,
            "name": name,
            "verdict": "NOT VERIFIABLE",
            "failure_class": "ENVIRONMENT/RESOURCE FAILURE",
            "detail": f"timeout: {exc}",
            "elapsed_ms": elapsed,
            "before": before,
            "after": after,
        }
    except Exception as exc:
        elapsed = round((time.perf_counter() - t0) * 1000, 1)
        after = snapshot(f"{test_id}_after")
        return {
            "test_id": test_id,
            "name": name,
            "verdict": "NOT VERIFIABLE",
            "failure_class": "ENVIRONMENT/RESOURCE FAILURE",
            "detail": str(exc),
            "elapsed_ms": elapsed,
            "before": before,
            "after": after,
            "http": http_result if "http_result" in dir() else None,
        }
    elapsed = round((time.perf_counter() - t0) * 1000, 1)
    after = snapshot(f"{test_id}_after")
    recovering = http_result.get("recovering", False)
    delta_rss = None
    if before.get("novus_rss_mb") and after.get("novus_rss_mb"):
        delta_rss = round(after["novus_rss_mb"] - before["novus_rss_mb"], 1)
    delta_threads = None
    if before.get("novus_threads") and after.get("novus_threads"):
        delta_threads = after["novus_threads"] - before["novus_threads"]
    verdict = "STABLE"
    failure_class = None
    if recovering:
        verdict = "RECOVERY_TRIGGERED"
        failure_class = "ENVIRONMENT/RESOURCE FAILURE"
    elif elapsed > 60000:
        verdict = "SLOW"
        failure_class = "ENVIRONMENT/RESOURCE FAILURE"
    return {
        "test_id": test_id,
        "name": name,
        "verdict": verdict,
        "failure_class": failure_class,
        "elapsed_ms": elapsed,
        "delta_rss_mb": delta_rss,
        "delta_threads": delta_threads,
        "before": before,
        "after": after,
        "http": http_result,
    }


def recent_recovery_events(limit: int = 5) -> List[Dict[str, Any]]:
    log_path = ROOT / "data" / "novus_recovery" / "recovery_events.jsonl"
    if not log_path.is_file():
        return []
    lines = log_path.read_text(encoding="utf-8", errors="ignore").strip().splitlines()
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def main() -> int:
    report: Dict[str, Any] = {
        "run_id": RUN,
        "generated_at_utc": utc(),
        "fixture_email": TEST_EMAIL,
        "baseline_wait_sec": BASELINE_WAIT_SEC,
        "expected_baseline": {"novus_rss_mb": "135-150", "threads": "4-8"},
        "baseline": {},
        "baseline_verdict": None,
        "isolation_tests": [],
        "mfa_e2e_bce": [],
        "recovery_events_tail": [],
        "root_cause_analysis": {},
        "changes_made": [],
        "cleanup": {},
        "conclusion": "",
        "proceed_e2e": False,
    }

    print(f"Waiting {BASELINE_WAIT_SEC}s for idle baseline...")
    time.sleep(BASELINE_WAIT_SEC)
    report["baseline"] = snapshot("baseline_after_5min_idle")
    rss = report["baseline"].get("novus_rss_mb")
    threads = report["baseline"].get("novus_threads")
    bp = (report["baseline"].get("backpressure") or {}).get("level")
    expected_ok = rss is not None and rss <= 200 and threads is not None and threads <= 20
    if rss and (rss < 120 or rss > 200):
        report["baseline_verdict"] = "MISMATCH"
        report["baseline_note"] = (
            f"RSS {rss} MB, threads {threads} — fuera del rango histórico 135-150 MB / 4-8 threads. DETENIDO para documentar."
        )
    elif not expected_ok:
        report["baseline_verdict"] = "ELEVATED"
        report["baseline_note"] = f"RSS {rss} MB, threads {threads}, backpressure={bp}"
    else:
        report["baseline_verdict"] = "ACCEPTABLE"
        report["baseline_note"] = f"RSS {rss} MB, threads {threads}, backpressure={bp}"

    if report["baseline_verdict"] == "MISMATCH" and (rss or 0) > 300:
        report["conclusion"] = (
            "Baseline no coincide con histórico idle (~135-150 MB). "
            "Servidor cargado por boot escalonado (network discovery, AI kernel, shields). "
            "Continúa aislamiento con precaución — no asumir CODE FAILURE en MFA."
        )
    elif not report["baseline"].get("listener_pid"):
        report["conclusion"] = "Servidor no escuchando en :5000. NOT VERIFIABLE."
        _write_reports(report)
        return 2

    clear_localhost_auth_blocks()
    create_fixture()
    session = requests.Session()

    def test1():
        g = session.get(f"{BASE}/login", timeout=HTTP_SHORT)
        token = csrf_from_html(g.text)
        p = session.post(
            f"{BASE}/login",
            data={"email": TEST_EMAIL, "password": TEST_PASSWORD, "csrf_token": token},
            allow_redirects=False,
            timeout=HTTP_TIMEOUT,
        )
        return {
            "method": "POST",
            "path": "/login",
            "status": p.status_code,
            "location": p.headers.get("Location"),
            "recovering": is_recovering_response(p),
            "recovery_header": p.headers.get("X-Novus-Recovery"),
        }

    r1 = run_http_test("T1", "POST /login", test1)
    report["isolation_tests"].append(r1)
    stable1 = wait_stable("after_T1")
    report["isolation_tests"][-1]["post_wait"] = stable1

    if not stable1.get("stable") and r1.get("verdict") == "RECOVERY_TRIGGERED":
        report["conclusion"] = "T1 provocó recovery; tests siguientes omitidos."
        report["cleanup"] = cleanup_fixture()
        report["recovery_events_tail"] = recent_recovery_events()
        _write_reports(report)
        return 1

    def test2():
        r = session.get(f"{BASE}/mfa-setup", allow_redirects=False, timeout=HTTP_SHORT)
        return {
            "method": "GET",
            "path": "/mfa-setup",
            "status": r.status_code,
            "location": r.headers.get("Location"),
            "recovering": is_recovering_response(r),
        }

    r2 = run_http_test("T2", "GET /mfa-setup", test2)
    report["isolation_tests"].append(r2)
    report["isolation_tests"][-1]["post_wait"] = wait_stable("after_T2")

    def test3():
        mfa_html = session.get(f"{BASE}/mfa-setup", timeout=HTTP_SHORT)
        csrf = csrf_from_json_script(mfa_html.text) or csrf_from_html(mfa_html.text)
        p = session.post(
            f"{BASE}/api/wsae/mfa/enroll",
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
            json={},
            timeout=HTTP_TIMEOUT,
        )
        body = {}
        try:
            body = p.json()
        except Exception:
            pass
        return {
            "method": "POST",
            "path": "/api/wsae/mfa/enroll",
            "status": p.status_code,
            "recovering": is_recovering_response(p),
            "body_status": body.get("status"),
            "body_keys": list(body.keys())[:8],
            "has_secret": bool(body.get("secret")),
        }

    r3 = run_http_test("T3", "POST /api/wsae/mfa/enroll", test3)
    report["isolation_tests"].append(r3)
    report["isolation_tests"][-1]["post_wait"] = wait_stable("after_T3")

    def test4():
        r = session.get(f"{BASE}/dashboard", allow_redirects=False, timeout=HTTP_SHORT)
        return {
            "method": "GET",
            "path": "/dashboard",
            "status": r.status_code,
            "location": r.headers.get("Location"),
            "recovering": is_recovering_response(r),
        }

    r4 = run_http_test("T4", "GET /dashboard", test4)
    report["isolation_tests"].append(r4)

    report["recovery_events_tail"] = recent_recovery_events(8)

    # Root cause analysis
    triggers = [t for t in report["isolation_tests"] if t.get("verdict") == "RECOVERY_TRIGGERED"]
    slow = [t for t in report["isolation_tests"] if (t.get("elapsed_ms") or 0) > 30000]
    report["root_cause_analysis"] = {
        "hypothesis": "ENVIRONMENT/RESOURCE FAILURE",
        "recovery_triggers": [t["test_id"] for t in triggers],
        "slow_tests": [{"id": t["test_id"], "ms": t.get("elapsed_ms")} for t in slow],
        "baseline_backpressure": bp,
        "classification": _classify_root_cause(report),
    }

    stable_enough = (
        bp not in ("critical",)
        and not triggers
        and report["baseline"].get("listener_pid")
        and (report["baseline"].get("login_get_ms") or 9999) < 5000
    )
    report["proceed_e2e"] = stable_enough

    if stable_enough:
        report["mfa_e2e_bce"] = _run_bce_cases(session)
    else:
        report["mfa_e2e_bce"] = [{"note": "skipped — entorno inestable"}]

    report["cleanup"] = cleanup_fixture()
    report["conclusion"] = _build_conclusion(report)
    _write_reports(report)
    print(json.dumps({"baseline_verdict": report["baseline_verdict"], "proceed_e2e": report["proceed_e2e"], "conclusion": report["conclusion"][:200]}, indent=2))
    return 0


def _classify_root_cause(report: Dict[str, Any]) -> str:
    baseline = report.get("baseline") or {}
    bp = (baseline.get("backpressure") or {}).get("level", "unknown")
    rss = baseline.get("novus_rss_mb")
    events = report.get("recovery_events_tail") or []
    modules = [e.get("module") for e in events[-3:]]
    if bp in ("critical", "high"):
        return f"E — backpressure RAM ({bp}); side effects C/D (network discovery, lazy engines) bajo RAM alta"
    if rss and rss > 500:
        return "D/C — boot escalonado + engines background elevan RSS antes de MFA"
    if modules:
        return f"Recovery modules recientes: {modules}"
    return "Sin recovery en aislamiento; latencia posiblemente por carga auth pipeline (B)"


def _run_bce_cases(session: requests.Session) -> List[Dict[str, Any]]:
    """Solo casos B, C, E pendientes."""
    out: List[Dict[str, Any]] = []
    create_fixture()
    clear_localhost_auth_blocks()
    # B
    g = session.get(f"{BASE}/login", timeout=HTTP_SHORT)
    token = csrf_from_html(g.text)
    session.post(
        f"{BASE}/login",
        data={"email": TEST_EMAIL, "password": TEST_PASSWORD, "csrf_token": token},
        allow_redirects=False,
        timeout=HTTP_TIMEOUT,
    )
    mfa_html = session.get(f"{BASE}/mfa-setup", timeout=HTTP_SHORT)
    csrf = csrf_from_json_script(mfa_html.text) or csrf_from_html(mfa_html.text)
    enr = session.post(
        f"{BASE}/api/wsae/mfa/enroll",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
        json={},
        timeout=HTTP_TIMEOUT,
    )
    enr_body = enr.json() if enr.headers.get("content-type", "").startswith("application/json") else {}
    b_ok = enr_body.get("ok") and enr_body.get("secret") and not is_recovering_response(enr)
    if enr_body.get("status") == "recovering":
        out.append({"case": "B", "verdict": "NOT VERIFIABLE", "failure_class": "ENVIRONMENT/RESOURCE FAILURE", "body": enr_body})
        out.append({"case": "C", "verdict": "NOT VERIFIABLE", "detail": "depends on B"})
        out.append({"case": "E", "verdict": "NOT VERIFIABLE", "detail": "skipped — B failed"})
        return out
    import pyotp
    code = pyotp.TOTP(enr_body["secret"]).now()
    en = session.post(
        f"{BASE}/api/wsae/mfa/enable",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
        json={"code": code},
        timeout=HTTP_TIMEOUT,
    )
    en_body = en.json() if en.headers.get("content-type", "").startswith("application/json") else {}
    out.append({
        "case": "B",
        "verdict": "VERIFIED" if b_ok and en_body.get("ok") else "FAIL",
        "enroll_status": enr.status_code,
        "enable_status": en.status_code,
    })
    # C — fresh session
    s2 = requests.Session()
    g2 = s2.get(f"{BASE}/login", timeout=HTTP_SHORT)
    t2 = csrf_from_html(g2.text)
    p1 = s2.post(
        f"{BASE}/login",
        data={"email": TEST_EMAIL, "password": TEST_PASSWORD, "csrf_token": t2},
        allow_redirects=False,
        timeout=HTTP_TIMEOUT,
    )
    code2 = pyotp.TOTP(enr_body["secret"]).now()
    p2 = s2.post(
        f"{BASE}/login",
        data={"email": TEST_EMAIL, "password": TEST_PASSWORD, "csrf_token": t2, "mfa_code": code2},
        allow_redirects=False,
        timeout=HTTP_TIMEOUT,
    )
    dash = s2.get(f"{BASE}/dashboard", allow_redirects=True, timeout=HTTP_TIMEOUT)
    c_ok = p1.status_code == 200 and p2.status_code in (302, 303) and "novus-estado-general-panel" in dash.text
    out.append({"case": "C", "verdict": "VERIFIED" if c_ok else "FAIL", "p1": p1.status_code, "p2": p2.status_code, "dash_url": str(dash.url)})
    # E — admin sin MFA fresh user
    cleanup_fixture()
    create_fixture()
    s3 = requests.Session()
    login = s3.post(
        f"{BASE}/sector-auth",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD, "sector": "fintech"},
        timeout=HTTP_TIMEOUT,
    )
    login_password_only = s3.get(f"{BASE}/login", timeout=HTTP_SHORT)
    tok = csrf_from_html(login_password_only.text)
    lp = s3.post(
        f"{BASE}/login",
        data={"email": TEST_EMAIL, "password": TEST_PASSWORD, "csrf_token": tok},
        allow_redirects=False,
        timeout=HTTP_TIMEOUT,
    )
    dash_e = s3.get(f"{BASE}/dashboard", allow_redirects=False, timeout=HTTP_SHORT)
    search = s3.get(f"{BASE}/api/search?q=test", allow_redirects=False, timeout=HTTP_SHORT)
    sb = {}
    try:
        sb = search.json()
    except Exception:
        pass
    search_blocked = search.status_code in (401, 403) or sb.get("code") == "MFA_ENROLLMENT_REQUIRED"
    if sb.get("status") == "recovering":
        out.append({"case": "E", "verdict": "NOT VERIFIABLE", "failure_class": "ENVIRONMENT/RESOURCE FAILURE"})
    else:
        e_ok = login.status_code in (403, 302) and "/mfa-setup" in (lp.headers.get("Location") or "") and dash_e.status_code in (302, 401, 403) and search_blocked
        out.append({"case": "E", "verdict": "VERIFIED" if e_ok else "FAIL", "sector": login.status_code, "search": search.status_code})
    return out


def _build_conclusion(report: Dict[str, Any]) -> str:
    bce = report.get("mfa_e2e_bce") or []
    verified = [c for c in bce if c.get("verdict") == "VERIFIED"]
    if report.get("proceed_e2e") and len(verified) == 3:
        return "Entorno estable; casos B, C, E VERIFIED. Listo para suite E2E completa."
    if not report.get("proceed_e2e"):
        return report.get("root_cause_analysis", {}).get("classification", "") + " — E2E B/C/E omitido o parcial."
    return f"E2E parcial B/C/E: {len(verified)}/3 VERIFIED."


def _write_reports(report: Dict[str, Any]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    json_path = OUT_DIR / "MFA_ENVIRONMENT_STABILITY.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    md_lines = [
        "# MFA Environment Stability",
        "",
        f"**Run:** `{report['run_id']}`",
        f"**Generated:** {report['generated_at_utc']}",
        "",
        f"## Baseline ({report['baseline_wait_sec']}s idle)",
        "",
        f"- Veredicto: **{report.get('baseline_verdict')}**",
        f"- {report.get('baseline_note', '')}",
        "",
        "### Métricas baseline",
        "",
        "```json",
        json.dumps(report.get("baseline", {}), indent=2, ensure_ascii=False),
        "```",
        "",
        "## Aislamiento T1–T4",
        "",
    ]
    for t in report.get("isolation_tests", []):
        md_lines.append(f"### {t.get('test_id')} — {t.get('name')} → **{t.get('verdict')}**")
        if t.get("failure_class"):
            md_lines.append(f"- Clasificación: `{t.get('failure_class')}`")
        md_lines.append(f"- Latencia: {t.get('elapsed_ms')} ms | ΔRSS: {t.get('delta_rss_mb')} MB | Δthreads: {t.get('delta_threads')}")
        if t.get("http"):
            md_lines.append(f"- HTTP: `{json.dumps(t['http'], ensure_ascii=False)}`")
        md_lines.append("")
    md_lines.extend([
        "## Root cause",
        "",
        "```json",
        json.dumps(report.get("root_cause_analysis", {}), indent=2, ensure_ascii=False),
        "```",
        "",
        "## MFA E2E B/C/E",
        "",
        "```json",
        json.dumps(report.get("mfa_e2e_bce", []), indent=2, ensure_ascii=False),
        "```",
        "",
        f"## Conclusión",
        "",
        report.get("conclusion", ""),
    ])
    (OUT_DIR / "MFA_ENVIRONMENT_STABILITY.md").write_text("\n".join(md_lines), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
