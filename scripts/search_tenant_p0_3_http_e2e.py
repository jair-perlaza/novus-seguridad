#!/usr/bin/env python3
"""
P0-3 HTTP E2E verification ONLY — harness fix for authenticated :5000.
Does NOT modify production P0-3 files.
TEST_FIXTURE / SYNTHETIC_TEST_ONLY — never LIVE.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "production_closure" / "search_tenant_p0_3"
OUT.mkdir(parents=True, exist_ok=True)

BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000").rstrip("/")
MARKER = uuid.uuid4().hex[:8].upper()
TENANT_A = f"P03E2E-A-{MARKER}"
TENANT_B = f"P03E2E-B-{MARKER}"
EMAIL_A = f"p03e2e.a.{MARKER.lower()}@novus-client.test"
EMAIL_B = f"p03e2e.b.{MARKER.lower()}@novus-client.test"
PASS = "NovusP03E2e2026!"
TITLE_A = f"P03E2E-ALERT-A-{MARKER}"
TITLE_B = f"P03E2E-ALERT-B-{MARKER}"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def chk(name: str, ok: bool, **detail) -> Dict[str, Any]:
    return {"id": name, "ok": bool(ok), "result": "PASS" if ok else "FAIL", **detail}


def _cookie_names(session) -> List[str]:
    try:
        return sorted({c.name for c in session.cookies})
    except Exception:
        return []


def diagnose_401() -> Dict[str, Any]:
    """Classify prior 401 without secrets."""
    import requests

    out: Dict[str, Any] = {
        "generated_at_utc": utc(),
        "base": BASE,
        "auth_mechanism": "Flask-Login session cookie + CSRF form token + _novus_login_session_id",
        "login_endpoint": f"{BASE}/login",
        "search_endpoints": [f"{BASE}/api/search", f"{BASE}/api/system/search"],
        "classification": [],
        "evidence": {},
    }
    s = requests.Session()
    t0 = time.perf_counter()
    r = s.get(f"{BASE}/login", timeout=90)
    out["evidence"]["GET_/login"] = {
        "status": r.status_code,
        "ms": round((time.perf_counter() - t0) * 1000, 1),
        "csrf_field_present": 'name="csrf_token"' in (r.text or ""),
        "cookie_names": _cookie_names(s),
    }
    # Unauth search — expected 401
    t1 = time.perf_counter()
    ru = s.get(f"{BASE}/api/search", params={"q": "probe"}, timeout=45)
    out["evidence"]["GET_/api/search_unauth"] = {
        "status": ru.status_code,
        "ms": round((time.perf_counter() - t1) * 1000, 1),
        "message": (ru.json() if ru.headers.get("content-type", "").startswith("application/json") else {}).get("message")
        if ru.status_code else None,
    }
    try:
        msg = ru.json().get("message")
    except Exception:
        msg = (ru.text or "")[:80]
    out["evidence"]["GET_/api/search_unauth"]["message"] = msg

    # Prior harness failure modes
    out["prior_harness_analysis"] = {
        "first_attempts_without_csrf": "Would fail login POST (403 CSRF) → no session → /api/search 401",
        "urllib_without_csrf_cookie_jar_issues": "Class C — incomplete cookie/CSRF handling",
        "flask_test_client_login_without_csrf": "Class C — CSRF not posted → no session → 401",
        "admin_role_triggers_mfa_enroll": "Would leave session without full _novus_login_session_id API access",
        "expected_unauth_401": "Class D — NOVUS correctly rejects unauthenticated API",
    }
    # Primary classification for observed prior 401 on authenticated tests:
    out["classification"] = [
        {
            "code": "C",
            "label": "Harness did not maintain cookie/session/CSRF correctly (and/or used admin→MFA path)",
            "primary": True,
        },
        {
            "code": "D",
            "label": "Unauthenticated /api/search correctly returns 401",
            "primary": False,
            "confirmed_now": ru.status_code == 401,
        },
    ]
    out["not_novus_auth_bug_without_further_evidence"] = True
    return out


def setup_fixtures() -> Dict[str, Any]:
    from database import SessionLocal, Usuario, Alerta
    from werkzeug.security import generate_password_hash

    db = SessionLocal()
    created: Dict[str, Any] = {"users": [], "alerts": [], "TEST_FIXTURE": True, "SYNTHETIC_TEST_ONLY": True}
    try:
        for email, tid in ((EMAIL_A, TENANT_A), (EMAIL_B, TENANT_B)):
            u = db.query(Usuario).filter(Usuario.email == email).first()
            if not u:
                u = Usuario(
                    email=email,
                    hashed_password=generate_password_hash(PASS),
                    is_active=True,
                    nit_pyme=tid,
                    sector="fintech",
                    role="analyst",  # avoid MFA-mandatory admin roles
                )
                db.add(u)
                db.commit()
                db.refresh(u)
            else:
                u.nit_pyme = tid
                u.role = "analyst"
                u.is_active = True
                u.hashed_password = generate_password_hash(PASS)
                db.commit()
            created["users"].append({"email": email, "tenant_id": tid, "id": u.id, "role": "analyst"})

        for title, tid in ((TITLE_A, TENANT_A), (TITLE_B, TENANT_B)):
            # Do NOT put QA_CONTENT_MARKERS (TEST_FIXTURE/SYNTHETIC_TEST_ONLY) in
            # titulo/descripcion — /api/search runs filter_lab_search_results and
            # would strip them in beta/production. Fixture identity is harness metadata + title prefix.
            a = Alerta(
                tenant_id=tid,
                titulo=title,
                descripcion=f"P03E2E isolation probe tenant={tid} marker={MARKER}",
                nivel="medio",
                fecha=datetime.now(timezone.utc).replace(tzinfo=None),
                activa=True,
            )
            db.add(a)
            db.commit()
            db.refresh(a)
            created["alerts"].append({"id": a.id, "titulo": title, "tenant_id": tid})
    finally:
        db.close()
    return created


def cleanup_fixtures(created: Dict[str, Any]) -> None:
    from database import SessionLocal, Usuario, Alerta

    db = SessionLocal()
    try:
        ids = [a["id"] for a in created.get("alerts") or []]
        if ids:
            db.query(Alerta).filter(Alerta.id.in_(ids)).delete(synchronize_session=False)
        for u in created.get("users") or []:
            db.query(Usuario).filter(Usuario.id == u["id"]).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def login(email: str) -> Tuple[Any, Dict[str, Any]]:
    import requests

    s = requests.Session()
    meta: Dict[str, Any] = {"email": email, "ok": False}
    t0 = time.perf_counter()
    r = s.get(f"{BASE}/login", timeout=90)
    meta["get_login_status"] = r.status_code
    meta["get_login_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text or "")
    if not m:
        meta["detail"] = "csrf_missing"
        return s, meta
    meta["csrf_obtained"] = True
    meta["csrf_token_len"] = len(m.group(1))
    t1 = time.perf_counter()
    r2 = s.post(
        f"{BASE}/login",
        data={"email": email, "password": PASS, "csrf_token": m.group(1)},
        timeout=90,
        allow_redirects=True,
    )
    meta["post_login_ms"] = round((time.perf_counter() - t1) * 1000, 1)
    meta["post_status"] = r2.status_code
    meta["final_url"] = str(r2.url)[:200]
    text_l = (r2.text or "").lower()
    meta["mfa_required"] = "mfa_required" in text_l or "/mfa" in str(r2.url).lower()
    meta["cookie_names"] = _cookie_names(s)
    # Successful full login: landed on dashboard (or 200 HTML) without MFA gate
    meta["ok"] = (
        r2.status_code == 200
        and not meta["mfa_required"]
        and ("dashboard" in str(r2.url).lower() or "novus" in text_l[:500] or len(meta["cookie_names"]) > 0)
    )
    # Stronger check: authenticated API works
    probe = s.get(f"{BASE}/api/search", params={"q": "ping"}, timeout=90)
    meta["probe_search_status"] = probe.status_code
    # Full success for tenanted users requires 200; missing-tenant probes use 403 separately
    meta["ok"] = meta["ok"] and probe.status_code == 200
    if probe.status_code == 200:
        try:
            meta["probe_tenant_id"] = probe.json().get("tenant_id")
        except Exception:
            pass
    elif probe.status_code in (401, 403):
        try:
            pj = probe.json()
            meta["probe_message"] = str(pj.get("message") or "")[:120]
            meta["probe_code"] = pj.get("code") or pj.get("error")
        except Exception:
            meta["probe_message"] = (probe.text or "")[:120]
    return s, meta


def search(session, q: str, path: str = "/api/search") -> Dict[str, Any]:
    t0 = time.perf_counter()
    try:
        resp = session.get(f"{BASE}{path}", params={"q": q, "limit": 50}, timeout=120)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        try:
            body = resp.json()
        except Exception:
            body = {"raw": (resp.text or "")[:400]}
        return {"status": resp.status_code, "ms": ms, "body": body, "path": path, "error": None}
    except Exception as exc:
        return {
            "status": None,
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "body": {},
            "path": path,
            "error": str(exc)[:160],
        }


def results_blob(payload: Dict[str, Any]) -> str:
    body = payload.get("body") or {}
    return json.dumps({"results": body.get("results"), "count": body.get("count"), "tenant_id": body.get("tenant_id")}, ensure_ascii=False)


def resources() -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        import psutil

        out["harness_rss_mb"] = round(psutil.Process(os.getpid()).memory_info().rss / 1e6, 2)
        out["harness_threads"] = psutil.Process(os.getpid()).num_threads()
        novus = []
        for p in psutil.process_iter(["pid", "name", "cmdline", "memory_info", "num_threads"]):
            try:
                cmd = " ".join(p.info.get("cmdline") or [])
                if "main.py" in cmd or (p.info.get("name") or "").lower().startswith("python"):
                    if "main.py" in cmd:
                        mi = p.info.get("memory_info")
                        novus.append(
                            {
                                "pid": p.info.get("pid"),
                                "rss_mb": round((mi.rss if mi else 0) / 1e6, 2),
                                "threads": p.info.get("num_threads"),
                            }
                        )
            except Exception:
                continue
        out["novus_processes"] = novus
    except Exception as exc:
        out["error"] = str(exc)[:120]
    return out


def run_e2e(created: Dict[str, Any]) -> Dict[str, Any]:
    import requests

    checks: List[Dict[str, Any]] = []
    alert_a_id = created["alerts"][0]["id"]
    alert_b_id = created["alerts"][1]["id"]

    sess_a, meta_a = login(EMAIL_A)
    sess_b, meta_b = login(EMAIL_B)
    checks.append(chk("login_a", meta_a.get("ok") is True, meta={k: v for k, v in meta_a.items() if k != "email"}))
    checks.append(chk("login_b", meta_b.get("ok") is True, meta={k: v for k, v in meta_b.items() if k != "email"}))

    if not (meta_a.get("ok") and meta_b.get("ok")):
        return {
            "checks": checks,
            "blocked_reason": "login_failed",
            "meta_a": {k: v for k, v in meta_a.items() if "password" not in k.lower()},
            "meta_b": {k: v for k, v in meta_b.items() if "password" not in k.lower()},
        }

    # A → A
    ra = search(sess_a, TITLE_A, "/api/search")
    blob_a = results_blob(ra)
    checks.append(
        chk(
            "http_api_search_a_to_a",
            ra["status"] == 200 and TITLE_A in blob_a and TITLE_B not in blob_a,
            status=ra["status"],
            ms=ra["ms"],
            count=(ra["body"] or {}).get("count"),
            tenant_id=(ra["body"] or {}).get("tenant_id"),
            message=str((ra["body"] or {}).get("message") or "")[:120],
            ids=[r.get("id") for r in ((ra["body"] or {}).get("results") or [])],
            names=[r.get("name") for r in ((ra["body"] or {}).get("results") or [])][:10],
            error=ra.get("error"),
        )
    )
    # B → B
    rb = search(sess_b, TITLE_B, "/api/search")
    checks.append(
        chk(
            "http_api_search_b_to_b",
            rb["status"] == 200 and TITLE_B in results_blob(rb) and TITLE_A not in results_blob(rb),
            status=rb["status"],
            ms=rb["ms"],
            count=(rb["body"] or {}).get("count"),
            tenant_id=(rb["body"] or {}).get("tenant_id"),
        )
    )
    # A → B
    ra_cross = search(sess_a, TITLE_B, "/api/search")
    checks.append(
        chk(
            "http_api_search_a_to_b",
            TITLE_B not in results_blob(ra_cross) and f"alert-{alert_b_id}" not in results_blob(ra_cross),
            status=ra_cross["status"],
            ms=ra_cross["ms"],
            ids=[r.get("id") for r in ((ra_cross["body"] or {}).get("results") or [])],
        )
    )
    # B → A
    rb_cross = search(sess_b, TITLE_A, "/api/search")
    checks.append(
        chk(
            "http_api_search_b_to_a",
            TITLE_A not in results_blob(rb_cross) and f"alert-{alert_a_id}" not in results_blob(rb_cross),
            status=rb_cross["status"],
            ms=rb_cross["ms"],
        )
    )
    # Alert specific (same as above titles)
    checks.append(chk("alert_a_search_b", TITLE_A not in results_blob(rb_cross)))
    checks.append(chk("alert_b_search_a", TITLE_B not in results_blob(ra_cross)))

    # system search
    sa = search(sess_a, TITLE_A, "/api/system/search")
    sb = search(sess_b, TITLE_A, "/api/system/search")
    checks.append(
        chk(
            "http_system_search_a_to_a",
            sa["status"] == 200 and TITLE_A in results_blob(sa),
            status=sa["status"],
            ms=sa["ms"],
        )
    )
    checks.append(
        chk(
            "http_system_search_b_to_a",
            TITLE_A not in results_blob(sb),
            status=sb["status"],
            ms=sb["ms"],
        )
    )

    # Direct ID probe
    by_id = search(sess_b, str(alert_a_id), "/api/search")
    checks.append(
        chk(
            "direct_id_b_to_a",
            f"alert-{alert_a_id}" not in results_blob(by_id) and TITLE_A not in results_blob(by_id),
            status=by_id["status"],
            ids=[r.get("id") for r in ((by_id["body"] or {}).get("results") or [])],
        )
    )

    # Cache sequence (reuse prior responses when possible to reduce load)
    checks.append(
        chk(
            "cache_isolation",
            TITLE_A in results_blob(ra)
            and TITLE_A not in results_blob(rb_cross)
            and TITLE_B in results_blob(rb)
            and TITLE_B not in results_blob(ra_cross),
            note="validated from A→A/B→B/cross responses (same query keys)",
        )
    )

    # Missing auth — unauthenticated
    bare = requests.get(f"{BASE}/api/search", params={"q": TITLE_A}, timeout=30)
    checks.append(chk("missing_auth_denied", bare.status_code in (401, 403), status=bare.status_code))

    # Missing canonical tenant — authenticated analyst without nit_pyme/company_id
    no_tenant_meta = _probe_missing_tenant()
    checks.append(
        chk(
            "missing_tenant_denied",
            no_tenant_meta.get("ok") is True,
            status=no_tenant_meta.get("status"),
            code=no_tenant_meta.get("code"),
            message=no_tenant_meta.get("message"),
            detail=no_tenant_meta.get("detail"),
        )
    )

    # Security smoke (presence + unauth deny)
    try:
        rr = requests.get(f"{BASE}/login", timeout=30)
        checks.append(chk("smoke/login", rr.status_code == 200, status=rr.status_code))
    except Exception as exc:
        checks.append(chk("smoke/login", False, error=str(exc)[:120]))

    files_ok = all(
        (ROOT / p).exists()
        for p in (
            "services/web_security_auth_enterprise/mfa_totp.py",
            "services/csrf_service.py",
            "services/http_abuse_guard.py",
            "services/enterprise_access_control.py",
            "services/cryptovault_key_rotation.py",
        )
    )
    checks.append(chk("security_controls_present", files_ok))

    return {
        "checks": checks,
        "login_a": {k: v for k, v in meta_a.items() if k != "email"},
        "login_b": {k: v for k, v in meta_b.items() if k != "email"},
        "latencies": {
            "login_a_ms": meta_a.get("post_login_ms"),
            "login_b_ms": meta_b.get("post_login_ms"),
            "search_a_ms": ra.get("ms"),
            "search_b_ms": rb.get("ms"),
            "system_a_ms": sa.get("ms"),
            "system_b_ms": sb.get("ms"),
        },
    }


def _probe_missing_tenant() -> Dict[str, Any]:
    """Login as TEST_FIXTURE user with no canonical tenant → expect 403 NO_TENANT_CONTEXT."""
    from database import SessionLocal, Usuario
    from werkzeug.security import generate_password_hash
    import requests

    email = f"p03e2e.notenant.{MARKER.lower()}@novus-client.test"
    out: Dict[str, Any] = {"ok": False, "email_created": True}
    db = SessionLocal()
    uid = None
    try:
        u = db.query(Usuario).filter(Usuario.email == email).first()
        if not u:
            u = Usuario(
                email=email,
                hashed_password=generate_password_hash(PASS),
                is_active=True,
                nit_pyme=None,
                sector="fintech",
                role="analyst",
            )
            db.add(u)
            db.commit()
            db.refresh(u)
        else:
            u.nit_pyme = None
            u.role = "analyst"
            u.is_active = True
            u.hashed_password = generate_password_hash(PASS)
            db.commit()
        uid = u.id
    finally:
        db.close()

    try:
        s, meta = login(email)
        out["login_ok"] = bool(meta.get("cookie_names"))
        out["probe_status_on_login"] = meta.get("probe_search_status")
        r = s.get(f"{BASE}/api/search", params={"q": TITLE_A}, timeout=90)
        try:
            body = r.json()
        except Exception:
            body = {}
        out["status"] = r.status_code
        out["code"] = body.get("code") or body.get("error") or body.get("message")
        out["message"] = str(body.get("message") or "")[:160]
        blob = json.dumps(body, ensure_ascii=False)
        denied = r.status_code in (401, 403)
        no_leak = TITLE_A not in blob and TITLE_B not in blob and not (body.get("results") or [])
        # Prefer explicit NO_TENANT_CONTEXT
        code_s = str(out.get("code") or "")
        msg_s = out["message"]
        tenantish = "NO_TENANT" in code_s.upper() or "NO_TENANT" in msg_s.upper() or r.status_code == 403
        out["ok"] = denied and no_leak and tenantish
        out["detail"] = "authenticated_without_canonical_tenant"
        return out
    finally:
        db = SessionLocal()
        try:
            if uid:
                db.query(Usuario).filter(Usuario.id == uid).delete(synchronize_session=False)
                db.commit()
        finally:
            db.close()


def restart_and_retest() -> Dict[str, Any]:
    """
    Soft restart check: verify server still up and re-login isolation.
    Full process kill avoided under RAM pressure (can wedge :5000).
    Documents limitation if hard restart not performed.
    """
    import requests

    out: Dict[str, Any] = {
        "restarted": False,
        "mode": "soft_relogin_same_process",
        "limitation": None,
        "checks": [],
    }
    try:
        r = requests.get(f"{BASE}/login", timeout=10)
        out["checks"].append(chk("restart_server_up", r.status_code == 200, status=r.status_code))
    except Exception as exc:
        out["checks"].append(chk("restart_server_up", False, error=str(exc)[:120]))
        out["limitation"] = "NO PUEDO CONFIRMARLO hard restart — server unreachable"
        return out

    # Soft: new sessions after prior traffic (not OS process restart)
    out["limitation"] = (
        "Hard process restart skipped to avoid wedging :5000 under RAM pressure; "
        "re-login isolation exercised instead. NO PUEDO CONFIRMARLO hard Waitress restart."
    )
    sa, ma = login(EMAIL_A)
    sb, mb = login(EMAIL_B)
    out["checks"].append(chk("restart_login_a", ma.get("ok") is True))
    out["checks"].append(chk("restart_login_b", mb.get("ok") is True))
    if ma.get("ok") and mb.get("ok"):
        ra = search(sa, TITLE_A)
        rb = search(sb, TITLE_B)
        rx = search(sa, TITLE_B)
        ry = search(sb, TITLE_A)
        out["checks"].append(chk("restart_a_to_a", ra.get("status") == 200 and TITLE_A in results_blob(ra), status=ra.get("status"), error=ra.get("error")))
        out["checks"].append(chk("restart_b_to_b", rb.get("status") == 200 and TITLE_B in results_blob(rb), status=rb.get("status"), error=rb.get("error")))
        out["checks"].append(chk("restart_a_to_b", TITLE_B not in results_blob(rx), status=rx.get("status"), error=rx.get("error")))
        out["checks"].append(chk("restart_b_to_a", TITLE_A not in results_blob(ry), status=ry.get("status"), error=ry.get("error")))
        out["restarted"] = True  # soft restart path completed
    return out


def main() -> int:
    before_diag = diagnose_401()
    # Preserve prior evidence — merge only
    prev_path = OUT / "p0_3_http_e2e_before_after.json"
    prev: Dict[str, Any] = {}
    if prev_path.exists():
        try:
            prev = json.loads(prev_path.read_text(encoding="utf-8"))
        except Exception:
            prev = {}
    prev["phase_before_diag"] = before_diag
    prev_path.write_text(json.dumps(prev, indent=2), encoding="utf-8")

    if before_diag["evidence"].get("GET_/login", {}).get("status") != 200:
        report = {
            "verdict": "HTTP_E2E_NOT_VERIFIABLE",
            "reason": "server_login_unavailable",
            "diagnosis": before_diag,
        }
        (OUT / "p0_3_http_e2e.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        (OUT / "p0_3_http_e2e_report.md").write_text(
            "# HTTP E2E\n\n## VERDICT\n\n`HTTP_E2E_NOT_VERIFIABLE`\n\n**NO PUEDO CONFIRMARLO** — /login no respondió 200.\n",
            encoding="utf-8",
        )
        print(json.dumps({"verdict": "HTTP_E2E_NOT_VERIFIABLE"}, indent=2))
        return 1

    created = setup_fixtures()
    try:
        e2e = run_e2e(created)
        if e2e.get("blocked_reason") == "login_failed":
            # Still try to classify — if csrf works but probe 401, may be session id issue
            verdict = "HTTP_E2E_NOT_VERIFIABLE"
            if (e2e.get("meta_a") or {}).get("detail") == "csrf_missing":
                cause = "C — CSRF missing on login page"
            elif (e2e.get("meta_a") or {}).get("mfa_required") or (e2e.get("meta_b") or {}).get("mfa_required"):
                cause = "Harness/env — MFA required for fixture users (unexpected for analyst)"
            elif (e2e.get("meta_a") or {}).get("probe_search_status") == 401:
                cause = "C or E — login POST may succeed but session lacks _novus_login_session_id (API 401)"
            else:
                cause = "NO PUEDO CONFIRMARLO — login automation failed"
            payload = {
                "generated_at_utc": utc(),
                "verdict": verdict,
                "diagnosis": before_diag,
                "e2e": e2e,
                "cause": cause,
                "production_files_modified": [],
                "resources": resources(),
            }
            (OUT / "p0_3_http_e2e.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
            (OUT / "p0_3_http_e2e_report.md").write_text(
                f"# P0-3 HTTP E2E REPORT\n\n## VERDICT\n\n`{verdict}`\n\n## CAUSA\n\n{cause}\n\n"
                f"## DIAGNÓSTICO 401 PREVIO\n\nClasificación primaria: **C** (harness cookie/CSRF/sesión).\n"
                f"Unauth `/api/search` → **D** (401 correcto).\n\n**NO PUEDO CONFIRMARLO** el aislamiento HTTP autenticado.\n",
                encoding="utf-8",
            )
            print(json.dumps({"verdict": verdict, "cause": cause}, indent=2))
            return 1

        # Restart isolation
        restart = restart_and_retest()
        checks = list(e2e.get("checks") or []) + list(restart.get("checks") or [])
        by = {c["id"]: c for c in checks}

        def g(i: str) -> bool:
            return bool((by.get(i) or {}).get("ok"))

        required = [
            "login_a",
            "login_b",
            "http_api_search_a_to_a",
            "http_api_search_b_to_b",
            "http_api_search_a_to_b",
            "http_api_search_b_to_a",
            "alert_a_search_b",
            "alert_b_search_a",
            "http_system_search_a_to_a",
            "http_system_search_b_to_a",
            "direct_id_b_to_a",
            "cache_isolation",
            "missing_auth_denied",
            "missing_tenant_denied",
            "security_controls_present",
            "restart_a_to_a",
            "restart_b_to_b",
            "restart_a_to_b",
            "restart_b_to_a",
        ]
        all_ok = all(g(i) for i in required)
        restart_ok = g("restart_server_up") and g("restart_a_to_a") and g("restart_b_to_b") and g("restart_a_to_b") and g("restart_b_to_a")
        hard_restart = restart.get("mode") == "hard_process_restart" and bool(restart.get("restarted"))
        soft_core = (
            g("login_a")
            and g("login_b")
            and g("http_api_search_a_to_a")
            and g("http_api_search_b_to_b")
            and g("http_api_search_a_to_b")
            and g("http_api_search_b_to_a")
            and g("alert_a_search_b")
            and g("alert_b_search_a")
            and g("http_system_search_a_to_a")
            and g("http_system_search_b_to_a")
            and g("missing_auth_denied")
            and g("missing_tenant_denied")
            and g("cache_isolation")
        )
        if all_ok and hard_restart:
            verdict = "HTTP_E2E_PASS"
        elif soft_core:
            # Soft restart / RAM limitation → PASS_WITH_LIMITATIONS (not silent PASS)
            verdict = "HTTP_E2E_PASS_WITH_LIMITATIONS"
        else:
            verdict = "HTTP_E2E_BLOCKED"

        payload = {
            "generated_at_utc": utc(),
            "verdict": verdict,
            "NOVUS_ENV": "beta",
            "DEBUG": False,
            "port": 5000,
            "diagnosis_401": before_diag,
            "classification_primary": "C",
            "fixtures": {
                "marker": MARKER,
                "tenant_a": TENANT_A,
                "tenant_b": TENANT_B,
                "alert_titles": [TITLE_A, TITLE_B],
                "TEST_FIXTURE": True,
                "SYNTHETIC_TEST_ONLY": True,
            },
            "checks": checks,
            "latencies": e2e.get("latencies"),
            "restart": {k: v for k, v in restart.items() if k != "checks"},
            "resources": resources(),
            "production_files_modified": [],
            "required_pass": {i: g(i) for i in required},
        }
        (OUT / "p0_3_http_e2e.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

        before_after = {
            "before": {
                "http_authenticated": "NO PUEDO CONFIRMARLO",
                "cause": "harness 401 — incomplete CSRF/session (Class C) + correct unauth 401 (Class D)",
            },
            "after": {
                "verdict": verdict,
                "login_a": g("login_a"),
                "login_b": g("login_b"),
                "A_to_A": g("http_api_search_a_to_a"),
                "B_to_B": g("http_api_search_b_to_b"),
                "A_to_B": g("http_api_search_a_to_b"),
                "B_to_A": g("http_api_search_b_to_a"),
                "restart_ok": restart_ok,
            },
            "diagnosis": before_diag,
        }
        # preserve prior file content by merging
        prev_path = OUT / "p0_3_http_e2e_before_after.json"
        prev = {}
        if prev_path.exists():
            try:
                prev = json.loads(prev_path.read_text(encoding="utf-8"))
            except Exception:
                prev = {}
        prev["http_e2e"] = before_after
        prev_path.write_text(json.dumps(prev, indent=2), encoding="utf-8")

        report = f"""# P0-3 HTTP E2E REPORT

## VERDICT

`{verdict}`

## DIAGNÓSTICO DEL 401 PREVIO

**Clasificación primaria: C** — el harness no manejó correctamente CSRF/cookie/sesión (y/o usó rutas de login incompletas).

**También D** — `/api/search` sin autenticación responde **401** correctamente (`Autenticación requerida`).

No se demostró bug de autenticación de NOVUS (E) ni fallo de tenant (F) en este diagnóstico.

## CAMBIOS

Solo harness: `scripts/search_tenant_p0_3_http_e2e.py`

**Archivos de producción P0-3 modificados:** ninguno.

## EVIDENCIA

| Prueba | Resultado |
|--------|-----------|
| login A | {"PASS" if g("login_a") else "FAIL"} |
| login B | {"PASS" if g("login_b") else "FAIL"} |
| `/api/search` A→A | {"PASS" if g("http_api_search_a_to_a") else "FAIL"} |
| `/api/search` B→B | {"PASS" if g("http_api_search_b_to_b") else "FAIL"} |
| `/api/search` A→B | {"PASS" if g("http_api_search_a_to_b") else "FAIL"} |
| `/api/search` B→A | {"PASS" if g("http_api_search_b_to_a") else "FAIL"} |
| alerta A→B | {"PASS" if g("alert_a_search_b") else "FAIL"} |
| alerta B→A | {"PASS" if g("alert_b_search_a") else "FAIL"} |
| `/api/system/search` | {"PASS" if g("http_system_search_a_to_a") and g("http_system_search_b_to_a") else "FAIL"} |
| cache | {"PASS" if g("cache_isolation") else "FAIL"} |
| restart | {"PASS" if restart_ok else "FAIL / NO PUEDO CONFIRMARLO"} |
| security smoke | {"PASS" if g("security_controls_present") and g("missing_auth_denied") else "FAIL"} |

## LIMITATIONS

{("- Hard Waitress process restart: " + (restart.get("limitation") or "n/a")) if verdict == "HTTP_E2E_PASS_WITH_LIMITATIONS" or restart.get("limitation") else ""}
{"" if all_ok else "- Algún check requerido falló — ver p0_3_http_e2e.json"}
{"" if restart_ok else "- Soft restart isolation incomplete — ver JSON"}
{"" if g("missing_tenant_denied") else "- missing_tenant_denied FAIL"}

## STOP

No se inicia P0-4 ni otras fases.
"""
        # Always document soft-restart limitation clearly
        if restart.get("limitation"):
            payload["limitations"] = [restart.get("limitation")]
            (OUT / "p0_3_http_e2e.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

        (OUT / "p0_3_http_e2e_report.md").write_text(report, encoding="utf-8")
        print(json.dumps({"verdict": verdict, "all_ok": all_ok, "restart_ok": restart_ok, "soft_core": soft_core}, indent=2))
        return 0 if verdict.startswith("HTTP_E2E_PASS") else 1
    finally:
        cleanup_fixtures(created)


if __name__ == "__main__":
    raise SystemExit(main())
