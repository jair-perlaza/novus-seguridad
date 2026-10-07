#!/usr/bin/env python3
"""Post-fix MFA validation — T2/T3/B/C/E only. No code changes."""
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
OUT = ROOT / "data" / "novus_compliance_audit"
BASE = "http://127.0.0.1:5000"
RUN = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
EMAIL = f"mfa-e2e-test-{RUN}@example.com".lower()
PWD = f"MfaE2eTest!{RUN[-6:]}"
HTTP = 120
SHORT = 30


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def listener_pid() -> Optional[int]:
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            return c.pid
    return None


def snap(label: str) -> Dict[str, Any]:
    s: Dict[str, Any] = {"label": label, "ts": utc()}
    s["system_ram_pct"] = round(psutil.virtual_memory().percent, 1)
    pid = listener_pid()
    s["pid"] = pid
    if pid:
        p = psutil.Process(pid)
        s["novus_rss_mb"] = round(p.memory_info().rss / 1048576, 1)
        s["novus_threads"] = p.num_threads()
    try:
        from services.resource_backpressure_service import get_status
        s["backpressure"] = get_status()
    except Exception as exc:
        s["backpressure"] = {"error": str(exc)}
    t0 = time.perf_counter()
    try:
        r = requests.get(f"{BASE}/login", timeout=SHORT)
        s["login_get_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        s["login_get_status"] = r.status_code
        s["recovery"] = bool(r.headers.get("X-Novus-Recovery"))
    except Exception as exc:
        s["login_get_error"] = str(exc)
    return s


def is_recovery(resp: requests.Response) -> bool:
    if resp.headers.get("X-Novus-Recovery"):
        return True
    t = (resp.text or "").lower()
    if "recuperando el servicio" in t and "btn-enroll" not in t:
        return True
    try:
        b = resp.json()
        return bool(b.get("_novusRecovery") or b.get("status") == "recovering")
    except Exception:
        return False


def clear_auth_blocks() -> None:
    from database import SessionLocal, AuthOriginSanction, IPBloqueada
    db = SessionLocal()
    try:
        for ip in ("127.0.0.1", "::1", "localhost"):
            for row in db.query(AuthOriginSanction).filter(
                AuthOriginSanction.origin_key == ip, AuthOriginSanction.status == "active"
            ).all():
                row.status = "revoked"
            for row in db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == ip).all():
                db.delete(row)
        db.commit()
    finally:
        db.close()


def setup_user() -> None:
    from database import SessionLocal, Usuario
    db = SessionLocal()
    try:
        db.query(Usuario).filter(Usuario.email == EMAIL).delete()
        db.add(
            Usuario(
                email=EMAIL,
                hashed_password=generate_password_hash(PWD),
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


def cleanup_user() -> Dict[str, Any]:
    from database import SessionLocal, Usuario
    stats = {"email": EMAIL, "user_deleted": False, "mfa_store_cleaned": False}
    db = SessionLocal()
    try:
        if db.query(Usuario).filter(Usuario.email == EMAIL).first():
            db.query(Usuario).filter(Usuario.email == EMAIL).delete()
            db.commit()
            stats["user_deleted"] = True
    finally:
        db.close()
    store = ROOT / "data" / "web_security_auth_enterprise" / "mfa_store.json"
    if store.is_file():
        data = json.loads(store.read_text(encoding="utf-8") or "{}")
        if EMAIL in data:
            del data[EMAIL]
            store.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            stats["mfa_store_cleaned"] = True
    return stats


def csrf_html(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def csrf_script(html: str) -> str:
    m = re.search(r"const csrf = (.+?);", html)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    return ""


def delta(b: Dict[str, Any], a: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rss_mb": round((a.get("novus_rss_mb") or 0) - (b.get("novus_rss_mb") or 0), 1) if b.get("novus_rss_mb") else None,
        "threads": (a.get("novus_threads") or 0) - (b.get("novus_threads") or 0) if b.get("novus_threads") else None,
    }


def main() -> int:
    report: Dict[str, Any] = {
        "run_id": RUN,
        "generated_at_utc": utc(),
        "phase": "post_fix_validation",
        "fix_validated": {"template": "auth.logout_seguro", "status": "pending"},
        "before": {},
        "tests": {},
        "fixtures": {"email": EMAIL, "role": "company_admin"},
        "cleanup": {},
        "overall_verdict": "NOT VERIFIABLE",
    }

    if not listener_pid():
        report["error"] = "no listener on :5000"
        report["overall_verdict"] = "NOT VERIFIABLE"
        _write(report)
        return 2

    report["before"] = snap("before")
    clear_auth_blocks()
    setup_user()
    session = requests.Session()

    # Login to enrollment session
    try:
        g = session.get(f"{BASE}/login", timeout=SHORT)
        tok = csrf_html(g.text)
        lp = session.post(
            f"{BASE}/login",
            data={"email": EMAIL, "password": PWD, "csrf_token": tok},
            allow_redirects=False,
            timeout=HTTP,
        )
    except requests.exceptions.RequestException as exc:
        report["tests"]["login"] = {"verdict": "NOT VERIFIABLE", "error": str(exc)}
        report["overall_verdict"] = "NOT VERIFIABLE"
        report["cleanup"] = cleanup_user()
        _write(report)
        return 1

    report["tests"]["login"] = {
        "status": lp.status_code,
        "location": lp.headers.get("Location"),
        "elapsed_note": "post-fix login",
    }

    # T2 — template fix
    b2 = snap("T2_before")
    try:
        mfa = session.get(f"{BASE}/mfa-setup", timeout=HTTP)
    except requests.exceptions.RequestException as exc:
        report["tests"]["T2_mfa_setup"] = {"verdict": "NOT VERIFIABLE", "error": str(exc)}
        report["overall_verdict"] = "NOT VERIFIABLE"
        report["cleanup"] = cleanup_user()
        _write(report)
        return 1
    a2 = snap("T2_after")
    build_err = "auth.logout" in mfa.text and "logout_seguro" not in mfa.text
    has_enroll = "btn-enroll" in mfa.text
    rec = is_recovery(mfa)
    if build_err or "BuildError" in mfa.text:
        t2v = "FAIL"
    elif rec:
        t2v = "NOT VERIFIABLE"
    elif mfa.status_code == 200 and has_enroll:
        t2v = "VERIFIED"
        report["fix_validated"]["status"] = "PASS"
    else:
        t2v = "FAIL"
    report["tests"]["T2_mfa_setup"] = {
        "verdict": t2v,
        "status": mfa.status_code,
        "has_btn_enroll": has_enroll,
        "recovery": rec,
        "build_error_auth_logout": build_err,
        "body_snippet": mfa.text[:500],
        "delta": delta(b2, a2),
        "before": b2,
        "after": a2,
    }

    if t2v != "VERIFIED":
        report["overall_verdict"] = "FAILED" if t2v == "FAIL" else "NOT VERIFIABLE"
        report["cleanup"] = cleanup_user()
        _write(report)
        return 1

    csrf = csrf_script(mfa.text) or csrf_html(mfa.text)

    # T3 enroll
    b3 = snap("T3_before")
    try:
        enr = session.post(
            f"{BASE}/api/wsae/mfa/enroll",
            headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
            json={},
            timeout=HTTP,
        )
    except requests.exceptions.RequestException as exc:
        report["tests"]["T3_enroll"] = {"verdict": "NOT VERIFIABLE", "error": str(exc)}
        report["overall_verdict"] = "PARTIALLY VERIFIED"
        report["cleanup"] = cleanup_user()
        _write(report)
        return 1
    a3 = snap("T3_after")
    eb = enr.json() if "json" in enr.headers.get("content-type", "") else {}
    t3v = "VERIFIED" if eb.get("ok") and eb.get("secret") and not is_recovery(enr) else (
        "NOT VERIFIABLE" if is_recovery(enr) else "FAIL"
    )
    report["tests"]["T3_enroll"] = {
        "verdict": t3v,
        "status": enr.status_code,
        "ok": eb.get("ok"),
        "has_secret": bool(eb.get("secret")),
        "recovery": is_recovery(enr),
        "delta": delta(b3, a3),
    }

    if t3v != "VERIFIED":
        report["overall_verdict"] = "PARTIALLY VERIFIED" if t2v == "VERIFIED" else "FAILED"
        report["cleanup"] = cleanup_user()
        _write(report)
        return 1

    import pyotp
    secret = eb["secret"]
    code = pyotp.TOTP(secret).now()

    # B — enable
    bb = snap("B_before")
    en = session.post(
        f"{BASE}/api/wsae/mfa/enable",
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
        json={"code": code},
        timeout=HTTP,
    )
    ab = snap("B_after")
    enb = en.json() if en.headers.get("content-type", "").startswith("application/json") else {}
    mfa_st = session.get(f"{BASE}/api/wsae/mfa/status", timeout=SHORT)
    ms = mfa_st.json() if mfa_st.ok else {}
    bv = "VERIFIED" if enb.get("ok") and ms.get("enabled") else "FAIL"
    report["tests"]["B_enrollment"] = {
        "verdict": bv,
        "enable_status": en.status_code,
        "enabled": ms.get("enabled"),
        "policy_locked": ms.get("policy_locked"),
        "delta": delta(bb, ab),
    }

    if bv != "VERIFIED":
        report["overall_verdict"] = "PARTIALLY VERIFIED"
        report["cleanup"] = cleanup_user()
        _write(report)
        return 1

    # C — login with TOTP
    bc = snap("C_before")
    s2 = requests.Session()
    g2 = s2.get(f"{BASE}/login", timeout=SHORT)
    t2 = csrf_html(g2.text)
    p1 = s2.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PWD, "csrf_token": t2},
        allow_redirects=False,
        timeout=HTTP,
    )
    code2 = pyotp.TOTP(secret).now()
    p2 = s2.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PWD, "csrf_token": t2, "mfa_code": code2},
        allow_redirects=False,
        timeout=HTTP,
    )
    dash = s2.get(f"{BASE}/dashboard", allow_redirects=True, timeout=HTTP)
    ac = snap("C_after")
    cv = "VERIFIED" if p1.status_code == 200 and p2.status_code in (302, 303) and (
        "novus-estado-general-panel" in dash.text or dash.status_code == 200
    ) else ("NOT VERIFIABLE" if is_recovery(dash) else "FAIL")
    report["tests"]["C_login_totp"] = {
        "verdict": cv,
        "step1": p1.status_code,
        "step2": p2.status_code,
        "step2_location": p2.headers.get("Location"),
        "dashboard_url": str(dash.url),
        "has_panel": "novus-estado-general-panel" in dash.text,
        "delta": delta(bc, ac),
    }

    # E — bypass without MFA (fresh user)
    cleanup_user()
    setup_user()
    be = snap("E_before")
    s3 = requests.Session()
    sec = s3.post(
        f"{BASE}/sector-auth",
        json={"email": EMAIL, "password": PWD, "sector": "fintech"},
        timeout=HTTP,
    )
    lg = s3.get(f"{BASE}/login", timeout=SHORT)
    tok_e = csrf_html(lg.text)
    lp_e = s3.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PWD, "csrf_token": tok_e},
        allow_redirects=False,
        timeout=HTTP,
    )
    dash_e = s3.get(f"{BASE}/dashboard", allow_redirects=False, timeout=SHORT)
    search = s3.get(f"{BASE}/api/search?q=test", allow_redirects=False, timeout=SHORT)
    ae = snap("E_after")
    sb = search.json() if search.headers.get("content-type", "").startswith("application/json") else {}
    search_blocked = search.status_code in (401, 403) or sb.get("code") == "MFA_ENROLLMENT_REQUIRED"
    if sb.get("status") == "recovering" or sb.get("_novusRecovery"):
        ev = "NOT VERIFIABLE"
    else:
        ev = "VERIFIED" if (
            sec.status_code in (403, 302)
            and "/mfa-setup" in (lp_e.headers.get("Location") or "")
            and dash_e.status_code in (302, 401, 403)
            and search_blocked
        ) else "FAIL"
    report["tests"]["E_bypass"] = {
        "verdict": ev,
        "sector_auth": sec.status_code,
        "login_location": lp_e.headers.get("Location"),
        "dashboard": dash_e.status_code,
        "search": search.status_code,
        "search_blocked": search_blocked,
        "delta": delta(be, ae),
    }

    verdicts = [report["tests"][k]["verdict"] for k in ("T2_mfa_setup", "T3_enroll", "B_enrollment", "C_login_totp", "E_bypass")]
    if all(v == "VERIFIED" for v in verdicts):
        report["overall_verdict"] = "VERIFIED"
    elif any(v == "FAIL" for v in verdicts):
        report["overall_verdict"] = "FAILED" if not any(v == "VERIFIED" for v in verdicts) else "PARTIALLY VERIFIED"
    elif any(v == "NOT VERIFIABLE" for v in verdicts):
        report["overall_verdict"] = "PARTIALLY VERIFIED" if any(v == "VERIFIED" for v in verdicts) else "NOT VERIFIABLE"

    report["after"] = snap("after")
    report["cleanup"] = cleanup_user()
    _write(report)
    print(json.dumps({"overall_verdict": report["overall_verdict"], "T2": t2v, "tests": verdicts}, indent=2))
    return 0 if report["overall_verdict"] == "VERIFIED" else 1


def _write(report: Dict[str, Any]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    # merge into E2E final json
    final_path = OUT / "MFA_ADMIN_HTTP_E2E_FINAL.json"
    existing = {}
    if final_path.is_file():
        try:
            existing = json.loads(final_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    existing["post_fix_validation"] = report
    existing["p0_4_verdict"] = report.get("overall_verdict", existing.get("p0_4_verdict"))
    existing["generated_at_utc"] = utc()
    final_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
    md = _md(report, existing)
    (OUT / "MFA_ADMIN_HTTP_E2E_FINAL.md").write_text(md, encoding="utf-8")


def _md(report: Dict[str, Any], existing: Dict[str, Any]) -> str:
    lines = [
        "# MFA ADMIN HTTP E2E FINAL — P0-4",
        "",
        f"**Post-fix validation:** `{report['run_id']}`",
        f"**Generated:** {utc()}",
        "",
        f"## Veredicto: {report.get('overall_verdict', 'NOT VERIFIABLE')}",
        "",
        f"### Fix template: **{report.get('fix_validated', {}).get('status', 'pending')}**",
        "",
        "## Post-reinicio — recursos",
        "",
        f"| Métrica | Before | After |",
        f"|---------|--------|-------|",
    ]
    b, a = report.get("before", {}), report.get("after", {})
    lines.append(f"| RSS MB | {b.get('novus_rss_mb')} | {a.get('novus_rss_mb')} |")
    lines.append(f"| Threads | {b.get('novus_threads')} | {a.get('novus_threads')} |")
    lines.append(f"| RAM sistema % | {b.get('system_ram_pct')} | {a.get('system_ram_pct')} |")
    lines.append("")
    lines.append("## Pruebas post-fix")
    lines.append("")
    for k, v in (report.get("tests") or {}).items():
        lines.append(f"- **{k}**: {v.get('verdict')}")
    lines.append("")
    lines.append("## Cleanup")
    lines.append("```json")
    lines.append(json.dumps(report.get("cleanup", {}), indent=2))
    lines.append("```")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
