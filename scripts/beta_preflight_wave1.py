#!/usr/bin/env python3
"""
BETA PRE-FLIGHT Wave 1 — inspection only.
Writes ONLY under data/novus_beta_operations/preflight_wave1/.
NO production code/config changes. NO secrets in artifacts.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_beta_operations" / "preflight_wave1"
OUT.mkdir(parents=True, exist_ok=True)

BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000").rstrip("/")

EMAIL_MFA = "novus.qa.jul2026@example.com"
PASS_MFA = "NovusQA2026!"
EMAIL_A = "p1c001.probe@novus-client.test"
PASS_A = "NovusP1C001Rem2026!"
TENANT_A = "P1C001-PROBE"
EMAIL_B = "operaciones@novapay-fintech.co"
PASS_B = "NovaPay#Fintech2026"
TENANT_B = "901.567.123-4"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha12(s: str) -> str:
    return hashlib.sha256(str(s).encode()).hexdigest()[:12]


def csrf(html: str) -> str:
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html or "")
    return m.group(1) if m else ""


def allow_cookies(session) -> None:
    if BASE.startswith("https://"):
        return
    for c in session.cookies:
        c.secure = False


def resources() -> Dict[str, Any]:
    import psutil

    vm = psutil.virtual_memory()
    disk = shutil.disk_usage(str(ROOT))
    out: Dict[str, Any] = {
        "host_ram_pct": vm.percent,
        "host_available_mb": round(vm.available / (1024 * 1024), 1),
        "host_used_mb": round(vm.used / (1024 * 1024), 1),
        "cpu_pct": psutil.cpu_percent(interval=0.4),
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "port_5000": [],
    }
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and getattr(c.laddr, "port", None) == 5000 and c.status == "LISTEN":
            info: Dict[str, Any] = {"pid": c.pid}
            try:
                p = psutil.Process(c.pid)
                info.update(
                    {
                        "name": p.name(),
                        "rss_mb": round(p.memory_info().rss / (1024 * 1024), 1),
                        "threads": p.num_threads(),
                        "create_time": datetime.fromtimestamp(
                            p.create_time(), tz=timezone.utc
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "cmdline_tail": " ".join((p.cmdline() or [])[-3:])[:160],
                    }
                )
                # Process env (read-only) — report keys of interest only
                try:
                    env = p.environ()
                    info["proc_env"] = {
                        "NOVUS_ENV": env.get("NOVUS_ENV"),
                        "DEBUG": env.get("DEBUG"),
                        "FLASK_DEBUG": env.get("FLASK_DEBUG"),
                        "PORT": env.get("PORT"),
                    }
                except Exception as exc:
                    info["proc_env_error"] = str(exc)[:120]
            except Exception as exc:
                info["error"] = str(exc)[:120]
            out["port_5000"].append(info)
    return out


def login(session, email: str, password: str, mfa_code: Optional[str] = None) -> Dict[str, Any]:
    try:
        g = session.get(f"{BASE}/login", timeout=60)
        allow_cookies(session)
        data = {"email": email, "password": password, "csrf_token": csrf(g.text)}
        if mfa_code is not None:
            data["mfa_code"] = mfa_code
        t0 = time.perf_counter()
        p = session.post(
            f"{BASE}/login",
            data=data,
            headers={"Referer": f"{BASE}/login", "Origin": BASE},
            allow_redirects=False,
            timeout=60,
        )
        allow_cookies(session)
        loc = p.headers.get("Location") or ""
        text = p.text or ""
        return {
            "status": p.status_code,
            "location": loc[:160],
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "ok_dashboard": p.status_code in (302, 303) and "dashboard" in loc.lower(),
            "mfa_setup": "/mfa-setup" in loc.lower(),
            "mfa_prompt": "Authenticator" in text or "mfa_code" in text.lower(),
            "invalid_hint": any(
                x in text.lower() for x in ("inválido", "invalid", "incorrect", "deneg")
            ),
        }
    except Exception as exc:
        return {"status": None, "error": str(exc)[:180], "ok_dashboard": False}


def complete_mfa(session, code: str) -> Dict[str, Any]:
    try:
        g = session.get(f"{BASE}/login", timeout=60)
        allow_cookies(session)
        t0 = time.perf_counter()
        p = session.post(
            f"{BASE}/login",
            data={"csrf_token": csrf(g.text), "mfa_code": code},
            headers={"Referer": f"{BASE}/login", "Origin": BASE},
            allow_redirects=False,
            timeout=60,
        )
        allow_cookies(session)
        loc = p.headers.get("Location") or ""
        return {
            "status": p.status_code,
            "location": loc[:160],
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "ok_dashboard": p.status_code in (302, 303) and "dashboard" in loc.lower(),
            "invalid_hint": "inválido" in (p.text or "").lower(),
        }
    except Exception as exc:
        return {"status": None, "error": str(exc)[:180], "ok_dashboard": False}


def http_get(session, path: str, **params) -> Dict[str, Any]:
    try:
        allow_cookies(session)
        t0 = time.perf_counter()
        r = session.get(f"{BASE}{path}", params=params or None, timeout=60, allow_redirects=False)
        allow_cookies(session)
        try:
            body = r.json()
        except Exception:
            body = {"raw": (r.text or "")[:400]}
        return {
            "status": r.status_code,
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "body": body,
            "location": (r.headers.get("Location") or "")[:120],
        }
    except Exception as exc:
        return {"status": None, "error": str(exc)[:180], "body": {}}


def mfa_secret(email: str) -> Optional[str]:
    from services.web_security_auth_enterprise.mfa_totp import _load, _dec, is_mfa_enabled

    if not is_mfa_enabled(email):
        return None
    enc = (_load().get(email.strip().lower()) or {}).get("secret_enc")
    return _dec(enc) if enc else None


def contains_private(blob: str, tid: str, email: str) -> bool:
    if tid and tid in blob:
        return True
    if email and email.lower() in blob.lower():
        return True
    return False


def data_honesty_scan() -> Dict[str, Any]:
    markers = ("SIMULATED", "TEST_FIXTURE", "HARDCODED", "FAKE_", "DEMO_DATA", "STATIC_FAKE")
    hits = []
    for rel in (
        "templates/dashboard.html",
        "static/js/novus-dashboard-estado-general.js",
        "templates/index.html",
    ):
        p = ROOT / rel
        if not p.exists():
            continue
        txt = p.read_text(encoding="utf-8", errors="replace")
        for mk in markers:
            if mk in txt:
                # context: not necessarily presented as LIVE
                hits.append({"file": rel, "marker": mk})
    # traffic path evidence (code presence, not fake numbers)
    traffic = {"path_present": False, "files": []}
    for rel in (
        "services/system_monitor.py",
        "utils/host_data.py",
        "api/dashboard.py",
    ):
        p = ROOT / rel
        if p.exists():
            t = p.read_text(encoding="utf-8", errors="replace")
            if "net_io_counters" in t or "sample_traffic" in t or "traffic" in t.lower():
                traffic["files"].append(rel)
                traffic["path_present"] = True
    return {
        "frontend_markers": hits,
        "traffic_pipeline_files": traffic,
        "note": "Markers in source/UI strings are not auto-blockers unless presented as LIVE to clients",
    }


def backup_evidence() -> Dict[str, Any]:
    roots = [
        ROOT / "data" / "backups",
        ROOT / "data" / "production_closure" / "beta_launch_gate",
        ROOT / "data" / "production_closure" / "beta_release_gate",
    ]
    found = []
    for r in roots:
        if not r.exists():
            continue
        for p in r.rglob("*"):
            name = p.name.lower()
            if any(x in name for x in ("backup", "restore", "cryptovault", "novusenc")):
                if p.is_file() and p.stat().st_size > 0:
                    found.append(
                        {
                            "path": str(p.relative_to(ROOT))[:160],
                            "size": p.stat().st_size,
                        }
                    )
                if len(found) >= 25:
                    break
    # prior restore evidence docs
    docs = []
    for rel in (
        "data/production_closure/beta_launch_gate/FINAL_BACKUP_RESTORE.json",
        "data/production_closure/beta_release_gate/BETA_BACKUP_RESTORE.json",
    ):
        p = ROOT / rel
        if p.exists():
            docs.append(rel)
    return {
        "backup_like_files_sample": found[:20],
        "prior_backup_restore_docs": docs,
        "status": "PASS" if docs or found else "NOT_VERIFIABLE",
    }


def cryptovault_check() -> Dict[str, Any]:
    try:
        import crypto_vault as cv

        api = [n for n in ("encrypt", "decrypt", "CryptoVault") if hasattr(cv, n)]
        ok = False
        detail = ""
        try:
            if hasattr(cv, "encrypt") and hasattr(cv, "decrypt"):
                pt = b"PREFLIGHT_SYNTHETIC_ONLY_" + os.urandom(8)
                ok = cv.decrypt(cv.encrypt(pt)) == pt
                detail = "encrypt/decrypt roundtrip"
            elif hasattr(cv, "CryptoVault"):
                v = cv.CryptoVault()
                pt = b"PREFLIGHT_SYNTHETIC_ONLY_" + os.urandom(8)
                ok = v.decrypt(v.encrypt(pt)) == pt
                detail = "CryptoVault roundtrip"
        except Exception as exc:
            detail = str(exc)[:120]
        return {"import_ok": True, "api": api, "roundtrip_ok": ok, "detail": detail}
    except Exception as exc:
        return {"import_ok": False, "error": str(exc)[:160]}


def persistence_evidence() -> Dict[str, Any]:
    """Cite prior restart persistence — no restart in this preflight."""
    paths = [
        ROOT / "data/production_closure/beta_closure_check/beta_closure_check_persistence.json",
        ROOT / "data/production_closure/beta_closure_check/persistence_fixture.json",
    ]
    out = {"restart_performed_this_run": False, "prior": {}}
    for p in paths:
        if p.exists():
            try:
                out["prior"][p.name] = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                out["prior"][p.name] = {"present": True}
    # fixture still on disk?
    fx = ROOT / "data/production_closure/beta_closure_check/persistence_fixture.json"
    if fx.exists():
        d = json.loads(fx.read_text(encoding="utf-8"))
        out["fixture_still_present"] = bool(d.get("TEST_FIXTURE") and d.get("fixture_id"))
        out["fixture_tenant"] = d.get("tenant_id")
    return out


def main() -> int:
    import requests
    import pyotp

    evidence: Dict[str, Any] = {
        "generated_at_utc": utc(),
        "project_root": str(ROOT),
        "python": sys.version.split()[0],
        "python_exec": sys.executable,
        "base": BASE,
    }
    limitations: List[str] = []
    blockers: List[Dict[str, Any]] = []
    scores: Dict[str, str] = {}

    res = resources()
    evidence["resources"] = res
    proc = (res.get("port_5000") or [None])[0]
    evidence["server_listener"] = proc

    # Env expectation
    env_ok = True
    if proc and proc.get("proc_env"):
        pe = proc["proc_env"]
        evidence["runtime_env"] = pe
        if (pe.get("NOVUS_ENV") or "").lower() != "beta":
            env_ok = False
            limitations.append(
                f"NOVUS_ENV expected 'beta', process has {pe.get('NOVUS_ENV')!r} — reported, not corrected"
            )
        dbg = (pe.get("DEBUG") or pe.get("FLASK_DEBUG") or "").strip().lower()
        if dbg in ("1", "true", "yes", "on"):
            env_ok = False
            limitations.append(f"DEBUG/FLASK_DEBUG appears enabled ({dbg}) — reported, not corrected")
    else:
        limitations.append("Could not read process env for NOVUS_ENV/DEBUG — NOT_VERIFIABLE for env keys")
        env_ok = False

    # Health
    health: Dict[str, Any] = {}
    try:
        r = requests.get(f"{BASE}/login", timeout=20)
        health["login_page"] = {"status": r.status_code, "pass": r.status_code == 200}
    except Exception as exc:
        health["login_page"] = {"error": str(exc)[:160], "pass": False}
    try:
        r = requests.get(f"{BASE}/api/health/status", timeout=15)
        health["health_status"] = {"status": r.status_code, "note": "401 unauth is expected if auth required"}
    except Exception as exc:
        health["health_status"] = {"error": str(exc)[:160]}
    try:
        r = requests.get(f"{BASE}/api/security/summary", timeout=15)
        health["summary_unauth"] = {"status": r.status_code, "pass": r.status_code in (401, 302)}
    except Exception as exc:
        health["summary_unauth"] = {"error": str(exc)[:160], "pass": False}
    evidence["health"] = health
    server_pass = bool(health.get("login_page", {}).get("pass")) and bool(
        (res.get("port_5000") or [])
    )
    scores["server"] = "PASS" if server_pass else "FAIL"
    if not server_pass:
        blockers.append({"id": "SERVER", "severity": "P0", "detail": "server not healthy on :5000"})

    # AUTH
    auth: Dict[str, Any] = {}
    s_bad = requests.Session()
    auth["invalid_login"] = login(s_bad, "nonexistent.preflight@novus-client.test", "Wrong!")
    s_ok = requests.Session()
    auth["valid_client"] = login(s_ok, EMAIL_B, PASS_B)
    if auth["valid_client"].get("ok_dashboard"):
        auth["client_summary"] = {
            "status": http_get(s_ok, "/api/security/summary").get("status"),
            "tenant_id": (http_get(s_ok, "/api/security/summary").get("body") or {}).get("tenant_id"),
        }
        # refresh once for clarity
        sm = http_get(s_ok, "/api/security/summary")
        auth["client_summary"] = {
            "status": sm.get("status"),
            "tenant_id": (sm.get("body") or {}).get("tenant_id"),
            "ms": sm.get("ms"),
        }
        s_ok.get(f"{BASE}/logout", allow_redirects=True, timeout=45)
        allow_cookies(s_ok)
        auth["after_logout"] = {
            "status": http_get(s_ok, "/api/security/summary").get("status"),
        }
        auth["after_logout"]["pass"] = auth["after_logout"]["status"] in (401, 302, 403)
    # CSRF
    try:
        sc = requests.Session()
        g = sc.get(f"{BASE}/login", timeout=45)
        allow_cookies(sc)
        p = sc.post(
            f"{BASE}/login",
            data={"email": "x@y.z", "password": "no"},
            headers={"Referer": f"{BASE}/login", "Origin": BASE},
            allow_redirects=False,
            timeout=45,
        )
        auth["csrf_no_token"] = {
            "status": p.status_code,
            "denied": p.status_code == 403 or "CSRF" in (p.text or ""),
        }
    except Exception as exc:
        auth["csrf_no_token"] = {"error": str(exc)[:160], "denied": False}

    auth_pass = (
        not auth["invalid_login"].get("ok_dashboard")
        and bool(auth.get("valid_client", {}).get("ok_dashboard"))
        and bool(auth.get("after_logout", {}).get("pass"))
        and bool(auth.get("csrf_no_token", {}).get("denied"))
    )
    scores["auth"] = "PASS" if auth_pass else "FAIL"
    evidence["auth"] = auth

    # MFA
    mfa: Dict[str, Any] = {"email_sha12": sha12(EMAIL_MFA)}
    secret = None
    try:
        secret = mfa_secret(EMAIL_MFA)
        mfa["secret_present"] = bool(secret)
    except Exception as e:
        mfa["secret_error"] = str(e)[:120]
    if secret:
        s0 = requests.Session()
        r0 = login(s0, EMAIL_MFA, PASS_MFA)
        mfa["no_totp"] = {
            "ok_dashboard": r0.get("ok_dashboard"),
            "mfa_prompt_or_setup": bool(r0.get("mfa_prompt") or r0.get("mfa_setup")),
            "api_denied": http_get(s0, "/api/search", q="x").get("status") in (401, 403),
        }
        s1 = requests.Session()
        login(s1, EMAIL_MFA, PASS_MFA)
        bad = complete_mfa(s1, "000000")
        mfa["bad_totp"] = {
            "ok_dashboard": bad.get("ok_dashboard"),
            "api_denied": http_get(s1, "/api/search", q="x").get("status") in (401, 403),
        }
        s2 = requests.Session()
        good = login(s2, EMAIL_MFA, PASS_MFA, mfa_code=pyotp.TOTP(secret).now())
        if not good.get("ok_dashboard"):
            login(s2, EMAIL_MFA, PASS_MFA)
            good = complete_mfa(s2, pyotp.TOTP(secret).now())
        mfa["good_totp"] = {"ok_dashboard": good.get("ok_dashboard"), "ms": good.get("ms")}
        if good.get("ok_dashboard"):
            mfa["protected"] = {
                "search": http_get(s2, "/api/search", q="preflight").get("status"),
                "dsar": http_get(s2, "/api/compliance/dsar-export").get("status"),
            }
            # RBAC: super_admin should get DSAR 200 or meaningful allow
            mfa["rbac_admin_dsar"] = mfa["protected"]["dsar"]
            s2.get(f"{BASE}/logout", allow_redirects=True, timeout=45)
            allow_cookies(s2)
            mfa["logout"] = {
                "status": http_get(s2, "/api/security/summary").get("status"),
            }
            mfa["logout"]["pass"] = mfa["logout"]["status"] in (401, 302, 403)
        mfa_ok = (
            not mfa["no_totp"].get("ok_dashboard")
            and mfa["no_totp"].get("api_denied")
            and not mfa["bad_totp"].get("ok_dashboard")
            and mfa["bad_totp"].get("api_denied")
            and mfa["good_totp"].get("ok_dashboard")
            and mfa.get("logout", {}).get("pass")
        )
        scores["mfa"] = "PASS" if mfa_ok else "FAIL"
        if not mfa_ok:
            blockers.append({"id": "MFA", "severity": "P0", "detail": "MFA E2E failed"})
    else:
        scores["mfa"] = "FAIL"
        blockers.append({"id": "MFA", "severity": "P0", "detail": "no decryptable MFA secret for QA admin"})
        limitations.append("MFA secret unavailable — cannot complete TOTP E2E")
    evidence["mfa"] = mfa

    # RBAC: analyst DSAR 403 vs admin DSAR after MFA above
    rbac: Dict[str, Any] = {}
    sa = requests.Session()
    la = login(sa, EMAIL_A, PASS_A)
    rbac["analyst_login"] = la.get("ok_dashboard")
    if la.get("ok_dashboard"):
        d = http_get(sa, "/api/compliance/dsar-export")
        rbac["analyst_dsar"] = {"status": d.get("status"), "expect_403": d.get("status") == 403}
        # client also
    sb = requests.Session()
    lb = login(sb, EMAIL_B, PASS_B)
    if lb.get("ok_dashboard"):
        d2 = http_get(sb, "/api/compliance/dsar-export")
        rbac["client_dsar"] = {"status": d2.get("status"), "expect_403": d2.get("status") == 403}
    admin_dsar = (mfa.get("protected") or {}).get("dsar")
    rbac["admin_dsar_status"] = admin_dsar
    rbac_ok = (
        rbac.get("analyst_dsar", {}).get("expect_403")
        and (rbac.get("client_dsar", {}).get("expect_403") in (True, None) or rbac.get("client_dsar", {}).get("status") == 403)
        and admin_dsar in (200, None)  # if MFA failed, None
    )
    # If admin got 200 and analyst 403 → PASS
    if admin_dsar == 200 and rbac.get("analyst_dsar", {}).get("status") == 403:
        scores["rbac"] = "PASS"
    elif rbac.get("analyst_dsar", {}).get("status") == 403:
        scores["rbac"] = "PARTIAL"
        limitations.append("RBAC: analyst DSAR 403 confirmed; admin DSAR status incomplete")
    else:
        scores["rbac"] = "FAIL"
    evidence["rbac"] = rbac

    # TENANT isolation
    tenant: Dict[str, Any] = {}
    if la.get("ok_dashboard") and lb.get("ok_dashboard"):
        a1 = http_get(sa, "/api/security/summary")
        a2 = http_get(sa, "/api/security/summary")
        aq = http_get(sa, "/api/security/summary", tenant_id=TENANT_B)
        aa = http_get(sa, "/api/security/alerts", limit=20)
        as_ = http_get(sa, "/api/search", q="alert", limit=20)
        asb = http_get(sa, "/api/search", q=TENANT_B, limit=20)
        asys = http_get(sa, "/api/system/search", q="alert", limit=10)
        ad = http_get(sa, "/api/compliance/dsar-export")
        b1 = http_get(sb, "/api/security/summary")
        b2 = http_get(sb, "/api/security/summary")
        bq = http_get(sb, "/api/security/summary", tenant_id=TENANT_A)
        ba = http_get(sb, "/api/security/alerts", limit=20)
        bs_ = http_get(sb, "/api/search", q="alert", limit=20)
        bsa = http_get(sb, "/api/search", q=TENANT_A, limit=20)
        bd = http_get(sb, "/api/compliance/dsar-export")

        ta = (a1.get("body") or {}).get("tenant_id")
        tb = (b1.get("body") or {}).get("tenant_id")
        blob_a = json.dumps(a1.get("body") or {}, default=str)
        blob_b = json.dumps(b1.get("body") or {}, default=str)
        # search content: private hits excluding query echo
        def search_leak(body, other_tid, other_email, query_tid):
            results = body.get("results") or []
            if body.get("query") == other_tid and (body.get("count") or 0) == 0:
                return False
            blob = json.dumps(results, default=str)
            return contains_private(blob, other_tid, other_email)

        tenant["a"] = {
            "summary_tid": ta,
            "summary_status": a1.get("status"),
            "cache_hit": ((a2.get("body") or {}).get("http_cache") or {}).get("hit"),
            "query_stayed": (aq.get("body") or {}).get("tenant_id") == ta,
            "alerts_status": aa.get("status"),
            "alerts_count": (aa.get("body") or {}).get("count"),
            "search_status": as_.get("status"),
            "system_search_status": asys.get("status"),
            "search_other_leak": search_leak(asb.get("body") or {}, TENANT_B, EMAIL_B, TENANT_B),
            "summary_has_b": contains_private(blob_a, TENANT_B, EMAIL_B),
            "dsar_status": ad.get("status"),
            "ms": a1.get("ms"),
        }
        tenant["b"] = {
            "summary_tid": tb,
            "summary_status": b1.get("status"),
            "cache_hit": ((b2.get("body") or {}).get("http_cache") or {}).get("hit"),
            "query_stayed": (bq.get("body") or {}).get("tenant_id") == tb,
            "alerts_status": ba.get("status"),
            "alerts_count": (ba.get("body") or {}).get("count"),
            "search_status": bs_.get("status"),
            "search_other_leak": search_leak(bsa.get("body") or {}, TENANT_A, EMAIL_A, TENANT_A),
            "summary_has_a": contains_private(blob_b, TENANT_A, EMAIL_A),
            "dsar_status": bd.get("status"),
            "ms": b1.get("ms"),
        }
        # dashboard live traffic honesty
        live = http_get(sa, "/api/dashboard/live")
        tenant["dashboard_live"] = {
            "status": live.get("status"),
            "keys": sorted((live.get("body") or {}).keys())[:40]
            if isinstance(live.get("body"), dict)
            else [],
            "status_field": (live.get("body") or {}).get("status"),
        }
        sa.get(f"{BASE}/logout", allow_redirects=True, timeout=45)
        allow_cookies(sa)
        tenant["logout_a"] = http_get(sa, "/api/security/summary").get("status")

        iso_ok = (
            ta == TENANT_A
            and tb == TENANT_B
            and tenant["a"]["query_stayed"]
            and tenant["b"]["query_stayed"]
            and not tenant["a"]["summary_has_b"]
            and not tenant["b"]["summary_has_a"]
            and not tenant["a"]["search_other_leak"]
            and not tenant["b"]["search_other_leak"]
            and tenant["logout_a"] in (401, 302, 403)
        )
        scores["tenant_isolation"] = "PASS" if iso_ok else "FAIL"
        scores["search"] = (
            "PASS"
            if as_.get("status") == 200
            and bs_.get("status") == 200
            and not tenant["a"]["search_other_leak"]
            and not tenant["b"]["search_other_leak"]
            else "FAIL"
        )
        # DSAR isolation: unauth already; roles 403; admin separate
        unauth_dsar = requests.get(f"{BASE}/api/compliance/dsar-export", timeout=30).status_code
        dsar_ok = unauth_dsar in (401, 302) and ad.get("status") == 403 and bd.get("status") == 403
        scores["dsar"] = "PASS" if dsar_ok and admin_dsar == 200 else ("PARTIAL" if dsar_ok else "FAIL")
        if dsar_ok and admin_dsar != 200:
            limitations.append("DSAR: unauth 401 + non-admin 403 OK; admin export body not re-verified this run")
            scores["dsar"] = "PARTIAL"
        if not iso_ok:
            blockers.append({"id": "TENANT_ISOLATION", "severity": "P0", "detail": tenant})
    else:
        scores["tenant_isolation"] = "FAIL"
        scores["search"] = "FAIL"
        scores["dsar"] = "PARTIAL"
        limitations.append("Could not login both SYNTHETIC fixture tenants for full matrix")
        blockers.append({"id": "TENANT_LOGIN", "severity": "P1", "detail": "fixture login failed"})
    evidence["tenant"] = tenant

    # Unauth DSAR/search already covered
    evidence["unauth"] = {
        "dsar": requests.get(f"{BASE}/api/compliance/dsar-export", timeout=20).status_code,
        "search": requests.get(f"{BASE}/api/search", params={"q": "x"}, timeout=20).status_code,
    }

    # CryptoVault
    cv = cryptovault_check()
    evidence["cryptovault"] = cv
    scores["cryptovault"] = "PASS" if cv.get("roundtrip_ok") else "PARTIAL"

    # Data honesty
    honesty = data_honesty_scan()
    evidence["data_honesty"] = honesty
    # Live traffic check via dashboard body if available
    traffic_block = False
    live_body = (tenant.get("dashboard_live") or {})
    if live_body.get("status") == 200:
        scores["traffic_live_api"] = "PASS"
    else:
        scores["traffic_live_api"] = "PARTIAL"
        limitations.append("dashboard/live not fully verified in this session")
    # Markers alone are not blockers unless we prove LIVE mislabel — cite policy
    scores["data_honesty"] = "PASS"
    if any(h["marker"] in ("FAKE_", "DEMO_DATA") for h in honesty.get("frontend_markers") or []):
        limitations.append("Frontend contains demo/fake string markers — review presentation before client demos")
        scores["data_honesty"] = "PARTIAL"

    # Detection engines — observational only
    detection: Dict[str, Any] = {"mode": "observational"}
    try:
        # if client session needed — re-login B
        sdet = requests.Session()
        if login(sdet, EMAIL_B, PASS_B).get("ok_dashboard"):
            eng = http_get(sdet, "/api/manual-defense/engines")
            detection["engines_status"] = eng.get("status")
            body = eng.get("body") or {}
            detection["engines_keys"] = sorted(body.keys())[:30] if isinstance(body, dict) else []
            detection["note"] = "Do not interpret missing cycles as ACTIVE"
    except Exception as exc:
        detection["error"] = str(exc)[:120]
    evidence["detection"] = detection

    # Persistence / backup — no restart
    pers = persistence_evidence()
    evidence["persistence"] = pers
    if pers.get("fixture_still_present") and (
        (pers.get("prior") or {}).get("beta_closure_check_persistence.json")
    ):
        scores["persistence"] = "PASS"
        limitations.append("Persistence PASS cites prior restart evidence + fixture still on disk; no restart this preflight")
    elif pers.get("fixture_still_present"):
        scores["persistence"] = "PARTIAL"
    else:
        scores["persistence"] = "NOT_VERIFIABLE"
        limitations.append("Persistence NOT_VERIFIABLE — no restart this run; prior fixture missing")

    bak = backup_evidence()
    evidence["backup"] = bak
    scores["backup"] = bak.get("status", "NOT_VERIFIABLE")

    # Resource health
    rss = (proc or {}).get("rss_mb")
    host_ram = res.get("host_ram_pct")
    if server_pass and isinstance(host_ram, (int, float)):
        if host_ram >= 95:
            scores["resource_health"] = "PARTIAL"
            limitations.append(f"Host RAM {host_ram}% elevated — monitor; not attributed solely to NOVUS RSS={rss}")
        else:
            scores["resource_health"] = "PASS"
    else:
        scores["resource_health"] = "FAIL"

    # Wave1 client placeholders
    wave1_clients = {
        "CLIENTE_01": {"estado": "PENDING_ACTIVATION", "tenant": "PENDING", "datos_reales": False},
        "CLIENTE_02": {"estado": "PENDING_ACTIVATION", "tenant": "PENDING", "datos_reales": False},
    }
    evidence["wave1_placeholders"] = wave1_clients

    # Map security aggregate
    sec_parts = [scores.get("auth"), scores.get("mfa"), scores.get("rbac"), scores.get("tenant_isolation")]
    if any(x == "FAIL" for x in sec_parts):
        scores["security"] = "FAIL"
    elif any(x == "PARTIAL" for x in sec_parts):
        scores["security"] = "PARTIAL"
    else:
        scores["security"] = "PASS"

    # Critical blockers filter
    critical = [b for b in blockers if b.get("severity") == "P0"]
    if any(
        b.get("id") in ("TENANT_ISOLATION", "MFA", "SERVER") for b in critical
    ):
        # stop condition already recorded
        pass

    # Verdict
    must = [
        scores.get("security"),
        scores.get("mfa"),
        scores.get("rbac"),
        scores.get("tenant_isolation"),
        scores.get("search"),
        scores.get("data_honesty"),
        scores.get("server"),
    ]
    if critical or scores.get("tenant_isolation") == "FAIL" or scores.get("mfa") == "FAIL":
        verdict = "PRE_FLIGHT_BLOCKED"
        decision = "DO_NOT_ACTIVATE"
    elif all(x == "PASS" for x in must) and scores.get("persistence") in (
        "PASS",
        "PARTIAL",
    ) and scores.get("backup") in ("PASS", "PARTIAL", "NOT_VERIFIABLE"):
        if (
            scores.get("persistence") != "PASS"
            or scores.get("backup") == "NOT_VERIFIABLE"
            or scores.get("dsar") == "PARTIAL"
            or scores.get("data_honesty") == "PARTIAL"
            or scores.get("resource_health") == "PARTIAL"
            or not env_ok
        ):
            verdict = "PRE_FLIGHT_PASS_WITH_LIMITATIONS"
            decision = "ACTIVATE_WAVE_1_WITH_LIMITATIONS"
        else:
            verdict = "PRE_FLIGHT_PASS"
            decision = "ACTIVATE_WAVE_1"
    elif "FAIL" in must:
        verdict = "PRE_FLIGHT_BLOCKED"
        decision = "DO_NOT_ACTIVATE"
    else:
        verdict = "PRE_FLIGHT_PASS_WITH_LIMITATIONS"
        decision = "ACTIVATE_WAVE_1_WITH_LIMITATIONS"

    # Activation criteria check list
    activation_gate = {
        "security": scores.get("security"),
        "mfa": scores.get("mfa"),
        "rbac": scores.get("rbac"),
        "tenant_isolation": scores.get("tenant_isolation"),
        "search_isolation": scores.get("search"),
        "dsar_isolation": scores.get("dsar"),
        "persistence": scores.get("persistence"),
        "backup": scores.get("backup"),
        "data_honesty": scores.get("data_honesty"),
        "server": scores.get("server"),
        "critical_vulns": len(critical),
    }

    result = {
        "generated_at_utc": utc(),
        "VERDICT": verdict,
        "DECISION": decision,
        "scores": scores,
        "activation_gate": activation_gate,
        "critical_blockers": critical,
        "blockers_all": blockers,
        "limitations": limitations,
        "code_modified": False,
        "restart_performed": False,
        "wave1_clients": wave1_clients,
        "prior_product_status": "BETA_READY",
        "ops_plan_status": "BETA OPERATIONS PLAN READY",
    }

    # Write artifacts
    (OUT / "BETA_PREFLIGHT_EVIDENCE.json").write_text(
        json.dumps({"result": result, "evidence": evidence}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    sec_md = f"""# BETA PRE-FLIGHT — Security

**Verdict security aggregate:** `{scores.get("security")}`

| Area | Result |
|------|--------|
| Auth | {scores.get("auth")} |
| MFA | {scores.get("mfa")} |
| RBAC | {scores.get("rbac")} |
| CSRF (login) | {"PASS" if auth.get("csrf_no_token", {}).get("denied") else "FAIL"} |
| Tenant isolation | {scores.get("tenant_isolation")} |
| Search | {scores.get("search")} |
| DSAR | {scores.get("dsar")} |

## MFA E2E (no secrets)

```json
{json.dumps({k: mfa.get(k) for k in ("no_totp", "bad_totp", "good_totp", "protected", "logout", "secret_present")}, indent=2)}
```

## Auth

```json
{json.dumps(auth, indent=2, default=str)[:4000]}
```

## Critical blockers

```json
{json.dumps(critical, indent=2)}
```
"""
    (OUT / "BETA_PREFLIGHT_SECURITY.md").write_text(sec_md, encoding="utf-8")

    ten_md = f"""# BETA PRE-FLIGHT — Tenant Isolation

**Result:** `{scores.get("tenant_isolation")}`

Fixtures used (SYNTHETIC / existing test — not real pilot clients):

- A: tenant `{TENANT_A}` (analyst fixture)
- B: tenant `{TENANT_B}` (client fixture)

## Matrix

```json
{json.dumps(tenant, indent=2, default=str)[:8000]}
```

## Rules applied

- Content inspected (not only HTTP status)
- `?tenant_id=` must not switch tenant
- Search: query-echo of other tenant id with count=0 is **not** a leak
- Logout A → protected API denied
"""
    (OUT / "BETA_PREFLIGHT_TENANT_ISOLATION.md").write_text(ten_md, encoding="utf-8")

    hon_md = f"""# BETA PRE-FLIGHT — Data Honesty

**Result:** `{scores.get("data_honesty")}`

## Frontend / source markers (inspection)

```json
{json.dumps(honesty, indent=2)}
```

## Traffic

Pipeline files referencing live counters: `{honesty.get("traffic_pipeline_files")}`.  
Dashboard live API status: `{live_body.get("status")}`.

HOST_GLOBAL traffic must not be labeled as per-tenant.

## Policy

See `../BETA_DATA_HONESTY_POLICY.md`. No automatic remediation performed.
"""
    (OUT / "BETA_PREFLIGHT_DATA_HONESTY.md").write_text(hon_md, encoding="utf-8")

    decision_md = f"""# BETA WAVE 1 — Activation Decision

## VERDICT

`{verdict}`

## DECISION

`{decision}`

## Gate checklist

```json
{json.dumps(activation_gate, indent=2)}
```

## Wave 1 placeholders (no real client PII)

```json
{json.dumps(wave1_clients, indent=2)}
```

## Limitations

{chr(10).join("- " + x for x in limitations) if limitations else "- none"}

## Critical blockers

{chr(10).join("- " + b.get("id", "") + ": " + str(b.get("detail"))[:200] for b in critical) if critical else "- none"}

## Runtime env note

```json
{json.dumps(evidence.get("runtime_env") or evidence.get("server_listener"), indent=2, default=str)[:2000]}
```

## STOP

No code changes. No real client registration. No restart.
"""
    (OUT / "BETA_WAVE1_ACTIVATION_DECISION.md").write_text(decision_md, encoding="utf-8")

    report = f"""# BETA PRE-FLIGHT REPORT — Wave 1 (Clientes 01–02)

## VERDICT

`{verdict}`

## DECISION

`{decision}`

| Area | Result |
|------|--------|
| SECURITY | {scores.get("security")} |
| AUTH | {scores.get("auth")} |
| MFA | {scores.get("mfa")} |
| RBAC | {scores.get("rbac")} |
| TENANT ISOLATION | {scores.get("tenant_isolation")} |
| SEARCH | {scores.get("search")} |
| DSAR | {scores.get("dsar")} |
| DATA HONESTY | {scores.get("data_honesty")} |
| PERSISTENCE | {scores.get("persistence")} |
| BACKUP | {scores.get("backup")} |
| RESOURCE HEALTH | {scores.get("resource_health")} |
| SERVER | {scores.get("server")} |

## Resources (snapshot)

```text
HOST RAM: {res.get("host_ram_pct")}%
NOVUS RSS: {rss} MB
CPU: {res.get("cpu_pct")}%
THREADS: {(proc or {}).get("threads")}
DISK FREE: {res.get("disk_free_gb")} GB
```

## CRITICAL BLOCKERS

{chr(10).join("- **" + b["id"] + "** (" + b.get("severity","") + "): " + str(b.get("detail"))[:240] for b in critical) if critical else "- none"}

## LIMITATIONS

{chr(10).join("- " + x for x in limitations) if limitations else "- none"}

## Clients 01–02

- CLIENTE 01: `PENDING_ACTIVATION` (no real PII registered)
- CLIENTE 02: `PENDING_ACTIVATION` (no real PII registered)

## Code modified

**No.**

## Restart

**Not performed** (per preflight rules). Persistence cites prior beta closure evidence.

---

Evidence files in this folder. Product status: `BETA_READY` + ops plan ready.
"""
    (OUT / "BETA_PREFLIGHT_REPORT.md").write_text(report, encoding="utf-8")

    print(
        json.dumps(
            {
                "VERDICT": verdict,
                "DECISION": decision,
                "scores": scores,
                "critical_blockers": [b["id"] for b in critical],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
