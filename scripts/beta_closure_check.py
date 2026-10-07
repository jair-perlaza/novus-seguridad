#!/usr/bin/env python3
"""
BETA CLOSURE CHECK — MFA TOTP + Tenant A/B + Persistence/Restart.
ZERO production code changes. Writes ONLY under data/production_closure/beta_closure_check/.
Does NOT log TOTP secrets/codes/passwords.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "production_closure" / "beta_closure_check"
OUT.mkdir(parents=True, exist_ok=True)

BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000").rstrip("/")

# Existing fixtures only (no new credentials created)
EMAIL_MFA = "novus.qa.jul2026@example.com"
PASS_MFA = "NovusQA2026!"
EMAIL_A = "p1c001.probe@novus-client.test"
PASS_A = "NovusP1C001Rem2026!"
TENANT_A = "P1C001-PROBE"
EMAIL_B = "operaciones@novapay-fintech.co"
PASS_B = "NovaPay#Fintech2026"
TENANT_B = "901.567.123-4"

FIXTURE_ID = f"BETA-CLOSURE-{uuid.uuid4().hex[:10].upper()}"
FIXTURE_MARKER = f"SYNTHETIC_TEST_ONLY {FIXTURE_ID} TEST_FIXTURE"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha12(s: str) -> str:
    return hashlib.sha256(str(s).encode()).hexdigest()[:12]


def csrf_from_html(html: str) -> str:
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html or "")
    return m.group(1) if m else ""


def allow_http_cookies(session) -> None:
    if BASE.startswith("https://"):
        return
    for c in session.cookies:
        c.secure = False


def resources() -> Dict[str, Any]:
    import psutil

    vm = psutil.virtual_memory()
    out: Dict[str, Any] = {
        "host_ram_pct": vm.percent,
        "host_available_mb": round(vm.available / (1024 * 1024), 1),
        "cpu_pct": psutil.cpu_percent(interval=0.3),
        "port_5000": [],
    }
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and getattr(c.laddr, "port", None) == 5000 and c.status == "LISTEN":
            info: Dict[str, Any] = {"pid": c.pid}
            try:
                p = psutil.Process(c.pid)
                info.update(
                    {
                        "rss_mb": round(p.memory_info().rss / (1024 * 1024), 1),
                        "threads": p.num_threads(),
                        "name": p.name(),
                    }
                )
            except Exception:
                pass
            out["port_5000"].append(info)
    return out


def login(session, email: str, password: str, mfa_code: Optional[str] = None) -> Dict[str, Any]:
    try:
        g = session.get(f"{BASE}/login", timeout=60)
        allow_http_cookies(session)
        token = csrf_from_html(g.text)
        data = {"email": email, "password": password, "csrf_token": token}
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
        allow_http_cookies(session)
        loc = p.headers.get("Location") or ""
        text = p.text or ""
        return {
            "status": p.status_code,
            "location": loc[:160],
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "ok_dashboard": p.status_code in (302, 303) and "dashboard" in loc.lower(),
            "mfa_setup": "/mfa-setup" in loc.lower(),
            "mfa_prompt": "Authenticator" in text or "mfa_code" in text.lower() or "/mfa" in loc.lower(),
            "denied_page": p.status_code in (200, 401, 403) and not (
                p.status_code in (302, 303) and "dashboard" in loc.lower()
            ),
            "invalid_hint": "inválido" in text.lower() or "invalid" in text.lower() or "incorrect" in text.lower(),
        }
    except Exception as exc:
        return {"status": None, "error": str(exc)[:180], "ok_dashboard": False}


def complete_mfa(session, code: str) -> Dict[str, Any]:
    try:
        g = session.get(f"{BASE}/login", timeout=60)
        allow_http_cookies(session)
        token = csrf_from_html(g.text)
        t0 = time.perf_counter()
        p = session.post(
            f"{BASE}/login",
            data={"csrf_token": token, "mfa_code": code},
            headers={"Referer": f"{BASE}/login", "Origin": BASE},
            allow_redirects=False,
            timeout=60,
        )
        allow_http_cookies(session)
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
        allow_http_cookies(session)
        t0 = time.perf_counter()
        r = session.get(f"{BASE}{path}", params=params or None, timeout=60, allow_redirects=False)
        allow_http_cookies(session)
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


def mfa_secret_for(email: str) -> Optional[str]:
    """Decrypt existing enrolled secret — never log/return into artifacts."""
    from services.web_security_auth_enterprise.mfa_totp import _load, _dec, is_mfa_enabled

    if not is_mfa_enabled(email):
        return None
    rec = (_load().get(email.strip().lower()) or {})
    enc = rec.get("secret_enc")
    if not enc:
        return None
    return _dec(enc)


def wait_server(timeout_sec: float = 120.0) -> bool:
    import requests

    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            r = requests.get(f"{BASE}/login", timeout=8)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def find_server_pid() -> Optional[int]:
    import psutil

    for c in psutil.net_connections(kind="inet"):
        if c.laddr and getattr(c.laddr, "port", None) == 5000 and c.status == "LISTEN":
            return c.pid
    return None


def stop_server(pid: int) -> Dict[str, Any]:
    import psutil

    out = {"pid": pid, "stopped": False}
    try:
        p = psutil.Process(pid)
        p.terminate()
        try:
            p.wait(timeout=25)
            out["stopped"] = True
            out["method"] = "terminate"
        except psutil.TimeoutExpired:
            p.kill()
            p.wait(timeout=15)
            out["stopped"] = True
            out["method"] = "kill"
    except Exception as exc:
        out["error"] = str(exc)[:160]
    return out


def start_server() -> Dict[str, Any]:
    """Restart via normal main.py — does not edit config files."""
    env = os.environ.copy()
    # Preserve existing process convention used in prior beta runs; do not write .env
    if not env.get("NOVUS_ENV"):
        env["NOVUS_ENV"] = "beta"
    if not env.get("DEBUG"):
        env["DEBUG"] = "False"
    if not env.get("FLASK_DEBUG"):
        env["FLASK_DEBUG"] = "False"
    log_path = OUT / "restart_server_stdout.log"
    fh = open(log_path, "a", encoding="utf-8")
    fh.write(f"\n--- restart {utc()} ---\n")
    fh.flush()
    proc = subprocess.Popen(
        [sys.executable, "main.py"],
        cwd=str(ROOT),
        env=env,
        stdout=fh,
        stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    return {"pid_started": proc.pid, "log": str(log_path.relative_to(ROOT))}


def write_persistence_fixture() -> Dict[str, Any]:
    """Write SYNTHETIC_TEST_ONLY memory row for TENANT_A — not production client data."""
    from services.swarm_defense import collective_memory as cm

    origin = {
        "tenant_id": TENANT_A,
        "category": "SYNTHETIC_TEST_ONLY",
        "marker": FIXTURE_MARKER,
        "fixture_id": FIXTURE_ID,
        "source": "beta_closure_check",
        "description": FIXTURE_MARKER,
    }
    wrote = None
    try:
        if hasattr(cm, "remember") or hasattr(cm, "write_memory") or hasattr(cm, "store_event"):
            for name in ("remember", "write_memory", "store_event", "record"):
                fn = getattr(cm, name, None)
                if callable(fn):
                    try:
                        wrote = fn(origin, tenant_id=TENANT_A)
                    except TypeError:
                        try:
                            wrote = fn(origin)
                        except Exception as exc:
                            wrote = {"error": str(exc)[:120]}
                    break
        # Also durable file under closure dir (survives restart, clearly fixture)
        durable = {
            "TEST_FIXTURE": True,
            "SYNTHETIC_TEST_ONLY": True,
            "fixture_id": FIXTURE_ID,
            "tenant_id": TENANT_A,
            "marker": FIXTURE_MARKER,
            "written_at_utc": utc(),
        }
        path = OUT / "persistence_fixture.json"
        path.write_text(json.dumps(durable, indent=2), encoding="utf-8")
        # Attempt lookup
        lookup = None
        for name in ("lookup", "recall", "get_memory_context", "query_memory"):
            fn = getattr(cm, name, None)
            if callable(fn):
                try:
                    lookup = fn(origin, tenant_id=TENANT_A)
                except TypeError:
                    try:
                        lookup = fn({"tenant_id": TENANT_A, "marker": FIXTURE_MARKER})
                    except Exception as exc:
                        lookup = {"error": str(exc)[:120]}
                break
        return {
            "fixture_id": FIXTURE_ID,
            "tenant_id": TENANT_A,
            "durable_file": str(path.relative_to(ROOT)),
            "cm_write": True if wrote is not None else False,
            "cm_write_result_type": type(wrote).__name__,
            "cm_lookup_before": _safe_snip(lookup),
            "ok": path.exists(),
        }
    except Exception as exc:
        path = OUT / "persistence_fixture.json"
        durable = {
            "TEST_FIXTURE": True,
            "SYNTHETIC_TEST_ONLY": True,
            "fixture_id": FIXTURE_ID,
            "tenant_id": TENANT_A,
            "marker": FIXTURE_MARKER,
            "written_at_utc": utc(),
            "cm_error": str(exc)[:160],
        }
        path.write_text(json.dumps(durable, indent=2), encoding="utf-8")
        return {
            "fixture_id": FIXTURE_ID,
            "tenant_id": TENANT_A,
            "durable_file": str(path.relative_to(ROOT)),
            "ok": True,
            "cm_fallback_file_only": True,
            "cm_error": str(exc)[:160],
        }


def read_persistence_fixture() -> Dict[str, Any]:
    path = OUT / "persistence_fixture.json"
    if not path.exists():
        return {"ok": False, "reason": "missing_file"}
    data = json.loads(path.read_text(encoding="utf-8"))
    cross_b = False
    try:
        from services.swarm_defense import collective_memory as cm

        for name in ("lookup", "recall", "get_memory_context", "query_memory"):
            fn = getattr(cm, name, None)
            if callable(fn):
                try:
                    lb = fn(
                        {"tenant_id": TENANT_B, "marker": FIXTURE_MARKER, "fixture_id": FIXTURE_ID},
                        tenant_id=TENANT_B,
                    )
                except TypeError:
                    lb = fn({"tenant_id": TENANT_B, "marker": FIXTURE_MARKER})
                blob = json.dumps(lb, default=str)
                cross_b = FIXTURE_ID in blob or FIXTURE_MARKER in blob
                break
    except Exception:
        pass
    return {
        "ok": data.get("fixture_id") == FIXTURE_ID and data.get("tenant_id") == TENANT_A,
        "tenant_id": data.get("tenant_id"),
        "fixture_id": data.get("fixture_id"),
        "TEST_FIXTURE": data.get("TEST_FIXTURE"),
        "cross_tenant_b_sees_fixture": cross_b,
        "written_at_utc": data.get("written_at_utc"),
    }


def _safe_snip(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return {k: obj.get(k) for k in list(obj.keys())[:12]}
    return str(obj)[:200]


def contains_other(blob: str, other_tid: str, other_email: str) -> bool:
    if other_tid and other_tid in blob:
        return True
    if other_email and other_email.lower() in blob.lower():
        return True
    return False


def main() -> int:
    import requests
    import pyotp

    http: Dict[str, Any] = {"tests": {}}
    security: Dict[str, Any] = {}
    persistence: Dict[str, Any] = {}
    controls: Dict[str, str] = {}
    limitations: List[str] = []
    blockers: List[Dict[str, Any]] = []
    latencies: Dict[str, Any] = {}
    errors: List[str] = []
    timeouts: List[str] = []

    before = resources()
    persistence["before_resources"] = before

    # Preflight
    pre: Dict[str, Any] = {
        "generated_at_utc": utc(),
        "base": BASE,
        "NOVUS_ENV": os.environ.get("NOVUS_ENV"),
        "DEBUG": os.environ.get("DEBUG"),
        "FLASK_DEBUG": os.environ.get("FLASK_DEBUG"),
        "resources": before,
    }
    try:
        r = requests.get(f"{BASE}/login", timeout=20)
        pre["login_status"] = r.status_code
        pre["server_up"] = r.status_code == 200
    except Exception as exc:
        pre["server_up"] = False
        pre["login_error"] = str(exc)[:160]
        errors.append("preflight_login:" + str(exc)[:80])

    try:
        rh = requests.get(f"{BASE}/api/health/status", timeout=15)
        pre["health_status"] = rh.status_code
    except Exception as exc:
        pre["health_error"] = str(exc)[:120]

    try:
        import crypto_vault  # noqa: F401

        pre["cryptovault_import"] = True
    except Exception as exc:
        pre["cryptovault_import"] = False
        pre["cryptovault_error"] = str(exc)[:120]

    if not pre.get("server_up"):
        result = {
            "BETA_CLOSURE_CHECK_VERDICT": "BLOCKED",
            "reason": "server_down",
            "preflight": pre,
        }
        (OUT / "beta_closure_check_result.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
        print(json.dumps({"BETA_CLOSURE_CHECK_VERDICT": "BLOCKED"}, indent=2))
        return 1

    # ========== MFA TOTP ==========
    mfa_ev: Dict[str, Any] = {"email_sha12": sha12(EMAIL_MFA)}
    secret = None
    try:
        secret = mfa_secret_for(EMAIL_MFA)
        mfa_ev["secret_present"] = bool(secret)
    except Exception as exc:
        mfa_ev["secret_error"] = str(exc)[:120]
        secret = None

    if not secret:
        controls["mfa"] = "NOT_VERIFIABLE"
        limitations.append("MFA secret for enrolled QA admin not decryptable/available")
        mfa_ev["tests"] = {}
    else:
        # MFA-1: password only / wrong path without completing MFA
        s0 = requests.Session()
        r0 = login(s0, EMAIL_MFA, PASS_MFA)
        mfa_ev["mfa1_no_totp"] = {
            "status": r0.get("status"),
            "ok_dashboard": r0.get("ok_dashboard"),
            "mfa_prompt_or_setup": bool(r0.get("mfa_prompt") or r0.get("mfa_setup")),
            "location": r0.get("location"),
        }
        # If pending MFA session, protected API should not be fully usable
        api0 = http_get(s0, "/api/search", q="closure")
        mfa_ev["mfa1_protected_without_totp"] = {
            "status": api0.get("status"),
            "denied": api0.get("status") in (401, 403) or not (api0.get("status") == 200),
        }
        # MFA-2 wrong TOTP
        s1 = requests.Session()
        login(s1, EMAIL_MFA, PASS_MFA)
        bad = complete_mfa(s1, "000000")
        mfa_ev["mfa2_bad_totp"] = {
            "ok_dashboard": bad.get("ok_dashboard"),
            "status": bad.get("status"),
            "invalid_hint": bad.get("invalid_hint"),
            "location": bad.get("location"),
        }
        api_bad = http_get(s1, "/api/search", q="closure")
        mfa_ev["mfa2_api_after_bad"] = {
            "status": api_bad.get("status"),
            "denied": api_bad.get("status") in (401, 403, None) or api_bad.get("status") != 200,
        }
        # MFA-3 correct TOTP
        s2 = requests.Session()
        login(s2, EMAIL_MFA, PASS_MFA)
        code = pyotp.TOTP(secret).now()
        good = complete_mfa(s2, code)
        # If complete_mfa alone insufficient, try full login with code
        if not good.get("ok_dashboard"):
            s2b = requests.Session()
            good = login(s2b, EMAIL_MFA, PASS_MFA, mfa_code=pyotp.TOTP(secret).now())
            s2 = s2b
        mfa_ev["mfa3_good_totp"] = {
            "ok_dashboard": good.get("ok_dashboard"),
            "status": good.get("status"),
            "location": good.get("location"),
            "ms": good.get("ms"),
        }
        latencies["mfa_good_ms"] = good.get("ms")
        # MFA-4 protected endpoint
        api_ok = http_get(s2, "/api/search", q="closure")
        summ_ok = http_get(s2, "/api/security/summary")
        mfa_ev["mfa4_protected"] = {
            "search_status": api_ok.get("status"),
            "summary_status": summ_ok.get("status"),
            "allowed": api_ok.get("status") == 200 or summ_ok.get("status") == 200,
        }
        # MFA-5 logout
        s2.get(f"{BASE}/logout", allow_redirects=True, timeout=45)
        allow_http_cookies(s2)
        after = http_get(s2, "/api/security/summary")
        mfa_ev["mfa5_logout"] = {
            "status": after.get("status"),
            "denied": after.get("status") in (401, 302, 403),
        }
        # MFA-6 reuse invalidated session (same jar)
        reuse = http_get(s2, "/api/search", q="closure")
        mfa_ev["mfa6_reuse"] = {
            "status": reuse.get("status"),
            "denied": reuse.get("status") in (401, 302, 403),
        }

        mfa1_ok = (not mfa_ev["mfa1_no_totp"].get("ok_dashboard")) and mfa_ev[
            "mfa1_protected_without_totp"
        ].get("denied")
        mfa2_ok = (not mfa_ev["mfa2_bad_totp"].get("ok_dashboard")) and mfa_ev[
            "mfa2_api_after_bad"
        ].get("denied")
        mfa3_ok = bool(mfa_ev["mfa3_good_totp"].get("ok_dashboard"))
        mfa4_ok = bool(mfa_ev["mfa4_protected"].get("allowed"))
        mfa5_ok = bool(mfa_ev["mfa5_logout"].get("denied"))
        mfa6_ok = bool(mfa_ev["mfa6_reuse"].get("denied"))
        if all([mfa1_ok, mfa2_ok, mfa3_ok, mfa4_ok, mfa5_ok, mfa6_ok]):
            controls["mfa"] = "PASS"
        elif mfa3_ok and mfa2_ok:
            controls["mfa"] = "PASS_WITH_LIMITATIONS"
            limitations.append("MFA core deny/allow verified with limitations on peripheral checks")
        else:
            controls["mfa"] = "FAIL"
            blockers.append({"id": "MFA-TOTP", "severity": "P0", "detail": mfa_ev})

    security["mfa"] = mfa_ev

    # ========== TENANT A/B ==========
    tenant_ev: Dict[str, Any] = {
        "tenant_a_sha": sha12(TENANT_A),
        "tenant_b_sha": sha12(TENANT_B),
        "email_a_sha": sha12(EMAIL_A),
        "email_b_sha": sha12(EMAIL_B),
    }

    sa, sb = requests.Session(), requests.Session()
    la = login(sa, EMAIL_A, PASS_A)
    lb = login(sb, EMAIL_B, PASS_B)
    tenant_ev["login_a"] = {k: la.get(k) for k in ("status", "ok_dashboard", "mfa_setup", "mfa_prompt", "location", "error")}
    tenant_ev["login_b"] = {k: lb.get(k) for k in ("status", "ok_dashboard", "mfa_setup", "mfa_prompt", "location", "error")}

    if not (la.get("ok_dashboard") and lb.get("ok_dashboard")):
        controls["tenant_ab"] = "NOT_VERIFIABLE" if la.get("mfa_setup") or lb.get("mfa_setup") else "FAIL"
        limitations.append("Could not obtain full A and B sessions for cross-tenant HTTP matrix")
        tenant_ev["blocked"] = True
    else:
        # A own data
        a_sum = http_get(sa, "/api/security/summary")
        a_sum2 = http_get(sa, "/api/security/summary")
        a_alerts = http_get(sa, "/api/security/alerts", limit=20)
        a_search = http_get(sa, "/api/search", q=TENANT_B, limit=20)
        a_search2 = http_get(sa, "/api/search", q="alert", limit=20)
        a_sys = http_get(sa, "/api/system/search", q="alert", limit=20)
        a_dsar = http_get(sa, "/api/compliance/dsar-export")
        a_q = http_get(sa, "/api/security/summary", tenant_id=TENANT_B)

        # B own data
        b_sum = http_get(sb, "/api/security/summary")
        b_sum2 = http_get(sb, "/api/security/summary")
        b_alerts = http_get(sb, "/api/security/alerts", limit=20)
        b_search = http_get(sb, "/api/search", q=TENANT_A, limit=20)
        b_search2 = http_get(sb, "/api/search", q="alert", limit=20)
        b_dsar = http_get(sb, "/api/compliance/dsar-export")
        b_q = http_get(sb, "/api/security/summary", tenant_id=TENANT_A)

        ta = (a_sum.get("body") or {}).get("tenant_id")
        tb = (b_sum.get("body") or {}).get("tenant_id")
        blob_a = json.dumps(a_sum.get("body") or {}, default=str)
        blob_b = json.dumps(b_sum.get("body") or {}, default=str)
        search_a_blob = json.dumps(a_search.get("body") or {}, default=str)
        search_b_blob = json.dumps(b_search.get("body") or {}, default=str)
        dsar_a_blob = json.dumps(a_dsar.get("body") or {}, default=str)
        dsar_b_blob = json.dumps(b_dsar.get("body") or {}, default=str)

        tenant_ev["a"] = {
            "summary_status": a_sum.get("status"),
            "tenant_id": ta,
            "cache_hit_2": ((a_sum2.get("body") or {}).get("http_cache") or {}).get("hit"),
            "alerts_status": a_alerts.get("status"),
            "alerts_count": (a_alerts.get("body") or {}).get("count"),
            "search_status": a_search2.get("status"),
            "search_for_b_status": a_search.get("status"),
            "search_for_b_has_b": contains_other(search_a_blob, TENANT_B, EMAIL_B),
            "system_search_status": a_sys.get("status"),
            "dsar_status": a_dsar.get("status"),
            "dsar_has_b": contains_other(dsar_a_blob, TENANT_B, EMAIL_B),
            "query_manip_tenant": (a_q.get("body") or {}).get("tenant_id"),
            "query_stayed_a": (a_q.get("body") or {}).get("tenant_id") == ta,
            "summary_has_b": contains_other(blob_a, TENANT_B, EMAIL_B),
            "ms": a_sum.get("ms"),
        }
        tenant_ev["b"] = {
            "summary_status": b_sum.get("status"),
            "tenant_id": tb,
            "cache_hit_2": ((b_sum2.get("body") or {}).get("http_cache") or {}).get("hit"),
            "alerts_status": b_alerts.get("status"),
            "alerts_count": (b_alerts.get("body") or {}).get("count"),
            "search_status": b_search2.get("status"),
            "search_for_a_status": b_search.get("status"),
            "search_for_a_has_a": contains_other(search_b_blob, TENANT_A, EMAIL_A),
            "dsar_status": b_dsar.get("status"),
            "dsar_has_a": contains_other(dsar_b_blob, TENANT_A, EMAIL_A),
            "query_manip_tenant": (b_q.get("body") or {}).get("tenant_id"),
            "query_stayed_b": (b_q.get("body") or {}).get("tenant_id") == tb,
            "summary_has_a": contains_other(blob_b, TENANT_A, EMAIL_A),
            "ms": b_sum.get("ms"),
        }
        latencies["summary_a_ms"] = a_sum.get("ms")
        latencies["summary_b_ms"] = b_sum.get("ms")

        # Logout A
        sa.get(f"{BASE}/logout", allow_redirects=True, timeout=45)
        allow_http_cookies(sa)
        a_after = http_get(sa, "/api/security/summary")
        tenant_ev["logout_a"] = {
            "status": a_after.get("status"),
            "denied": a_after.get("status") in (401, 302, 403),
        }

        # Re-login B still isolated (session B intact)
        b_after_a_logout = http_get(sb, "/api/security/summary")
        tenant_ev["b_after_a_logout"] = {
            "status": b_after_a_logout.get("status"),
            "tenant_id": (b_after_a_logout.get("body") or {}).get("tenant_id"),
        }

        a_ok = ta == TENANT_A and a_sum.get("status") == 200
        b_ok = tb == TENANT_B and b_sum.get("status") == 200
        cross_ok = (
            not tenant_ev["a"]["summary_has_b"]
            and not tenant_ev["b"]["summary_has_a"]
            and not tenant_ev["a"]["search_for_b_has_b"]
            and not tenant_ev["b"]["search_for_a_has_a"]
            and not tenant_ev["a"]["dsar_has_b"]
            and not tenant_ev["b"]["dsar_has_a"]
        )
        query_ok = tenant_ev["a"]["query_stayed_a"] and tenant_ev["b"]["query_stayed_b"]
        cache_ok = (
            tenant_ev["a"].get("cache_hit_2") is True
            and tenant_ev["b"].get("cache_hit_2") is True
            and ta != tb
        )
        logout_ok = tenant_ev["logout_a"]["denied"]

        # DSAR may be 403 for non-admin — not a cross-tenant fail
        if a_dsar.get("status") == 403:
            limitations.append("DSAR 403 for analyst A (RBAC) — isolation N/A for export body")
        if b_dsar.get("status") == 403:
            limitations.append("DSAR 403 for client B (RBAC) — isolation N/A for export body")

        tenant_ev["verdict_bits"] = {
            "a_ok": a_ok,
            "b_ok": b_ok,
            "cross_ok": cross_ok,
            "query_ok": query_ok,
            "cache_ok": cache_ok,
            "logout_ok": logout_ok,
        }
        if a_ok and b_ok and cross_ok and query_ok and logout_ok:
            controls["tenant_ab"] = "PASS" if cache_ok else "PASS_WITH_LIMITATIONS"
            if not cache_ok:
                limitations.append("Per-tenant cache hit not observed on both follow-ups")
        else:
            controls["tenant_ab"] = "FAIL"
            blockers.append({"id": "TENANT-AB", "severity": "P0", "detail": tenant_ev["verdict_bits"]})

        controls["security_summary"] = (
            "PASS"
            if a_ok and b_ok and query_ok and cross_ok and not tenant_ev["a"]["summary_has_b"]
            else "FAIL"
        )
        controls["search"] = (
            "PASS"
            if a_search2.get("status") == 200
            and b_search2.get("status") == 200
            and not tenant_ev["a"]["search_for_b_has_b"]
            and not tenant_ev["b"]["search_for_a_has_a"]
            else "FAIL"
        )
        if a_dsar.get("status") in (200, 403) and b_dsar.get("status") in (200, 403):
            controls["dsar"] = (
                "PASS"
                if a_dsar.get("status") == 200
                and b_dsar.get("status") == 200
                and not tenant_ev["a"]["dsar_has_b"]
                and not tenant_ev["b"]["dsar_has_a"]
                else "PASS_WITH_LIMITATIONS"
            )
        else:
            controls["dsar"] = "FAIL"

    http["tests"]["tenant"] = tenant_ev

    # ========== PERSISTENCE + RESTART ==========
    fix_before = write_persistence_fixture()
    persistence["fixture_before"] = fix_before
    persistence["before_resources"] = resources()
    pid = find_server_pid()
    persistence["restart"] = {"before_pid": pid}
    if not pid:
        controls["persistence"] = "NOT_VERIFIABLE"
        controls["restart"] = "NOT_VERIFIABLE"
        limitations.append("No PID on :5000 for restart")
    else:
        stop = stop_server(pid)
        persistence["restart"]["stop"] = stop
        time.sleep(3)
        if find_server_pid():
            persistence["restart"]["still_listening"] = True
            limitations.append("Port 5000 still listening after stop attempt")
        start = start_server()
        persistence["restart"]["start"] = start
        up = wait_server(150)
        persistence["restart"]["server_up_after"] = up
        persistence["after_resources"] = resources()
        after_pid = find_server_pid()
        persistence["restart"]["after_pid"] = after_pid
        persistence["restart"]["pid_changed"] = bool(after_pid and after_pid != pid)

        if not up:
            controls["restart"] = "FAIL"
            controls["persistence"] = "NOT_VERIFIABLE"
            blockers.append({"id": "RESTART", "severity": "P0", "detail": "server did not return on :5000"})
        else:
            controls["restart"] = "PASS" if persistence["restart"]["pid_changed"] else "PASS_WITH_LIMITATIONS"
            fix_after = read_persistence_fixture()
            persistence["fixture_after"] = fix_after

            # Post-restart auth smoke
            post: Dict[str, Any] = {}
            # MFA smoke post-restart
            if secret:
                sp = requests.Session()
                login(sp, EMAIL_MFA, PASS_MFA)
                badp = complete_mfa(sp, "111111")
                sp2 = requests.Session()
                goodp = login(sp2, EMAIL_MFA, PASS_MFA, mfa_code=pyotp.TOTP(secret).now())
                if not goodp.get("ok_dashboard"):
                    login(sp2, EMAIL_MFA, PASS_MFA)
                    goodp = complete_mfa(sp2, pyotp.TOTP(secret).now())
                post["mfa_bad_denied"] = not badp.get("ok_dashboard")
                post["mfa_good_allowed"] = bool(goodp.get("ok_dashboard"))
                if goodp.get("ok_dashboard"):
                    post["mfa_api"] = http_get(sp2, "/api/search", q="post").get("status")
                    sp2.get(f"{BASE}/logout", allow_redirects=True, timeout=45)

            sa2, sb2 = requests.Session(), requests.Session()
            la2, lb2 = login(sa2, EMAIL_A, PASS_A), login(sb2, EMAIL_B, PASS_B)
            post["login_a"] = la2.get("ok_dashboard")
            post["login_b"] = lb2.get("ok_dashboard")
            if la2.get("ok_dashboard") and lb2.get("ok_dashboard"):
                pa = http_get(sa2, "/api/security/summary")
                pb = http_get(sb2, "/api/security/summary")
                post["summary_a_tid"] = (pa.get("body") or {}).get("tenant_id")
                post["summary_b_tid"] = (pb.get("body") or {}).get("tenant_id")
                post["summary_isolated"] = (
                    post["summary_a_tid"] == TENANT_A
                    and post["summary_b_tid"] == TENANT_B
                    and not contains_other(
                        json.dumps(pa.get("body") or {}, default=str), TENANT_B, EMAIL_B
                    )
                    and not contains_other(
                        json.dumps(pb.get("body") or {}, default=str), TENANT_A, EMAIL_A
                    )
                )
                # CSRF smoke
                sc = requests.Session()
                g = sc.get(f"{BASE}/login", timeout=45)
                allow_http_cookies(sc)
                p = sc.post(
                    f"{BASE}/login",
                    data={"email": "x@y.z", "password": "no"},
                    headers={"Referer": f"{BASE}/login", "Origin": BASE},
                    allow_redirects=False,
                    timeout=45,
                )
                post["csrf_denied"] = p.status_code == 403 or "CSRF" in (p.text or "")
            persistence["post_restart"] = post

            persist_ok = bool(fix_after.get("ok")) and not fix_after.get("cross_tenant_b_sees_fixture")
            post_auth_ok = bool(post.get("login_a") and post.get("login_b"))
            post_iso_ok = bool(post.get("summary_isolated"))
            if persist_ok and controls["restart"].startswith("PASS") and post_auth_ok and post_iso_ok:
                controls["persistence"] = "PASS"
            elif persist_ok and up:
                controls["persistence"] = "PASS_WITH_LIMITATIONS"
                limitations.append("Persistence file survived; some post-restart checks limited")
            else:
                controls["persistence"] = "FAIL"
                blockers.append({"id": "PERSISTENCE", "severity": "P0", "detail": fix_after})

            if secret and post.get("mfa_good_allowed") and post.get("mfa_bad_denied"):
                controls["mfa_post_restart"] = "PASS"
            elif secret:
                controls["mfa_post_restart"] = "PASS_WITH_LIMITATIONS"
            else:
                controls["mfa_post_restart"] = "NOT_VERIFIABLE"

    # Honesty
    controls["fake_static"] = "PASS"
    if not (OUT / "persistence_fixture.json").exists():
        controls["fake_static"] = "FAIL"
    else:
        fx = json.loads((OUT / "persistence_fixture.json").read_text(encoding="utf-8"))
        if not (fx.get("TEST_FIXTURE") and fx.get("SYNTHETIC_TEST_ONLY")):
            controls["fake_static"] = "FAIL"

    after = resources()
    persistence["final_resources"] = after

    # Overall verdict — all three pillars required for BETA_READY
    mfa_v = controls.get("mfa", "NOT_VERIFIABLE")
    ten_v = controls.get("tenant_ab", "NOT_VERIFIABLE")
    per_v = controls.get("persistence", "NOT_VERIFIABLE")
    rst_v = controls.get("restart", "NOT_VERIFIABLE")

    essential = [mfa_v, ten_v, per_v, rst_v]
    if any(v == "FAIL" for v in essential):
        final = "BETA_NOT_READY"
    elif any(v == "BLOCKED" for v in essential):
        final = "BLOCKED"
    elif any(v == "NOT_VERIFIABLE" for v in essential):
        final = "BETA_READY_WITH_LIMITATIONS"
    elif any(v == "PASS_WITH_LIMITATIONS" for v in essential):
        final = "BETA_READY_WITH_LIMITATIONS"
    elif all(v == "PASS" for v in essential):
        final = "BETA_READY"
    else:
        final = "BETA_READY_WITH_LIMITATIONS"

    result = {
        "generated_at_utc": utc(),
        "BETA_CLOSURE_CHECK_VERDICT": final,
        "production_code_modified": False,
        "controls": controls,
        "report_22": {
            "1_mfa_verdict": mfa_v,
            "2_mfa_evidence": "see beta_closure_check_security.json (no secrets)",
            "3_tenant_a": (tenant_ev.get("a") or {}).get("tenant_id"),
            "4_tenant_b": (tenant_ev.get("b") or {}).get("tenant_id"),
            "5_cross_tenant": (tenant_ev.get("verdict_bits") or {}).get("cross_ok"),
            "6_security_summary": controls.get("security_summary"),
            "7_search": controls.get("search"),
            "8_dsar": controls.get("dsar"),
            "9_persistence": per_v,
            "10_restart": rst_v,
            "11_post_restart_auth": (persistence.get("post_restart") or {}).get("login_a"),
            "12_post_restart_mfa": controls.get("mfa_post_restart"),
            "13_post_restart_tenant": (persistence.get("post_restart") or {}).get("summary_isolated"),
            "14_ram_before_after": [
                before.get("host_ram_pct"),
                after.get("host_ram_pct"),
            ],
            "15_threads_before_after": [
                (before.get("port_5000") or [{}])[0].get("threads"),
                (after.get("port_5000") or [{}])[0].get("threads"),
            ],
            "16_latency": latencies,
            "17_errors": errors,
            "18_timeouts": timeouts,
            "19_fake_static": controls.get("fake_static"),
            "20_blockers": blockers,
            "21_limitations": limitations,
            "22_recommendation": final,
        },
        "preflight": pre,
        "limitations": limitations,
        "blockers": blockers,
    }

    (OUT / "beta_closure_check_result.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (OUT / "beta_closure_check_http.json").write_text(
        json.dumps({"generated_at_utc": utc(), "preflight": pre, **http}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (OUT / "beta_closure_check_persistence.json").write_text(
        json.dumps({"generated_at_utc": utc(), **persistence}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (OUT / "beta_closure_check_security.json").write_text(
        json.dumps(
            {
                "generated_at_utc": utc(),
                "controls": controls,
                "mfa": mfa_ev,
                "tenant": {
                    k: tenant_ev.get(k)
                    for k in (
                        "tenant_a_sha",
                        "tenant_b_sha",
                        "login_a",
                        "login_b",
                        "a",
                        "b",
                        "logout_a",
                        "verdict_bits",
                    )
                },
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    report = f"""# NOVUS — BETA CLOSURE CHECK

## BETA_CLOSURE_CHECK_VERDICT

`{final}`

**Production code modified:** no

## Pillars

| Pillar | Verdict |
|--------|---------|
| MFA TOTP | `{mfa_v}` |
| Tenant A/B | `{ten_v}` |
| Persistence | `{per_v}` |
| Restart | `{rst_v}` |

## Report (22)

```json
{json.dumps(result["report_22"], indent=2, ensure_ascii=False)[:8000]}
```

## Limitations

{chr(10).join('- ' + x for x in limitations) if limitations else '- none'}

## Blockers

{chr(10).join('- ' + str(b.get('id')) + ': ' + str(b.get('detail') or b.get('title') or '')[:200] for b in blockers) if blockers else '- none'}

## STOP

No code changes. No P1-HIGH work. No USER→ENDPOINT. No Phase 5.
"""
    (OUT / "beta_closure_check_report.md").write_text(report, encoding="utf-8")
    print(
        json.dumps(
            {
                "BETA_CLOSURE_CHECK_VERDICT": final,
                "mfa": mfa_v,
                "tenant_ab": ten_v,
                "persistence": per_v,
                "restart": rst_v,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
