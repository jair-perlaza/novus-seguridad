#!/usr/bin/env python3
"""Post-restart cookie replay + relogin for session revocation P0."""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import pyotp
import requests

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:5000"
EMAIL = "synthetic.session.p0@novus.test.local"
PASS = "SyntheticSessionP0!99"
NIT = "901777501-SYN-SESS"
SPOOF = "TENANT-01"
CK = ROOT / "data/novus_beta_operations/registration_remediation/session_revocation_p0.checkpoint.json"
OUT = ROOT / "data/novus_beta_operations/registration_remediation/session_revocation_p0.json"


def csrf(html: str) -> str:
    m = re.search(r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', html)
    return m.group(1) if m else ""


def wait_ready(timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if requests.get(BASE + "/login", timeout=5).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def main():
    if not CK.exists():
        print("NO_CHECKPOINT")
        return 2
    ck = json.loads(CK.read_text(encoding="utf-8"))
    cookies = ck["cookies"]
    secret = ck["secret"]
    if not wait_ready():
        print("NOT_READY")
        return 2

    replay = requests.Session()
    for k, v in cookies.items():
        replay.cookies.set(k, v)

    rd = replay.get(BASE + "/dashboard", timeout=60, allow_redirects=False)
    rs = replay.get(BASE + "/api/security/summary", timeout=30, allow_redirects=False)
    rd2 = replay.get(BASE + "/dashboard", timeout=60, allow_redirects=True)
    dash_blocked = rd.status_code in (302, 401) or "login" in (rd.headers.get("Location") or "")
    if rd2.status_code == 200 and len(rd2.text) > 100000 and "login" not in rd2.url:
        dash_blocked = False
    elif "login" in (rd2.url or ""):
        dash_blocked = True
    api_blocked = rs.status_code in (401, 403)
    print("post_restart_replay_dash", rd.status_code, rd.headers.get("Location"), "follow", rd2.url, len(rd2.text))
    print("post_restart_replay_api", rs.status_code)

    # new login
    s = requests.Session()
    g = s.get(BASE + "/login", timeout=30)
    s.post(BASE + "/login", data={"email": EMAIL, "password": PASS, "csrf_token": csrf(g.text)}, timeout=120, allow_redirects=False)
    g2 = s.get(BASE + "/login", timeout=30)
    bad = s.post(BASE + "/login", data={"mfa_code": "000000", "csrf_token": csrf(g2.text)}, timeout=60, allow_redirects=False)
    g3 = s.get(BASE + "/login", timeout=30)
    good = s.post(
        BASE + "/login",
        data={"mfa_code": pyotp.TOTP(secret).now(), "csrf_token": csrf(g3.text)},
        timeout=120,
        allow_redirects=False,
    )
    d = s.get(BASE + "/dashboard", timeout=60, allow_redirects=True)
    sum_r = s.get(BASE + "/api/security/summary", timeout=60)
    spoof = s.get(BASE + f"/api/security/summary?tenant_id={SPOOF}", timeout=60)
    tid = sum_r.json().get("tenant_id") if sum_r.ok else None
    tid_s = spoof.json().get("tenant_id") if spoof.ok else None
    print("post_restart_login_mfa", good.status_code, good.headers.get("Location"), "bad", bad.status_code)
    print("post_restart_dashboard", d.status_code, len(d.text), "tenant", tid, "spoof", tid_s)

    result = {
        "cookie_replay_dashboard_denied": dash_blocked,
        "cookie_replay_api_denied": api_blocked,
        "relogin_mfa_ok": good.status_code in (302, 303) and "dashboard" in (good.headers.get("Location") or ""),
        "dashboard_ok": d.status_code == 200 and len(d.text) > 100000,
        "tenant_ok": tid == NIT and tid_s == NIT,
    }
    print("RESULT", json.dumps(result))

    if OUT.exists():
        data = json.loads(OUT.read_text(encoding="utf-8"))
        data["tests"]["post_restart_cookie_replay_denied"] = {
            "ok": dash_blocked and api_blocked,
            "detail": {"dash": rd.status_code, "api": rs.status_code, "follow": rd2.url},
        }
        data["tests"]["post_restart_relogin_mfa_dashboard"] = {
            "ok": result["relogin_mfa_ok"] and result["dashboard_ok"] and result["tenant_ok"],
            "detail": result,
        }
        data["restart_tests"] = result
        data["resources"] = data.get("resources") or {}
        try:
            import psutil

            data["resources"]["ram_post_restart"] = round(psutil.virtual_memory().percent, 1)
            for c in psutil.net_connections(kind="inet"):
                if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN":
                    p = psutil.Process(c.pid)
                    data["resources"]["pid"] = p.pid
                    data["resources"]["rss_mb"] = round(p.memory_info().rss / 1e6, 1)
                    data["resources"]["threads"] = p.num_threads()
                    break
        except Exception:
            pass
        crit = all(
            data["tests"].get(k, {}).get("ok")
            for k in (
                "cookie_replay_dashboard_denied",
                "cookie_replay_apis_denied",
                "relogin_mfa",
                "tenant_canonical",
                "post_restart_cookie_replay_denied",
                "post_restart_relogin_mfa_dashboard",
            )
        )
        data["final_verdict"] = "SESSION_REVOCATION_P0_PASS" if crit else "SESSION_REVOCATION_P0_FAIL"
        OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return 0 if crit else 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
