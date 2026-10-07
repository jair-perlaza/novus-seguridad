#!/usr/bin/env python3
"""Post-restart login → MFA → dashboard for SYNTHETIC final user A."""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import pyotp
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
BASE = "http://127.0.0.1:5000"
EMAIL = "synthetic.final.a@novus.test.local"
PASS = "SyntheticFinal!99xx"
NIT = "901777001-SYN-FINAL"
SECRET = sys.argv[1] if len(sys.argv) > 1 else ""
SPOOF = "TENANT-01"
OUT = ROOT / "data/novus_beta_operations/registration_remediation/registration_final_e2e.json"


def csrf(html: str) -> str:
    m = re.search(r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', html)
    return m.group(1) if m else ""


def wait_ready(timeout=180):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            r = requests.get(BASE + "/login", timeout=5)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def main():
    if not SECRET:
        print("NO_SECRET")
        return 2
    if not wait_ready():
        print("NOT_READY")
        return 2

    s = requests.Session()
    g = s.get(BASE + "/login", timeout=30)
    tok = csrf(g.text)
    t0 = time.time()
    p = s.post(
        BASE + "/login",
        data={"email": EMAIL, "password": PASS, "csrf_token": tok},
        timeout=120,
        allow_redirects=False,
    )
    login_lat = round(time.time() - t0, 3)
    print("login", p.status_code, p.headers.get("Location"), login_lat)

    # MFA step
    g2 = s.get(BASE + "/login", timeout=30)
    # wrong code
    bad = s.post(
        BASE + "/login",
        data={"mfa_code": "000000", "csrf_token": csrf(g2.text)},
        timeout=60,
        allow_redirects=False,
    )
    print("mfa_bad", bad.status_code, "mfa_required" in bad.text.lower() or bad.status_code == 200)

    g3 = s.get(BASE + "/login", timeout=30)
    code = pyotp.TOTP(SECRET).now()
    t1 = time.time()
    good = s.post(
        BASE + "/login",
        data={"mfa_code": code, "csrf_token": csrf(g3.text)},
        timeout=120,
        allow_redirects=False,
    )
    mfa_lat = round(time.time() - t1, 3)
    loc = good.headers.get("Location") or ""
    print("mfa_ok", good.status_code, loc, mfa_lat)

    d = s.get(BASE + "/dashboard", timeout=120, allow_redirects=True)
    print("dashboard", d.status_code, d.url, len(d.text))

    def jget(path):
        r = s.get(BASE + path, timeout=60)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"_raw": r.text[:200]}

    ss, summary = jget("/api/security/summary")
    ssp, summary_spoof = jget(f"/api/security/summary?tenant_id={SPOOF}")
    ds, dsar = jget("/api/compliance/dsar-export?limit=5")
    dsp, dsar_spoof = jget(f"/api/compliance/dsar-export?limit=5&tenant_id={SPOOF}")
    se, search = jget("/api/search?q=TEST_FIXTURE&limit=5")

    print("summary", ss, summary.get("tenant_id"))
    print("summary_spoof", ssp, summary_spoof.get("tenant_id"))
    print("dsar", ds, dsar.get("tenant_id"))
    print("dsar_spoof", dsp, dsar_spoof.get("tenant_id"))
    print("search", se, search.get("count"))

    # logout
    cookies = requests.utils.dict_from_cookiejar(s.cookies)
    lo = s.get(BASE + "/logout", timeout=30, allow_redirects=False)
    d2 = s.get(BASE + "/dashboard", timeout=30, allow_redirects=False)
    s3 = requests.Session()
    for k, v in cookies.items():
        s3.cookies.set(k, v)
    d3 = s3.get(BASE + "/dashboard", timeout=30, allow_redirects=False)
    print("logout", lo.status_code, lo.headers.get("Location"))
    print("after_logout", d2.status_code, d2.headers.get("Location"))
    print("cookie_reuse", d3.status_code, d3.headers.get("Location"), "url", d3.url)

    result = {
        "login_status": p.status_code,
        "login_loc": p.headers.get("Location"),
        "login_latency_s": login_lat,
        "mfa_bad_rejected": bad.status_code == 200 and "dashboard" not in (bad.headers.get("Location") or ""),
        "mfa_ok_status": good.status_code,
        "mfa_ok_loc": loc,
        "mfa_latency_s": mfa_lat,
        "dashboard_ok": d.status_code == 200 and "login" not in d.url,
        "dashboard_len": len(d.text),
        "tenant_summary": summary.get("tenant_id"),
        "tenant_summary_spoof": summary_spoof.get("tenant_id"),
        "tenant_dsar": dsar.get("tenant_id"),
        "tenant_dsar_spoof": dsar_spoof.get("tenant_id"),
        "spoof_ignored": summary_spoof.get("tenant_id") == NIT and dsar_spoof.get("tenant_id") == NIT,
        "search_status": se,
        "logout_ok": lo.status_code in (302, 303),
        "after_logout_blocked": d2.status_code in (302, 401) or "login" in (d2.headers.get("Location") or ""),
        "cookie_reuse_blocked": d3.status_code in (302, 401) or "login" in (d3.headers.get("Location") or ""),
        "cookie_reuse_status": d3.status_code,
    }
    print("RESULT_JSON", json.dumps(result))

    if OUT.exists():
        data = json.loads(OUT.read_text(encoding="utf-8"))
        data["restart_tests"]["post"] = result
        data["persistence_tests"]["post_restart_tenant"] = NIT
        data["persistence_tests"]["mfa_survived_restart"] = bool(result["mfa_ok_status"] in (302, 303) and "dashboard" in (result["mfa_ok_loc"] or ""))
        OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    ok = (
        result["dashboard_ok"]
        and result["tenant_summary"] == NIT
        and result["spoof_ignored"]
        and result["after_logout_blocked"]
        and result["mfa_bad_rejected"]
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
