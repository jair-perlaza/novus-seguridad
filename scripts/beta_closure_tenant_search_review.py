#!/usr/bin/env python3
"""Diagnostic only — inspect search bodies for false-positive query echo. No production changes."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "production_closure" / "beta_closure_check"

BASE = "http://127.0.0.1:5000"
EMAIL_A = "p1c001.probe@novus-client.test"
PASS_A = "NovusP1C001Rem2026!"
TENANT_A = "P1C001-PROBE"
EMAIL_B = "operaciones@novapay-fintech.co"
PASS_B = "NovaPay#Fintech2026"
TENANT_B = "901.567.123-4"


def csrf(html: str) -> str:
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html or "")
    return m.group(1) if m else ""


def allow(s):
    for c in s.cookies:
        c.secure = False


def login(s, email, password):
    import requests

    g = s.get(f"{BASE}/login", timeout=60)
    allow(s)
    p = s.post(
        f"{BASE}/login",
        data={"email": email, "password": password, "csrf_token": csrf(g.text)},
        headers={"Referer": f"{BASE}/login", "Origin": BASE},
        allow_redirects=False,
        timeout=60,
    )
    allow(s)
    return p.status_code in (302, 303)


def analyze(body, other_tid, other_email, self_query_tid=None):
    results = body.get("results") or body.get("items") or []
    q = body.get("query") or body.get("q")
    hits = []
    for i, r in enumerate(results[:50]):
        blob = json.dumps(r, default=str)
        if other_email.lower() in blob.lower():
            hits.append({"i": i, "why": "email", "snip": blob[:160]})
        elif other_tid in blob and not (self_query_tid and other_tid == self_query_tid and other_tid == q):
            # tid in result payload — exclude pure query echo fields
            if '"tenant_id"' in blob or "nit" in blob.lower() or other_email.split("@")[0] in blob:
                hits.append({"i": i, "why": "tenant_marker", "snip": blob[:160]})
    return {
        "status_body_keys": sorted(body.keys()) if isinstance(body, dict) else [],
        "query_echo": q,
        "count": body.get("count") or len(results),
        "private_hits": hits[:10],
        "query_only_echo": bool(q == other_tid) and len(hits) == 0,
    }


def main():
    import requests

    out = {}
    sa, sb = requests.Session(), requests.Session()
    out["login_a"] = login(sa, EMAIL_A, PASS_A)
    out["login_b"] = login(sb, EMAIL_B, PASS_B)
    if not (out["login_a"] and out["login_b"]):
        (OUT / "tenant_search_content_review.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(json.dumps(out, indent=2))
        return 1

    ra = sa.get(f"{BASE}/api/search", params={"q": TENANT_B, "limit": 20}, timeout=60)
    rb = sb.get(f"{BASE}/api/search", params={"q": TENANT_A, "limit": 20}, timeout=60)
    ba, bb = ra.json(), rb.json()
    out["a_search_b"] = {
        "http": ra.status_code,
        "analysis": analyze(ba, TENANT_B, EMAIL_B, TENANT_B),
        "top_keys": list(ba.keys()),
        "sample_result_keys": list((ba.get("results") or [{}])[0].keys()) if ba.get("results") else [],
    }
    out["b_search_a"] = {
        "http": rb.status_code,
        "analysis": analyze(bb, TENANT_A, EMAIL_A, TENANT_A),
        "sample_result_keys": list((bb.get("results") or [{}])[0].keys()) if bb.get("results") else [],
    }
    # Also search neutral term
    ra2 = sa.get(f"{BASE}/api/search", params={"q": "alert", "limit": 20}, timeout=60).json()
    rb2 = sb.get(f"{BASE}/api/search", params={"q": "alert", "limit": 20}, timeout=60).json()
    out["a_alert_has_b"] = TENANT_B in json.dumps(ra2, default=str) or EMAIL_B in json.dumps(ra2, default=str)
    out["b_alert_has_a"] = TENANT_A in json.dumps(rb2, default=str) or EMAIL_A in json.dumps(rb2, default=str)
    out["summary_a"] = sa.get(f"{BASE}/api/security/summary", timeout=60).json().get("tenant_id")
    out["summary_b"] = sb.get(f"{BASE}/api/security/summary", timeout=60).json().get("tenant_id")
    out["false_positive_likely"] = (
        out["a_search_b"]["analysis"].get("query_only_echo")
        or out["a_search_b"]["analysis"].get("count") == 0
    ) and (
        out["b_search_a"]["analysis"].get("query_only_echo")
        or out["b_search_a"]["analysis"].get("count") == 0
    ) and not out["a_alert_has_b"] and not out["b_alert_has_a"]

    (OUT / "tenant_search_content_review.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({
        "false_positive_likely": out["false_positive_likely"],
        "a_search_b": out["a_search_b"]["analysis"],
        "b_search_a": out["b_search_a"]["analysis"],
        "a_alert_has_b": out["a_alert_has_b"],
        "b_alert_has_a": out["b_alert_has_a"],
        "summary_a": out["summary_a"],
        "summary_b": out["summary_b"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
