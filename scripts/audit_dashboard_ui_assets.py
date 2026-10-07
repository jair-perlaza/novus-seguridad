#!/usr/bin/env python3
"""Verifica CSP y carga de assets del Dashboard (index.html) autenticado."""
from __future__ import annotations

import json
import os
import re
import sys

import requests

BASE = os.environ.get("NOVUS_AUDIT_BASE", "").strip()
if not BASE:
    try:
        with open(
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ngrok", "manager_status.json"),
            encoding="utf-8",
        ) as fh:
            pub = json.load(fh).get("public_url")
            if pub:
                BASE = pub.rstrip("/")
    except Exception:
        pass
if not BASE:
    BASE = "http://127.0.0.1:5000"
EMAIL = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
PASSWORD = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")


def main() -> int:
    s = requests.Session()
    login = s.get(f"{BASE}/login", timeout=30)
    m = re.search(r'name="csrf_token" value="([^"]+)"', login.text)
    csrf = m.group(1) if m else ""
    s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": csrf},
        allow_redirects=True,
        timeout=60,
    )
    dash = s.get(f"{BASE}/dashboard", timeout=60)
    csp = dash.headers.get("Content-Security-Policy", "")
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', dash.text, re.I)
    styles = re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', dash.text, re.I)
    results = {"http_dashboard": dash.status_code, "csp": csp, "assets": []}
    for url in scripts + styles:
        full = url if url.startswith("http") else BASE + url
        try:
            r = s.get(full, timeout=30)
            results["assets"].append({"url": url, "http": r.status_code, "ok": r.status_code == 200})
        except Exception as exc:
            results["assets"].append({"url": url, "http": 0, "ok": False, "error": str(exc)})
    blocked_by_old_csp = []
    if "cdn.tailwindcss.com" not in csp:
        blocked_by_old_csp.append("cdn.tailwindcss.com (script-src)")
    if "cdn.jsdelivr.net" not in csp:
        blocked_by_old_csp.append("cdn.jsdelivr.net (script-src)")
    if "cdnjs.cloudflare.com" not in csp:
        blocked_by_old_csp.append("cdnjs.cloudflare.com (style-src/font-src)")
    results["csp_allows_ui_cdns"] = len(blocked_by_old_csp) == 0
    results["csp_gaps"] = blocked_by_old_csp
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ui_repair")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "dashboard_assets_audit.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0 if dash.status_code == 200 and results["csp_allows_ui_cdns"] else 1


if __name__ == "__main__":
    sys.exit(main())
