#!/usr/bin/env python3
"""Verifica estructura visual del Dashboard autenticado (sin imprimir credenciales)."""
from __future__ import annotations

import json
import os
import re
import sys

import requests

BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000").rstrip("/")
EMAIL = os.environ.get("NOVUS_QA_EMAIL", "")
PASSWORD = os.environ.get("NOVUS_QA_PASSWORD", "")


def main() -> int:
    if not EMAIL or not PASSWORD:
        print(json.dumps({"error": "Set NOVUS_QA_EMAIL and NOVUS_QA_PASSWORD"}, indent=2))
        return 2

    s = requests.Session()
    login = s.get(f"{BASE}/login", timeout=30)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', login.text)
    if not m:
        print(json.dumps({"error": "csrf_missing"}, indent=2))
        return 1
    s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": m.group(1)},
        allow_redirects=True,
        timeout=60,
    )
    dash = s.get(f"{BASE}/dashboard", timeout=60)
    html = dash.text
    csp = dash.headers.get("Content-Security-Policy", "")

    checks = {
        "http": dash.status_code,
        "has_tailwind_cdn": "cdn.tailwindcss.com" in html,
        "has_novus_shell": 'class="novus-shell' in html or "novus-shell" in html,
        "kpi_cards": html.count("dashboard-kpi-clickable"),
        "hero_cards": html.count("novus-hero-card"),
        "sidebar": "novus-sidebar" in html,
        "grid_kpi": "grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7" in html,
        "csp_allows_tailwind": "cdn.tailwindcss.com" in csp,
        "on_dashboard_not_login": "Prioridad Actual" in html or "dashboard-kpi-clickable" in html,
    }

    assets = []
    for url in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        full = url if url.startswith("http") else BASE + url
        try:
            r = s.get(full, timeout=30)
            assets.append({"url": url, "http": r.status_code, "ok": r.status_code == 200})
        except Exception as exc:
            assets.append({"url": url, "http": 0, "ok": False, "error": str(exc)[:120]})

    out = {"checks": checks, "assets": assets, "pass": all(
        [
            checks["http"] == 200,
            checks["on_dashboard_not_login"],
            checks["has_tailwind_cdn"],
            checks["kpi_cards"] >= 7,
            checks["hero_cards"] >= 2,
            checks["sidebar"],
            checks["csp_allows_tailwind"],
            all(a.get("ok") for a in assets if "tailwind" in a.get("url", "") or a.get("url", "").startswith("/static")),
        ]
    )}
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ui_repair", "dashboard_visual_check.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
