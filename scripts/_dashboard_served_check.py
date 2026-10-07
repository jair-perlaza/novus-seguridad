#!/usr/bin/env python3
"""Login de prueba y verifica HTML servido de /dashboard (estructura visual)."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]

BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000").rstrip("/")
EMAIL = os.environ.get("NOVUS_QA_EMAIL", "operaciones@novapay-fintech.co")
PASSWORD = os.environ.get("NOVUS_QA_PASSWORD", "NovaPay#Fintech2026")


def main() -> int:
    s = requests.Session()
    login_page = s.get(f"{BASE}/login", timeout=30)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', login_page.text)
    if not m:
        print(json.dumps({"error": "csrf_missing", "login_http": login_page.status_code}))
        return 1
    post = s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": m.group(1)},
        allow_redirects=True,
        timeout=60,
    )
    dash = s.get(f"{BASE}/dashboard", timeout=60)
    html = dash.text
    # Evitar falsos positivos por comentarios HTML
    html_no_comments = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    checks = {
        "login_http": post.status_code,
        "dashboard_http": dash.status_code,
        "on_dashboard": "Prioridad Actual" in html and "novus-shell" in html,
        "tailwind_mirror": "@tailwindcss/browser" in html_no_comments,
        "novus_responsive_css": "novus-responsive.css" in html,
        "hero_cards": html.count("novus-hero-card") >= 2,
        "kpi_cards": html.count("dashboard-kpi-clickable") >= 7,
        "sidebar": "novus-sidebar" in html,
        "font_awesome": "font-awesome" in html,
        "apply_live_kpis": "vulnAnalysisOk" in html,
        "traffic_meta_arg": "live.traffic_meta" in html,
    }
    disk_html = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
    checks["tailwind_mirror_template_disk"] = "@tailwindcss/browser" in disk_html
    out = {
        "checks": checks,
        "pass": all(checks.values()) and checks["tailwind_mirror_template_disk"],
        "url_final": post.url,
    }
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ui_repair", "dashboard_served_html_check.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
