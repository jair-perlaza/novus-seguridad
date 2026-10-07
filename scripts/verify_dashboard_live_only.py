"""Verificación rápida en vivo (sin importar main.py)."""
import os
import re
import sys
import time

import requests

BASE = "http://127.0.0.1:5000"
MARKERS = [
    "data-novus-search-inline",
    "novus-estado-general-panel",
    "novus-eg-progress",
    "novus-dashboard-estado-general.js",
]


def main() -> int:
    s = requests.Session()
    g = s.get(BASE + "/login", timeout=60)
    t = re.search(r'name="csrf_token" value="([^"]+)"', g.text)
    token = t.group(1) if t else ""
    pwd = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
    email = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
    s.post(
        BASE + "/login",
        data={"email": email, "password": pwd, "csrf_token": token},
        timeout=60,
        allow_redirects=True,
    )
    dash = s.get(BASE + "/", timeout=120)
    ok = all(m in dash.text for m in MARKERS)
    print("dashboard_bytes", len(dash.text))
    print("markers_ok", ok)
    for m in MARKERS:
        print(m, m in dash.text)
    t0 = time.time()
    mon = s.get(BASE + "/api/monitoring/status", timeout=180)
    print("monitoring_ms", int((time.time() - t0) * 1000))
    print("monitoring_http", mon.status_code)
    if mon.ok:
        j = mon.json()
        print("monitoring_status", j.get("status"), "progress_pct", j.get("progress_pct"))
        print("stages_count", len(j.get("stages") or []))
        print("defense_motors", bool(j.get("defense_motors")))
    rep = s.get(BASE + "/reportes", timeout=120)
    print("reportes_bytes", len(rep.text))
    print("reportes_has_auto", "AUTO-" in rep.text or "Monitoreo automático" in rep.text)
    return 0 if ok and mon.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
