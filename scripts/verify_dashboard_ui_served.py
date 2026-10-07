"""Verifica plantilla servida (test_client) y HTML en vivo en :5000."""
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

MARKERS = {
    "inline_search_attr": 'data-novus-search-inline="true"',
    "search_input_id": 'id="search-input"',
    "cursor_text_class": "cursor-text",
    "estado_general_panel": 'id="novus-estado-general-panel"',
    "eg_progress": 'id="novus-eg-progress"',
    "eg_summary": 'id="novus-eg-summary"',
    "dashboard_estado_js": "novus-dashboard-estado-general.js",
    "global_search_js": "novus-global-search.js",
}


def check_html(label: str, html: str) -> list[str]:
    fails = []
    print(f"\n=== {label} bytes={len(html)} ===")
    for name, needle in MARKERS.items():
        ok = needle in html
        print(f"  {'OK' if ok else 'FAIL'} {name}")
        if not ok:
            fails.append(name)
    bad = 'data-novus-search-trigger readonly' in html and 'search-input' in html
    print(f"  {'OK' if not bad else 'FAIL'} no_readonly_search_trigger")
    if bad:
        fails.append("no_readonly_search_trigger")
    return fails


def _csrf_from_html(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def verify_test_client() -> list[str]:
    from main import app

    qa_email = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
    qa_pass = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
    client = app.test_client()
    login_get = client.get("/login")
    token = _csrf_from_html(login_get.get_data(as_text=True))
    r = client.post(
        "/login",
        data={"email": qa_email, "password": qa_pass, "csrf_token": token},
        follow_redirects=True,
    )
    html = r.get_data(as_text=True)
    if "novus-estado-general-panel" not in html:
        print("test_client login/dashboard FAIL", r.status_code, "csrf_len", len(token))
        return ["test_client_login"]
    return check_html("test_client /dashboard", html)


def verify_live_server() -> list[str]:
    import requests

    base = os.environ.get("NOVUS_BASE", "http://127.0.0.1:5000")
    s = requests.Session()
    r = s.get(base + "/login", timeout=30)
    token = _csrf_from_html(r.text)
    qa_email = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
    qa_pass = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
    post = s.post(
        base + "/login",
        data={"email": qa_email, "password": qa_pass, "csrf_token": token},
        timeout=30,
        allow_redirects=True,
    )
    if post.status_code != 200 or "novus-estado-general-panel" not in post.text:
        print("live login FAIL", post.status_code, post.url)
        return ["live_login"]
    fails = check_html("live GET /", s.get(base + "/", timeout=30).text)
    js = s.get(base + "/static/js/novus-global-search.js", timeout=20)
    print(f"\nstatic novus-global-search.js status={js.status_code} initInline={'initInline' in js.text}")
    if "initInline" not in js.text:
        fails.append("static_js_initInline")
    mon = s.get(base + "/api/monitoring/status", timeout=20)
    if mon.ok:
        j = mon.json()
        print(
            "monitoring",
            j.get("status"),
            "progress_pct",
            j.get("progress_pct"),
            "stages",
            len(j.get("stages") or []),
        )
    else:
        fails.append("monitoring_api")
    rep = s.get(base + "/reportes", timeout=30)
    auto = "AUTO-" in rep.text or "Monitoreo automático" in rep.text or "continuous_monitoring" in rep.text
    print(f"reportes auto hint={'OK' if auto else 'CHECK'} bytes={len(rep.text)}")
    return fails


def main() -> int:
    print("PROJECT_ROOT", ROOT)
    print("MAIN", os.path.join(ROOT, "main.py"))
    print("TEMPLATE", os.path.join(ROOT, "templates", "index.html"))
    fails = verify_test_client()
    fails += verify_live_server()
    if fails:
        print("\nFAILED", fails)
        return 1
    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
