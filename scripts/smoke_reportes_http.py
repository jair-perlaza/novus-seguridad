import os
import re
import sys

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

BASE = "http://127.0.0.1:5000"


def main():
    s = requests.Session()
    r = s.get(BASE + "/login", timeout=60)
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    token = m.group(1) if m else ""
    pwd = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
    s.post(
        BASE + "/login",
        data={
            "email": "novus.qa.jul2026@example.com",
            "password": pwd,
            "csrf_token": token,
        },
        timeout=60,
    )
    rep = s.get(BASE + "/reportes", timeout=60)
    print("reportes_bytes", len(rep.text))
    print("build_tag", "reports-executive-presentation-20260722" in rep.text)
    print("pane_executive", "novus-report-pane-executive" in rep.text)
    dv = s.get(BASE + "/api/reports/RPT-20260721142636/detail-view", timeout=60)
    j = dv.json()
    view = j.get("view") or {}
    pres = view.get("presentation") or {}
    print("detail_status", j.get("status"))
    print("has_presentation", bool(pres))
    blob = str(pres).lower()
    for token in ("learning_summary", "trust_factors", "confidence_score"):
        print(f"leak_{token}", token in blob)
    print("devices", len(pres.get("devices") or []))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
