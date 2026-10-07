import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> int:
    from main import app

    email = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
    pwd = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
    c = app.test_client()
    lg = c.get("/login")
    tok = re.search(r'name="csrf_token" value="([^"]+)"', lg.get_data(as_text=True))
    token = tok.group(1) if tok else ""
    c.post("/login", data={"email": email, "password": pwd, "csrf_token": token})
    t0 = time.time()
    r = c.get("/api/monitoring/status")
    ms = int((time.time() - t0) * 1000)
    print("status", r.status_code, "ms", ms)
    if r.is_json:
        j = r.get_json()
        print("keys", sorted(j.keys())[:15])
        print("progress_pct", j.get("progress_pct"), "stages", len(j.get("stages") or []))
    return 0 if r.status_code == 200 and ms < 15000 else 1


if __name__ == "__main__":
    raise SystemExit(main())
