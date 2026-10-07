"""One-shot live authenticated recovery test against running NOVUS server."""
import re
import time
import json
import requests

BASE = "http://127.0.0.1:5000"
QA_EMAIL = "novus.qa.jul2026@example.com"
QA_PASS = "NovusQA2026!"

PATHS = [
    "/dashboard",
    "/security-operations-center",
    "/asset-intelligence",
    "/vulnerability-intelligence",
    "/incident-management",
    "/threat-intelligence-center",
    "/playbook-center",
    "/security-data-lake",
    "/security-data-analytics",
    "/identity-intelligence",
    "/identity-attack-path",
    "/deception-center",
    "/network",
    "/endpoints",
    "/health-center",
    "/api/tie/dashboard",
    "/api/sope/dashboard",
    "/api/imcm/dashboard",
    "/api/security/summary",
]

s = requests.Session()
t0 = time.perf_counter()
r = s.get(BASE + "/login", timeout=30)
login_get_ms = round((time.perf_counter() - t0) * 1000, 1)
csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
csrf_val = csrf.group(1) if csrf else None

t1 = time.perf_counter()
r2 = s.post(
    BASE + "/login",
    data={"email": QA_EMAIL, "password": QA_PASS, "csrf_token": csrf_val or ""},
    allow_redirects=True,
    timeout=30,
)
login_post_ms = round((time.perf_counter() - t1) * 1000, 1)
login_post_body_snip = r2.text[:1200] if r2.text else ""

results = []
for p in PATHS:
    t = time.perf_counter()
    try:
        rr = s.get(BASE + p, timeout=60)
        results.append(
            {
                "path": p,
                "status": rr.status_code,
                "ms": round((time.perf_counter() - t) * 1000, 1),
                "redirected_to_login": "/login" in rr.url and p != "/login",
            }
        )
    except Exception as e:
        results.append({"path": p, "error": str(e)})

out = {
    "cookies_after_get": dict(s.cookies),
    "login_get": {"status": r.status_code, "ms": login_get_ms, "csrf": bool(csrf_val), "csrf_val_prefix": (csrf_val or "")[:8]},
    "login_post": {
        "status": r2.status_code,
        "ms": login_post_ms,
        "final_url": r2.url,
        "body_snip": login_post_body_snip,
        "csrf_error": "CSRF" in login_post_body_snip,
    },
    "routes": results,
}
print(json.dumps(out, indent=2))
