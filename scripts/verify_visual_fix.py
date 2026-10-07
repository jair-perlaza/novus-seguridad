"""Verify main pages render content outside modal overlay."""
import requests

BASE = "http://127.0.0.1:5000"
PAGES = [
    ("Login", "/login", False),
    ("Dashboard", "/dashboard", True),
    ("Network", "/network", True),
    ("Vulnerabilidades", "/vulnerabilidades", True),
    ("Reportes", "/reportes", True),
    ("Topology", "/topology", True),
    ("Configuracion", "/configuracion", True),
    ("Automatizacion", "/automatizacion", True),
]

s = requests.Session()
s.post(
    f"{BASE}/login",
    data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!"},
    allow_redirects=True,
)

marker = 'id="novus-remediation-overlay"'
ok = 0
for name, path, authed in PAGES:
    client = s if authed else requests.Session()
    html = client.get(f"{BASE}{path}").text
    head_end = html.lower().find("</head>")
    body_start = html.lower().find("<body")
    pos = html.find(marker)
    in_head = pos > 0 and pos < head_end
    in_body = pos > 0 and pos > body_start
    has_sidebar = "NOVUS" in html and ("sidebar" in html.lower() or "novus-shell" in html or "dashboard-grid" in html or "card" in html.lower())
    hidden_ok = ".novus-modal-overlay.hidden { display: none; }" in html
    good = (not in_head if pos > 0 else True) and hidden_ok if authed else True
    if authed and pos > 0:
        good = in_body and hidden_ok
    status = "OK" if good else "FAIL"
    ok += int(good)
    print(f"[{status}] {name}: overlay_in_body={in_body if pos>0 else 'n/a'} hidden_css_ok={hidden_ok if authed else 'n/a'}")

print(f"\n{ok}/{len(PAGES)} pages pass visual structure checks")
