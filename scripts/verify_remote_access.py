"""Verificación de preparación para acceso remoto privado."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

BASE = "http://127.0.0.1:5000"

PAGES = [
    "/", "/dashboard", "/inteligencia", "/network", "/topology", "/vulnerabilidades",
    "/amenazas", "/incidentes", "/endpoints", "/automatizacion", "/reportes", "/configuracion",
]
APIS = [
    "/api/dashboard/live", "/api/threat-intel/dashboard", "/api/network/nodes",
    "/api/security/summary", "/api/ai/status", "/api/playbooks/", "/api/search/",
]


def main():
    print("=== RUTAS SIN AUTH ===")
    ok_count = 0
    for p in PAGES + APIS:
        r = requests.get(BASE + p, allow_redirects=False, timeout=15)
        if p.startswith("/api/"):
            ok = r.status_code == 401
        else:
            loc = r.headers.get("Location") or ""
            ok = r.status_code in (302, 401) and (r.status_code == 401 or "/login" in loc)
        tag = "OK" if ok else "FAIL"
        print(f"  {p}: {r.status_code} {tag}")
        ok_count += int(ok)

    r = requests.get(BASE + "/test-sector-auth", allow_redirects=False, timeout=15)
    print(f"  /test-sector-auth: {r.status_code} {'OK' if r.status_code == 404 else 'WARN'}")

    s = requests.Session()
    r = s.post(
        BASE + "/login",
        data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!"},
        allow_redirects=True,
        timeout=15,
    )
    print(f"login: {r.status_code}")

    for p in ["/", "/inteligencia", "/api/threat-intel/dashboard", "/api/ai/status"]:
        r = s.get(BASE + p, timeout=30)
        print(f"auth {p}: {r.status_code}")

    r = s.get(BASE + "/logout", allow_redirects=False, timeout=15)
    print(f"logout: {r.status_code} loc={r.headers.get('Location', '')}")

    from core.config import Config
    from core.public_url import get_public_base_url

    print(f"PUBLIC_BASE_URL: {Config.PUBLIC_BASE_URL or '(vacío — usar Host del túnel)'}")
    print(f"BEHIND_PROXY: {Config.BEHIND_PROXY}")
    print(f"ALLOW_PUBLIC_REGISTRATION: {Config.ALLOW_PUBLIC_REGISTRATION}")
    print("DONE")


if __name__ == "__main__":
    main()
