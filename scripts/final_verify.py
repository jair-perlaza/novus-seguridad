"""Verificación final: login + módulos + versión reciente en puerto 5000."""
import sys
import requests

BASE = "http://127.0.0.1:5000"
EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"


def main():
    s = requests.Session()
    s.headers.update({"User-Agent": "NOVUS-FinalVerify/1.0"})

    r = s.post(f"{BASE}/login", data={"email": EMAIL, "password": PASSWORD}, allow_redirects=True, timeout=20)
    login_ok = r.status_code == 200 and "login" not in r.url.lower()
    print(f"[{'OK' if login_ok else 'FAIL'}] Login -> {r.url}")

    pages = [
        ("Dashboard", "/dashboard"),
        ("Network", "/network"),
        ("Vulnerabilidades", "/vulnerabilidades"),
        ("Reportes", "/reportes"),
        ("XDR", "/amenazas"),
        ("Incidentes", "/incidentes"),
        ("Configuración", "/configuracion"),
    ]
    ok_count = int(login_ok)
    for name, path in pages:
        pr = s.get(f"{BASE}{path}", timeout=20)
        good = pr.status_code == 200
        ok_count += int(good)
        print(f"[{'OK' if good else 'FAIL'}] {name} ({path}) -> {pr.status_code}")

    apis = [
        ("Dashboard live", "/api/dashboard/live"),
        ("Security summary", "/api/system/security/summary"),
        ("AI status", "/api/ai/status"),
        ("Network nodes", "/api/network/nodes"),
    ]
    latest = False
    for name, path in apis:
        ar = s.get(f"{BASE}{path}", timeout=20)
        good = ar.status_code == 200
        ok_count += int(good)
        if path.endswith("security/summary") and good:
            data = ar.json()
            latest = "vault" in data and data.get("vault", {}).get("vault_active") is True
            print(f"[{'OK' if good else 'FAIL'}] {name} -> vault_active={data.get('vault', {}).get('vault_active')}")
        else:
            print(f"[{'OK' if good else 'FAIL'}] {name} -> {ar.status_code}")

    print(f"[{'OK' if latest else 'FAIL'}] Versión reciente (CryptoVault en summary)")
    total = 1 + len(pages) + len(apis) + 1
    print(f"\n=== {ok_count}/{total} checks PASS ===")
    return 0 if login_ok and latest and ok_count >= total - 1 else 1


if __name__ == "__main__":
    sys.exit(main())
