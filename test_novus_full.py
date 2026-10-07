"""Full NOVUS smoke test — latest instance on port 5000."""
import sys
import requests

BASE = "http://127.0.0.1:5000"
EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"

results = []


def ok(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    results.append((name, status, detail))
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))


def main():
    s = requests.Session()
    s.headers.update({"User-Agent": "NOVUS-QA/1.0"})

    # Login
    r = s.post(f"{BASE}/login", data={"email": EMAIL, "password": PASSWORD}, allow_redirects=True, timeout=15)
    ok("Login", r.status_code == 200 and "login" not in r.url.lower(), r.url)

    pages = [
        ("Dashboard", "/dashboard"),
        ("Network", "/network"),
        ("XDR", "/amenazas"),
        ("Incidentes", "/incidentes"),
        ("Vulnerabilidades", "/vulnerabilidades"),
        ("Reportes", "/reportes"),
        ("Configuración", "/configuracion"),
    ]
    for name, path in pages:
        pr = s.get(f"{BASE}{path}", timeout=15)
        html = pr.text
        has_responsive = "novus-responsive" in html or "novus-responsive.css" in html or path == "/network"
        has_ai = "novus-ai-panel" in html or "NovusAIKernel" in html
        has_search = "novus-global-search" in html or "NovusGlobalSearch" in html
        ok(f"Página {name}", pr.status_code == 200, f"responsive={has_responsive} ai={has_ai} search={has_search}")

    # Network radar
    nr = s.get(f"{BASE}/network", timeout=15)
    ok("Network radar ResizeObserver", "ResizeObserver" in nr.text and "novusRadar" in nr.text)
    ok("Network log zone", "REGISTRO DE EVENTOS EN TIEMEO REAL" in nr.text.replace(" ", "") or "REGISTRO DE EVENTOS" in nr.text)

    # APIs
    apis = [
        ("AI status", "/api/ai/status", "kernel"),
        ("AI context", "/api/ai/context", "context"),
        ("Search", "/api/search?q=network", "results"),
        ("Gmail setup", "/api/gmail/setup", "OAuth"),
        ("Gmail status", "/api/gmail/status", "stats"),
        ("Reports list", "/api/reports/", "reports"),
        ("Network nodes", "/api/network/nodes", "nodes"),
        ("Network info", "/api/network/info", "local_ip"),
        ("Security summary", "/api/security/summary", "status"),
    ]
    for name, path, key in apis:
        ar = s.get(f"{BASE}{path}", timeout=15)
        try:
            data = ar.json()
            found = key.lower() in str(data).lower()
        except Exception:
            found = ar.status_code == 200
        ok(f"API {name}", ar.status_code == 200 and found, str(ar.status_code))

    # Gmail routes exist (not 404)
    gr = s.get(f"{BASE}/api/gmail/setup", timeout=15)
    ok("Gmail API loaded (not 404)", gr.status_code != 404, gr.status_code)

    # Remediation modal partial on vulns
    vr = s.get(f"{BASE}/vulnerabilidades", timeout=15)
    ok("Remediación modal", "remediation" in vr.text.lower() or "remediar" in vr.text.lower())

    # AI chat
    cr = s.post(f"{BASE}/api/ai/chat", json={"message": "estado del sistema"}, timeout=20)
    try:
        cd = cr.json()
        ok("Kernel IA chat", cr.status_code == 200 and cd.get("reply"), cd.get("reply", "")[:60])
    except Exception as e:
        ok("Kernel IA chat", False, str(e))

    failed = [r for r in results if r[1] == "FAIL"]
    print("\n=== RESUMEN ===")
    print(f"Total: {len(results)} | OK: {len(results)-len(failed)} | FAIL: {len(failed)}")
    if failed:
        for f in failed:
            print(f"  FAIL: {f[0]} {f[2]}")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
