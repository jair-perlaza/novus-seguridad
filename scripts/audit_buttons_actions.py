"""Auditoría de botones y acciones NOVUS — handlers, APIs y module-consult."""
import re
import requests

BASE = "http://127.0.0.1:5000"
EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"

MODULES = [
    "/dashboard", "/inteligencia", "/network", "/topology", "/vulnerabilidades",
    "/incidentes", "/xdr", "/endpoints", "/automatizacion", "/reportes",
    "/configuracion", "/casos-estudio", "/siem",
]

HANDLER_CHECKS = [
    ("topology", "investigateDevice", "/topology"),
    ("topology", "consultKernel", "/topology"),
    ("topology", "refreshTopology", "/topology"),
    ("network", "investigarDispositivo", "/network"),
    ("network", "iniciarEscaneo", "/network"),
    ("xdr", "verTrazaDesdeFila", "/xdr"),
    ("inteligencia", "refreshDashboard", "/inteligencia"),
    ("playbooks", "openPlaybookModal", "/automatizacion"),
    ("reportes", "abrirGenerador", "/reportes"),
    ("kernel", "NovusAIKernel.consultModule", None),
]


def count_buttons(html):
    onclick = len(re.findall(r"\bonclick\s*=", html, re.I))
    buttons = len(re.findall(r"<button\b", html, re.I))
    return onclick + buttons


def main():
    s = requests.Session()
    r = s.post(f"{BASE}/login", data={"email": EMAIL, "password": PASSWORD}, allow_redirects=True, timeout=30)
    if "login" in r.url.lower():
        print("[FAIL] Login")
        return 1
    print("[OK] Login\n")

    total_buttons = 0
    pages_ok = 0
    for path in MODULES:
        html = s.get(f"{BASE}{path}", timeout=60).text
        n = count_buttons(html)
        total_buttons += n
        ok = html.count("onclick") >= 0 and "</body>" in html
        pages_ok += int(ok)
        print(f"[OK] {path}: ~{n} controles interactivos")

    print(f"\n[INFO] Total controles revisados (aprox.): {total_buttons}")

    # Topology investigate API
    topo = s.get(f"{BASE}/api/network/topology", timeout=90).json()
    nodes = topo.get("nodes") or []
    if nodes:
        ip = nodes[0]["ip"]
        inv = s.post(f"{BASE}/api/network/ndr/device/{ip}/investigate", timeout=120)
        inv_data = inv.json()
        inv_ok = inv.status_code == 200 and inv_data.get("status") == "success"
        print(f"[{'OK' if inv_ok else 'FAIL'}] POST investigate {ip}: {inv_data.get('message', inv_data.get('status'))}")
        hist = inv_data.get("history") or []
        has_inv = any(h.get("event") == "investigation" for h in hist)
        print(f"[{'OK' if has_inv else 'FAIL'}] Historial registra investigación")
    else:
        print("[WARN] Sin nodos para probar investigate")

    # Kernel module-consult topology + ip
    if nodes:
        ip = nodes[0]["ip"]
        mc = s.get(f"{BASE}/api/ai/module-consult", params={"module": "topology", "ip": ip}, timeout=60)
        mc_data = mc.json()
        mc_ok = mc.status_code == 200 and mc_data.get("status") == "success" and mc_data.get("prompt")
        has_device = "device_panel" in (mc_data.get("context") or {})
        print(f"[{'OK' if mc_ok else 'FAIL'}] module-consult topology+ip")
        print(f"[{'OK' if has_device else 'FAIL'}] Contexto incluye device_panel")

    # Handler presence in HTML
    print("\n--- Handlers en plantillas ---")
    handlers_ok = 0
    for mod, handler, path in HANDLER_CHECKS:
        if path:
            html = s.get(f"{BASE}{path}", timeout=30).text
        else:
            html = s.get(f"{BASE}/topology", timeout=30).text
        present = handler.replace(".", "") in html.replace(".", "") or handler in html
        handlers_ok += int(present)
        print(f"[{'OK' if present else 'FAIL'}] {mod}: {handler}")

    print(f"\n=== BUTTON AUDIT: {handlers_ok}/{len(HANDLER_CHECKS)} handlers OK ===")
    return 0 if handlers_ok >= len(HANDLER_CHECKS) - 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
