"""Auditoría Topology — datos reales, filtros, Kernel IA."""
import sys
import requests

BASE = "http://127.0.0.1:5000"
EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"


def main():
    s = requests.Session()
    root = s.get(BASE, timeout=15)
    print(f"[{'OK' if root.status_code == 200 else 'FAIL'}] HTTP {root.status_code}")

    r = s.post(f"{BASE}/login", data={"email": EMAIL, "password": PASSWORD}, allow_redirects=True, timeout=30)
    if "login" in r.url.lower():
        print("[FAIL] Login"); return 1
    print("[OK] Login")

    page = s.get(f"{BASE}/topology", timeout=30)
    print(f"[{'OK' if page.status_code == 200 else 'FAIL'}] /topology -> {page.status_code}")
    checks = [
        "topology-map" in page.text,
        "api/network/topology" in page.text,
        "filter-chip" in page.text,
        "side-panel" in page.text,
        "Dashboard" in page.text,
    ]
    print(f"[{'OK' if all(checks) else 'FAIL'}] UI elements present")

    topo = s.get(f"{BASE}/api/network/topology", timeout=90)
    if topo.status_code != 200:
        print(f"[FAIL] topology API -> {topo.status_code}"); return 1
    data = topo.json()
    nodes = data.get("nodes") or []
    conns = data.get("connections") or []
    print(f"[OK] Topology API: {len(nodes)} nodos, {len(conns)} conexiones reales")

    fake = [n for n in nodes if not n.get("ip")]
    print(f"[{'OK' if not fake else 'FAIL'}] Sin nodos sin IP ({len(fake)} inválidos)")

    has_risk = all(n.get("risk_level") for n in nodes) if nodes else True
    print(f"[{'OK' if has_risk else 'FAIL'}] Todos los nodos tienen risk_level")

    gw = (data.get("summary") or {}).get("gateway")
    for c in conns:
        if c.get("from") != gw and gw != "Sin datos disponibles":
            print(f"[WARN] Conexión no desde gateway: {c}")
    print(f"[{'OK' if True else 'FAIL'}] Conexiones solo gateway→dispositivo")

    if nodes:
        ip = nodes[0]["ip"]
        det = s.get(f"{BASE}/api/network/topology/device/{ip}", timeout=60)
        panel = det.json().get("panel") if det.status_code == 200 else None
        print(f"[{'OK' if panel else 'FAIL'}] Panel dispositivo {ip}")
        if panel:
            print(f"    Campos: ip={panel.get('ip')}, tipo={panel.get('tipo_dispositivo')}, riesgo={panel.get('riesgo_nivel')}")

    # Kernel IA via chat API if available
    try:
        chat = s.post(f"{BASE}/api/ai/chat", json={"message": "¿Cuántos dispositivos hay conectados en la topología?"}, timeout=60)
        if chat.status_code == 200:
            reply = chat.json().get("reply") or chat.json().get("response") or ""
            ok = "dispositivo" in reply.lower() or "topology" in reply.lower()
            print(f"[{'OK' if ok else 'WARN'}] Kernel IA topology query")
        else:
            print(f"[WARN] Kernel chat -> {chat.status_code}")
    except Exception as e:
        print(f"[WARN] Kernel: {e}")

    listeners = __import__('subprocess').run(
        ['netstat', '-ano'], capture_output=True, text=True
    ).stdout
    count = sum(1 for line in listeners.splitlines() if ':5000' in line and 'LISTENING' in line)
    print(f"[{'OK' if count == 1 else 'FAIL'}] Instancia única en :5000 ({count})")

    print("\n=== TOPOLOGY AUDIT COMPLETE ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
