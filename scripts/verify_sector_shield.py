"""Verify sector shield API integration."""
import requests

BASE = "http://127.0.0.1:5000"
EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"


def main():
    s = requests.Session()
    s.post(f"{BASE}/login", data={"email": EMAIL, "password": PASSWORD}, allow_redirects=True)

    r = s.get(f"{BASE}/api/system/sector-shield/status")
    d = r.json()
    print(f"[{'OK' if d.get('status')=='success' else 'FAIL'}] status -> {d.get('shield_name')} / {d.get('shield_status')}")

    r = s.post(f"{BASE}/api/system/sector-shield/scan")
    d = r.json()
    print(f"[{'OK' if d.get('status')=='success' else 'FAIL'}] scan -> {d.get('message', d.get('status'))[:60]}")

    r = s.post(f"{BASE}/api/system/config/save", json={
        "pentest_mode": "estandar",
        "whatsapp_alerts": True,
        "email_reports": False,
        "sector_activo": "logistica",
    })
    print(f"[{'OK' if r.json().get('status')=='success' else 'FAIL'}] config sector -> logistica")

    r = s.get(f"{BASE}/api/system/sector-shield/status")
    d = r.json()
    ok = d.get("sector_key") == "logistica" or "Log" in (d.get("shield_name") or "")
    print(f"[{'OK' if ok else 'FAIL'}] shield after sector change -> {d.get('shield_name')} ({d.get('sector_key')})")

    for action in ("analyze-vulnerabilities", "update-rules", "policies", "history", "reports"):
        method = "POST" if action in ("analyze-vulnerabilities", "update-rules") else "GET"
        url = f"{BASE}/api/system/sector-shield/{action}"
        r = s.post(url) if method == "POST" else s.get(url)
        good = r.status_code == 200 and r.json().get("status") == "success"
        print(f"[{'OK' if good else 'FAIL'}] {action} -> {r.status_code}")

    r = s.get(f"{BASE}/dashboard")
    html = r.text
    print(f"[{'OK' if 'Escudo Sectorial Activo' in html and 'loadSectorShield' in html else 'FAIL'}] dashboard panel embedded")

    print(f"\nPort check: {BASE}")


if __name__ == "__main__":
    main()
