"""Prueba rápida module-consult API."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app

client = app.test_client()
client.post(
    "/login",
    data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!"},
    follow_redirects=True,
)

mods = ["dashboard", "vulnerabilidades", "network", "inteligencia", "xdr", "aspe"]
ok_all = True
for mod in mods:
    r = client.get(f"/api/ai/module-consult?module={mod}")
    d = r.get_json() or {}
    ok = r.status_code == 200 and d.get("status") == "success" and len(d.get("prompt", "")) > 100
    ok_all = ok_all and ok
    print(f"[{'OK' if ok else 'FAIL'}] {mod} status={r.status_code} prompt_len={len(d.get('prompt', ''))} real={d.get('has_real_data')}")

# build_sector_protection
from services.novus_security_integration import novus_security
prof = novus_security.security_engine.build_sector_protection("logistica")
resp = prof.get("response") or {}
no_data = resp.get("status") == "NO_DATA"
print(f"[{'FAIL' if no_data else 'OK'}] build_sector_protection status={resp.get('status')} telemetry={bool(resp.get('telemetry'))}")

raise SystemExit(0 if ok_all and not no_data else 1)
