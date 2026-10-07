"""Prueba NDCI — crear caso, listar, kernel query, PDF."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Base, engine
Base.metadata.create_all(bind=engine)

from main import app
from services.ndci_service import ndci_service

client = app.test_client()
client.post(
    "/login",
    data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!"},
    follow_redirects=True,
)

# Crear caso desde telemetría actual (sin deep scan)
case = ndci_service.create_case(
    user_email="novus.qa.jul2026@example.com",
    origen="test_audit",
    source_ref="NDCI-AUDIT",
    message="Auditoría NDCI — telemetría en vivo",
    titulo="Auditoría inicial NDCI",
)
cid = case.get("id")
print(f"[OK] Caso creado: {cid}")

r = client.get(f"/api/ndci/cases/{cid}")
assert r.status_code == 200 and r.get_json().get("status") == "success"
print("[OK] GET case API")

r = client.get("/api/ndci/cases")
assert r.status_code == 200 and len(r.get_json().get("cases", [])) >= 1
print("[OK] LIST cases API")

r = client.get(f"/api/ndci/cases/{cid}/pdf")
assert r.status_code == 200
print(f"[OK] PDF export ({r.content_type})")

r = client.get("/casos-estudio")
assert r.status_code == 200
print("[OK] UI /casos-estudio")

reply = ndci_service.answer_kernel_query(f"Muéstrame el caso {cid.split('-')[-1]}")
assert reply and cid.split("-")[-1] in reply or cid in reply
print(f"[OK] Kernel query: {reply[:80]}...")

print("\nNDCI audit: ALL PASS")
