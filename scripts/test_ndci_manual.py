"""Prueba generación manual de casos NDCI."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Base, engine
Base.metadata.create_all(bind=engine)

from main import app
from services.ndci_service import ndci_service, MANUAL_ANALYSIS_TYPES

client = app.test_client()
client.post(
    "/login",
    data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!"},
    follow_redirects=True,
)

# Options API
r = client.get("/api/ndci/manual/options")
assert r.status_code == 200, r.get_data(as_text=True)
opts = r.get_json()
assert opts.get("status") == "success"
assert len(opts.get("analysis_types", [])) == len(MANUAL_ANALYSIS_TYPES)
print(f"[OK] manual/options — {len(opts.get('analysis_types'))} tipos")

# Manual case — infraestructura
case = ndci_service.create_manual_case(
    analysis_type="infraestructura_completa",
    user_email="novus.qa.jul2026@example.com",
)
cid = case.get("id")
assert cid and case.get("origen") == "manual"
exp = case.get("expediente") or {}
assert exp.get("identificacion", {}).get("modalidad") == "manual"
assert exp.get("inventario_completo") is not None or exp.get("infraestructura")
print(f"[OK] Caso manual infraestructura: {cid}")

r = client.post("/api/ndci/cases/manual", json={"analysis_type": "estado_red"})
assert r.status_code == 200, r.get_json()
api_case = r.get_json().get("case", {})
print(f"[OK] API manual estado_red: {api_case.get('id')}")

r = client.get(f"/api/ndci/cases/{cid}")
assert r.status_code == 200
print("[OK] GET case manual")

r = client.get(f"/api/ndci/cases/{cid}/pdf")
assert r.status_code == 200
print("[OK] PDF export manual case")

r = client.get("/casos-estudio")
assert r.status_code == 200
assert "NUEVO CASO DE ESTUDIO" in r.get_data(as_text=True)
print("[OK] UI botón NUEVO CASO DE ESTUDIO")

reply = ndci_service.answer_kernel_query(f"Muéstrame el caso {cid}")
assert reply and (cid in reply or cid.split("-")[-1] in reply)
print(f"[OK] Kernel consulta caso manual")

# Invalid type
r = client.post("/api/ndci/cases/manual", json={"analysis_type": "invalido"})
assert r.status_code == 400
print("[OK] Validación tipo inválido")

print("\nNDCI MANUAL: ALL PASS")
