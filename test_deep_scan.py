"""Prueba integración Deep Scan — sin caché, informe generado."""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.app import create_app
from database import inicializar_db, ensure_tables_exist, SessionLocal, Usuario
from werkzeug.security import generate_password_hash
from models.user import User

app = create_app("testing")

@app.login_manager.user_loader
def load_user(user_id):
    if user_id is None or not str(user_id).isdigit():
        return None
    return User.get_by_id(user_id)

inicializar_db()
ensure_tables_exist()

EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"

with app.app_context():
    db = SessionLocal()
    u = db.query(Usuario).filter(Usuario.email == EMAIL).first()
    if not u:
        u = Usuario(email=EMAIL, hashed_password=generate_password_hash(PASSWORD), sector="fintech", is_active=True)
        db.add(u)
        db.commit()
    db.close()

client = app.test_client()
client.post("/login", data={"email": EMAIL, "password": PASSWORD}, follow_redirects=True)

# 1. Intent classification
from services.ai_orchestrator import kernel_orchestrator
intent = kernel_orchestrator.classify_intent("Escanea mi portátil")
assert intent["primary_intent"] == "deep_scan", intent
print("[PASS] Intent deep_scan clasificado")

# 2. Chat triggers deep scan (not cached orchestrator)
r = client.post("/api/ai/chat", json={"message": "Escanea mi portátil"})
data = r.get_json()
assert data.get("deep_scan") is True, data
assert data.get("scan_id"), data
scan_id = data["scan_id"]
print(f"[PASS] Chat inició Deep Scan: {scan_id}")

# 3. Poll until complete (max 180s)
deadline = time.time() + 180
state = "running"
while time.time() < deadline and state == "running":
    sr = client.get(f"/api/ai/deep-scan/{scan_id}/status")
    sd = sr.get_json()
    state = sd.get("scan_state", "running")
    if state == "running":
        time.sleep(2)

assert state == "completed", f"scan_state={state}, error={sd.get('error')}"
print(f"[PASS] Deep Scan completado en {sd.get('elapsed_sec')}s")

# 4. Report
rr = client.get(f"/api/ai/deep-scan/{scan_id}/report")
rep = rr.get_json()
assert rep["status"] == "success", rep
report = rep["report"]
assert report.get("text_report"), "sin informe"
assert "DEEP SCAN" in report["text_report"]
assert report["summary"]["processes"] > 0, "sin procesos analizados"
print(f"[PASS] Informe generado — riesgo: {report['risk_level']}, hallazgos: {len(report['findings'])}")
print(f"       Archivos: {report['summary']['files']}, Procesos: {report['summary']['processes']}")
print(f"       Motores: {', '.join(report['engines_used'][:4])}...")
print("\nTODAS LAS PRUEBAS DEEP SCAN: OK")
