"""Verifica que consultas SOC ejecutan workflow — NO chatbot de resumen."""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.app import create_app
from database import inicializar_db, ensure_tables_exist, SessionLocal, Usuario
from werkzeug.security import generate_password_hash
from models.user import User
from services.soc_workflow_resolver import resolve_soc_workflow

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

QUERIES = [
    ("Escanea mi portátil", "full"),
    ("Busca procesos ocultos", "rootkit"),
    ("Busca aplicaciones ejecutándose en segundo plano", "background"),
    ("Analiza programas instalados", "installed"),
    ("Busca malware", "malware"),
    ("Analiza memoria", "memory"),
    ("Busca rootkits", "rootkit"),
    ("Analiza servicios", "services"),
    ("Analiza tareas programadas", "scheduled"),
    ("Analiza el registro", "registry"),
    ("Analiza conexiones", "connections"),
    ("Busca aplicaciones sospechosas", "processes"),
    ("Revisa procesos", "processes"),
    ("Busca software ejecutándose sin autorización", "processes"),
]

client = app.test_client()
client.post("/login", data={"email": EMAIL, "password": PASSWORD}, follow_redirects=True)

passed = 0
failed = []

print("=== RESOLVER SOC ===")
for q, expected_profile in QUERIES:
    wf = resolve_soc_workflow(q)
    ok = wf and wf["profile"] == expected_profile
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {q} -> {wf['profile'] if wf else None} (esperado: {expected_profile})")
    if ok:
        passed += 1
    else:
        failed.append(q)

print(f"\nResolver: {passed}/{len(QUERIES)}")

print("\n=== KERNEL CHAT (debe iniciar soc_workflow, NO resumen) ===")
chat_pass = 0
for q, _ in QUERIES[:5]:
    r = client.post("/api/ai/chat", json={"message": q})
    d = r.get_json()
    ok = (
        d.get("soc_workflow") is True
        and d.get("scan_id")
        and d.get("defer_full_reply") is True
        and "RESUMEN EJECUTIVO" not in (d.get("reply") or "")
        and "CPU" not in (d.get("reply") or "")[:80]
    )
    print(f"[{'PASS' if ok else 'FAIL'}] Chat: {q[:40]}... soc_workflow={d.get('soc_workflow')} profile={d.get('profile')}")
    if ok:
        chat_pass += 1

print(f"Chat SOC: {chat_pass}/5")

# Verificar que consulta NO-SOC sigue usando orquestador
r2 = client.post("/api/ai/chat", json={"message": "¿Cómo está el tráfico de la red?"})
d2 = r2.get_json()
no_soc = not d2.get("soc_workflow") and d2.get("reply")
print(f"[{'PASS' if no_soc else 'FAIL'}] Consulta red NO dispara SOC workflow")

# Un workflow completo corto (processes profile)
r3 = client.post("/api/ai/chat", json={"message": "Revisa procesos"})
d3 = r3.get_json()
scan_id = d3.get("scan_id")
deadline = time.time() + 180
state = "running"
while time.time() < deadline and state == "running":
    sr = client.get(f"/api/ai/deep-scan/{scan_id}/status")
    sd = sr.get_json()
    state = sd.get("scan_state", "running")
    if state == "running":
        time.sleep(2)

rep = client.get(f"/api/ai/deep-scan/{scan_id}/report").get_json()
has_report = rep.get("status") == "success" and "ANALISTA SOC" in rep.get("report", {}).get("text_report", "")
has_processes = rep.get("report", {}).get("summary", {}).get("processes", 0) > 0
print(f"[{'PASS' if has_report and has_processes else 'FAIL'}] Informe SOC generado (procesos={rep.get('report',{}).get('summary',{}).get('processes')})")

total_ok = passed == len(QUERIES) and chat_pass >= 5 and no_soc and has_report
sys.exit(0 if total_ok else 1)
