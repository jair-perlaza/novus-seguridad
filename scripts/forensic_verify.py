"""Verificación forense sin reiniciar servidor — Flask test client."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.app import create_app
from database import inicializar_db, ensure_tables_exist, SessionLocal, Usuario
from werkzeug.security import generate_password_hash

from models.user import User

app = create_app('testing')

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

# Login
r = client.post('/login', data={'email': EMAIL, 'password': PASSWORD}, follow_redirects=True)
assert r.status_code == 200, f"Login failed: {r.status_code}"

checks = []

def check(name, cond, detail=""):
    checks.append((name, cond, detail))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))

# Audit API
ar = client.get('/api/audit/data-sources')
check("Audit API status", ar.status_code == 200)
ad = ar.get_json()
check("Audit entries", ad and ad.get('total_components', 0) > 0, str(ad.get('total_components')))
check("No SIMULADO entries", not any(e.get('status') == 'SIMULADO' for e in ad.get('entries', [])))

# Network nodes - no Online status
nr = client.get('/api/network/nodes')
nd = nr.get_json()
nodes = nd.get('nodes', [])
online_fake = [n for n in nodes if n.get('status') == 'Online']
check("Network nodes sin 'Online' falso", len(online_fake) == 0, f"found {len(online_fake)}")

# Security summary
sr = client.get('/api/security/summary')
sd = sr.get_json()
check("Security summary", sr.status_code == 200)

# Dashboard live
dr = client.get('/api/dashboard/live')
dd = dr.get_json()
check("Dashboard live psutil", dd.get('status') == 'success' and 'cpu' in dd)

# Vulnerability scanner - no static CVEs
from vulnerability_scanner import vulnerability_scanner
vulns = vulnerability_scanner.check_package_vulnerabilities()
check("CVE estáticos eliminados", len(vulns) == 0)

# Gmail domain_age
from services.gmail_analyzer_service import analyze_message
# Just verify module loads
check("Gmail analyzer import", True)

# Pages sin Cali
for path in ['/dashboard', '/configuracion', '/amenazas', '/vulnerabilidades']:
    pr = client.get(path)
    check(f"Página {path}", pr.status_code == 200 and 'Cali, Colombia' not in pr.get_data(as_text=True))

# Kernel IA
cr = client.post('/api/ai/chat', json={'message': '¿Cuántas vulnerabilidades tiene mi equipo?'})
cd = cr.get_json()
check("Kernel IA responde", cr.status_code == 200 and cd.get('reply'))
mods = (cd.get('intent') or {}).get('modules', [])
check("Kernel no activa network por vulns", 'network' not in (mods or []), str(mods))

passed = sum(1 for _, c, _ in checks if c)
print(f"\nTOTAL: {passed}/{len(checks)} passed")
sys.exit(0 if passed == len(checks) else 1)
