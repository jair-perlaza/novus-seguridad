import re
import sys
from pathlib import Path

import requests
from werkzeug.security import generate_password_hash

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from database import SessionLocal, Usuario

BASE = "http://127.0.0.1:5000"
email = "MFA-E2E-TEST-debug@example.com"
pwd = "TestPass123!"

db = SessionLocal()
db.query(Usuario).filter(Usuario.email == email).delete()
db.add(Usuario(
    email=email,
    hashed_password=generate_password_hash(pwd),
    role="company_admin",
    nit_pyme="MFA-E2E-DEBUG",
    is_active=True,
))
db.commit()
db.close()

s = requests.Session()
g = s.get(BASE + "/login", timeout=15)
t = re.search(r'name="csrf_token" value="([^"]+)"', g.text).group(1)
p = s.post(
    BASE + "/login",
    data={"email": email, "password": pwd, "csrf_token": t},
    allow_redirects=False,
    timeout=15,
)
print("status", p.status_code)
print("location", p.headers.get("Location"))
print("has_mfa_setup", "mfa-setup" in (p.headers.get("Location") or ""))
print("body_mfa", "mfa" in p.text.lower())
print("body_error", "error" in p.text.lower())
for needle in ("incorrectos", "Error al procesar", "MFA", "mfa-setup", "Acceder"):
    print(needle, needle.lower() in p.text.lower())
