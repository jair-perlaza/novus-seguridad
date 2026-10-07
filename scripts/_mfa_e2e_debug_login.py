"""Debug one-shot admin login for MFA E2E."""
import re
import sys
import time
from pathlib import Path

import requests
from werkzeug.security import generate_password_hash

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from database import SessionLocal, Usuario
from scripts.mfa_admin_http_e2e_final import clear_localhost_auth_blocks

BASE = "http://127.0.0.1:5000"
email = "MFA-E2E-TEST-debug@example.com"
pwd = "TestPass123!"

clear_localhost_auth_blocks()

db = SessionLocal()
db.query(Usuario).filter(Usuario.email == email).delete()
db.add(
    Usuario(
        email=email,
        hashed_password=generate_password_hash(pwd),
        role="company_admin",
        nit_pyme="MFA-E2E-DEBUG",
        sector="fintech",
        is_active=True,
        is_temporal=False,
    )
)
db.commit()
db.close()

s = requests.Session()
g = s.get(BASE + "/login", timeout=90)
t = re.search(r'name="csrf_token" value="([^"]+)"', g.text)
if not t:
    print("NO CSRF TOKEN")
    sys.exit(1)
token = t.group(1)
t0 = time.perf_counter()
p = s.post(
    BASE + "/login",
    data={"email": email, "password": pwd, "csrf_token": token},
    allow_redirects=False,
    timeout=90,
)
elapsed = round(time.perf_counter() - t0, 1)
print("elapsed_s", elapsed)
print("status", p.status_code)
print("location", p.headers.get("Location"))
print("recovery", p.headers.get("X-Novus-Recovery"))
print("cookies", list(s.cookies.keys()))
for needle in (
    "incorrectos",
    "bloqueado",
    "Error al procesar",
    "MFA",
    "mfa-setup",
    "mfa_required",
    "Authenticator",
    "Acceder",
):
    print(needle, needle.lower() in p.text.lower())
print("body_snip", p.text[:1200].replace("\n", " "))
