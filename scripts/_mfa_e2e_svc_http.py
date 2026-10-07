"""Service + HTTP gate check without restarting server."""
import re
import sys
import time
from pathlib import Path

import requests
from werkzeug.security import generate_password_hash

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from database import SessionLocal, Usuario
from models.user import User
from scripts.mfa_admin_http_e2e_final import clear_localhost_auth_blocks
from services.web_security_auth_enterprise.mfa_policy import check_mfa_login_gate

BASE = "http://127.0.0.1:5000"
email = "mfa-e2e-test-svc@example.com"
pwd = "TestPass123!"

print("clear", clear_localhost_auth_blocks())

db = SessionLocal()
db.query(Usuario).filter(Usuario.email == email).delete()
db.add(
    Usuario(
        email=email,
        hashed_password=generate_password_hash(pwd),
        role="company_admin",
        nit_pyme="MFA-E2E-SVC",
        sector="fintech",
        is_active=True,
        is_temporal=False,
    )
)
db.commit()
db.close()

user = User.authenticate(email, pwd)
print("auth_user", bool(user), getattr(user, "role", None) if user else None)
gate = check_mfa_login_gate(user, email) if user else None
print("gate", gate)

s = requests.Session()
g = s.get(BASE + "/login", timeout=30)
print("get_login_ms", g.elapsed.total_seconds())
t = re.search(r'name="csrf_token" value="([^"]+)"', g.text)
if not t:
    print("NO_CSRF")
    sys.exit(2)
token = t.group(1)
t0 = time.perf_counter()
try:
    p = s.post(
        BASE + "/login",
        data={"email": email, "password": pwd, "csrf_token": token},
        allow_redirects=False,
        timeout=180,
    )
    elapsed = round(time.perf_counter() - t0, 1)
    print("post_elapsed_s", elapsed)
    print("status", p.status_code, "loc", p.headers.get("Location"))
    low = p.text.lower()
    for needle in (
        "incorrectos",
        "bloqueado",
        "error al procesar",
        "mfa-setup",
        "authenticator",
        "demasiados intentos",
        "csrf",
    ):
        print(needle, needle in low)
    print("body_snip", p.text[:900].replace("\n", " "))
except Exception as exc:
    print("post_error", type(exc).__name__, exc)
    elapsed = round(time.perf_counter() - t0, 1)
    print("post_elapsed_s", elapsed)

db = SessionLocal()
db.query(Usuario).filter(Usuario.email == email).delete()
db.commit()
db.close()
