"""Quick post-fix validation T2/T3 + B/C/E (no 5min wait)."""
import json
import re
import sys
import time
from pathlib import Path

import requests
from werkzeug.security import generate_password_hash

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
BASE = "http://127.0.0.1:5000"
RUN = "postfix"
EMAIL = f"mfa-e2e-test-{RUN}@example.com".lower()
PWD = "TestPass123!"

from database import SessionLocal, Usuario, AuthOriginSanction, IPBloqueada

db = SessionLocal()
for ip in ("127.0.0.1", "::1"):
    for row in db.query(AuthOriginSanction).filter(AuthOriginSanction.origin_key == ip, AuthOriginSanction.status == "active").all():
        row.status = "revoked"
    for row in db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == ip).all():
        db.delete(row)
db.query(Usuario).filter(Usuario.email == EMAIL).delete()
db.add(Usuario(email=EMAIL, hashed_password=generate_password_hash(PWD), role="company_admin", nit_pyme="mfa-e2e-postfix", sector="fintech", is_active=True, is_temporal=False))
db.commit()
db.close()

s = requests.Session()
g = s.get(BASE + "/login", timeout=30)
tok = re.search(r'name="csrf_token" value="([^"]+)"', g.text).group(1)
p = s.post(BASE + "/login", data={"email": EMAIL, "password": PWD, "csrf_token": tok}, allow_redirects=False, timeout=120)
print("login", p.status_code, p.headers.get("Location"))
mfa = s.get(BASE + "/mfa-setup", timeout=30)
print("mfa-setup", mfa.status_code, "recovering", "recuperando" in mfa.text.lower(), "btn-enroll", "btn-enroll" in mfa.text)
csrf_m = re.search(r"const csrf = (.+?);", mfa.text)
csrf = json.loads(csrf_m.group(1)) if csrf_m else re.search(r'name="csrf_token" value="([^"]+)"', mfa.text).group(1)
enr = s.post(BASE + "/api/wsae/mfa/enroll", headers={"Content-Type": "application/json", "X-CSRF-Token": csrf}, json={}, timeout=120)
eb = enr.json() if "json" in enr.headers.get("content-type", "") else {}
print("enroll", enr.status_code, eb.get("ok"), bool(eb.get("secret")), eb.get("status"))
if eb.get("secret"):
    import pyotp
    code = pyotp.TOTP(eb["secret"]).now()
    en = s.post(BASE + "/api/wsae/mfa/enable", headers={"Content-Type": "application/json", "X-CSRF-Token": csrf}, json={"code": code}, timeout=120)
    print("enable", en.status_code, en.json() if en.ok else en.text[:200])
