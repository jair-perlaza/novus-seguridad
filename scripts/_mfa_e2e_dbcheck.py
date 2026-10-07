"""Check test user persistence without printing secrets."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from werkzeug.security import generate_password_hash, check_password_hash
from database import SessionLocal, Usuario, DATABASE_URL
from models.user import User

email = "mfa-e2e-test-dbcheck@example.com"
pwd = "TestPass123!"

print("db_url", DATABASE_URL)

db = SessionLocal()
db.query(Usuario).filter(Usuario.email == email).delete()
db.add(
    Usuario(
        email=email,
        hashed_password=generate_password_hash(pwd),
        role="company_admin",
        nit_pyme="MFA-E2E-DB",
        sector="fintech",
        is_active=True,
        is_temporal=False,
    )
)
db.commit()
u = db.query(Usuario).filter(Usuario.email == email).first()
print("row_exists", u is not None)
print("is_active", getattr(u, "is_active", None))
print("role", getattr(u, "role", None))
print("password_matches", bool(u and check_password_hash(u.hashed_password, pwd)))
db.close()
print("authenticate_ok", User.authenticate(email, pwd) is not None)

db = SessionLocal()
db.query(Usuario).filter(Usuario.email == email).delete()
db.commit()
db.close()
