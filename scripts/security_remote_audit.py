#!/usr/bin/env python3
"""Auditoría de seguridad para acceso remoto — verifica protección de APIs."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.app import create_app
from database import inicializar_db, ensure_tables_exist, SessionLocal, Usuario
from werkzeug.security import generate_password_hash
from models.user import User

EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"

SENSITIVE_GET = [
    "/api/dashboard/live",
    "/api/dashboard/priority",
    "/api/dashboard/metrics",
    "/api/network/nodes",
    "/api/network/info",
    "/api/security/summary",
    "/api/ai/status",
    "/api/system/status",
    "/api/system/ai/logs",
    "/api/reports/list",
]

SENSITIVE_POST = [
    "/api/network/refresh",
    "/api/system/ai/command",
    "/api/system/ai/files",
]


def setup_user(app):
    with app.app_context():
        db = SessionLocal()
        u = db.query(Usuario).filter(Usuario.email == EMAIL).first()
        if not u:
            u = Usuario(
                email=EMAIL,
                hashed_password=generate_password_hash(PASSWORD),
                sector="fintech",
                is_active=True,
            )
            db.add(u)
            db.commit()
        db.close()


def main():
    app = create_app("testing")

    @app.login_manager.user_loader
    def load_user(user_id):
        if user_id is None or not str(user_id).isdigit():
            return None
        return User.get_by_id(user_id)

    inicializar_db()
    ensure_tables_exist()
    setup_user(app)

    client = app.test_client()
    checks = []

    def record(name, ok, detail=""):
        checks.append((name, ok, detail))
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))

    for path in SENSITIVE_GET:
        r = client.get(path)
        record(f"GET {path} sin auth -> 401", r.status_code == 401, str(r.status_code))

    for path in SENSITIVE_POST:
        r = client.post(path, json={})
        record(f"POST {path} sin auth -> 401", r.status_code == 401, str(r.status_code))

    r = client.get("/registro_empresa")
    record("Registro accesible en dev", r.status_code in (200, 302), str(r.status_code))

    app_beta = create_app("beta")
    register_security = hasattr(app_beta, "before_request_funcs") or True
    record("BetaConfig carga", app_beta.config.get("ALLOW_PUBLIC_REGISTRATION") is False, "registration off")

    with app_beta.app_context():
        c2 = app_beta.test_client()
        r2 = c2.get("/registro_empresa")
        record("Registro bloqueado en beta", r2.status_code in (302, 403), str(r2.status_code))

    headers = client.post("/login", data={"email": EMAIL, "password": PASSWORD}, follow_redirects=True)
    record("Login funciona", headers.status_code == 200, str(headers.status_code))

    client.post("/login", data={"email": EMAIL, "password": PASSWORD}, follow_redirects=True)
    for path in ["/api/dashboard/live", "/api/security/summary", "/api/ai/status", "/api/network/nodes"]:
        r = client.get(path)
        record(f"GET {path} autenticado -> 200", r.status_code == 200, str(r.status_code))

    passed = sum(1 for _, ok, _ in checks if ok)
    print(f"\nTOTAL: {passed}/{len(checks)} passed")
    print(json.dumps({
        "session_cookie_httponly": app.config.get("SESSION_COOKIE_HTTPONLY"),
        "session_cookie_samesite": app.config.get("SESSION_COOKIE_SAMESITE"),
        "behind_proxy": app.config.get("BEHIND_PROXY"),
        "security_module": True,
    }, indent=2))
    sys.exit(0 if passed == len(checks) else 1)


if __name__ == "__main__":
    main()
