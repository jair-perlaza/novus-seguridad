#!/usr/bin/env python3
"""Auditoría RBAC + protección Casos de Estudio."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = 0
FAIL = 0

SUPER_EMAIL = "novus.qa.jul2026@example.com"
SUPER_PASS = "NovusQA2026!"
CLIENT_EMAIL = "operaciones@novapay-fintech.co"
CLIENT_PASS = "NovaPay#Fintech2026"


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [OK] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")


def login(client, email, password):
    return client.post("/login", data={"email": email, "password": password}, follow_redirects=True)


def main():
    from migrate_database import migrate_database
    from database import ensure_tables_exist, SessionLocal, Usuario
    from werkzeug.security import generate_password_hash

    migrate_database()
    ensure_tables_exist()

    db = SessionLocal()
    try:
        qa = db.query(Usuario).filter(Usuario.email == SUPER_EMAIL).first()
        if qa:
            qa.role = "super_admin"
            qa.hashed_password = generate_password_hash(SUPER_PASS)
        client_u = db.query(Usuario).filter(Usuario.email == CLIENT_EMAIL).first()
        if client_u:
            client_u.role = "client"
            client_u.hashed_password = generate_password_hash(CLIENT_PASS)
        else:
            db.add(Usuario(
                email=CLIENT_EMAIL,
                hashed_password=generate_password_hash(CLIENT_PASS),
                is_active=True,
                sector="Fintech",
                nit_pyme="901.567.123-4",
                role="client",
            ))
        db.commit()
    finally:
        db.close()

    from core.app import create_app
    from models.user import User

    app = create_app("development")

    @app.login_manager.user_loader
    def load_user(user_id):
        return User.get_by_id(user_id)

    client = app.test_client()

    from services.rbac_service import (
        MODULE_ACCESS,
        ROLE_SUPER_ADMIN,
        can_access_module_by_email,
        role_label,
    )
    from services.ndci_service import NDCI_ENC_PREFIX, _store_expediente, _load_expediente

    check("super_admin can access casos_estudio", can_access_module_by_email(SUPER_EMAIL, "casos_estudio"))
    check("client cannot access casos_estudio", not can_access_module_by_email(CLIENT_EMAIL, "casos_estudio"))

    enc = _store_expediente({"test": "evidence", "nivel_riesgo": "MEDIO"})
    check("NDCI encryption uses CryptoVault", enc.startswith(NDCI_ENC_PREFIX))
    dec = _load_expediente(enc)
    check("NDCI decryption roundtrip", dec.get("test") == "evidence")

    login(client, SUPER_EMAIL, SUPER_PASS)
    r = client.get("/casos-estudio")
    check("super_admin page /casos-estudio", r.status_code == 200)

    r = client.get("/api/ndci/cases")
    check("super_admin API /api/ndci/cases", r.status_code == 200 and r.get_json().get("status") == "success")

    client.get("/logout")

    client_client = app.test_client()
    login(client_client, CLIENT_EMAIL, CLIENT_PASS)

    r = client_client.get("/casos-estudio")
    check("client page /casos-estudio denied", r.status_code == 403)

    r = client_client.get("/api/ndci/cases")
    check("client API /api/ndci/cases denied", r.status_code == 403)

    r = client_client.get("/api/ndci/cases/NOVUS-CS-2026-000001")
    check("client API get case denied", r.status_code == 403)

    r = client_client.post("/api/ai/module-consult", json={"module": "casos_estudio", "extra": {}})
    check("client module-consult casos_estudio denied", r.status_code == 403)

    for _ in range(3):
        client_client.get("/casos-estudio")

    from services.evidence_center_service import list_evidence
    audits = list_evidence(limit=10, motor="rbac_service")
    check("rbac denials audited", len(audits) >= 1)

    report_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "rbac")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "audit_report.md")
    lines = [
        "# Auditoría RBAC + Casos de Estudio",
        "",
        "## Implementación RBAC",
        "- Columna `role` en tabla `usuarios`",
        "- Servicio canónico: `services/rbac_service.py`",
        "- Decoradores: `utils/rbac.py` (`require_module`, `require_api_resource`, `require_roles`)",
        "- Roles: Super Administrador, Administrador de Empresa, Analista/Operador, Cliente",
        "",
        "## Visibilidad por rol",
        "",
        "| Módulo | super_admin | company_admin | analyst | client |",
        "|---|:---:|:---:|:---:|:---:|",
    ]
    for mod, roles in sorted(MODULE_ACCESS.items()):
        lines.append(
            f"| {mod} | {'✓' if ROLE_SUPER_ADMIN in roles else '—'} | "
            f"{'✓' if 'company_admin' in roles else '—'} | "
            f"{'✓' if 'analyst' in roles else '—'} | "
            f"{'✓' if 'client' in roles else '—'} |"
        )
    lines.extend([
        "",
        "## Protección Casos de Estudio",
        "- Módulo UI + menú: solo `super_admin` (`can_access.casos_estudio`)",
        "- Ruta `/casos-estudio`: `@require_module('casos_estudio')`",
        "- APIs `/api/ndci/*`: `@require_api_resource('ndci')`",
        "- Kernel IA / module-consult: verificación RBAC",
        "- Cifrado AES-256-GCM vía CryptoVault (`NOVUSENC:v1:`) en DB, archivos y knowledge.jsonl",
        "- Denegaciones: auditoría cifrada + evidencias + escalación auth_protection",
        "",
        f"## Pruebas: {PASS} OK / {FAIL} FAIL",
    ])
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"\nInforme: {report_path}")
    print(f"\n=== RESULTADO: {PASS} OK, {FAIL} FAIL ===")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
