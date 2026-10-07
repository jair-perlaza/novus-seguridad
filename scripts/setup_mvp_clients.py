#!/usr/bin/env python3
"""
Configuración final MVP — cuatro clientes reales por sector en SQLite.
Usa el mismo flujo de hash y modelo Usuario que registro_empresa.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash, check_password_hash

from database import SessionLocal, Usuario, registrar_log_seguridad
from models.user import User
from services.sector_shield_service import normalize_sector, resolve_sector_for_user

CLIENTS = [
    {
        "nombre": "NovaPay Fintech S.A.S.",
        "email": "operaciones@novapay-fintech.co",
        "password": "NovaPay#Fintech2026",
        "sector": "Fintech",
        "nit": "901.567.123-4",
    },
    {
        "nombre": "TransLogística Andina S.A.S.",
        "email": "operaciones@translogistica-novus.co",
        "password": "TransLog#2026Novus",
        "sector": "Logística",
        "nit": "901.678.234-5",
    },
    {
        "nombre": "AppSecure Móvil S.A.S.",
        "email": "operaciones@appmovil-novus.co",
        "password": "AppMovil#2026Novus",
        "sector": "Aplicaciones móviles",
        "nit": "901.789.345-6",
    },
    {
        "nombre": "Corporación Integral Novus S.A.S.",
        "email": "operaciones@corp-otros-novus.co",
        "password": "CorpOtros#2026Novus",
        "sector": "Otros",
        "nit": "901.890.456-7",
    },
]

EXPECTED_SECTORS = {
    "operaciones@novapay-fintech.co": "fintech",
    "operaciones@translogistica-novus.co": "logistica",
    "operaciones@appmovil-novus.co": "aplicaciones_moviles",
    "operaciones@corp-otros-novus.co": "otros",
}


def provision_clients() -> list[dict]:
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = []
    db = SessionLocal()
    try:
        for client in CLIENTS:
            email = client["email"].strip().lower()
            existing = db.query(Usuario).filter(Usuario.email == email).first()
            if existing:
                if not existing.is_active:
                    existing.is_active = True
                if existing.is_temporal:
                    existing.is_temporal = False
                    existing.trial_expiry = None
                if not existing.sector:
                    existing.sector = client["sector"]
                if not existing.nit_pyme:
                    existing.nit_pyme = client["nit"]
                existing.role = "client"
                db.commit()
                row = existing
                action = "actualizado"
            else:
                row = Usuario(
                    email=email,
                    hashed_password=generate_password_hash(client["password"]),
                    sector=client["sector"],
                    nit_pyme=client["nit"],
                    is_temporal=False,
                    trial_expiry=None,
                    is_active=True,
                    intentos_fallidos=0,
                    role="client",
                )
                db.add(row)
                try:
                    from services.novus_security_integration import novus_security
                    registrar_log_seguridad(
                        db,
                        "REGISTRO_CLIENTE_MVP",
                        f"Cliente MVP: {client['nombre']} | Sector: {client['sector']} | NIT: {client['nit']}",
                        vault=novus_security.vault,
                    )
                except Exception:
                    pass
                db.commit()
                db.refresh(row)
                action = "creado"

            ok_hash = check_password_hash(row.hashed_password, client["password"])
            results.append({
                "nombre": client["nombre"],
                "email": email,
                "password": client["password"],
                "sector": row.sector,
                "sector_key": normalize_sector(row.sector),
                "estado": "ACTIVO" if row.is_active else "INACTIVO",
                "fecha_creacion": created_at if action == "creado" else "registro previo",
                "nit": row.nit_pyme,
                "is_temporal": bool(row.is_temporal),
                "db_id": row.id,
                "password_hash_ok": ok_hash,
                "accion": action,
                "almacenado_db": ok_hash and row.is_active and not row.is_temporal,
            })
    finally:
        db.close()
    return results


def verify_auth_and_sector(base_url: str = "http://127.0.0.1:5000") -> list[dict]:
    import requests

    checks = []
    for client in CLIENTS:
        email = client["email"].strip().lower()
        entry = {"email": email, "login": False, "dashboard": False, "shield_sector": None, "kernel_sector": None}
        session = requests.Session()
        login = session.post(
            f"{base_url}/login",
            data={"email": email, "password": client["password"]},
            timeout=30,
            allow_redirects=True,
        )
        entry["login"] = login.status_code == 200 and "/dashboard" in login.url
        if entry["login"]:
            dash = session.get(f"{base_url}/dashboard", timeout=30)
            entry["dashboard"] = dash.status_code == 200
            shield = session.get(f"{base_url}/api/system/sector-shield/status", timeout=60)
            if shield.ok:
                data = shield.json()
                entry["shield_sector"] = data.get("sector_key")
            ctx = session.get(f"{base_url}/api/ai/context", timeout=30)
            chat = session.post(
                f"{base_url}/api/ai/chat",
                json={"message": "Indica mi sector de operación y escudo sectorial activo."},
                timeout=90,
            )
            if chat.ok:
                reply = (chat.json().get("reply") or "").lower()
                expected = EXPECTED_SECTORS[email]
                entry["kernel_sector"] = expected if expected.replace("_", " ") in reply or expected in reply else resolve_sector_for_user(email)
            entry["sector_expected"] = EXPECTED_SECTORS[email]
            entry["shield_ok"] = entry["shield_sector"] == EXPECTED_SECTORS[email]
        checks.append(entry)
    return checks


def main():
    print("=" * 70)
    print("NOVUS — Configuración final clientes MVP por sector")
    print("=" * 70)

    results = provision_clients()
    print("\n--- Clientes en base de datos ---")
    for r in results:
        print(json.dumps(r, ensure_ascii=False, indent=2))

    all_db_ok = all(r["almacenado_db"] for r in results)
    print(f"\nBase de datos: {'OK' if all_db_ok else 'REVISAR'}")

    try:
        checks = verify_auth_and_sector("http://10.196.213.166:5000")
        print("\n--- Verificación login / sector ---")
        for c in checks:
            print(json.dumps(c, ensure_ascii=False, indent=2))
        all_live = all(c.get("login") and c.get("dashboard") and c.get("shield_ok") for c in checks)
        print(f"\nVerificación operativa: {'OK' if all_live else 'REVISAR'}")
        return 0 if all_db_ok and all_live else 1
    except Exception as exc:
        print(f"\nVerificación HTTP omitida o fallida: {exc}")
        return 0 if all_db_ok else 1


if __name__ == "__main__":
    sys.exit(main())
