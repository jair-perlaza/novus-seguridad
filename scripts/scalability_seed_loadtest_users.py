#!/usr/bin/env python3
"""
Sembrar 600+ usuarios LOADTEST aislados — 1 usuario = 1 tenant = 1 sesión independiente.
Genera: data/production_closure/loadtest_users_manifest.json
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure" / "loadtest_users_manifest.json"
COUNT = int(os.environ.get("NOVUS_LOADTEST_USER_COUNT", "600"))


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    from werkzeug.security import generate_password_hash

    from database import SessionLocal, TenantMonitoringScope, Usuario
    from services.loadtest_runtime import loadtest_password

    password = loadtest_password()
    pwd_hash = generate_password_hash(password)
    now = utc()
    users = []
    db = SessionLocal()
    created_u = 0
    created_t = 0
    try:
        for i in range(COUNT):
            email = f"loadtest-user-{i:04d}@loadtest.novus.local"
            tenant = f"LOADTEST-T{i:04d}"
            u = db.query(Usuario).filter(Usuario.email == email).first()
            if not u:
                db.add(
                    Usuario(
                        email=email,
                        hashed_password=pwd_hash,
                        is_active=True,
                        is_temporal=True,
                        nit_pyme=tenant,
                        role="analyst",
                        sector="fintech",
                    )
                )
                created_u += 1
            t = db.query(TenantMonitoringScope).filter(TenantMonitoringScope.tenant_id == tenant).first()
            if not t:
                db.add(
                    TenantMonitoringScope(
                        tenant_id=tenant,
                        monitoring_enabled=True,
                        monitoring_mode="platform_node",
                        configured_at=now,
                    )
                )
                created_t += 1
            users.append({"email": email, "tenant_id": tenant, "index": i})
        db.commit()
    finally:
        db.close()

    manifest = {
        "generated_at": utc(),
        "count": COUNT,
        "created_users": created_u,
        "created_tenants": created_t,
        "password_env": "NOVUS_LOADTEST_PASSWORD",
        "isolated_prefix": "LOADTEST-",
        "users": users,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"ok": True, "created_users": created_u, "created_tenants": created_t, "total": COUNT, "out": str(OUT)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
