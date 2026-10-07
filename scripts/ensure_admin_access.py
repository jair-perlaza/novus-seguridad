"""Lista usuarios SQLite y garantiza credenciales admin funcionales."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash, check_password_hash
from database import SessionLocal, Usuario, inicializar_db, ensure_tables_exist
from models.user import User

ADMIN_EMAIL = "novus.qa.jul2026@example.com"
ADMIN_PASSWORD = "NovusQA2026!"


def main():
    from services.production_runtime_guard import qa_seed_scripts_enabled

    if not qa_seed_scripts_enabled():
        print("NOVUS_ALLOW_QA_SEED=1 requerido para sembrar usuario QA (runtime producción bloqueado).")
        return 2

    inicializar_db()
    ensure_tables_exist()
    db = SessionLocal()
    try:
        users = db.query(Usuario).all()
        print("=== USUARIOS EN BD ===")
        for u in users:
            print(
                f"id={u.id} email={u.email} activo={u.is_active} "
                f"sector={u.sector or 'N/D'} nit={u.nit_pyme or 'N/D'}"
            )

        admin = db.query(Usuario).filter(Usuario.email == ADMIN_EMAIL).first()
        if not admin:
            admin = Usuario(
                email=ADMIN_EMAIL,
                hashed_password=generate_password_hash(ADMIN_PASSWORD),
                is_active=True,
                is_temporal=False,
                sector="fintech",
                nit_pyme="QA-NOVUS-2026",
                role="super_admin",
            )
            db.add(admin)
            db.commit()
            print(f"\nCREADO: {ADMIN_EMAIL}")
        else:
            admin.hashed_password = generate_password_hash(ADMIN_PASSWORD)
            admin.is_active = True
            admin.role = "super_admin"
            admin.nit_pyme = "QA-NOVUS-2026"
            db.commit()
            print(f"\nACTUALIZADO password: {ADMIN_EMAIL}")

        ok = User.authenticate(ADMIN_EMAIL, ADMIN_PASSWORD)
        print(f"AUTH TEST: {'OK' if ok else 'FAIL'}")
        if ok:
            print(f"ROLE: {ok.role}")
        return 0 if ok else 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
