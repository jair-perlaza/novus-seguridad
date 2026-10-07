"""
Validación de protección avanzada contra accesos no autorizados.
Comprueba escalado configurable por origen sin afectar IPs legítimas.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Base, SessionLocal, AuthAccessEvent, AuthOriginSanction, IPBloqueada, engine
from core.app import create_app
from models.user import User

Base.metadata.create_all(bind=engine)

PASS = 0
FAIL = 0


def check(name: str, ok: bool, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {name} — {detail}")
    else:
        FAIL += 1
        print(f"  FAIL  {name} — {detail}")


def _make_app():
    app = create_app("development")

    @app.login_manager.user_loader
    def load_user(user_id):
        if user_id is None or not str(user_id).isdigit():
            return None
        return User.get_by_id(user_id)

    return app


def main():
    print("=== AUTH PROTECTION TESTS ===\n")
    app = _make_app()
    client = app.test_client()

    attacker_ip = "198.51.100.77"
    legit_ip = "198.51.100.88"

    from services.auth_protection_config import get_auth_protection_config
    from services.auth_protection_service import (
        auth_protection,
        is_origin_blocked,
        record_auth_attempt,
    )
    cfg = get_auth_protection_config()

    db = SessionLocal()
    try:
        for ip in (attacker_ip, legit_ip):
            db.query(AuthOriginSanction).filter(AuthOriginSanction.origin_key == ip).delete()
            db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == ip).delete()
            db.query(AuthAccessEvent).filter(AuthAccessEvent.ip_address == ip).delete()
        db.commit()
    finally:
        db.close()

    print("--- Intentos 1-3: registro y riesgo (sin bloqueo) ---")
    for i in range(cfg["risk_log_attempts_max"]):
        record_auth_attempt(
            success=False, email=f"attacker{i}@evil.test", route="login",
            ip=attacker_ip, user_agent="TestBot/1.0", session_id="sess-attacker",
        )
    status = is_origin_blocked(attacker_ip)
    check("Sin bloqueo antes del umbral", not status.get("blocked"), str(status))

    print("\n--- Intento 4: monitoreo reforzado ---")
    record_auth_attempt(
        success=False, email="attacker@evil.test", route="login",
        ip=attacker_ip, user_agent="TestBot/1.0", session_id="sess-attacker",
    )
    db = SessionLocal()
    try:
        sanction = db.query(AuthOriginSanction).filter(
            AuthOriginSanction.origin_key == attacker_ip,
            AuthOriginSanction.sanction_level == 1,
        ).first()
        check("Monitoreo reforzado activo", sanction is not None, f"level={getattr(sanction, 'sanction_level', None)}")
    finally:
        db.close()
    check("Monitoreo no bloquea origen", not is_origin_blocked(attacker_ip).get("blocked"), "ok")

    print("\n--- Intento 5: bloqueo temporal ---")
    record_auth_attempt(
        success=False, email="attacker@evil.test", route="login",
        ip=attacker_ip, user_agent="TestBot/1.0", session_id="sess-attacker",
    )
    blocked = is_origin_blocked(attacker_ip)
    check("Bloqueo IP atacante", blocked.get("blocked") is True, blocked)

    db = SessionLocal()
    try:
        ev_count = db.query(AuthAccessEvent).filter(AuthAccessEvent.ip_address == attacker_ip).count()
        check("Eventos registrados", ev_count >= cfg["block_attempt"], f"count={ev_count}")
        ip_row = db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == attacker_ip).first()
        check("Evidencia en IPBloqueada", ip_row is not None and ip_row.failed_attempts >= cfg["block_attempt"],
              f"attempts={getattr(ip_row, 'failed_attempts', None)}")
        check("User-Agent registrado", bool(getattr(ip_row, "user_agent", None)), getattr(ip_row, "user_agent", ""))
    finally:
        db.close()

    incidents = auth_protection.list_incidents(limit=5)
    check("Incidente generado", len(incidents) >= 1, incidents[0].get("id") if incidents else "none")

    print("\n--- IP legítima no afectada ---")
    legit_blocked = is_origin_blocked(legit_ip)
    check("IP legítima sin bloqueo", not legit_blocked.get("blocked"), legit_blocked)

    with app.test_request_context(
        "/login", method="POST",
        environ_base={"REMOTE_ADDR": attacker_ip},
    ):
        gate = auth_protection.check_login_allowed()
    check("Login bloqueado para atacante", gate.get("allowed") is False, gate.get("message", "")[:60])

    login_page = client.get("/login", environ_base={"REMOTE_ADDR": legit_ip})
    import re
    csrf_m = re.search(r'name="csrf_token" value="([^"]+)"', login_page.get_data(as_text=True))
    csrf_tok = csrf_m.group(1) if csrf_m else ""
    client.post(
        "/login",
        data={
            "email": "novus.qa.jul2026@example.com",
            "password": "NovusQA2026!",
            "csrf_token": csrf_tok,
        },
        follow_redirects=True,
        environ_base={"REMOTE_ADDR": legit_ip},
    )
    r = client.get("/api/system/auth-protection/status", environ_base={"REMOTE_ADDR": legit_ip})
    check(
        "API auth-protection accesible (usuario legítimo)",
        r.status_code == 200 and r.get_json().get("status") == "success",
        f"HTTP {r.status_code}",
    )

    r_cfg = client.get("/api/system/auth-protection/config", environ_base={"REMOTE_ADDR": legit_ip})
    check("API config auth-protection", r_cfg.status_code == 200 and "config" in (r_cfg.get_json() or {}), "ok")

    r_blocks = client.get("/api/system/blocked-ips", environ_base={"REMOTE_ADDR": legit_ip})
    check("API blocked-ips", r_blocks.status_code == 200 and "blocks" in (r_blocks.get_json() or {}), "ok")

    r_dev = client.get("/api/system/device-connections", environ_base={"REMOTE_ADDR": legit_ip})
    check("API device-connections", r_dev.status_code == 200 and "events" in (r_dev.get_json() or {}), "ok")

    r_inc = client.get("/api/system/auth-protection/incidents", environ_base={"REMOTE_ADDR": legit_ip})
    check(
        "Incidentes consultables vía API",
        r_inc.status_code == 200 and "incidents" in (r_inc.get_json() or {}),
        f"HTTP {r_inc.status_code}",
    )

    ctx = auth_protection.get_kernel_context()
    check("Contexto Kernel IA", ctx.get("module") == "auth_protection" and "incidents" in ctx, "ok")
    check("Kernel incluye bloqueos", "blocked_ips" in ctx, "ok")

    kernel_reply = auth_protection.answer_kernel_query("intentos fallidos de login brute force")
    check("Respuesta Kernel auth", kernel_reply is not None and "Protección" in kernel_reply, "ok")

    kernel_dev = auth_protection.answer_kernel_query("dispositivos conectados recientemente")
    check("Respuesta Kernel dispositivos", kernel_dev is not None, "ok")

    print(f"\n=== RESULTADO: {PASS} PASS / {FAIL} FAIL ===")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
