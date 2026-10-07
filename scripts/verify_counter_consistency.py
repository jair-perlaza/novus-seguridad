#!/usr/bin/env python3
"""Verifica consistencia de contadores entre Dashboard, Endpoints y Security Summary."""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.app import create_app
from database import inicializar_db, ensure_tables_exist, SessionLocal, Usuario
from werkzeug.security import generate_password_hash
from models.user import User

EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"

app = create_app("testing")


@app.login_manager.user_loader
def load_user(user_id):
    if user_id is None or not str(user_id).isdigit():
        return None
    return User.get_by_id(user_id)


inicializar_db()
ensure_tables_exist()

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

client = app.test_client()
client.post("/login", data={"email": EMAIL, "password": PASSWORD}, follow_redirects=True)

checks = []


def check(name, ok, detail=""):
    checks.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


summary = client.get("/api/security/summary").get_json()
live = client.get("/api/dashboard/live").get_json()
endpoints_page = client.get("/api/security/live-endpoints").get_json()

counters = summary.get("counters") or {}
inv = summary.get("endpoint_inventory") or []
endpoints_total = counters.get("endpoints_total")
threats_summary = summary.get("total_threats")
threats_live = live.get("threats_total") if live.get("threats_total") is not None else live.get("amenazas")
endpoints_live = live.get("endpoints_total")
endpoints_api = endpoints_page.get("total_endpoints")

check(
    "endpoints_total == len(inventory)",
    endpoints_total == len(inv),
    f"counter={endpoints_total} inventory={len(inv)}",
)
check(
    "dashboard/live endpoints == summary",
    endpoints_live == endpoints_total,
    f"live={endpoints_live} summary={endpoints_total}",
)
check(
    "live-endpoints API == summary",
    endpoints_api == endpoints_total,
    f"api={endpoints_api} summary={endpoints_total}",
)
check(
    "threats live == summary",
    threats_live == threats_summary,
    f"live={threats_live} summary={threats_summary}",
)
check(
    "sin ransomware activo sin evidencia",
    summary.get("has_active_ransomware") is False or len(summary.get("ransomware_active") or []) > 0,
    f"active={summary.get('has_active_ransomware')} count={len(summary.get('ransomware_active') or [])}",
)

priority = client.get("/api/dashboard/priority").get_json()
priority_title = (priority.get("title") or "").lower()
check(
    "prioridad sin ransomware fantasma",
    "ransomware" not in priority_title,
    priority.get("title"),
)
check(
    "prioridad sin heuristica permisos Windows",
    "permisos inseguros" not in priority_title,
    priority.get("title"),
)
check(
    "prioridad sin entropy fantasma",
    "high_entropy" not in priority_title,
    priority.get("title"),
)
check(
    "prioridad estable sin hallazgos criticos verificados",
    priority.get("priority_type") == "stable",
    priority.get("title"),
)
check(
    "prioridad verificada incluye motor y confianza",
    priority.get("priority_type") == "stable"
    or (
        priority.get("has_verified_priority")
        and (priority.get("details") or {}).get("motor")
        and (priority.get("details") or {}).get("confianza")
    ),
    f"motor={(priority.get('details') or {}).get('motor')}",
)

passed = sum(1 for _, ok, _ in checks if ok)
print(f"\nTOTAL: {passed}/{len(checks)} passed")
print(json.dumps({"counters": counters, "inventory_len": len(inv)}, indent=2))
sys.exit(0 if passed == len(checks) else 1)
