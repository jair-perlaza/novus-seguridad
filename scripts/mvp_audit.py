#!/usr/bin/env python3
"""
Auditoría MVP NOVUS — métricas verificables basadas en pruebas reales.
NO modifica código.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RESULTS = {"modules": {}, "kernel": {}, "security": {}, "db": {}, "performance": {}, "scores": {}}


def record(category: str, name: str, passed: bool, detail: str = ""):
    RESULTS.setdefault(category, {})[name] = {"pass": passed, "detail": detail}


def score_category(items: dict) -> float:
    if not items:
        return 0.0
    return round(sum(1 for v in items.values() if v["pass"]) / len(items) * 100, 1)


def run_db_audit():
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "novus_vault_v2.db")
    if not os.path.exists(db_path):
        record("db", "database_exists", False, "novus_vault_v2.db no encontrada")
        return
    record("db", "database_exists", True)
    conn = sqlite3.connect(db_path)
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    expected = ["usuarios", "alertas", "vulnerabilidades", "playbooks", "logs", "inteligencia_casos"]
    for t in expected:
        record("db", f"table_{t}", t in tables, "presente" if t in tables else "ausente")
    for t in expected:
        if t in tables:
            try:
                c = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                record("db", f"rows_{t}", True, str(c))
            except Exception as e:
                record("db", f"rows_{t}", False, str(e))
    conn.close()


def run_data_audit():
    from services.data_audit_registry import get_audit_summary
    s = get_audit_summary()
    c = s["counts"]
    total = s["total_components"]
    real = c.get("REAL", 0)
    sim = c.get("SIMULADO", 0)
    record("scores", "data_real_pct", sim == 0, f"{real}/{total} REAL, SIMULADO={sim}")
    RESULTS["data_audit"] = {"counts": c, "total": total, "real_pct": round(real / total * 100, 1) if total else 0}


def run_flask_audit():
    from core.app import create_app
    from database import inicializar_db, ensure_tables_exist, SessionLocal, Usuario
    from werkzeug.security import generate_password_hash
    from models.user import User

    app = create_app("testing")

    @app.login_manager.user_loader
    def load_user(user_id):
        if user_id is None or not str(user_id).isdigit():
            return None
        return User.get_by_id(user_id)

    inicializar_db()
    ensure_tables_exist()
    email = "novus.qa.jul2026@example.com"
    pwd = "NovusQA2026!"
    db = SessionLocal()
    u = db.query(Usuario).filter(Usuario.email == email).first()
    if not u:
        u = Usuario(email=email, hashed_password=generate_password_hash(pwd), sector="fintech", is_active=True)
        db.add(u)
        db.commit()
    db.close()

    client = app.test_client()
    client.post("/login", data={"email": email, "password": pwd}, follow_redirects=True)

    pages = [
        ("dashboard", "/dashboard"),
        ("network", "/network"),
        ("xdr", "/amenazas"),
        ("incidentes", "/incidentes"),
        ("vulnerabilidades", "/vulnerabilidades"),
        ("reportes", "/reportes"),
        ("configuracion", "/configuracion"),
        ("topology", "/topology"),
        ("inteligencia", "/inteligencia"),
        ("siem", "/siem"),
        ("endpoints", "/endpoints"),
        ("automatizacion", "/automatizacion"),
        ("layout_novus", "/layout_novus"),
    ]
    for name, path in pages:
        t0 = time.time()
        r = client.get(path)
        elapsed = round(time.time() - t0, 2)
        ok = r.status_code == 200
        record("modules", f"page_{name}", ok, f"HTTP {r.status_code} {elapsed}s")

    apis = [
        ("dashboard_live", "/api/dashboard/live", "cpu"),
        ("network_nodes", "/api/network/nodes", "nodes"),
        ("network_info", "/api/network/info", "local_ip"),
        ("security_summary", "/api/security/summary", "status"),
        ("security_threats", "/api/security/threats", "threat"),
        ("reports_list", "/api/reports/", "reports"),
        ("playbooks", "/api/playbooks/", "playbooks"),
        ("search", "/api/search?q=network", "results"),
        ("ai_status", "/api/ai/status", "kernel"),
        ("ai_context", "/api/ai/context", "context"),
        ("threat_intel", "/api/threat-intel/stats", "stats"),
        ("audit_sources", "/api/audit/data-sources", "entries"),
        ("sector_shield", "/api/system/sector-shield/status", "status"),
        ("vault_summary", "/api/system/security/summary", "status"),
        ("endpoints_live", "/api/system/endpoints/live", "endpoints"),
    ]
    for name, path, key in apis:
        t0 = time.time()
        r = client.get(path)
        elapsed = round(time.time() - t0, 2)
        try:
            body = r.get_json() or {}
            ok = r.status_code == 200 and key.lower() in str(body).lower()
        except Exception:
            ok = r.status_code == 200
        record("modules", f"api_{name}", ok, f"HTTP {r.status_code} {elapsed}s")

    # Kernel quick messages
    kernel_msgs = [
        ("deep_scan", "Deep Scan"),
        ("vulns", "buscar vulnerabilidades"),
        ("sistema", "analizar sistema"),
        ("devices", "dispositivos conectados"),
        ("network", "escanear red"),
        ("slow_pc", "Mi computador esta lento"),
    ]
    for name, msg in kernel_msgs:
        t0 = time.time()
        r = client.post("/api/ai/chat", json={"message": msg})
        elapsed = round(time.time() - t0, 2)
        d = r.get_json() or {}
        err = (d.get("reply") or "").startswith("Error en operador")
        ok = r.status_code == 200 and not err and (d.get("reply") or d.get("working"))
        record("kernel", name, ok, f"{elapsed}s err={err}")

    # Performance samples
    t0 = time.time()
    client.get("/api/dashboard/live")
    record("performance", "dashboard_api_ms", True, str(round((time.time() - t0) * 1000)))

    from services.kernel_planner import build_plan
    t0 = time.time()
    build_plan("escanear red", session_id="audit-perf")
    record("performance", "kernel_plan_ms", True, str(round((time.time() - t0) * 1000)))

    import psutil
    record("performance", "cpu_pct", True, str(psutil.cpu_percent(interval=0.5)))
    record("performance", "ram_pct", True, str(psutil.virtual_memory().percent))


def compute_scores():
    mod = score_category(RESULTS.get("modules", {}))
    ker = score_category(RESULTS.get("kernel", {}))
    db = score_category(RESULTS.get("db", {}))
    sec_items = {k: v for k, v in RESULTS.get("modules", {}).items() if "security" in k or "sector" in k or "vault" in k}
    sec = score_category(sec_items)
    data_pct = RESULTS.get("data_audit", {}).get("real_pct", 0)
    functional = round((mod + ker) / 2, 1)
    integration = round(mod * 0.85 + ker * 0.15, 1)  # kernel pulls multiple modules
    stability = round((mod * 0.4 + ker * 0.3 + db * 0.2 + (100 if data_pct > 80 else data_pct) * 0.1), 1)
    coverage = round(len([v for v in RESULTS.get("modules", {}).values() if v["pass"]]) / max(1, len(RESULTS.get("modules", {}))) * 100, 1)

    RESULTS["scores"] = {
        "stability_pct": stability,
        "functional_operational_pct": functional,
        "integration_pct": integration,
        "real_data_pct": data_pct,
        "functional_coverage_pct": coverage,
        "module_pages_pct": mod,
        "kernel_pct": ker,
        "database_pct": db,
    }

    # MVP gate: critical failures
    critical = []
    if ker < 80:
        critical.append("Kernel IA < 80%")
    if mod < 70:
        critical.append("Módulos < 70%")
    if data_pct < 75:
        critical.append("Datos reales < 75%")
    RESULTS["mvp_ready"] = len(critical) == 0 and stability >= 75
    RESULTS["critical_blockers"] = critical


def main():
    print("=" * 70)
    print("NOVUS MVP AUDIT —", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 70)
    run_db_audit()
    run_data_audit()
    run_flask_audit()
    compute_scores()
    print(json.dumps(RESULTS["scores"], indent=2))
    print("\nMVP READY:", RESULTS["mvp_ready"])
    if RESULTS.get("critical_blockers"):
        print("BLOCKERS:", RESULTS["critical_blockers"])
    fails = [(cat, k, v) for cat, items in RESULTS.items() if isinstance(items, dict) for k, v in items.items() if isinstance(v, dict) and not v.get("pass")]
    print(f"\nFAILURES: {len(fails)}")
    for cat, k, v in fails[:30]:
        print(f"  [{cat}] {k}: {v.get('detail')}")
    out = os.path.join(os.path.dirname(__file__), "mvp_audit_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {out}")
    return 0 if RESULTS["mvp_ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
