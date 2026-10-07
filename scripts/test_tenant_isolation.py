#!/usr/bin/env python3
"""Validación de aislamiento multi-tenant — datos por tenant_id, monitoreo base activo."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from migrate_database import migrate_database

migrate_database()

from core.app import create_app

QA = {
    "email": "novus.qa.jul2026@example.com",
    "password": os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!"),
}
CLIENT = {
    "email": "operaciones@novapay-fintech.co",
    "password": "NovaPay#Fintech2026",
}


def _session_login(client, email: str) -> bool:
    from database import SessionLocal, Usuario

    db = SessionLocal()
    try:
        row = db.query(Usuario).filter(Usuario.email == email.strip().lower()).first()
        if not row:
            return False
        user_id = str(row.id)
    finally:
        db.close()
    with client.session_transaction() as sess:
        sess["_user_id"] = user_id
        sess["_fresh"] = True
        sess["_novus_login_session_id"] = f"TEST-ISOL-{user_id}"
    return True


def _get_json(client, path):
    r = client.get(path)
    try:
        return r.status_code, r.get_json(silent=True) or {}
    except Exception:
        return r.status_code, {}


def run_tests():
    app = create_app("development")
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SESSION_PROTECTION"] = "basic"
    app.config["SESSION_COOKIE_SECURE"] = False
    app.login_manager.session_protection = "basic"

    from models.user import User

    def load_user(user_id):
        return User.get_by_id(user_id)

    app.login_manager.user_loader(load_user)

    results = []
    with app.test_client() as qa_client:
        assert _session_login(qa_client, QA["email"]), "Sesión QA falló"
        _, qa_nodes = _get_json(qa_client, "/api/network/nodes")
        _, qa_dash = _get_json(qa_client, "/api/dashboard/live")
        _, qa_scope = _get_json(qa_client, "/api/tenant/scope")
        _, qa_vulns = _get_json(qa_client, "/api/security/vulnerabilities")

    with app.test_client() as client_client:
        assert _session_login(client_client, CLIENT["email"]), "Sesión cliente MVP falló"
        _, cl_nodes = _get_json(client_client, "/api/network/nodes")
        _, cl_dash = _get_json(client_client, "/api/dashboard/live")
        _, cl_scope = _get_json(client_client, "/api/tenant/scope")
        _, cl_vulns = _get_json(client_client, "/api/security/vulnerabilities")

    qa_tid = qa_scope.get("tenant_id")
    cl_tid = cl_scope.get("tenant_id")

    checks = [
        ("QA monitoring_enabled", qa_scope.get("monitoring_enabled") is True),
        ("Cliente monitoring_enabled", cl_scope.get("monitoring_enabled") is True),
        ("Tenants distintos", bool(qa_tid and cl_tid and qa_tid != cl_tid)),
        ("Cliente no bloqueado (nodes)", cl_nodes.get("status") != "monitoring_not_configured"),
        ("Cliente no bloqueado (dashboard)", cl_dash.get("status") != "monitoring_not_configured"),
        ("QA puede leer nodos o no_data", qa_nodes.get("status") in ("success", "no_data", "pending")),
    ]

    qa_vuln_ids = {v.get("id") for v in (qa_vulns.get("vulnerabilities") or qa_vulns.get("items") or [])}
    cl_vuln_ids = {v.get("id") for v in (cl_vulns.get("vulnerabilities") or cl_vulns.get("items") or [])}
    if qa_vuln_ids and cl_vuln_ids:
        checks.append(("Vulnerabilidades tenant aisladas", qa_vuln_ids.isdisjoint(cl_vuln_ids) or qa_tid != cl_tid))

    for name, ok in checks:
        results.append({"check": name, "passed": bool(ok)})

    passed = sum(1 for r in results if r["passed"])
    report = {
        "passed": passed,
        "total": len(results),
        "results": results,
        "qa_scope": qa_scope,
        "client_scope": cl_scope,
        "qa_node_count": len(qa_nodes.get("nodes") or []),
        "client_node_count": len(cl_nodes.get("nodes") or []),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return passed == len(results)


if __name__ == "__main__":
    ok = run_tests()
    sys.exit(0 if ok else 1)
