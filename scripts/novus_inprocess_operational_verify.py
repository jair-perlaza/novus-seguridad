#!/usr/bin/env python3
"""Verificación operativa in-process — APIs reales sin login HTTP (MFA)."""
from __future__ import annotations

import json
import re
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_release_candidate" / "NOVUS_INPROCESS_OPERATIONAL_VERIFY.json"

QA_EMAIL = "novus.qa.jul2026@example.com"
CLIENT_EMAIL = "operaciones@novapay-fintech.co"

FAKE_MARKERS = (
    "simulated", "fixture", "demo threat", "fake_", "lorem ipsum",
    "mock data", "synthetic alert",
)

MODULES = [
    ("/api/tenant/scope", "tenant_scope"),
    ("/api/dashboard/live", "dashboard"),
    ("/api/network/nodes?trigger_discovery=false", "network"),
    ("/api/monitoring/network-config", "network_config"),
    ("/api/security/summary", "security_summary"),
    ("/api/security/threats", "threats"),
    ("/api/security/vulnerabilities", "vulnerabilities"),
    ("/api/security/endpoints", "endpoints"),
    ("/api/reports", "reports"),
    ("/api/system/evidence-center", "evidence"),
    ("/api/system/login-sessions", "sessions"),
    ("/api/notifications?kind=security", "notifications_security"),
    ("/api/notifications?kind=system", "notifications_system"),
    ("/api/ai/status", "ai_kernel"),
    ("/api/health/status", "health"),
    ("/api/network/topology", "topology"),
]


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _walk_fake(obj, path=""):
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            hits.extend(_walk_fake(v, f"{path}.{k}" if path else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.extend(_walk_fake(v, f"{path}[{i}]"))
    elif isinstance(obj, str):
        low = obj.lower()
        for m in FAKE_MARKERS:
            if m in low:
                hits.append(f"{path}:{m}")
    return hits


def _login_client(app, email: str):
    from database import SessionLocal, Usuario

    db = SessionLocal()
    try:
        row = db.query(Usuario).filter(Usuario.email == email.strip().lower()).first()
        if not row:
            raise RuntimeError(f"user_not_found:{email}")
        user_id = str(row.id)
    finally:
        db.close()

    client = app.test_client()
    csrf = secrets.token_urlsafe(32)
    with client.session_transaction() as sess:
        sess["_user_id"] = user_id
        sess["_fresh"] = True
        sess["_novus_login_session_id"] = f"TEST-INPROC-{user_id}"
        sess["_csrf_token"] = csrf
    return client, user_id, csrf


def _get(client, path: str) -> dict:
    r = client.get(path)
    body = r.get_json(silent=True) or {}
    return {"http": r.status_code, "body": body}


def _csrf_token(client) -> str | None:
    with client.session_transaction() as sess:
        return sess.get("_csrf_token")


def _post_action(client, action: str, csrf: str | None) -> dict:
    headers = {"Content-Type": "application/json"}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    r = client.post(
        "/api/monitoring/network-config/action",
        json={"action": action},
        headers=headers,
    )
    body = r.get_json(silent=True) or {}
    return {"http": r.status_code, "body": body, "ok": body.get("status") == "success"}


def main() -> int:
    from migrate_database import migrate_database

    migrate_database()
    from core.app import create_app

    app = create_app("development")
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_PROTECTION"] = "basic"
    app.login_manager.session_protection = "basic"

    report = {
        "generated_at": _utc(),
        "mode": "inprocess_flask_test_client",
        "tests": [],
        "modules": [],
        "pass": True,
    }

    for rel in (
        "services/ai_kernel.py",
        "services/network_snapshot_service.py",
        "services/network_monitoring_service.py",
        "services/notification_center_service.py",
    ):
        p = subprocess.run([sys.executable, "-m", "py_compile", str(ROOT / rel)], capture_output=True)
        report["tests"].append({"name": f"py_compile:{rel}", "pass": p.returncode == 0})

    p = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "tenant_isolation_service_test.py")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    report["tests"].append({
        "name": "tenant_isolation_service",
        "pass": "VERIFIED" in (p.stdout or "") and p.returncode == 0,
        "verdict": "VERIFIED" if "VERIFIED" in (p.stdout or "") else "FAIL",
    })

    try:
        from services.tenant_scope_service import ensure_tenant_monitoring_seeded

        seed = ensure_tenant_monitoring_seeded()
        report["monitoring_seed"] = seed
    except Exception as exc:
        report["monitoring_seed"] = {"error": str(exc)[:200]}

    qa_client, _, qa_csrf = _login_client(app, QA_EMAIL)
    cl_client, _, _ = _login_client(app, CLIENT_EMAIL)

    for client, label in ((qa_client, "qa"), (cl_client, "client")):
        for path, name in MODULES:
            row = {"tenant": label, "name": name, "path": path}
            try:
                got = _get(client, path)
                row["http"] = got["http"]
                body = got["body"]
                row["fake_hits"] = _walk_fake(body)
                row["pass"] = got["http"] == 200 and not row["fake_hits"]
                if name == "tenant_scope":
                    row["monitoring_enabled"] = body.get("monitoring_enabled")
                    row["tenant_id"] = body.get("tenant_id")
                if name == "network":
                    fresh = body.get("data_freshness") or (body.get("snapshot_meta") or {}).get("data_freshness")
                    row["data_freshness"] = fresh
                    row["observed_device_count"] = body.get("observed_device_count")
                    stale_as_live = fresh == "live" and (body.get("snapshot_meta") or {}).get("snapshot_stale")
                    row["pass"] = row["pass"] and not stale_as_live
                if name == "network_config":
                    row["provenance"] = body.get("provenance")
                if name == "notifications_security":
                    kinds = {n.get("notification_kind") for n in (body.get("notifications") or [])}
                    row["kinds_seen"] = sorted(k for k in kinds if k)
                    row["pass"] = row["pass"] and kinds <= {"security", None}
                if name == "ai_kernel":
                    row["operational_status"] = body.get("operational_status")
            except Exception as exc:
                row["pass"] = False
                row["error"] = str(exc)[:200]
            report["modules"].append(row)
            report["tests"].append({"name": f"{label}:{name}", "pass": row.get("pass", False)})

    actions = {}
    for action in ("stop_discovery", "resume_discovery", "discover_now", "refresh"):
        actions[action] = _post_action(qa_client, action, qa_csrf)
    report["network_actions"] = actions
    report["tests"].append({
        "name": "network_actions",
        "pass": all(v.get("http") == 200 for v in actions.values()),
    })

    qa_scope = _get(qa_client, "/api/tenant/scope")["body"]
    cl_scope = _get(cl_client, "/api/tenant/scope")["body"]
    report["tenant_isolation"] = {
        "qa_tenant": qa_scope.get("tenant_id"),
        "client_tenant": cl_scope.get("tenant_id"),
        "distinct": bool(
            qa_scope.get("tenant_id")
            and cl_scope.get("tenant_id")
            and qa_scope.get("tenant_id") != cl_scope.get("tenant_id")
        ),
        "qa_monitoring": qa_scope.get("monitoring_enabled"),
        "client_monitoring": cl_scope.get("monitoring_enabled"),
    }
    report["tests"].append({
        "name": "tenant_distinct",
        "pass": report["tenant_isolation"]["distinct"],
    })
    report["tests"].append({
        "name": "monitoring_auto_qa",
        "pass": qa_scope.get("monitoring_enabled") is True,
    })
    report["tests"].append({
        "name": "monitoring_auto_client",
        "pass": cl_scope.get("monitoring_enabled") is True,
    })

    r401 = app.test_client().get("/api/dashboard/live")
    report["recovery_middleware"] = {
        "unauth_dashboard": r401.status_code,
        "pass": r401.status_code in (401, 302),
    }
    report["tests"].append({
        "name": "recovery_unauth_401",
        "pass": report["recovery_middleware"]["pass"],
    })

    report["pass"] = all(t.get("pass") for t in report["tests"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"pass": report["pass"], "tests": len(report["tests"]), "out": str(OUT)}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
