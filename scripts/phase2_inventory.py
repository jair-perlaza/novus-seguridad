#!/usr/bin/env python3
"""Phase 2 Etapa 1 — inventario real del estado actual (sin modificar semántica)."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure" / "phase2_inventory.json"
DB = ROOT / "novus_vault_v2.db"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def host() -> dict:
    try:
        import psutil

        vm = psutil.virtual_memory()
        return {
            "ram_pct": round(vm.percent, 1),
            "ram_avail_gb": round(vm.available / (1024**3), 2),
            "cpu_count": psutil.cpu_count() or 0,
            "cpu_pct": round(psutil.cpu_percent(interval=0.2), 1),
        }
    except Exception as exc:
        return {"error": str(exc)[:120]}


def table_stats(con: sqlite3.Connection) -> list:
    tables = [
        r[0]
        for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY 1"
        ).fetchall()
    ]
    out = []
    for t in tables:
        try:
            n = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
        except Exception as exc:
            out.append({"table": t, "rows": None, "error": str(exc)[:80]})
            continue
        idxs = con.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name=?",
            (t,),
        ).fetchall()
        # page estimate via dbstat if available
        size_bytes = None
        try:
            size_bytes = con.execute(
                "SELECT SUM(pgsize) FROM dbstat WHERE name=?", (t,)
            ).fetchone()[0]
        except Exception:
            pass
        out.append(
            {
                "table": t,
                "rows": n,
                "approx_size_bytes": size_bytes,
                "indexes": [{"name": i[0], "sql": i[1]} for i in idxs],
                "index_count": len(idxs),
            }
        )
    return sorted(out, key=lambda x: -(x.get("rows") or 0))


def cache_inventory() -> list:
    return [
        {
            "name": "auth_session_cache",
            "module": "services/auth_session_cache.py",
            "stores": "user_loader / session identity",
            "tenant_scope": "keyed by user id/email",
            "ttl": "process-local LRU",
            "cross_tenant_risk": "low if key is user-scoped",
            "survives_restart": False,
        },
        {
            "name": "http_endpoint_cache",
            "module": "services/http_endpoint_cache.py",
            "stores": "dashboard/security/defense endpoint payloads",
            "tenant_scope": "per-tenant / platform keys (Phase1 fix)",
            "ttl": "env-driven per endpoint",
            "cross_tenant_risk": "mitigated by tenant-keyed keys + singleflight",
            "survives_restart": False,
        },
        {
            "name": "performance_cache",
            "module": "services/performance_cache.py",
            "stores": "generic performance helpers",
            "tenant_scope": "MUST verify callers pass tenant",
            "ttl": "varies",
            "cross_tenant_risk": "depends on key construction",
            "survives_restart": False,
        },
        {
            "name": "engine_runtime_registry cache",
            "module": "services/engine_runtime_registry.py",
            "stores": "engine runtime summary",
            "tenant_scope": "platform-level summary",
            "ttl": "NOVUS_ENGINE_RUNTIME_CACHE_TTL (default 12s)",
            "cross_tenant_risk": "platform aggregate — no tenant PII expected",
            "survives_restart": False,
        },
    ]


def main() -> int:
    if not DB.is_file():
        print(f"DB missing: {DB}", file=sys.stderr)
        return 2

    con = sqlite3.connect(str(DB))
    try:
        con.execute("PRAGMA journal_mode")
        journal = con.execute("PRAGMA journal_mode").fetchone()[0]
        page_size = con.execute("PRAGMA page_size").fetchone()[0]
        page_count = con.execute("PRAGMA page_count").fetchone()[0]
        freelist = con.execute("PRAGMA freelist_count").fetchone()[0]
        tables = table_stats(con)

        # tenant / user summary
        usuarios = next((t for t in tables if t["table"] == "usuarios"), {})
        scopes = next((t for t in tables if t["table"] == "tenant_monitoring_scope"), {})
        loadtest_users = 0
        loadtest_tenants = 0
        try:
            loadtest_users = con.execute(
                "SELECT COUNT(*) FROM usuarios WHERE email LIKE 'loadtest-user-%@loadtest.novus.local'"
            ).fetchone()[0]
            loadtest_tenants = con.execute(
                "SELECT COUNT(*) FROM tenant_monitoring_scope WHERE tenant_id LIKE 'LOADTEST-%'"
            ).fetchone()[0]
        except Exception:
            pass
    finally:
        con.close()

    manifest_users = 0
    manifest_path = ROOT / "data" / "production_closure" / "loadtest_users_manifest.json"
    if manifest_path.is_file():
        try:
            manifest_users = len(json.loads(manifest_path.read_text(encoding="utf-8")).get("users") or [])
        except Exception:
            pass

    # notes on hot paths / lock risk from known schema
    query_risks = [
        {
            "table": "logs",
            "risk": "only fecha + id indexes — tenant-scoped filters may full-scan if filtering by tenant without index",
            "read_freq": "HIGH (SIEM/logs)",
            "write_freq": "HIGH (engines)",
            "lock_risk": "HIGH under concurrent writes",
        },
        {
            "table": "novus_notifications",
            "risk": "Phase1 fixed user_email OR-null MULTI-INDEX; tenant_id indexed",
            "read_freq": "HIGH",
            "write_freq": "MEDIUM",
            "lock_risk": "MEDIUM",
        },
        {
            "table": "platform_evidences",
            "risk": "tenant_id indexed; large row count",
            "read_freq": "MEDIUM",
            "write_freq": "HIGH",
            "lock_risk": "HIGH",
        },
        {
            "table": "endpoint_monitor_events",
            "risk": "no tenant_id index visible — possible full scans for tenant filters",
            "read_freq": "MEDIUM",
            "write_freq": "HIGH",
            "lock_risk": "MEDIUM",
        },
    ]

    inv = {
        "generated_at": utc(),
        "phase": "phase2_etapa1_inventory",
        "environment": {
            "db_path": str(DB),
            "db_size_bytes": DB.stat().st_size,
            "db_size_mb": round(DB.stat().st_size / 1e6, 2),
            "sqlite_journal_mode": journal,
            "page_size": page_size,
            "page_count": page_count,
            "freelist_count": freelist,
            "host": host(),
            "waitress_threads_env": os.environ.get("NOVUS_WAITRESS_THREADS", "NOT_SET"),
            "loadtest_mode_env": os.environ.get("NOVUS_LOADTEST_MODE", "NOT_SET"),
        },
        "tenants": {
            "tenant_monitoring_scope_rows": scopes.get("rows"),
            "loadtest_tenants": loadtest_tenants,
            "isolation_model": "1 user = 1 nit_pyme = 1 LOADTEST-T#### tenant",
            "scope_service": "services/tenant_scope_service.py",
        },
        "users": {
            "usuarios_rows": usuarios.get("rows"),
            "loadtest_users_db": loadtest_users,
            "manifest_users": manifest_users,
            "auth": "Flask-Login + CSRF login form",
            "mfa": "production MFA intact; LOADTEST does not disable MFA semantics for production users",
            "roles": "Usuario.role (analyst for loadtest)",
            "sessions": "cookie session; loadtest_sessions.pkl for bench",
        },
        "tables": tables,
        "query_risks": query_risks,
        "caches": cache_inventory(),
        "engines_note": "Classify via get_engine_runtime_summary — class import != ACTIVE",
        "phase1_baseline": {
            "verdict": "CLOSED",
            "ref": "data/production_closure/phase1_performance_final.json",
            "demonstrated_concurrent": 600,
            "sustained_30min_p95_max_ms": 1053,
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(inv, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"ok": True, "out": str(OUT), "db_mb": inv["environment"]["db_size_mb"], "tables": len(tables)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
