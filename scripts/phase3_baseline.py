#!/usr/bin/env python3
"""Phase 3 baseline + encrypted backup BEFORE any code changes."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure" / "phase3_baseline.json"
DB = ROOT / "novus_vault_v2.db"
BACKUP_DIR = ROOT / "data" / "backups" / f"phase3_baseline_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def host_idle() -> dict:
    import psutil

    # idle-ish sample
    cpu1 = psutil.cpu_percent(interval=0.5)
    cpu2 = psutil.cpu_percent(interval=1.0)
    vm = psutil.virtual_memory()
    server = None
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and getattr(c.laddr, "port", None) == 5000 and c.status == "LISTEN" and c.pid:
            p = psutil.Process(c.pid)
            server = {
                "pid": c.pid,
                "rss_mb": round(p.memory_info().rss / 1e6, 1),
                "threads": p.num_threads(),
                "cpu_pct": round(p.cpu_percent(interval=0.2), 1),
            }
            break
    return {
        "cpu_pct_samples": [cpu1, cpu2],
        "cpu_avg": round((cpu1 + cpu2) / 2, 1),
        "ram_pct": round(vm.percent, 1),
        "ram_avail_gb": round(vm.available / (1024**3), 2),
        "ram_total_gb": round(vm.total / (1024**3), 2),
        "server": server,
    }


def db_counts(con: sqlite3.Connection) -> dict:
    tables = [
        "usuarios",
        "tenant_monitoring_scope",
        "logs",
        "alertas",
        "novus_notifications",
        "platform_evidences",
        "endpoint_monitor_events",
        "login_session_audits",
        "auth_access_events",
        "vulnerabilidades",
    ]
    out = {}
    for t in tables:
        try:
            out[t] = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
        except Exception:
            out[t] = "NOT_AVAILABLE"
    try:
        out["loadtest_users"] = con.execute(
            "SELECT COUNT(*) FROM usuarios WHERE email LIKE 'loadtest-user-%@loadtest.novus.local'"
        ).fetchone()[0]
        out["loadtest_tenants"] = con.execute(
            "SELECT COUNT(*) FROM tenant_monitoring_scope WHERE tenant_id LIKE 'LOADTEST-%'"
        ).fetchone()[0]
    except Exception:
        pass
    return out


def code_fingerprint() -> dict:
    files = [
        "services/http_abuse_guard.py",
        "services/hostile_hardening_config.py",
        "services/hostile_environment_service.py",
        "database.py",
        "main.py",
        "scripts/phase2_capacity_levels.py",
    ]
    import hashlib

    out = {}
    for rel in files:
        p = ROOT / rel
        if p.is_file():
            out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    # try git
    git_hash = "NOT_AVAILABLE"
    try:
        import subprocess

        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode == 0:
            git_hash = r.stdout.strip()
    except Exception:
        pass
    return {"git_head": git_hash, "file_sha256_16": out}


def main() -> int:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    # file copy backup of DB + key configs
    if DB.is_file():
        shutil.copy2(DB, BACKUP_DIR / "novus_vault_v2.db")
    for rel in (
        "config/hostile_hardening.json",
        "data/production_closure/phase2_capacity_final.json",
        "data/production_closure/phase1_performance_final.json",
    ):
        src = ROOT / rel
        if src.is_file():
            dest = BACKUP_DIR / Path(rel).name
            shutil.copy2(src, dest)

    enc_bak = None
    try:
        from services.encrypted_backup_service import create_encrypted_backup

        enc_bak = create_encrypted_backup(label="phase3_baseline", actor="phase3_harness")
    except Exception as exc:
        enc_bak = {"ok": False, "error": str(exc)[:200]}

    con = sqlite3.connect(str(DB), timeout=10)
    try:
        counts = db_counts(con)
        journal = con.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        con.close()

    from services.hostile_hardening_config import get_hostile_hardening_config, DEFAULTS

    cfg = get_hostile_hardening_config()
    abuse = {
        k: cfg.get(k)
        for k in (
            "http_flood_per_ip_per_10s",
            "http_flood_session_dashboard_per_10s",
            "http_flood_session_authed_per_10s",
            "http_flood_nat_dashboard_per_ip_per_10s",
            "http_flood_nat_api_per_ip_per_10s",
            "http_flood_dashboard_read_per_10s",
            "user_dashboard_read_rate_limit_per_minute",
            "user_api_rate_limit_per_minute",
            "adaptive_rate_multiplier",
            "circuit_breaker_violations",
            "circuit_breaker_cooldown_sec",
            "bot_detection_enabled",
            "bot_block_enabled",
            "load_shedding",
        )
    }

    bp = {}
    try:
        from services import resource_backpressure_service as rbp

        bp = {
            "module": "services/resource_backpressure_service.py",
            "has_should_run": callable(getattr(rbp, "should_run_background", None)),
        }
    except Exception as exc:
        bp = {"error": str(exc)[:120]}

    caches = [
        "services/auth_session_cache.py",
        "services/http_endpoint_cache.py",
        "services/performance_cache.py",
        "services/engine_runtime_registry.py",
    ]

    engines = {"status": "NOT_VERIFIABLE_AT_BASELINE", "note": "Classify via live registry after server restart"}
    try:
        from services.engine_runtime_registry import get_engine_runtime_summary

        summary = get_engine_runtime_summary()
        engines_list = summary.get("engines") or []
        from collections import Counter

        engines = {
            "counts": dict(Counter((e.get("runtime_status") or "unknown") for e in engines_list)),
            "total": len(engines_list),
            "note": "Process-local probe at baseline; LOADTEST may pause heavy engines",
        }
    except Exception as exc:
        engines = {"error": str(exc)[:200]}

    baseline = {
        "generated_at": utc(),
        "phase": "phase3_baseline",
        "backup_dir": str(BACKUP_DIR),
        "encrypted_backup": {
            k: enc_bak.get(k)
            for k in ("ok", "path", "file", "sha256_plain", "size", "error", "reason")
            if isinstance(enc_bak, dict) and k in enc_bak
        },
        "code": code_fingerprint(),
        "db": {
            "path": str(DB),
            "size_bytes": DB.stat().st_size if DB.is_file() else None,
            "size_mb": round(DB.stat().st_size / 1e6, 2) if DB.is_file() else None,
            "journal_mode": journal,
            "counts": counts,
        },
        "host_idle": host_idle(),
        "waitress": {
            "threads_env": os.environ.get("NOVUS_WAITRESS_THREADS", "NOT_SET_IN_THIS_PROCESS"),
            "phase2_demonstrated": 48,
            "port": 5000,
        },
        "abuse_guard": abuse,
        "rate_limits": {
            "user_dashboard_read_rate_limit_per_minute": cfg.get("user_dashboard_read_rate_limit_per_minute"),
            "user_api_rate_limit_per_minute": cfg.get("user_api_rate_limit_per_minute"),
            "api_path_limits": cfg.get("api_path_limits"),
        },
        "backpressure": bp,
        "caches": caches,
        "engines": engines,
        "phase2_ref": {
            "MAX_DEMONSTRATED_CAPACITY": 1000,
            "saturation": 2000,
            "verdict": "CLOSED_WITH_LIMITATIONS",
        },
        "defaults_note": {
            "http_flood_dashboard_read_per_10s_in_defaults": DEFAULTS.get("http_flood_dashboard_read_per_10s"),
            "used_in_resolve_flood_buckets": False,
            "comment": "Key exists in DEFAULTS but http_abuse_guard._resolve_flood_buckets uses NAT/session buckets, not this key",
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(baseline, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"ok": True, "out": str(OUT), "backup": str(BACKUP_DIR), "db_mb": baseline["db"]["size_mb"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
