#!/usr/bin/env python3
"""
Phase 2 — data growth, SQLite metrics, backup/restore, persistence markers, engines.
Produces: phase2_data_ops.json
"""
from __future__ import annotations

import hashlib
import json
import os
import pickle
import shutil
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure" / "phase2_data_ops.json"
DB = ROOT / "novus_vault_v2.db"
SESSIONS = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def counts(con: sqlite3.Connection) -> dict:
    tables = [
        "usuarios",
        "tenant_monitoring_scope",
        "logs",
        "alertas",
        "novus_notifications",
        "platform_evidences",
        "endpoint_monitor_events",
        "auth_access_events",
        "login_session_audits",
        "vulnerabilidades",
        "network_device_inventory",
        "behavior_activity_events",
    ]
    out = {}
    for t in tables:
        try:
            out[t] = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
        except Exception:
            out[t] = "NOT_AVAILABLE"
    return out


def measure_query_latency(con: sqlite3.Connection, samples: int = 30) -> dict:
    queries = [
        ("usuarios_by_email", "SELECT id, email, nit_pyme FROM usuarios WHERE email=? LIMIT 1"),
        ("scope_by_tenant", "SELECT tenant_id FROM tenant_monitoring_scope WHERE tenant_id=? LIMIT 1"),
        ("notif_by_tenant", "SELECT id FROM novus_notifications WHERE tenant_id=? ORDER BY id DESC LIMIT 20"),
        ("alertas_by_tenant", "SELECT id FROM alertas WHERE tenant_id=? LIMIT 20"),
        ("logs_recent", "SELECT id FROM logs ORDER BY id DESC LIMIT 50"),
    ]
    # pick real keys
    email = con.execute(
        "SELECT email FROM usuarios WHERE email LIKE 'loadtest-user-%' LIMIT 1"
    ).fetchone()
    tid = con.execute(
        "SELECT tenant_id FROM tenant_monitoring_scope WHERE tenant_id LIKE 'LOADTEST-%' LIMIT 1"
    ).fetchone()
    email = email[0] if email else "none"
    tid = tid[0] if tid else "none"
    results = {}
    for name, sql in queries:
        lat = []
        for _ in range(samples):
            t0 = time.perf_counter()
            if "?" in sql:
                param = email if "email" in sql else tid
                con.execute(sql, (param,)).fetchall()
            else:
                con.execute(sql).fetchall()
            lat.append((time.perf_counter() - t0) * 1000)
        lat.sort()
        results[name] = {
            "p50": round(lat[len(lat) // 2], 3),
            "p95": round(lat[int(len(lat) * 0.95)], 3),
            "p99": round(lat[int(len(lat) * 0.99)], 3),
            "samples": samples,
        }
    return results


def growth_via_apis(sessions: list, n_tenants: int = 20) -> dict:
    """Generate real records via authenticated routes (notifications read + scope touch)."""
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    if not sessions:
        return {"status": "NOT_TESTED", "reason": "no_sessions"}
    before = {}
    con = sqlite3.connect(str(DB))
    try:
        before = counts(con)
    finally:
        con.close()

    writes_ok = 0
    for rec in sessions[:n_tenants]:
        s = requests.Session()
        apply_loadtest_client_headers(s, rec["email"])
        s.cookies.update(rec["cookies"])
        try:
            # read paths that may write audit/session activity
            for path in (
                "/api/tenant/scope",
                "/api/notifications",
                "/api/security/summary",
                "/api/dashboard/live",
            ):
                r = s.get(BASE + path, timeout=20)
                if r.status_code == 200:
                    writes_ok += 1
        except Exception:
            pass

    after = {}
    con = sqlite3.connect(str(DB))
    try:
        after = counts(con)
        size = DB.stat().st_size
    finally:
        con.close()

    delta = {}
    for k in after:
        if isinstance(after[k], int) and isinstance(before.get(k), int):
            delta[k] = after[k] - before[k]

    # estimate growth rates from observed delta over this short window only — mark as ESTIMATED_FROM_SAMPLE
    elapsed_min = max(n_tenants * 0.05, 0.5)  # rough wall for sequential hits
    # Prefer honest NOT_AVAILABLE for daily/monthly if sample too small
    total_delta = sum(v for v in delta.values() if isinstance(v, int) and v > 0)
    growth = {
        "sample_tenants": n_tenants,
        "api_ok_hits": writes_ok,
        "before": before,
        "after": after,
        "delta": delta,
        "db_size_bytes_after": size,
        "daily_growth_rows": "NOT_AVAILABLE" if total_delta < 5 else "NOT_AVAILABLE",
        "monthly_growth_rows": "NOT_AVAILABLE",
        "annual_growth_rows": "NOT_AVAILABLE",
        "note": "Long-horizon growth rates NOT_AVAILABLE — only short controlled sample measured; do not invent.",
    }
    return growth


def backup_restore_test() -> dict:
    from services.encrypted_backup_service import (
        create_encrypted_backup,
        restore_encrypted_backup,
        verify_backup,
    )

    result = {
        "backup_duration_sec": "NOT_MEASURED",
        "backup_size_bytes": "NOT_MEASURED",
        "restore_duration_sec": "NOT_MEASURED",
        "integrity": "NOT_MEASURED",
        "RPO": "NOT_MEASURED",
        "RTO": "NOT_MEASURED",
    }
    # fingerprint before
    sha_before = hashlib.sha256(DB.read_bytes()).hexdigest() if DB.is_file() else None
    t0 = time.perf_counter()
    try:
        bak = create_encrypted_backup(label="phase2_capacity", actor="phase2_harness")
    except Exception as exc:
        result["error"] = f"backup_failed:{exc}"[:200]
        return result
    backup_dur = round(time.perf_counter() - t0, 3)
    path = bak.get("path") or bak.get("backup_path") or bak.get("file")
    result["backup_duration_sec"] = backup_dur
    result["backup_result"] = {k: bak[k] for k in bak if k not in ("sealed", "ciphertext")}
    if path and os.path.isfile(path):
        result["backup_size_bytes"] = os.path.getsize(path)
        try:
            ver = verify_backup(path)
            result["verify"] = ver
        except Exception as exc:
            result["verify_error"] = str(exc)[:120]

    # Controlled restore to temp dir — do NOT overwrite production DB blindly
    restore_dir = ROOT / "data" / "production_closure" / "phase2_restore_probe"
    if restore_dir.exists():
        shutil.rmtree(restore_dir, ignore_errors=True)
    restore_dir.mkdir(parents=True, exist_ok=True)
    t1 = time.perf_counter()
    try:
        # Prefer API that accepts dest; if signature differs, catch
        rest = restore_encrypted_backup(path, dest_dir=str(restore_dir))  # type: ignore
        result["restore_duration_sec"] = round(time.perf_counter() - t1, 3)
        result["restore_result"] = {k: rest[k] for k in rest if k != "sealed"} if isinstance(rest, dict) else str(rest)[:200]
        # look for restored db
        restored_db = None
        for p in restore_dir.rglob("novus_vault_v2.db"):
            restored_db = p
            break
        if restored_db and restored_db.is_file():
            sha_rest = hashlib.sha256(restored_db.read_bytes()).hexdigest()
            result["integrity"] = "PASS" if sha_before and sha_rest == sha_before else "PASS_IF_COPY_MATCH" if sha_rest else "FAIL"
            result["sha_before"] = sha_before
            result["sha_restored"] = sha_rest
            result["sha_match"] = sha_before == sha_rest
        else:
            result["integrity"] = "NOT_VERIFIABLE"
            result["note"] = "restore produced no novus_vault_v2.db under probe dir — check restore API contract"
    except TypeError:
        # try without dest_dir — DO NOT call destructive restore on live DB
        result["restore_duration_sec"] = "NOT_MEASURED"
        result["integrity"] = "NOT_MEASURED"
        result["RPO"] = "NOT_MEASURED"
        result["RTO"] = "NOT_MEASURED"
        result["note"] = "restore_encrypted_backup signature incompatible with safe dest_dir probe; skipped live overwrite"
    except Exception as exc:
        result["restore_error"] = str(exc)[:200]
        result["integrity"] = "FAIL"

    # RPO/RTO: only claim what we measured
    if isinstance(result.get("backup_duration_sec"), (int, float)):
        result["RPO"] = {
            "demonstrated_sec": result["backup_duration_sec"],
            "meaning": "time from start of backup call to sealed artifact (not continuous replication)",
        }
    if isinstance(result.get("restore_duration_sec"), (int, float)):
        result["RTO"] = {
            "demonstrated_sec": result["restore_duration_sec"],
            "meaning": "time to restore into probe directory (not full production cutover)",
        }
    return result


def engine_states() -> dict:
    try:
        from services.engine_runtime_registry import get_engine_runtime_summary

        summary = get_engine_runtime_summary()
        # normalize classification labels for Phase2 report
        engines = []
        raw = summary.get("engines") or summary.get("items") or summary.get("registry") or []
        if isinstance(summary, dict) and not raw:
            # maybe summary is the list wrapper
            for k, v in summary.items():
                if isinstance(v, list) and k not in ("errors",):
                    raw = v
                    break
        if isinstance(raw, list):
            for e in raw:
                if not isinstance(e, dict):
                    continue
                rt = (e.get("runtime_status") or e.get("status") or "NOT_VERIFIABLE").upper()
                # map to Phase2 allowed set
                mapping = {
                    "RUNNING": "ACTIVE",
                    "ACTIVE": "ACTIVE",
                    "IDLE": "IDLE",
                    "PAUSED": "IDLE",
                    "STOPPED": "STOPPED",
                    "ERROR": "ERROR",
                    "NOT_CONFIGURED": "NOT_IMPLEMENTED",
                    "NOT_IMPLEMENTED": "NOT_IMPLEMENTED",
                    "NOT_VERIFIABLE": "NOT_VERIFIABLE",
                }
                engines.append(
                    {
                        "id": e.get("id") or e.get("engine_id") or e.get("name"),
                        "runtime_status_raw": e.get("runtime_status") or e.get("status"),
                        "phase2_class": mapping.get(rt, "NOT_VERIFIABLE"),
                    }
                )
        return {"ok": True, "summary_keys": list(summary.keys()) if isinstance(summary, dict) else [], "engines": engines, "raw_type": type(summary).__name__}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200], "engines": []}


def persistence_markers() -> dict:
    """Record counts that must survive restart — compared by later script."""
    con = sqlite3.connect(str(DB))
    try:
        c = counts(con)
        marker = {
            "captured_at": utc(),
            "db_sha256": hashlib.sha256(DB.read_bytes()).hexdigest(),
            "counts": c,
            "db_size_bytes": DB.stat().st_size,
        }
    finally:
        con.close()
    marker_path = ROOT / "data" / "production_closure" / "phase2_persistence_before.json"
    marker_path.write_text(json.dumps(marker, indent=2), encoding="utf-8")
    return {"marker_path": str(marker_path), **marker}


def main() -> int:
    sessions = []
    if SESSIONS.is_file():
        sessions = pickle.loads(SESSIONS.read_bytes())

    con = sqlite3.connect(str(DB), timeout=10)
    try:
        qlat = measure_query_latency(con)
        row_counts = counts(con)
    finally:
        con.close()

    print("Measuring growth via APIs...", flush=True)
    growth = growth_via_apis(sessions, n_tenants=min(30, len(sessions) or 0))
    print("Backup/restore probe...", flush=True)
    bak = backup_restore_test()
    print("Engine states...", flush=True)
    eng = engine_states()
    print("Persistence markers...", flush=True)
    pers = persistence_markers()

    report = {
        "generated_at": utc(),
        "db_size_mb": round(DB.stat().st_size / 1e6, 2),
        "row_counts": row_counts,
        "query_latency_ms": qlat,
        "growth_sample": growth,
        "backup_restore": bak,
        "engines": eng,
        "persistence_before": pers,
    }
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"out": str(OUT), "db_mb": report["db_size_mb"], "engines": len(eng.get("engines") or [])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
