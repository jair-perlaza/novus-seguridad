#!/usr/bin/env python3
"""
Fase 1 — backup completo + phase1_performance_before.json (línea base pre-cambios).
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

CLOSURE = ROOT / "data" / "production_closure"
BACKUP_ROOT = CLOSURE / "backups"


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_json(path: Path) -> dict | None:
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def git_head() -> str | None:
    git_dir = ROOT / ".git"
    head = git_dir / "HEAD"
    if not head.is_file():
        return None
    ref = head.read_text(encoding="utf-8").strip()
    if ref.startswith("ref: "):
        ref_path = git_dir / ref[5:]
        if ref_path.is_file():
            return ref_path.read_text(encoding="utf-8").strip()[:12]
    return ref[:12] if ref else None


def host_metrics() -> dict:
    try:
        import psutil

        vm = psutil.virtual_memory()
        novus = {"pid": None, "ram_mb": None, "threads": None}
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                cmd = " ".join(proc.info.get("cmdline") or [])
                if "main.py" not in cmd:
                    continue
                p = psutil.Process(proc.info["pid"])
                conns = p.connections(kind="inet")
                if not any(getattr(c.laddr, "port", None) == 5000 for c in conns if c.laddr):
                    continue
                novus["pid"] = proc.info["pid"]
                novus["ram_mb"] = round(p.memory_info().rss / (1024 * 1024), 1)
                novus["threads"] = p.num_threads()
                break
            except Exception:
                continue
        return {
            "ram_pct": round(vm.percent, 1),
            "ram_available_gb": round(vm.available / (1024**3), 2),
            "cpu_pct": round(psutil.cpu_percent(interval=0.5), 1),
            "novus": novus,
        }
    except Exception as exc:
        return {"error": str(exc)[:200]}


def db_stats() -> dict:
    db_path = ROOT / "novus_vault_v2.db"
    if not db_path.is_file():
        return {"error": "novus_vault_v2.db not found"}
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode")
    journal = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM novus_notifications")
    notif_total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM novus_notifications WHERE status='unread'")
    notif_unread = cur.fetchone()[0]
    conn.close()
    return {
        "path": str(db_path),
        "size_mb": round(db_path.stat().st_size / (1024 * 1024), 2),
        "journal_mode": journal,
        "notifications_total": notif_total,
        "notifications_unread": notif_unread,
    }


def endpoint_map(diagnosis: dict | None) -> dict:
    out = {}
    if not diagnosis:
        return out
    for row in diagnosis.get("endpoints_sequential") or []:
        path = (row.get("path") or "").split("?")[0]
        out[path] = {
            "p50_ms": row.get("p50_ms"),
            "p95_ms": row.get("p95_ms"),
            "p99_ms": row.get("p99_ms"),
            "max_ms": row.get("max_ms"),
            "status_codes": row.get("status_codes"),
        }
    return out


def load_levels(report: dict | None, path_filter: str | None = None) -> list:
    if not report:
        return []
    levels = report.get("levels") or []
    if path_filter:
        levels = [l for l in levels if (l.get("path") or "").startswith(path_filter)]
    return levels


def create_backup(stamp: str) -> Path:
    dest = BACKUP_ROOT / f"phase1_{stamp}"
    dest.mkdir(parents=True, exist_ok=True)

    def _ignore_backups(dirpath: str, names: list) -> set:
        ignored = set()
        if "backups" in names and Path(dirpath).name == "production_closure":
            ignored.add("backups")
        return ignored

    items = [
        ("novus_vault_v2.db", ROOT / "novus_vault_v2.db"),
        (".env", ROOT / ".env"),
        ("config", ROOT / "config"),
        ("data/production_closure/reports", CLOSURE),
    ]
    manifest = {"created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "items": []}
    for label, src in items:
        if not src.exists():
            continue
        target = dest / label
        target.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir() and label == "data/production_closure/reports":
            target.mkdir(parents=True, exist_ok=True)
            for child in src.iterdir():
                if child.name == "backups":
                    continue
                dst = target / child.name
                if child.is_dir():
                    if dst.exists():
                        shutil.rmtree(dst)
                    shutil.copytree(child, dst)
                else:
                    shutil.copy2(child, dst)
                manifest["items"].append({"label": f"{label}/{child.name}", "source": str(child)})
            continue
        if src.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(src, target, ignore=_ignore_backups)
        else:
            shutil.copy2(src, target)
        manifest["items"].append({"label": label, "source": str(src), "bytes": src.stat().st_size if src.is_file() else None})

    for script_name in (
        "scalability_performance_diagnosis.py",
        "scalability_isolated_600_test.py",
        "scalability_multiuser_load_test.py",
        "scalability_tenant_isolation_http.py",
    ):
        src = ROOT / "scripts" / script_name
        if src.is_file():
            dst = dest / "scripts" / script_name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            manifest["items"].append({"label": f"scripts/{script_name}", "source": str(src)})
    (dest / "backup_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return dest


def main() -> int:
    stamp = utc_stamp()
    backup_dir = create_backup(stamp)

    diagnosis = load_json(CLOSURE / "performance_diagnosis.json")
    isolated_600 = load_json(CLOSURE / "isolated_600_report.json")
    multiuser = load_json(CLOSURE / "multiuser_load_test_report.json")
    security = load_json(CLOSURE / "final_security_report.json")
    tenant_iso = load_json(CLOSURE / "tenant_isolation_http.json")

    eps = endpoint_map(diagnosis)
    idle = (diagnosis or {}).get("host_idle") or {}
    bg = (diagnosis or {}).get("background") or {}

    baseline = {
        "phase": "phase1_performance_before",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": git_head(),
        "backup_path": str(backup_dir),
        "reference_audit": {
            "host_ram_under_load_pct": "92-97",
            "novus_threads_observed": bg.get("novus_thread_count", 137),
            "waitress_threads_configured": int(os.environ.get("NOVUS_WAITRESS_THREADS", "96") or 96),
            "note": "Valores de auditoría conservados; mediciones frescas en host_current y db.",
        },
        "host_idle_audit": idle,
        "host_current": host_metrics(),
        "threads": {
            "novus_thread_count_audit": bg.get("novus_thread_count"),
            "novus_thread_count_current": (host_metrics().get("novus") or {}).get("threads"),
            "waitress_threads_env": os.environ.get("NOVUS_WAITRESS_THREADS"),
            "waitress_threads_recommended": None,
        },
        "database": db_stats(),
        "critical_apis_sequential_audit": eps,
        "load_test_isolated_600": load_levels(isolated_600),
        "load_test_multiuser_progressive": {
            "600_dashboard": next(
                (l for l in load_levels(multiuser, "/api/dashboard/live") if l.get("n") == 600),
                None,
            ),
            "600_security": next(
                (l for l in load_levels(multiuser, "/api/security/summary") if l.get("n") == 600),
                None,
            ),
        },
        "security_regression_audit": {
            "tenant_isolation_http": tenant_iso.get("summary") if tenant_iso else None,
            "final_security_verdict": security.get("verdict") if security else None,
        },
        "errors_5xx_audit": 0,
        "errors_429_audit": 0,
        "timeouts_audit": 0,
        "bottlenecks_audit": (diagnosis or {}).get("bottlenecks"),
        "diagnosis_verdict": (diagnosis or {}).get("diagnosis_verdict"),
    }

    try:
        from services.wsgi_server import recommended_threads

        baseline["threads"]["waitress_threads_recommended"] = recommended_threads()
    except Exception:
        pass

    out = CLOSURE / "phase1_performance_before.json"
    out.write_text(json.dumps(baseline, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"ok": True, "backup": str(backup_dir), "baseline": str(out)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
