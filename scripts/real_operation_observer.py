#!/usr/bin/env python3
"""
Observador ligero para operación real controlada NOVUS (7–14 días).
Solo lectura: psutil, tamaños de archivos, conteos DB, snapshot sin discovery.
NO dispara motores lazy ni baterías HTTP.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_real_operation_audit"
THRESHOLDS = {
    "ram_system_pct_warn": 85.0,
    "ram_system_pct_critical": 93.0,
    "novus_ram_mb_warn": 800.0,
    "db_growth_mb_per_day_warn": 50.0,
}


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_novus_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = p.info.get("cmdline") or []
            if len(cmd) >= 2 and str(cmd[-1]).endswith("main.py"):
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def port_listeners(port: int = 5000) -> List[int]:
    pids = []
    try:
        out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
        for line in out.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                pids.append(int(line.split()[-1]))
    except Exception:
        pass
    return pids


def dir_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    if path.is_dir():
        for f in path.rglob("*"):
            if f.is_file():
                try:
                    total += f.stat().st_size
                except OSError:
                    pass
    return total


def file_stat(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    if path.is_dir():
        return {"bytes": dir_size(path), "type": "dir"}
    st = path.stat()
    return {"bytes": st.st_size, "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(), "type": "file"}


def db_counts() -> dict:
    from database import (
        SessionLocal,
        Alerta,
        LoginSessionAudit,
        NetworkDeviceInventory,
        Vulnerabilidad,
        PlatformEvidence,
        Log,
        Usuario,
    )
    from sqlalchemy import func

    db = SessionLocal()
    try:
        return {
            "usuarios": db.query(func.count(Usuario.id)).scalar(),
            "alertas": db.query(func.count(Alerta.id)).scalar(),
            "vulnerabilidades": db.query(func.count(Vulnerabilidad.id)).scalar(),
            "network_inventory": db.query(func.count(NetworkDeviceInventory.id)).scalar(),
            "login_sessions": db.query(func.count(LoginSessionAudit.id)).scalar(),
            "platform_evidence": db.query(func.count(PlatformEvidence.id)).scalar(),
            "logs": db.query(func.count(Log.id)).scalar(),
        }
    except Exception as exc:
        return {"error": str(exc)[:160]}
    finally:
        db.close()


def snapshot_probe() -> dict:
    row: Dict[str, Any] = {}
    try:
        from services.network_snapshot_service import read_nodes_api, read_context_snapshot

        nodes = read_nodes_api(trigger_discovery=False, include_context=False)
        ctx = read_context_snapshot()
        meta = (nodes or {}).get("snapshot_meta") or {}
        row = {
            "nodes_count": nodes.get("count", len(nodes.get("nodes") or [])),
            "nodes_status": nodes.get("status"),
            "snapshot_stale": meta.get("snapshot_stale"),
            "snapshot_pending": meta.get("snapshot_pending"),
            "source_type": nodes.get("source_type"),
            "context_ip": ((ctx or {}).get("body") or {}).get("local_ip"),
        }
    except Exception as exc:
        row["error"] = str(exc)[:120]
    return row


def engine_status_light() -> dict:
    """Una sola petición ligera si NOVUS responde; sin arrancar motores."""
    import urllib.request

    row = {"listeners": port_listeners(5000)}
    try:
        req = urllib.request.Request("http://127.0.0.1:5000/api/engines/status", method="GET")
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
            row["http_status"] = resp.status
            if isinstance(body, dict):
                engines = body.get("engines") or body
                if isinstance(engines, dict):
                    row["engine_states"] = {
                        k: v.get("state") if isinstance(v, dict) else v
                        for k, v in list(engines.items())[:12]
                    }
    except Exception as exc:
        row["probe_error"] = str(exc)[:100]
    return row


def collect_sample() -> dict:
    pid = find_novus_pid()
    vm = psutil.virtual_memory()
    proc = {}
    if pid:
        try:
            p = psutil.Process(pid)
            proc = {
                "pid": pid,
                "ram_mb": round(p.memory_info().rss / (1024**2), 1),
                "cpu_pct": round(p.cpu_percent(interval=0.3), 1),
                "threads": p.num_threads(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc = {"pid": pid, "error": "process_inaccessible"}

    storage = {
        "novus_vault_v2.db": file_stat(ROOT / "novus_vault_v2.db"),
        "novus_vault_v2.db.novusenc": file_stat(ROOT / "novus_vault_v2.db.novusenc"),
        "data/network/nodes_snapshot.json": file_stat(ROOT / "data/network/nodes_snapshot.json"),
        "data/network/context_snapshot.json": file_stat(ROOT / "data/network/context_snapshot.json"),
        "data/security/summary_snapshot.json": file_stat(ROOT / "data/security/summary_snapshot.json"),
        "data/kernel_memory": file_stat(ROOT / "data/kernel_memory"),
        "data/behavioral_threat_detection/baseline_cache.json": file_stat(
            ROOT / "data/behavioral_threat_detection/baseline_cache.json"
        ),
        "data/encrypted_backups": file_stat(ROOT / "data/encrypted_backups"),
        "logs_dir": file_stat(ROOT / "logs") if (ROOT / "logs").exists() else file_stat(ROOT / "data/logs"),
    }

    return {
        "timestamp_utc": utc(),
        "system": {
            "ram_pct": round(vm.percent, 1),
            "ram_available_mb": round(vm.available / (1024**2), 1),
        },
        "novus_process": proc,
        "listeners_5000": port_listeners(5000),
        "storage": storage,
        "db_counts": db_counts(),
        "network_snapshot": snapshot_probe(),
        "engines": engine_status_light(),
    }


def check_incidents(sample: dict, baseline: Optional[dict]) -> List[dict]:
    incidents = []
    ram = sample["system"]["ram_pct"]
    if ram >= THRESHOLDS["ram_system_pct_critical"]:
        incidents.append({"severity": "critical", "type": "ram_system", "value": ram, "threshold": THRESHOLDS["ram_system_pct_critical"]})
    elif ram >= THRESHOLDS["ram_system_pct_warn"]:
        incidents.append({"severity": "warn", "type": "ram_system", "value": ram, "threshold": THRESHOLDS["ram_system_pct_warn"]})

    novus_mb = (sample.get("novus_process") or {}).get("ram_mb")
    if novus_mb and novus_mb >= THRESHOLDS["novus_ram_mb_warn"]:
        incidents.append({"severity": "warn", "type": "novus_ram", "value": novus_mb, "threshold": THRESHOLDS["novus_ram_mb_warn"]})

    if not sample.get("listeners_5000"):
        incidents.append({"severity": "critical", "type": "no_listener", "value": 0})

    if baseline:
        b_db = ((baseline.get("storage") or {}).get("novus_vault_v2.db") or {}).get("bytes") or 0
        c_db = ((sample.get("storage") or {}).get("novus_vault_v2.db") or {}).get("bytes") or 0
        if b_db and c_db > b_db + 100 * 1024 * 1024:
            incidents.append({"severity": "info", "type": "db_growth", "delta_mb": round((c_db - b_db) / (1024**2), 1)})

    for inc in incidents:
        inc["timestamp_utc"] = sample["timestamp_utc"]
    return incidents


def load_json(path: Path, default: Any) -> Any:
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return default


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def append_dashboard(sample: dict) -> None:
    dash_path = OUT / "REAL_OPERATION_DASHBOARD.json"
    dash = load_json(dash_path, {"samples": [], "started_at_utc": utc()})
    if not dash.get("started_at_utc"):
        dash["started_at_utc"] = utc()
    dash["last_sample_utc"] = sample["timestamp_utc"]
    dash["samples"].append(sample)
    # conservar últimas 2000 muestras (~14 días @ cada 10 min ≈ 2016)
    dash["samples"] = dash["samples"][-2000:]
    dash["sample_count"] = len(dash["samples"])
    save_json(dash_path, dash)


def append_incidents(incidents: List[dict]) -> None:
    if not incidents:
        return
    log_path = OUT / "REAL_OPERATION_INCIDENT_LOG.json"
    log = load_json(log_path, {"incidents": []})
    log["incidents"].extend(incidents)
    log["last_updated_utc"] = utc()
    save_json(log_path, log)


def main() -> int:
    parser = argparse.ArgumentParser(description="NOVUS real operation observer")
    parser.add_argument("--baseline", action="store_true", help="Escribir REAL_OPERATION_BASELINE.json")
    parser.add_argument("--no-dashboard", action="store_true", help="No append dashboard sample")
    args = parser.parse_args()

    sample = collect_sample()
    baseline_path = OUT / "REAL_OPERATION_BASELINE.json"

    if args.baseline or not baseline_path.is_file():
        save_json(baseline_path, {"captured_at_utc": sample["timestamp_utc"], **sample})

    baseline = load_json(baseline_path, None)
    incidents = check_incidents(sample, baseline if isinstance(baseline, dict) else None)

    if not args.no_dashboard:
        append_dashboard(sample)
    append_incidents(incidents)

    print(json.dumps({"ok": True, "ram_pct": sample["system"]["ram_pct"], "incidents": len(incidents)}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
