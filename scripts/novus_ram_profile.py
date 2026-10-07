#!/usr/bin/env python3
"""Muestreo RSS NOVUS — escenarios A-J (intervalos configurables)."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_release_candidate" / "NOVUS_RAM_PROFILE.json"
BASE = "http://127.0.0.1:5000"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_pid() -> int | None:
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            return c.pid
    return None


def sample(label: str) -> dict:
    pid = _find_pid()
    row = {"label": label, "ts": _utc(), "pid": pid, "host_ram_pct": round(psutil.virtual_memory().percent, 1)}
    if pid:
        p = psutil.Process(pid)
        row["rss_mb"] = round(p.memory_info().rss / (1024 * 1024), 1)
        row["threads"] = p.num_threads()
    return row


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--idle-min", type=float, default=5.0, help="Minutos idle entre A y B/C/D")
    ap.add_argument("--quick", action="store_true", help="Solo arranque + 30s idle")
    args = ap.parse_args()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = [sample("A_startup")]
    if args.quick:
        time.sleep(30)
        rows.append(sample("B_30s_idle"))
    else:
        for label, mins in (("B_5min_idle", args.idle_min), ("C_15min_idle", 15.0), ("D_30min_idle", 30.0)):
            if label == "B_5min_idle":
                wait = args.idle_min * 60
            elif label == "C_15min_idle":
                wait = max(0, (15.0 - args.idle_min) * 60)
            else:
                wait = max(0, (30.0 - 15.0) * 60)
            if wait > 0:
                time.sleep(wait)
            rows.append(sample(label))

    try:
        sys.path.insert(0, str(ROOT))
        from scripts.reports_regression_probe import login
        import requests

        s = requests.Session()
        login(s)
        rows.append(sample("E_login_mfa"))
        for path, label in (
            ("/dashboard", "F_dashboard"),
            ("/api/network/nodes?trigger_discovery=false", "G_network"),
            ("/api/security/threats", "H_threats"),
            ("/api/security/vulnerabilities", "I_vulnerabilities"),
            ("/api/reports", "J_reports"),
        ):
            s.get(BASE + path, timeout=120)
            rows.append(sample(label))
    except Exception as exc:
        rows.append({"error": str(exc)[:200]})

    OUT.write_text(json.dumps({"samples": rows}, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(OUT), "samples": len(rows)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
