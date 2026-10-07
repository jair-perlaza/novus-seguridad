#!/usr/bin/env python3
"""
Perfil RAM por componente — mide delta RSS tras cada endpoint/escenario.
Salida: data/novus_release_candidate/NOVUS_RAM_COMPONENT_PROFILE.json
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_release_candidate" / "NOVUS_RAM_COMPONENT_PROFILE.json"
BASE = "http://127.0.0.1:5000"

COMPONENTS = [
    ("base", None),
    ("boot_30s", "wait:30"),
    ("boot_300s", "wait:270"),
    ("login_mfa", "auth"),
    ("dashboard", "/api/dashboard/live"),
    ("health", "/api/health/status"),
    ("network", "/api/network/nodes?trigger_discovery=false"),
    ("discovery_status", "/api/monitoring/network-config"),
    ("threats", "/api/security/threats"),
    ("vulnerabilities", "/api/security/vulnerabilities"),
    ("endpoints", "/api/security/endpoints"),
    ("reports", "/api/reports"),
    ("search", "/api/search?q=alert"),
    ("evidence", "/api/system/evidence-center?limit=30"),
    ("sessions", "/api/system/login-sessions?limit=30"),
    ("config", "/api/monitoring/network-config"),
]


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pid() -> Optional[int]:
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            return c.pid
    return None


def _sample(label: str, *, note: str = "") -> Dict[str, Any]:
    pid = _pid()
    row: Dict[str, Any] = {
        "label": label,
        "ts": _utc(),
        "pid": pid,
        "host_ram_pct": round(psutil.virtual_memory().percent, 1),
        "note": note,
    }
    if pid:
        try:
            p = psutil.Process(pid)
            row["rss_mb"] = round(p.memory_info().rss / (1024 * 1024), 1)
            row["threads"] = p.num_threads()
        except Exception as exc:
            row["proc_error"] = str(exc)[:120]
    try:
        from services.resource_backpressure_service import get_status

        row["backpressure"] = get_status()
    except Exception:
        pass
    try:
        from services.performance_cache import cache_stats

        row["perf_cache"] = cache_stats()
    except Exception:
        pass
    return row


def _delta(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    br = before.get("rss_mb")
    ar = after.get("rss_mb")
    return {
        "rss_delta_mb": round(ar - br, 1) if br is not None and ar is not None else None,
        "host_ram_delta_pct": round(after.get("host_ram_pct", 0) - before.get("host_ram_pct", 0), 1),
        "threads_delta": (
            (after.get("threads") or 0) - (before.get("threads") or 0)
            if after.get("threads") is not None and before.get("threads") is not None
            else None
        ),
    }


def main() -> int:
    import argparse
    import requests
    from scripts.reports_regression_probe import login

    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="Solo boot 30s + secuencia API")
    ap.add_argument("--idle-min", type=float, default=5.0)
    args = ap.parse_args()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, Any]] = []
    prev = _sample("A_clean_boot")
    rows.append(prev)

    waits = [("B_idle_30s", 30)]
    if not args.quick:
        waits.extend([
            ("C_idle_5min", max(0, int(args.idle_min * 60) - 30)),
            ("D_idle_15min", max(0, 15 * 60 - int(args.idle_min * 60))),
            ("E_idle_30min", max(0, 30 * 60 - 15 * 60)),
        ])

    for label, sec in waits:
        if sec > 0:
            time.sleep(sec)
        cur = _sample(label)
        cur["delta_from_prev"] = _delta(prev, cur)
        rows.append(cur)
        prev = cur

    s = requests.Session()
    try:
        login(s)
    except Exception as exc:
        OUT.write_text(json.dumps({"error": f"login_failed: {exc}", "samples": rows}, indent=2), encoding="utf-8")
        print(json.dumps({"pass": False, "error": "login_failed"}))
        return 1

    for label, target in COMPONENTS:
        if target in (None, "wait:30", "wait:270", "auth"):
            if target == "auth":
                cur = _sample("F_login_mfa")
                cur["delta_from_prev"] = _delta(prev, cur)
                rows.append(cur)
                prev = cur
            continue
        t0 = time.perf_counter()
        try:
            r = s.get(BASE + target, timeout=180)
            http = r.status_code
            recovery = bool(r.headers.get("X-Novus-Recovery"))
        except Exception as exc:
            http = 0
            recovery = False
            err = str(exc)[:200]
        else:
            err = None
        time.sleep(2)
        cur = _sample(label, note=target)
        cur["http"] = http
        cur["recovery"] = recovery
        cur["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        if err:
            cur["error"] = err
        cur["delta_from_prev"] = _delta(prev, cur)
        rows.append(cur)
        prev = cur

    report = {
        "generated_at": _utc(),
        "samples": rows,
        "summary": {
            "peak_rss_mb": max((r.get("rss_mb") or 0) for r in rows),
            "peak_host_ram_pct": max((r.get("host_ram_pct") or 0) for r in rows),
            "largest_deltas": sorted(
                [
                    {
                        "label": r["label"],
                        "rss_delta_mb": (r.get("delta_from_prev") or {}).get("rss_delta_mb"),
                    }
                    for r in rows
                    if r.get("delta_from_prev", {}).get("rss_delta_mb") is not None
                ],
                key=lambda x: x.get("rss_delta_mb") or 0,
                reverse=True,
            )[:8],
        },
    }
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"out": str(OUT), "peak_rss_mb": report["summary"]["peak_rss_mb"], "samples": len(rows)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
