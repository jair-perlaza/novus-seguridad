#!/usr/bin/env python3
"""Medición RSS 0-5 min con ping ligero al dashboard live."""
from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_release_candidate" / "RSS_5MIN_SERIES.json"
BASE = "http://127.0.0.1:5000"
EMAIL = "operaciones@novapay-fintech.co"
PASSWORD = "NovaPay#Fintech2026"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def pid() -> int:
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            return c.pid
    raise RuntimeError("NOVUS not on :5000")


def stats(p: int) -> dict:
    proc = psutil.Process(p)
    return {
        "rss_mb": round(proc.memory_info().rss / 1024 / 1024, 1),
        "threads": proc.num_threads(),
        "cpu_pct": round(proc.cpu_percent(interval=0.2), 1),
    }


def login() -> requests.Session:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=30)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    csrf = m.group(1) if m else ""
    s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD, "csrf_token": csrf},
        allow_redirects=True,
        timeout=60,
    )
    return s


def main() -> int:
    p = pid()
    s = login()
    series = []
    for minute in range(6):
        row = {"minute": minute, "utc": utc(), **stats(p)}
        try:
            r = s.get(f"{BASE}/api/dashboard/live", timeout=30)
            row["dashboard_live_http"] = r.status_code
        except Exception as exc:
            row["dashboard_live_http"] = 0
            row["error"] = str(exc)[:120]
        series.append(row)
        if minute < 5:
            time.sleep(60)
    out = {
        "pid": p,
        "series": series,
        "growth_mb": round(series[-1]["rss_mb"] - series[0]["rss_mb"], 1),
        "stable": (series[-1]["rss_mb"] - series[0]["rss_mb"]) < 150,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
