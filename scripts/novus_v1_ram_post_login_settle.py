#!/usr/bin/env python3
"""Post-login RSS settle probe — async threads."""
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
OUT = ROOT / "data" / "novus_release_candidate" / "NOVUS_V1_RAM_POST_LOGIN_SETTLE.json"
BASE = "http://127.0.0.1:5000"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_pid() -> int | None:
    for p in psutil.process_iter(["pid", "cmdline"]):
        cmd = " ".join(p.info.get("cmdline") or [])
        if "main.py" in cmd.replace("\\", "/"):
            return p.info["pid"]
    return None


def sample(label: str) -> dict:
    pid = find_pid()
    row = {"label": label, "ts": utc()}
    if pid:
        proc = psutil.Process(pid)
        row["rss_mb"] = round(proc.memory_info().rss / 1024 / 1024, 1)
        row["threads"] = proc.num_threads()
    return row


def main() -> int:
    steps = [sample("before_login")]
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=30)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
    s.post(
        f"{BASE}/login",
        data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!", "csrf_token": csrf},
        allow_redirects=False,
        timeout=30,
    )
    steps.append(sample("immediate_post_login"))
    for wait in (5, 10, 20, 30, 60):
        time.sleep(5 if wait == 5 else 10 if wait <= 20 else 10 if wait == 30 else 30)
        row = sample(f"post_login_{wait}s")
        row["wait_sec"] = wait
        if len(steps) >= 2 and steps[-2].get("rss_mb") and row.get("rss_mb"):
            row["delta_from_prev_mb"] = round(row["rss_mb"] - steps[-2]["rss_mb"], 1)
        steps.append(row)
    report = {"generated_at_utc": utc(), "steps": steps}
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
