#!/usr/bin/env python3
"""
Perfil RAM post-login NOVUS V1 — identifica el primer paso con incremento significativo.
Solo lectura del proceso; no modifica código de aplicación.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_release_candidate" / "NOVUS_V1_RAM_LOGIN_PROFILE.json"
BASE = os.environ.get("NOVUS_TEST_BASE", "http://127.0.0.1:5000")
QA_EMAIL = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
QA_PASS = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
BOOT_GRACE_SEC = int(os.environ.get("NOVUS_BOOT_GRACE_SEC", "90"))
SIGNIFICANT_MB = float(os.environ.get("NOVUS_RAM_SIGNIFICANT_MB", "100"))


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if "main.py" in cmd.replace("\\", "/"):
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def sample(pid: Optional[int], label: str) -> Dict[str, Any]:
    mem = psutil.virtual_memory()
    row: Dict[str, Any] = {"label": label, "ts": utc(), "system_ram_pct": round(mem.percent, 1)}
    if pid:
        try:
            proc = psutil.Process(pid)
            row["rss_mb"] = round(proc.memory_info().rss / 1024 / 1024, 1)
            row["threads"] = proc.num_threads()
            try:
                row["thread_names"] = sorted({getattr(t, "name", None) or str(t.id) for t in proc.threads()})[:40]
            except Exception:
                row["thread_names"] = []
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    try:
        from services.resource_backpressure_service import get_backpressure_status

        row["backpressure"] = get_backpressure_status()
    except Exception:
        pass
    return row


def wait_stable(seconds: int) -> None:
    time.sleep(seconds)


def login_session() -> requests.Session:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=20)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    s.post(
        f"{BASE}/login",
        data={"email": QA_EMAIL, "password": QA_PASS, "csrf_token": csrf.group(1) if csrf else ""},
        allow_redirects=False,
        timeout=30,
    )
    return s


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    pid = find_pid()
    if not pid:
        print("ERROR: NOVUS main.py not running on :5000", file=sys.stderr)
        return 1

    steps: List[Dict[str, Any]] = []
    prev_rss: Optional[float] = None

    def record(label: str, *, after_action: Optional[str] = None) -> None:
        nonlocal prev_rss
        row = sample(pid, label)
        if after_action:
            row["after_action"] = after_action
        if prev_rss is not None and row.get("rss_mb") is not None:
            delta = round(row["rss_mb"] - prev_rss, 1)
            row["delta_mb"] = delta
            row["significant"] = delta >= SIGNIFICANT_MB
        if row.get("rss_mb") is not None:
            prev_rss = row["rss_mb"]
        steps.append(row)
        print(f"{label}: RSS={row.get('rss_mb')} MB delta={row.get('delta_mb')}")

    record("boot")
    wait_stable(BOOT_GRACE_SEC)
    record("post_boot_grace", after_action=f"sleep_{BOOT_GRACE_SEC}s")

    s = login_session()
    record("post_login_http", after_action="POST /login")
    wait_stable(3)
    record("post_login_settle", after_action="sleep_3s")

    modules = [
        ("dashboard", "/dashboard"),
        ("dashboard_live", "/api/dashboard/live"),
        ("security_summary", "/api/security/summary"),
        ("network_nodes", "/api/network/nodes?trigger_discovery=false"),
        ("threats", "/api/security/threats"),
        ("vulnerabilities", "/api/security/vulnerabilities"),
        ("reports", "/api/reports"),
        ("search", "/api/search?q=alert"),
        ("health", "/api/health/status"),
    ]
    for name, path in modules:
        try:
            s.get(f"{BASE}{path}", timeout=60)
        except Exception as exc:
            steps.append({"label": f"error_{name}", "path": path, "error": str(exc)[:200]})
        record(f"post_{name}", after_action=f"GET {path}")
        wait_stable(2)

    first_sig = next((s for s in steps if s.get("significant")), None)
    report = {
        "generated_at_utc": utc(),
        "pid": pid,
        "significant_threshold_mb": SIGNIFICANT_MB,
        "first_significant_step": first_sig,
        "steps": steps,
        "summary": {
            "rss_boot_mb": steps[0].get("rss_mb") if steps else None,
            "rss_final_mb": steps[-1].get("rss_mb") if steps else None,
            "max_delta_mb": max((s.get("delta_mb") or 0) for s in steps) if steps else None,
            "max_delta_step": max(steps, key=lambda x: x.get("delta_mb") or 0).get("label") if steps else None,
        },
    }
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
