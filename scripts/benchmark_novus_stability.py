"""
Medición real de tiempos — NOVUS estabilidad post-login.
Requiere servidor en http://127.0.0.1:5000
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Any, Dict, List

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

BASE = os.environ.get("NOVUS_BASE", "http://127.0.0.1:5000")
EMAIL = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
PWD = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")


def _csrf(session: requests.Session) -> str:
    r = session.get(BASE + "/login", timeout=60)
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def _login(session: requests.Session) -> float:
    t0 = time.perf_counter()
    token = _csrf(session)
    session.post(
        BASE + "/login",
        data={"email": EMAIL, "password": PWD, "csrf_token": token},
        timeout=120,
        allow_redirects=True,
    )
    return round(time.perf_counter() - t0, 3)


def _logout(session: requests.Session) -> float:
    t0 = time.perf_counter()
    session.get(BASE + "/logout", timeout=60, allow_redirects=True)
    return round(time.perf_counter() - t0, 3)


def _timed_get(session: requests.Session, path: str, timeout: int = 120) -> Dict[str, Any]:
    t0 = time.perf_counter()
    r = session.get(BASE + path, timeout=timeout)
    return {
        "path": path,
        "ms": round((time.perf_counter() - t0) * 1000, 1),
        "status": r.status_code,
        "bytes": len(r.content),
    }


def _wait_monitoring(session: requests.Session, max_wait: int = 900) -> Dict[str, Any]:
    t0 = time.perf_counter()
    last: Dict[str, Any] = {}
    while time.perf_counter() - t0 < max_wait:
        r = session.get(BASE + "/api/monitoring/status?poll=1", timeout=45)
        if r.ok:
            last = r.json()
            st = last.get("status")
            if st in ("completed", "partial", "error"):
                break
        time.sleep(4)
    last["wait_sec"] = round(time.perf_counter() - t0, 1)
    return last


def _find_auto_report(session_audit_id: str) -> Dict[str, Any]:
    rid = f"AUTO-{session_audit_id}"
    path = os.path.join(ROOT, "data", "reports", f"{rid}.json")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            return {"found": True, "report_id": rid, "report": json.load(fh)}
    idx_path = os.path.join(ROOT, "data", "reports", "index.json")
    if os.path.isfile(idx_path):
        with open(idx_path, encoding="utf-8") as fh:
            idx = json.load(fh)
        for e in idx:
            if e.get("id") == rid:
                return {"found": True, "report_id": rid, "index_entry": e}
    return {"found": False, "report_id": rid}


def main() -> int:
    report: Dict[str, Any] = {"base": BASE, "email": EMAIL, "timings": {}, "monitoring": {}, "report": {}}
    s = requests.Session()

    report["timings"]["login_sec"] = _login(s)
    report["timings"]["dashboard"] = _timed_get(s, "/")
    report["timings"]["monitoring_poll"] = _timed_get(s, "/api/monitoring/status?poll=1", timeout=45)
    report["timings"]["reportes"] = _timed_get(s, "/reportes", timeout=120)

    mon = _wait_monitoring(s, max_wait=900)
    report["monitoring"] = {
        "status": mon.get("status"),
        "progress_pct": mon.get("progress_pct"),
        "wait_sec": mon.get("wait_sec"),
        "report_id": mon.get("report_id"),
        "session_audit_id": mon.get("session_audit_id"),
    }
    sid = mon.get("session_audit_id")
    if sid:
        report["report"] = _find_auto_report(sid)

    report["timings"]["logout_sec"] = _logout(s)

    out_path = os.path.join(ROOT, "data", "stability_benchmark_latest.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    print(json.dumps(report, indent=2, ensure_ascii=False))
    ok = (
        report["timings"]["login_sec"] < 30
        and report["timings"]["monitoring_poll"]["ms"] < 5000
        and mon.get("status") in ("completed", "partial")
        and report["report"].get("found")
    )
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
