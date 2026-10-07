#!/usr/bin/env python3
"""
Construye sesiones HTTP independientes para load test — fase separada del benchmark.
Genera: data/production_closure/loadtest_sessions.pkl
"""
from __future__ import annotations

import json
import os
import pickle
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

MANIFEST = ROOT / "data" / "production_closure" / "loadtest_users_manifest.json"
OUT = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")
COUNT = int(os.environ.get("NOVUS_LOADTEST_SESSION_COUNT", "1000"))
WORKERS = int(os.environ.get("NOVUS_LOADTEST_LOGIN_WORKERS", "12"))


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def login_user(email: str, password: str) -> dict | None:
    import requests

    from services.loadtest_runtime import apply_loadtest_client_headers

    s = requests.Session()
    apply_loadtest_client_headers(s, email)
    try:
        r0 = s.get(BASE + "/login", timeout=30)
        csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r0.text)
        r1 = s.post(
            BASE + "/login",
            data={"email": email, "password": password, "csrf_token": csrf.group(1) if csrf else ""},
            timeout=60,
            allow_redirects=False,
        )
        if r1.status_code not in (200, 302):
            return None
        return {"email": email, "cookies": dict(s.cookies), "status": r1.status_code}
    except Exception:
        return None


def main() -> int:
    from services.loadtest_runtime import loadtest_password

    if not MANIFEST.is_file():
        print("Run scalability_seed_loadtest_users.py first", file=sys.stderr)
        return 2

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    password = loadtest_password()
    users = manifest["users"][:COUNT]
    sessions: list = []
    lock = threading.Lock()
    failures = 0

    def worker(u):
        nonlocal failures
        rec = login_user(u["email"], password)
        with lock:
            if rec:
                sessions.append(rec)
            else:
                failures += 1

    print(f"Building {len(users)} sessions with {WORKERS} workers...", flush=True)
    try:
        from services.tenant_scope_service import seed_loadtest_tenant_scopes

        seed = seed_loadtest_tenant_scopes(str(MANIFEST))
        print(f"LOADTEST tenant scope seed: {seed}", flush=True)
    except Exception as seed_exc:
        print(f"LOADTEST tenant scope seed skipped: {seed_exc}", flush=True)

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(worker, u) for u in users]
        done = 0
        for fut in as_completed(futs):
            fut.result()
            done += 1
            if done % 50 == 0:
                with lock:
                    n = len(sessions)
                print(f"  progress {done}/{len(users)} ok={n} fail={failures}", flush=True)

    elapsed = round((time.perf_counter() - t0) * 1000, 1)

    # Reintento secuencial para usuarios fallidos (login bajo carga)
    built_emails = {s["email"] for s in sessions}
    missing = [u for u in users if u["email"] not in built_emails]
    if missing:
        print(f"  retrying {len(missing)} failed logins...", flush=True)
        for u in missing:
            rec = login_user(u["email"], password)
            if rec:
                sessions.append(rec)
            time.sleep(0.05)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(pickle.dumps(sessions))
    summary = {
        "generated_at": utc(),
        "requested": len(users),
        "built": len(sessions),
        "failures": failures,
        "elapsed_ms": elapsed,
        "out": str(OUT),
    }
    print(json.dumps(summary, indent=2))
    return 0 if len(sessions) >= 600 else 1


if __name__ == "__main__":
    raise SystemExit(main())
