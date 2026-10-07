#!/usr/bin/env python3
"""Verificación post-cierre técnico — escribe data/production_closure/verify_snapshot.json"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

BASE = "http://127.0.0.1:5000"
EMAIL, PASS = "operaciones@novapay-fintech.co", "NovaPay#Fintech2026"
OUT = ROOT / "data" / "production_closure" / "verify_snapshot.json"


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    s = requests.Session()
    r0 = s.get(BASE + "/login", timeout=30)
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r0.text).group(1)
    s.post(
        BASE + "/login",
        data={"email": EMAIL, "password": PASS, "csrf_token": csrf},
        timeout=60,
    )
    out = {"ts": time.time()}
    for p in [
        "/api/manual-defense/summary",
        "/api/dashboard/live",
        "/api/security/summary",
        "/api/security/threats",
        "/api/security/vulnerabilities",
    ]:
        t0 = time.perf_counter()
        ar = s.get(BASE + p, timeout=120)
        body = ar.json() if "application/json" in ar.headers.get("content-type", "") else {}
        out[p] = {
            "http": ar.status_code,
            "ms": round((time.perf_counter() - t0) * 1000, 1),
            "body": body,
        }
    from services.engine_runtime_registry import get_engine_runtime_summary

    out["runtime_direct"] = get_engine_runtime_summary()
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
