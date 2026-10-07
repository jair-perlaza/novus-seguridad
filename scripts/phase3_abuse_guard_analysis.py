#!/usr/bin/env python3
"""Phase 3 — Abuse Guard root-cause probe (does not change limits)."""
from __future__ import annotations

import json
import os
import pickle
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

SESSIONS = ROOT / "data" / "production_closure" / "loadtest_sessions.pkl"
OUT = ROOT / "data" / "production_closure" / "phase3_abuse_guard_analysis.json"
BASE = os.environ.get("NOVUS_LOAD_BASE", "http://127.0.0.1:5000")


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def reset():
    import requests

    try:
        return requests.post(BASE + "/api/system/internal/benchmark/reset-abuse-guard", timeout=8).status_code
    except Exception as exc:
        return str(exc)


def burst(sessions, n, path="/api/tenant/scope"):
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    codes = Counter()
    buckets = Counter()
    samples = []

    def one(rec):
        s = requests.Session()
        apply_loadtest_client_headers(s, rec["email"])
        s.cookies.update(rec["cookies"])
        try:
            r = s.get(BASE + path, timeout=20)
            body = {}
            try:
                body = r.json()
            except Exception:
                pass
            return r.status_code, body.get("code"), body.get("bucket")
        except Exception as exc:
            return 0, "EXC", str(exc)[:40]

    with ThreadPoolExecutor(max_workers=min(n, 48)) as ex:
        futs = [ex.submit(one, sessions[i]) for i in range(n)]
        for fut in as_completed(futs):
            http, code, bucket = fut.result()
            codes[http] += 1
            if http == 429:
                key = bucket or code or "unknown"
                if isinstance(key, str) and key.startswith("sess:"):
                    key = "sess:*"
                buckets[str(key)] += 1
                if len(samples) < 10:
                    samples.append({"http": http, "code": code, "bucket": bucket})
    return {"n": n, "path": path, "http": dict(codes), "buckets_429": dict(buckets), "samples": samples}


def main() -> int:
    from services.hostile_hardening_config import get_hostile_hardening_config

    sessions = pickle.loads(SESSIONS.read_bytes())
    cfg = get_hostile_hardening_config()
    analysis = {
        "generated_at": utc(),
        "sessions_available": len(sessions),
        "config_relevant": {
            "http_flood_nat_dashboard_per_ip_per_10s": cfg.get("http_flood_nat_dashboard_per_ip_per_10s"),
            "http_flood_session_dashboard_per_10s": cfg.get("http_flood_session_dashboard_per_10s"),
            "http_flood_per_ip_per_10s": cfg.get("http_flood_per_ip_per_10s"),
            "user_dashboard_read_rate_limit_per_minute": cfg.get("user_dashboard_read_rate_limit_per_minute"),
            "adaptive_rate_multiplier": cfg.get("adaptive_rate_multiplier"),
            "load_shedding": cfg.get("load_shedding"),
        },
        "interpretation_notes": [
            "Dashboard authed GETs use sess:* + ip-nat:* buckets (not raw ip:80).",
            "NAT dashboard default 5000/10s — a single synchronized 2000-wave should NOT trip NAT alone.",
            "Phase2 warm_ok=56/2000 suggests residual circuit/flood state or invalid sessions, not necessarily NAT ceiling.",
            "Raising NAT limits only to pass a localhost multi-session bench would weaken shared-IP protection — forbidden unless evidenced as misconfiguration.",
        ],
        "bursts": [],
    }

    print("reset", reset(), flush=True)
    time.sleep(2)
    for n in (100, 600, 1000, 1200, 1500, 2000):
        if len(sessions) < n:
            analysis["bursts"].append({"n": n, "status": "NOT_TESTED", "reason": "insufficient_sessions"})
            continue
        print(f"burst n={n}", flush=True)
        reset()
        time.sleep(2)
        rec = burst(sessions, n)
        analysis["bursts"].append(rec)
        print(json.dumps({"n": n, "http": rec["http"], "buckets": rec["buckets_429"]}, indent=2), flush=True)
        time.sleep(5)

    # Classify
    sat = None
    for b in analysis["bursts"]:
        if b.get("http", {}).get(429, 0) > 0 and sat is None:
            sat = b["n"]
    analysis["first_burst_with_429"] = sat
    analysis["conclusion"] = (
        "LEGITIMATE_PROTECTION_OR_STATE"
        if sat
        else "NO_429_IN_BURST_UP_TO_MAX_TESTED"
    )

    OUT.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"out": str(OUT), "first_429_at": sat}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
