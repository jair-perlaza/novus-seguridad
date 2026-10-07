#!/usr/bin/env python3
"""
NOVUS Final Reality Audit — READ ONLY.
Probes authenticated HTTP, captures RAM, traces recovery — no code changes.
"""
from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil
import pyotp
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_release_candidate"
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")


def utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def pid():
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            return c.pid
    return None


def snap(label: str) -> dict:
    from services.resource_backpressure_service import get_status

    s = {"label": label, "ts": utc(), "ram_pct": round(psutil.virtual_memory().percent, 1)}
    p = pid()
    if p:
        pr = psutil.Process(p)
        s["rss_mb"] = round(pr.memory_info().rss / (1024 * 1024), 1)
        s["threads"] = pr.num_threads()
    bp = get_status()
    s["backpressure"] = bp.get("level")
    return s


def login(s: requests.Session) -> dict:
    r = s.get(BASE + "/login", timeout=60)
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text).group(1)
    r1 = s.post(BASE + "/login", data={"email": QA[0], "password": QA[1], "csrf_token": csrf}, timeout=90)
    csrf2 = re.search(r'name="csrf_token"\s+value="([^"]+)"', r1.text).group(1)
    from services.web_security_auth_enterprise.mfa_totp import _dec, _load

    code = pyotp.TOTP(_dec(_load()[QA[0]]["secret_enc"])).now()
    r2 = s.post(
        BASE + "/login",
        data={"email": QA[0], "password": QA[1], "csrf_token": csrf2, "mfa_code": code},
        timeout=120,
        allow_redirects=False,
    )
    return {"status": r2.status_code, "location": r2.headers.get("Location")}


def probe(s: requests.Session, path: str, label: str) -> dict:
    before = snap(f"before_{label}")
    t0 = time.perf_counter()
    r = s.get(BASE + path, timeout=120)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    after = snap(f"after_{label}")
    body = {}
    try:
        body = r.json()
    except Exception:
        pass
    rec = bool(r.headers.get("X-Novus-Recovery") or body.get("_novusRecovery"))
    return {
        "label": label,
        "path": path,
        "http_status": r.status_code,
        "original_status": r.headers.get("X-Novus-Original-Status"),
        "recovery": rec,
        "latency_ms": ms,
        "before": before,
        "after": after,
        "body_preview": _preview(path, body),
    }


def _preview(path: str, body: dict) -> dict:
    if not isinstance(body, dict):
        return {"raw_len": len(str(body))}
    if "summary" in path or "dashboard/live" in path:
        return {
            k: body.get(k)
            for k in ("status", "data_status", "total_threats", "counters", "live", "stale")
            if k in body
        }
    if "network" in path:
        nodes = body.get("nodes") or body.get("data", {}).get("nodes") if isinstance(body.get("data"), dict) else body.get("nodes")
        if nodes is None and isinstance(body.get("data"), list):
            nodes = body["data"]
        return {
            "status": body.get("status"),
            "node_count": len(nodes) if isinstance(nodes, list) else body.get("count"),
            "sample_ips": [n.get("ip") for n in (nodes or [])[:5] if isinstance(n, dict)],
            "discovery_method": body.get("discovery_method") or body.get("source"),
            "stale": body.get("stale") or body.get("data_status"),
        }
    if "threats" in path:
        t = body.get("threats") or body.get("data") or body.get("suspicious_processes")
        return {"status": body.get("status"), "count": len(t) if isinstance(t, list) else body.get("count"), "keys": list(body.keys())[:12]}
    if "vulnerabilit" in path:
        v = body.get("vulnerabilities") or body.get("data") or body.get("findings")
        return {"status": body.get("status"), "count": len(v) if isinstance(v, list) else body.get("count"), "sample_ids": [x.get("id") for x in (v or [])[:3] if isinstance(x, dict)]}
    if "reports" in path:
        r = body.get("reports")
        return {"status": body.get("status"), "count": body.get("count"), "sample_ids": [x.get("id") for x in (r or [])[:3] if isinstance(x, dict)]}
    if "search" in path:
        return {"status": body.get("status"), "count": body.get("count"), "query_echo": body.get("q")}
    if "health" in path:
        return {k: body.get(k) for k in ("ok", "engine", "orchestrator", "status") if k in body}
    return {"status": body.get("status"), "keys": list(body.keys())[:15]}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    s = requests.Session()
    report = {
        "generated_at": utc(),
        "audit_id": "NOVUS_FINAL_REALITY_AUDIT_LIVE",
        "mode": "READ_ONLY",
        "boot": snap("boot"),
    }
    time.sleep(2)
    report["t90s"] = snap("t90s") if False else snap("post_wait")
    report["login"] = login(s)
    report["login_snap"] = snap("post_login")

    steps = [
        ("/dashboard", "dashboard_html"),
        ("/api/dashboard/live", "dashboard_live"),
        ("/api/security/summary", "security_summary"),
        ("/api/network/nodes?trigger_discovery=false", "network_nodes"),
        ("/api/network/info", "network_info"),
        ("/api/security/threats", "threats"),
        ("/api/security/vulnerabilities", "vulnerabilities"),
        ("/api/security/endpoints", "endpoints"),
        ("/api/reports", "reports"),
        ("/api/search?q=alert", "search"),
        ("/api/health/status", "health"),
    ]
    report["probes"] = []
    for path, label in steps:
        report["probes"].append(probe(s, path, label))
        time.sleep(2)
    report["final"] = snap("final")

    out_path = OUT / "NOVUS_FINAL_REALITY_AUDIT_LIVE.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"written": str(out_path), "probes": len(report["probes"])}, indent=2))
    for p in report["probes"]:
        print(p["label"], p["http_status"], "recovery", p["recovery"], p.get("body_preview"))


if __name__ == "__main__":
    main()
