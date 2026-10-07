#!/usr/bin/env python3
"""
Transporte HTTP peer-to-peer del Swarm Mesh (sin broker central obligatorio).
TLS 1.3 cuando el peer expone HTTPS; HTTP permitido solo en lab local.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


def push_envelope(*, base_url: str, envelope: Dict[str, Any], timeout: float = 15.0) -> Dict[str, Any]:
    try:
        from services.web_security_auth_enterprise.ssrf_guard import is_url_safe

        safe, reason = is_url_safe(base_url)
        if not safe:
            return {"ok": False, "error": "ssrf_blocked", "reason": reason}
    except Exception as exc:
        return {"ok": False, "error": "ssrf_guard_error", "reason": str(exc)[:80]}
    url = base_url.rstrip("/") + "/api/swarm-mesh/ingest"
    data = json.dumps(envelope).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "X-Novus-Mesh": "1"},
        method="POST",
    )
    ctx = None
    if url.startswith("https://"):
        ctx = ssl.create_default_context()
        # Prefer TLS 1.2+ (1.3 when negotiated by peer)
        if hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read()[:4000]
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            parsed = json.loads(body.decode("utf-8", errors="ignore") or "{}")
            return {
                "ok": bool(parsed.get("ok")),
                "status": getattr(resp, "status", 200),
                "latency_ms": latency_ms,
                "response": parsed,
                "tls": url.startswith("https://"),
            }
    except urllib.error.HTTPError as e:
        body = e.read()[:1500] if hasattr(e, "read") else b""
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        try:
            parsed = json.loads(body.decode("utf-8", errors="ignore") or "{}")
        except Exception:
            parsed = {"raw": body[:200].decode("utf-8", errors="ignore")}
        return {"ok": False, "status": e.code, "latency_ms": latency_ms, "response": parsed, "error": str(e)}
    except Exception as exc:
        return {"ok": False, "status": None, "error": str(exc)[:200], "latency_ms": round((time.perf_counter() - t0) * 1000.0, 2)}


def fetch_peer_identity(base_url: str, timeout: float = 5.0) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/api/swarm-mesh/identity"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200]}
