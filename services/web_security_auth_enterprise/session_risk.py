"""
T10 — Risk Score por sesión (sin RNG).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional


def compute_session_risk(
    *,
    ip: Optional[str] = None,
    fingerprint_known: bool = True,
    new_device: bool = False,
    hour_utc: Optional[int] = None,
    failed_attempts_15m: int = 0,
    ape_unusual: bool = False,
    mfa_passed: bool = False,
    mfa_required_but_skipped: bool = False,
    duplicate_sessions: int = 0,
    swarm_signal: bool = False,
) -> Dict[str, Any]:
    score = 0
    factors = []

    if new_device:
        score += 18
        factors.append({"factor": "new_device", "weight": 18})
    if not fingerprint_known and fingerprint_known is False:
        score += 8
        factors.append({"factor": "unknown_fingerprint", "weight": 8})

    h = hour_utc if hour_utc is not None else datetime.now(timezone.utc).hour
    if h < 5 or h >= 23:
        score += 10
        factors.append({"factor": "off_hours_utc", "weight": 10, "hour": h})

    if failed_attempts_15m >= 5:
        score += 20
        factors.append({"factor": "failed_attempts", "weight": 20, "n": failed_attempts_15m})
    elif failed_attempts_15m >= 2:
        score += 8
        factors.append({"factor": "failed_attempts", "weight": 8, "n": failed_attempts_15m})

    if ape_unusual:
        score += 15
        factors.append({"factor": "ape_unusual", "weight": 15})

    if mfa_required_but_skipped:
        score += 25
        factors.append({"factor": "mfa_skipped", "weight": 25})
    if mfa_passed:
        score = max(0, score - 12)
        factors.append({"factor": "mfa_passed_discount", "weight": -12})

    if duplicate_sessions >= 2:
        score += 10
        factors.append({"factor": "duplicate_sessions", "weight": 10, "n": duplicate_sessions})

    if swarm_signal:
        score += 12
        factors.append({"factor": "swarm_signal", "weight": 12})

    if ip and (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.")):
        score = max(0, score - 5)
        factors.append({"factor": "private_ip_discount", "weight": -5})

    score = max(0, min(100, int(score)))
    level = (
        "critical"
        if score >= 80
        else "high"
        if score >= 60
        else "medium"
        if score >= 35
        else "low"
        if score >= 15
        else "info"
    )
    return {
        "score": score,
        "level": level,
        "factors": factors,
        "basis": "pesos fijos por señales verificables — sin RNG",
        "verified": True,
    }
