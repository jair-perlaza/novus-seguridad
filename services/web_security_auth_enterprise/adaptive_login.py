"""
T9 — Login adaptativo (APE + MFA step-up). No bloquea salvo riesgo crítico.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from utils.logger import logger


def evaluate_adaptive_login(
    *,
    user_email: str,
    ip: str,
    user_agent: str,
    fingerprint: dict,
    risk: dict,
    mfa_enabled: bool,
) -> Dict[str, Any]:
    """
    Decide step-up MFA / monitoreo. No bloqueo automático salvo critical.
    """
    score = int((risk or {}).get("score") or 0)
    level = str((risk or {}).get("level") or "info")
    require_mfa = False
    increase_monitoring = False
    block = False
    reasons = []

    if score >= 35 or level in ("medium", "high", "critical"):
        if mfa_enabled:
            require_mfa = True
            reasons.append("risk_requires_mfa_stepup")
        else:
            increase_monitoring = True
            reasons.append("risk_without_mfa_increase_monitoring")

    if score >= 60:
        increase_monitoring = True
        reasons.append("high_risk_monitoring")

    if score >= 85 and level == "critical":
        # Solo bloquear en critical extremo (p.ej. muchos fallos + mfa skip)
        factors = {f.get("factor") for f in (risk.get("factors") or [])}
        if "failed_attempts" in factors and "mfa_skipped" in factors:
            block = True
            reasons.append("critical_multi_indicator_block")

    # APE observe (learnable baseline signals only)
    try:
        from services.adaptive_profile_engine import observe_async

        observe_async(
            user_email,
            event_type="login_adaptive",
            evidence={
                "learnable": score < 50,
                "ip": ip,
                "fingerprint": (fingerprint or {}).get("fingerprint_sha256"),
                "risk_score": score,
                "risk_level": level,
                "user_agent_present": bool(user_agent),
            },
            risk_level=level if score >= 35 else "info",
            evaluate=score >= 35,
        )
    except Exception as exc:
        logger.debug("adaptive login ape: %s", exc)

    return {
        "require_mfa": require_mfa,
        "increase_monitoring": increase_monitoring,
        "block": block,
        "reasons": reasons,
        "risk": risk,
        "verified": True,
    }
