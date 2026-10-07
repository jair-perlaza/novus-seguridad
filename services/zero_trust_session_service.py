"""Zero Trust — puntuación de riesgo de sesión/dispositivo desde eventos reales."""
from __future__ import annotations

from typing import Any, Dict, Optional

from services.auth_protection_service import build_device_fingerprint, is_origin_blocked


def evaluate_session_risk(
    *,
    ip: str,
    user_agent: Optional[str] = None,
    email: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    fp = build_device_fingerprint(user_agent, ip)
    block = is_origin_blocked(ip, fp, session_id)
    score = 0
    factors = []
    if block.get("blocked"):
        score = 100
        factors.append({"factor": "origin_blocked", "detail": block.get("reason")})
    else:
        try:
            from database import SessionLocal, AuthAccessEvent
            from datetime import datetime, timedelta
            since = (datetime.now() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
            db = SessionLocal()
            try:
                fails = db.query(AuthAccessEvent).filter(
                    AuthAccessEvent.ip_address == ip,
                    AuthAccessEvent.success.is_(False),
                    AuthAccessEvent.timestamp >= since,
                ).count()
                if fails >= 3:
                    score += min(60, fails * 10)
                    factors.append({"factor": "recent_auth_failures", "count": fails})
            finally:
                db.close()
        except Exception:
            pass
    level = "bajo"
    if score >= 80:
        level = "critico"
    elif score >= 50:
        level = "alto"
    elif score >= 25:
        level = "medio"
    return {
        "risk_score": score,
        "risk_level": level,
        "device_fingerprint": fp,
        "factors": factors,
        "continuous_verification": score >= 50,
        "verified": True,
    }
