"""Login pipeline WSAE: fingerprint + risk + adaptive + session + forense."""
from __future__ import annotations

from typing import Any, Dict, Optional

from utils.logger import logger


def enrich_successful_login(user, *, route: str = "login", mfa_passed: bool = False) -> Dict[str, Any]:
    """
    Llamar tras login_user + open_login_session (o integrar desde finalize).
    """
    from flask import has_request_context, request, session
    from core.security import get_client_ip
    from services.web_security_auth_enterprise.device_fingerprint import (
        compute_device_fingerprint,
        ip_to_prefix,
    )
    from services.web_security_auth_enterprise.session_risk import compute_session_risk
    from services.web_security_auth_enterprise.adaptive_login import evaluate_adaptive_login
    from services.web_security_auth_enterprise.session_manager import register_session
    from services.web_security_auth_enterprise.mfa_totp import is_mfa_enabled
    from services.web_security_auth_enterprise.publish import publish_wsae, seal_wsae
    from services.login_session_audit_service import count_recent_failed_attempts
    from datetime import datetime, timezone

    ip = get_client_ip() if has_request_context() else "unknown"
    ua = request.headers.get("User-Agent", "") if has_request_context() else ""
    lang = request.headers.get("Accept-Language", "") if has_request_context() else ""
    fp = compute_device_fingerprint(user_agent=ua, accept_language=lang, ip_prefix=ip_to_prefix(ip))
    fails = count_recent_failed_attempts(user.email, ip)
    mfa_on = is_mfa_enabled(user.email)

    # known device? compare to session store later — first login = new
    new_device = True
    try:
        from services.web_security_auth_enterprise.session_manager import list_active_sessions

        for s in list_active_sessions(user.email):
            if s.get("fingerprint") == fp.get("fingerprint_sha256"):
                new_device = False
                break
    except Exception:
        pass

    risk = compute_session_risk(
        ip=ip,
        fingerprint_known=not new_device,
        new_device=new_device,
        hour_utc=datetime.now(timezone.utc).hour,
        failed_attempts_15m=fails,
        ape_unusual=False,
        mfa_passed=mfa_passed,
        mfa_required_but_skipped=False,
        duplicate_sessions=0,
    )

    zero_trust = {}
    try:
        from core.network_tracker import evaluate_login_zero_trust
        is_admin = bool(getattr(user, "is_admin", False) or getattr(user, "rol", "") in (
            "admin", "administrador", "ciso", "cto", "superadmin",
        ))
        zero_trust = evaluate_login_zero_trust(
            user=str(getattr(user, "nombre", user.email)),
            is_admin=is_admin,
            origin_ip=ip,
            user_agent=ua,
            email=user.email,
        )
        zt_score = int(zero_trust.get("risk_score") or 0)
        if zt_score > 0:
            merged = int(risk.get("score") or 0) + min(25, zt_score // 2)
            risk["score"] = min(100, merged)
            risk.setdefault("factors", []).append({
                "factor": "zero_trust_network",
                "weight": min(25, zt_score // 2),
                "detail": zero_trust.get("reasons"),
            })
            lvl = risk["score"]
            risk["level"] = (
                "critical" if lvl >= 80 else "high" if lvl >= 60 else "medium"
                if lvl >= 35 else "low" if lvl >= 15 else "info"
            )
    except Exception as exc:
        logger.debug("zero_trust login eval: %s", exc)
    adaptive = evaluate_adaptive_login(
        user_email=user.email,
        ip=ip,
        user_agent=ua,
        fingerprint=fp,
        risk=risk,
        mfa_enabled=mfa_on,
    )
    sid = session.get("_novus_login_session_id") if has_request_context() else None
    sess_reg = {}
    if sid:
        sess_reg = register_session(
            session_id=str(sid),
            user_email=user.email,
            ip=ip,
            fingerprint=fp.get("fingerprint_sha256"),
            risk=risk,
        )
        if has_request_context():
            session["_wsae_refresh_token"] = sess_reg.get("refresh_token")
            session["_wsae_device_fp"] = fp.get("fingerprint_sha256")
            session["_wsae_session_risk"] = risk
            session.modified = True

    fid = f"WSAE-LOGIN-{sid or 'na'}-{abs(hash(user.email + ip)) % 10**10}"
    evidence = {
        "user_email": user.email,
        "ip": ip,
        "route": route,
        "fingerprint": fp,
        "risk": risk,
        "adaptive": adaptive,
        "session": {"session_id": sid, "duplicates": sess_reg.get("duplicate_sessions")},
        "mfa_enabled": mfa_on,
        "mfa_passed": mfa_passed,
        "zero_trust": zero_trust,
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    try:
        publish_wsae(
            action="wsae_login_enriched",
            evidence=evidence,
            threat_type="auth_login",
            finding_id=fid,
            risk_level=str(risk.get("level") or "info"),
            user_email=user.email if int(risk.get("score") or 0) < 50 else None,
        )
        seal_wsae(finding_id=fid, action="wsae_login_enriched", evidence=evidence, risk_level=str(risk.get("level") or "info"))
    except Exception as exc:
        logger.debug("wsae login publish: %s", exc)

    return {
        "fingerprint": fp,
        "risk": risk,
        "adaptive": adaptive,
        "session_registration": sess_reg,
        "forensic_id": fid,
    }
