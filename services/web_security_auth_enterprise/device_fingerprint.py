"""
T8 — Device fingerprint técnico (no identificador absoluto).
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional


def compute_device_fingerprint(
    *,
    user_agent: Optional[str] = None,
    accept_language: Optional[str] = None,
    ip_prefix: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Huella débil basada en UA + idioma + /24 de IP.
    Nunca tratar como ID único absoluto.
    """
    ua = (user_agent or "").strip()
    lang = (accept_language or "").strip()[:80]
    ipp = (ip_prefix or "").strip()
    raw = f"ua={ua}|lang={lang}|ipp={ipp}"
    digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
    return {
        "fingerprint_sha256": digest,
        "components": {
            "user_agent_present": bool(ua),
            "accept_language_present": bool(lang),
            "ip_prefix": ipp or None,
        },
        "absolute_unique": False,
        "note": "Señal de riesgo/dispositivo nuevo — no identidad única",
        "verified": True,
    }


def ip_to_prefix(ip: Optional[str]) -> str:
    ip = (ip or "").strip()
    if not ip or ip.count(".") != 3:
        return ""
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24"
