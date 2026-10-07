"""Bloqueo de dominio real vía Web Shield blacklist (sin simulación)."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+[a-z]?$",
    re.I,
)


def normalize_domain(domain: str) -> Optional[str]:
    d = (domain or "").strip().lower().rstrip(".")
    if d.startswith("http://") or d.startswith("https://"):
        from urllib.parse import urlparse

        d = (urlparse(d).hostname or "").lower()
    if not d or not _DOMAIN_RE.match(d):
        return None
    return d


def block_domain(domain: str, *, reason: str = "", actor: str = "swarm") -> Dict[str, Any]:
    """Añade dominio a blacklist_domains de Web Shield (persistente)."""
    d = normalize_domain(domain)
    if not d:
        return {"ok": False, "status": "invalid_domain", "domain": domain}
    from services.web_shield_config import load_web_shield_config, save_web_shield_config

    cfg = load_web_shield_config()
    bl = list(cfg.get("blacklist_domains") or [])
    if d not in bl:
        bl.append(d)
        save_web_shield_config({"blacklist_domains": bl})
    return {
        "ok": True,
        "status": "executed",
        "domain": d,
        "blacklist_size": len(bl),
        "motor": "web_shield_config",
        "reason": reason,
        "actor": actor,
    }


def is_domain_blocked(domain: str) -> bool:
    d = normalize_domain(domain)
    if not d:
        return False
    from services.web_shield_config import load_web_shield_config

    bl = [x.lower() for x in (load_web_shield_config().get("blacklist_domains") or [])]
    return d in bl or any(d.endswith("." + b) for b in bl)
