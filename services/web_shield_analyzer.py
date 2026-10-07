"""Análisis verificable de URLs, TLS y dominios — NOVUS Web Shield."""
from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from utils.logger import logger

# Marcas frecuentes para heurística typosquatting (distancia de edición, no reputación externa)
_TYPOSQUAT_TARGETS = (
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "facebook.com", "instagram.com", "linkedin.com", "github.com", "office.com",
    "live.com", "outlook.com", "yahoo.com", "netflix.com", "whatsapp.com",
)

_SUSPICIOUS_TLD = (".zip", ".mov", ".click", ".top", ".xyz", ".ru", ".cn", ".tk")
_IP_HOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def _domain_from_url(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower().strip(".")
        return host or None
    except Exception:
        return None


def _punycode_homograph_risk(domain: str) -> Tuple[int, List[str]]:
    reasons: List[str] = []
    score = 0
    if domain.startswith("xn--"):
        score += 25
        reasons.append("Dominio Punycode (posible homógrafo)")
    if any(ord(c) > 127 for c in domain):
        score += 30
        reasons.append("Caracteres no ASCII en el dominio")
    return score, reasons


def _typosquat_risk(domain: str) -> Tuple[int, List[str]]:
    reasons: List[str] = []
    score = 0
    base = domain.lower()
    if base in _TYPOSQUAT_TARGETS:
        return 0, reasons
    for legit in _TYPOSQUAT_TARGETS:
        d = _levenshtein(base, legit)
        if 0 < d <= 2:
            score = max(score, 35 - d * 5)
            reasons.append(f"Similitud con {legit} (distancia {d})")
    return score, reasons


def _url_pattern_risk(url: str, domain: str) -> Tuple[int, List[str]]:
    reasons: List[str] = []
    score = 0
    if len(url) > 2000:
        score += 15
        reasons.append("URL excesivamente larga")
    if url.count("@") > 0:
        score += 25
        reasons.append("Carácter @ en URL (posible ofuscación)")
    if _IP_HOST.match(domain):
        score += 20
        reasons.append("Host es dirección IP directa")
    if domain.count(".") >= 4:
        score += 10
        reasons.append("Subdominios anómalos")
    for tld in _SUSPICIOUS_TLD:
        if domain.endswith(tld):
            score += 15
            reasons.append(f"TLD de alto abuso frecuente ({tld})")
    if re.search(r"(login|signin|verify|secure|account|bank|wallet)", url.lower()) and score < 40:
        score += 10
        reasons.append("Patrones frecuentes en phishing en la ruta")
    if url.lower().startswith("javascript:") or "data:text/html" in url.lower():
        score += 35
        reasons.append("Esquema javascript/data en URL")
    if re.search(r"\.(zip|rar|7z|iso|img|apk|dmg)(/|\?|$)", url.lower()):
        score += 12
        reasons.append("Enlace directo a archivo comprimido o instalador")
    if re.search(r"\.(js|vbs|wsf|hta)(\?|$)", url.lower()) and "github" not in domain:
        score += 18
        reasons.append("Recurso script ejecutable en URL")
    return score, reasons


def inspect_tls_certificate(domain: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """Verificación TLS real vía socket — sin APIs de reputación externas."""
    result: Dict[str, Any] = {
        "checked": False,
        "https_available": False,
        "cert_valid": None,
        "cert_expired": None,
        "cert_subject": None,
        "cert_issuer": None,
        "not_after": None,
        "error": None,
    }
    if not domain or _IP_HOST.match(domain):
        result["error"] = "Sin nombre de host válido para TLS"
        return result
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["checked"] = True
                result["https_available"] = True
                result["cert_subject"] = dict(x[0] for x in cert.get("subject", ()))
                result["cert_issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                not_after = cert.get("notAfter")
                result["not_after"] = not_after
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    result["cert_expired"] = exp < now
                    result["cert_valid"] = not result["cert_expired"]
                    if result["cert_expired"]:
                        result["tls_risk"] = 40
                    else:
                        result["tls_risk"] = 0
    except ssl.SSLCertVerificationError as exc:
        result["checked"] = True
        result["https_available"] = True
        result["cert_valid"] = False
        result["error"] = str(exc)
        result["tls_risk"] = 50
    except Exception as exc:
        result["error"] = str(exc)
        if "timed out" in str(exc).lower():
            result["tls_risk"] = 5
        else:
            result["tls_risk"] = 15
    return result


def analyze_url(
    url: str,
    *,
    whitelist: Optional[List[str]] = None,
    blacklist: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Calcula riesgo 0–100 con evidencia técnica verificable.
    """
    whitelist = [d.lower() for d in (whitelist or [])]
    blacklist = [d.lower() for d in (blacklist or [])]
    domain = _domain_from_url(url) or ""
    reasons: List[str] = []
    score = 0

    if not domain:
        return {
            "url": url,
            "domain": None,
            "risk_score": 100,
            "risk_level": "critico",
            "reasons": ["URL o dominio no parseable"],
            "tls": {},
            "domain_age": "Información no disponible",
            "source": "web_shield_analyzer",
        }

    # Defense-in-depth: block private/metadata destinations before any TLS connect.
    try:
        from services.web_security_auth_enterprise.ssrf_guard import is_url_safe

        safe, reason = is_url_safe(url)
        if not safe:
            return {
                "url": url,
                "domain": domain,
                "risk_score": 100,
                "risk_level": "critico",
                "reasons": [f"SSRF guard blocked: {reason}"],
                "tls": {},
                "domain_age": "Información no disponible",
                "source": "web_shield_analyzer",
                "ssrf_blocked": True,
            }
    except Exception:
        pass

    if domain in whitelist or any(domain.endswith("." + w) for w in whitelist):
        return {
            "url": url,
            "domain": domain,
            "risk_score": 0,
            "risk_level": "bajo",
            "reasons": ["Lista blanca local"],
            "tls": inspect_tls_certificate(domain),
            "domain_age": "Información no disponible",
            "policy": "allowlist",
            "source": "web_shield_analyzer",
        }

    if domain in blacklist or any(domain.endswith("." + b) for b in blacklist):
        return {
            "url": url,
            "domain": domain,
            "risk_score": 100,
            "risk_level": "critico",
            "reasons": ["Lista negra local"],
            "tls": {},
            "domain_age": "Información no disponible",
            "policy": "blocklist",
            "source": "web_shield_analyzer",
        }

    for fn in (_punycode_homograph_risk, _typosquat_risk):
        s, r = fn(domain)
        score += s
        reasons.extend(r)

    s2, r2 = _url_pattern_risk(url, domain)
    score += s2
    reasons.extend(r2)

    tls = inspect_tls_certificate(domain)
    score += int(tls.get("tls_risk") or 0)
    if tls.get("cert_expired"):
        reasons.append("Certificado TLS expirado")
    if tls.get("cert_valid") is False and tls.get("checked"):
        reasons.append("Certificado TLS no confiable o inválido")
    if not tls.get("https_available") and tls.get("checked"):
        reasons.append("Fallo al negociar HTTPS")

    score = max(0, min(100, score))
    if score >= 75:
        level = "critico"
    elif score >= 50:
        level = "alto"
    elif score >= 25:
        level = "medio"
    else:
        level = "bajo"

    return {
        "url": url,
        "domain": domain,
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons or ["Sin señales heurísticas adicionales"],
        "tls": tls,
        "domain_age": "Información no disponible",
        "source": "web_shield_analyzer",
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
