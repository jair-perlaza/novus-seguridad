"""
Verificación real de canal TLS (Fase 2).

No simula TLS 1.3. Solo reporta TLS activo cuando:
- el listener local acepta handshake SSL, o
- un endpoint público HTTPS configurado responde con TLS verificable.

Registra evidencia forense del método usado.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
from datetime import datetime
from typing import Any, Dict, Optional

from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_PATH = os.path.join(ROOT, "data", "cryptovault", "tls_channel_evidence.json")


def _save_evidence(payload: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(EVIDENCE_PATH), exist_ok=True)
    payload = dict(payload)
    payload["checked_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(EVIDENCE_PATH, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    try:
        from services.forensic_evidence_integrity_service import seal_evidence

        seal_evidence(
            source_id=f"TLS-{payload['checked_at'].replace(' ', '').replace(':', '')}",
            source_type="tls_channel",
            motor="tls_channel_service",
            evidence_type="tls_probe",
            payload=payload,
        )
    except Exception:
        pass


def probe_local_ssl(host: str = "127.0.0.1", port: Optional[int] = None) -> Dict[str, Any]:
    port = int(port or os.environ.get("PORT", "5000"))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=2.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ver = ssock.version() or ""
                cipher = ssock.cipher()
                return {
                    "ok": True,
                    "method": "local_ssl_handshake",
                    "host": host,
                    "port": port,
                    "tls_version": ver,
                    "cipher": cipher[0] if cipher else None,
                    "tls_1_3": ver == "TLSv1.3",
                }
    except ssl.SSLError as exc:
        return {
            "ok": False,
            "method": "local_ssl_handshake",
            "host": host,
            "port": port,
            "reason": "ssl_error",
            "detail": str(exc)[:200],
        }
    except Exception as exc:
        return {
            "ok": False,
            "method": "local_ssl_handshake",
            "host": host,
            "port": port,
            "reason": "no_tls_listener",
            "detail": str(exc)[:200],
        }


def probe_public_https(url: Optional[str] = None) -> Dict[str, Any]:
    if not url:
        url = (os.environ.get("NOVUS_PUBLIC_URL") or "").rstrip("/")
    if not url:
        # Evidencia de despliegue gestionado (ngrok/cloudflare)
        ra = os.path.join(ROOT, "data", "remote_access.json")
        if os.path.isfile(ra):
            try:
                with open(ra, encoding="utf-8") as fh:
                    info = json.load(fh)
                url = (info.get("public_url") or info.get("proxy_required_env", {}).get("NOVUS_PUBLIC_URL") or "").rstrip("/")
            except Exception:
                url = ""
    if not url.startswith("https://"):
        return {"ok": False, "method": "public_https", "reason": "no_https_public_url"}
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname
        port = int(parsed.port or 443)
        if not host:
            return {"ok": False, "method": "public_https", "reason": "bad_url"}
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ver = ssock.version() or ""
                cipher = ssock.cipher()
                cert = ssock.getpeercert()
                return {
                    "ok": True,
                    "method": "public_https_handshake",
                    "url": url,
                    "host": host,
                    "port": port,
                    "tls_version": ver,
                    "tls_1_3": ver == "TLSv1.3",
                    "cipher": cipher[0] if cipher else None,
                    "certificate_verified": True,
                    "cert_subject": str((cert or {}).get("subject", ""))[:200],
                }
    except Exception as exc:
        return {
            "ok": False,
            "method": "public_https",
            "url": url,
            "reason": "https_probe_failed",
            "detail": str(exc)[:300],
        }


def assess_tls_channel(*, persist: bool = True) -> Dict[str, Any]:
    """
    Evaluación honesta del canal TLS.
    """
    local = probe_local_ssl()
    public = probe_public_https()
    behind = os.environ.get("NOVUS_BEHIND_PROXY", "False").lower() == "true"
    result: Dict[str, Any] = {
        "local": local,
        "public": public,
        "behind_proxy": behind,
        "tls_active": False,
        "tls_1_3_verified": False,
        "status_label": "",
        "evidence_basis": [],
    }
    if local.get("ok"):
        result["tls_active"] = True
        result["tls_1_3_verified"] = bool(local.get("tls_1_3"))
        result["evidence_basis"].append("local_ssl_handshake")
        ver = local.get("tls_version") or "TLS"
        result["status_label"] = f"TLS_VERIFIED_LOCAL {ver}"
        if result["tls_1_3_verified"]:
            result["status_label"] = "TLS_1_3_VERIFIED_LOCAL"
    elif public.get("ok"):
        result["tls_active"] = True
        result["tls_1_3_verified"] = bool(public.get("tls_1_3"))
        result["evidence_basis"].append("public_https_handshake")
        ver = public.get("tls_version") or "TLS"
        if result["tls_1_3_verified"]:
            result["status_label"] = f"TLS_1_3_VERIFIED_PUBLIC {ver}"
        else:
            result["status_label"] = f"TLS_VERIFIED_PUBLIC {ver} (not_1_3)"
    elif behind:
        result["tls_active"] = False
        result["status_label"] = (
            "TLS_NOT_VERIFIED_AT_APP "
            "(behind_proxy_claimed_but_no_local_ssl_and_no_public_https_proof)"
        )
        result["evidence_basis"].append("proxy_claim_without_proof")
    else:
        result["tls_active"] = False
        result["status_label"] = "TLS_NOT_TERMINATED_BY_APP (plaintext_listener)"
        result["evidence_basis"].append("plaintext_local_listener")

    if persist:
        _save_evidence(result)
    return result


def get_tls_status_label() -> str:
    try:
        return assess_tls_channel(persist=True).get("status_label") or "TLS_STATUS_UNKNOWN"
    except Exception as exc:
        logger.debug("tls assess: %s", exc)
        return "TLS_STATUS_ERROR"
