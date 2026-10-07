"""
Sonda TLS real — metadatos is_secure / versión / huella de certificado (sin inventar is_secure=True).
"""
from __future__ import annotations

import hashlib
import os
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def probe_tls_endpoint(
    host: str,
    port: int = 443,
    *,
    timeout: float = 4.0,
    server_hostname: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Handshake TLS real contra host:port.
    is_secure = True solo si el handshake con verificación de certificado tiene éxito.
    """
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "collected_at_utc": _utc(),
        "is_secure": False,
        "tls_version": None,
        "server_cert_pin": None,
        "proxy_chain": [],
        "ok": False,
    }
    sni = server_hostname or host
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                ver = ssock.version()  # e.g. TLSv1.3
                result["tls_version_str"] = ver
                # Map to float for verify_tunnel_integrity compatibility
                if ver and ver.startswith("TLSv"):
                    try:
                        result["tls_version"] = float(ver.replace("TLSv", ""))
                    except ValueError:
                        result["tls_version"] = 1.2 if "1.2" in ver else 1.3
                cert_bin = ssock.getpeercert(binary_form=True)
                if cert_bin:
                    result["server_cert_pin"] = hashlib.sha256(cert_bin).hexdigest()
                result["cipher"] = ssock.cipher()
                result["is_secure"] = True
                result["ok"] = True
    except ssl.SSLCertVerificationError as exc:
        result["ok"] = True  # probe ran; connection not trusted
        result["is_secure"] = False
        result["error"] = f"cert_verify_failed:{exc}"[:240]
        # Retry without verify to still capture version/pin for analysis
        try:
            ctx2 = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=sni) as ssock:
                    ver = ssock.version()
                    result["tls_version_str"] = ver
                    if ver and ver.startswith("TLSv"):
                        try:
                            result["tls_version"] = float(ver.replace("TLSv", ""))
                        except ValueError:
                            result["tls_version"] = 1.2
                    cert_bin = ssock.getpeercert(binary_form=True)
                    if cert_bin:
                        result["server_cert_pin"] = hashlib.sha256(cert_bin).hexdigest()
        except Exception as exc2:
            result["unverified_probe_error"] = str(exc2)[:160]
    except Exception as exc:
        result["error"] = str(exc)[:240]
    return result


def build_tls_connection_metadata(*, targets: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """
    Metadatos TLS para MITM shield.
    - Si NOVUS_EXPECTED_CERT_PIN está definido, sondea NOVUS_TLS_PROBE_HOST (default 1.1.1.1)
      y compara pin real.
    - Si no hay pin esperado, sondea un endpoint público y reporta is_secure real del handshake.
    Nunca fuerza is_secure=True sin handshake exitoso.
    """
    host = os.environ.get("NOVUS_TLS_PROBE_HOST") or "1.1.1.1"
    if targets:
        host = targets[0]
    port = int(os.environ.get("NOVUS_TLS_PROBE_PORT") or "443")
    sni = os.environ.get("NOVUS_TLS_PROBE_SNI") or ("cloudflare-dns.com" if host == "1.1.1.1" else host)

    probe = probe_tls_endpoint(host, port, server_hostname=sni)
    expected = os.environ.get("NOVUS_EXPECTED_CERT_PIN")
    meta = {
        "is_secure": bool(probe.get("is_secure")),
        "tls_version": probe.get("tls_version") or 0.0,
        "server_cert_pin": probe.get("server_cert_pin"),
        "proxy_chain": [],
        "probe_host": host,
        "probe_ok": probe.get("ok"),
        "tls_version_str": probe.get("tls_version_str"),
        "collected_at_utc": probe.get("collected_at_utc"),
        "source": "network_endpoint_enterprise.tls_probe",
    }
    if expected:
        meta["expected_cert_pin"] = expected
        # Pin mismatch is evaluated by verify_tunnel_integrity
    if probe.get("error"):
        meta["probe_error"] = probe["error"]
    return meta
