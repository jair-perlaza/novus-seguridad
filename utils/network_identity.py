"""
Identificación de red local — solo datos observables (sin inventar SSID, ISP, etc.).
"""
from __future__ import annotations

import json
import platform
import re
import subprocess
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

UNAVAILABLE = "Información no disponible mediante análisis local."


def _run_netsh(args: list, timeout: int = 8) -> Optional[str]:
    if platform.system() != "Windows":
        return None
    try:
        flags = 0x08000000  # CREATE_NO_WINDOW
        r = subprocess.run(
            ["netsh", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=flags,
        )
        out = (r.stdout or "").strip()
        return out if out and r.returncode == 0 else None
    except Exception:
        return None


def get_wifi_association() -> Dict[str, Any]:
    """
    SSID / BSSID / cifrado vía netsh en Windows.
    En Ethernet o sin WLAN activa devuelve campos con UNAVAILABLE o null explícito.
    """
    result: Dict[str, Any] = {
        "ssid": None,
        "bssid": None,
        "encryption_type": None,
        "connection_medium": None,
        "source": None,
        "note": None,
    }
    if platform.system() != "Windows":
        result["note"] = UNAVAILABLE
        return result

    text = _run_netsh(["wlan", "show", "interfaces"])
    if not text:
        result["note"] = UNAVAILABLE
        return result

    result["source"] = "netsh wlan show interfaces"
    ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    bssid = re.search(r"^\s*BSSID\s*:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    auth = re.search(r"^\s*Authentication\s*:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    cipher = re.search(r"^\s*Cipher\s*:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    state = re.search(r"^\s*State\s*:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)

    if ssid:
        name = ssid.group(1).strip()
        if name and name.lower() not in ("", "n/a"):
            result["ssid"] = name
    if bssid:
        mac = bssid.group(1).strip()
        if mac and mac.lower() not in ("", "n/a", "not connected"):
            result["bssid"] = mac

    parts = []
    if auth:
        parts.append(auth.group(1).strip())
    if cipher:
        parts.append(cipher.group(1).strip())
    if parts:
        result["encryption_type"] = " / ".join(parts)

    st = (state.group(1).strip().lower() if state else "")
    if "connected" in st:
        result["connection_medium"] = "Wi-Fi"
    elif result.get("ssid"):
        result["connection_medium"] = "Wi-Fi"
    else:
        result["connection_medium"] = None
        if not result.get("ssid"):
            result["note"] = UNAVAILABLE

    return result


def fetch_public_ip_and_isp(*, timeout_sec: float = 4.0) -> Dict[str, Any]:
    """
    IP pública e ISP solo si hay consulta externa exitosa (ip-api.com, sin clave).
    Si falla la red o la API, no se inventan valores.
    """
    out: Dict[str, Any] = {
        "public_ip": None,
        "isp": None,
        "source": None,
        "note": UNAVAILABLE,
    }
    url = "http://ip-api.com/json/?fields=status,query,isp,org"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NOVUS-NetworkHistory/1.0"})
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        if data.get("status") != "success":
            return out
        out["public_ip"] = data.get("query")
        isp = data.get("isp") or data.get("org")
        if isp:
            out["isp"] = str(isp)[:200]
        out["source"] = "ip-api.com (consulta externa en login/análisis)"
        out["note"] = None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        pass
    return out
