"""
DNS del host — parseo estructurado (Windows netsh). Sin stdout crudo en UI/API cliente.
"""
from __future__ import annotations

import platform
import re
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from utils.network_identity import UNAVAILABLE

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_IFACE_HDR = re.compile(
    r'(?:Configuraci[oó]n|Configuration)\s+(?:para|for)\s+(?:la\s+)?(?:interfaz|interface)\s+"([^"]+)"',
    re.I,
)
_NONE_TOKENS = frozenset({"ninguno", "none", "n/a", ""})
_RAW_OS_MARKERS = (
    "configuraci",
    "configuration for interface",
    "servidores dns configurados",
    "dns servers configured",
    "registrar con el sufijo",
    "register with suffix",
    "traceback",
    "exception",
)


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _looks_like_raw_os_text(text: str) -> bool:
    low = (text or "").lower()
    return any(m in low for m in _RAW_OS_MARKERS)


def parse_netsh_dns_output(text: str, *, preferred_interface: Optional[str] = None) -> List[Dict[str, Any]]:
    """Parsea salida de `netsh interface ip show dns` (ES/EN)."""
    blocks: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _IFACE_HDR.match(line)
        if m:
            current = {"interface": m.group(1), "servers": [], "method": None}
            blocks.append(current)
            continue
        if current is None:
            continue
        low = line.lower()
        if "dns" not in low:
            continue
        if "dhcp" in low:
            current["method"] = "dhcp"
        elif "estátic" in low or "static" in low:
            current["method"] = "static"
        elif current.get("method") is None:
            current["method"] = "unknown"
        if ":" in line:
            tail = line.split(":", 1)[-1].strip()
        else:
            tail = ""
        if tail.lower() in _NONE_TOKENS:
            continue
        for ip in _IP_RE.findall(tail):
            if ip not in current["servers"]:
                current["servers"].append(ip)
    if preferred_interface:
        hit = next((b for b in blocks if b.get("interface") == preferred_interface), None)
        if hit:
            return [hit]
    wifi = next(
        (b for b in blocks if b.get("interface") and ("wi-fi" in b["interface"].lower() or "wifi" in b["interface"].lower())),
        None,
    )
    if wifi:
        return [wifi]
    with_servers = next((b for b in blocks if b.get("servers")), None)
    if with_servers:
        return [with_servers]
    return blocks[:1] if blocks else []


def _pick_block(blocks: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    return blocks[0] if blocks else None


def build_dns_payload(
    *,
    servers: List[str],
    interface: Optional[str],
    method: Optional[str],
    source: str,
    available: bool,
    data_freshness: str = "LIVE",
    observed_at: Optional[str] = None,
) -> Dict[str, Any]:
    obs = observed_at or _utc()
    display = ", ".join(servers) if servers else "DNS no disponible"
    return {
        "available": bool(available and servers),
        "servers": list(servers),
        "interface": interface or UNAVAILABLE,
        "method": method,
        "source": source,
        "timestamp": obs,
        "observed_at_utc": obs,
        "data_freshness": data_freshness,
        "display": display if servers else "DNS no disponible",
        "data_origin": "live_os_query",
    }


def _decode_netsh_output(stdout: bytes, stderr: bytes) -> str:
    raw = (stdout or b"") + (stderr or b"")
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            text = raw.decode(enc)
            if parse_netsh_dns_output(text):
                return text
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def get_live_dns_info(*, preferred_interface: Optional[str] = None) -> Dict[str, Any]:
    """Consulta netsh y devuelve estructura normalizada — sin raw_excerpt."""
    if platform.system().lower() != "windows":
        return build_dns_payload(
            servers=[],
            interface=preferred_interface,
            method=None,
            source="unsupported_platform",
            available=False,
        )
    try:
        proc = subprocess.run(
            ["netsh", "interface", "ip", "show", "dns"],
            capture_output=True,
            timeout=12,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        text = _decode_netsh_output(proc.stdout or b"", proc.stderr or b"")
        blocks = parse_netsh_dns_output(text, preferred_interface=preferred_interface)
        block = _pick_block(blocks)
        if not block or not block.get("servers"):
            return build_dns_payload(
                servers=[],
                interface=(block or {}).get("interface") or preferred_interface,
                method=(block or {}).get("method"),
                source="netsh interface ip show dns",
                available=proc.returncode == 0,
            )
        return build_dns_payload(
            servers=block["servers"],
            interface=block.get("interface"),
            method=block.get("method"),
            source="netsh interface ip show dns",
            available=True,
        )
    except Exception:
        return build_dns_payload(
            servers=[],
            interface=preferred_interface,
            method=None,
            source="netsh interface ip show dns",
            available=False,
        )


def normalize_dns_value(value: Any, *, preferred_interface: Optional[str] = None) -> Dict[str, Any]:
    """
    Normaliza cualquier valor DNS persistido/cacheado a estructura cliente.
    Nunca expone raw_excerpt ni texto OS crudo.
    """
    if value is None or value == "" or value == UNAVAILABLE:
        return get_live_dns_info(preferred_interface=preferred_interface)

    if isinstance(value, str):
        if _looks_like_raw_os_text(value):
            blocks = parse_netsh_dns_output(value, preferred_interface=preferred_interface)
            block = _pick_block(blocks)
            if block and block.get("servers"):
                return build_dns_payload(
                    servers=block["servers"],
                    interface=block.get("interface"),
                    method=block.get("method"),
                    source="netsh interface ip show dns (parsed_cache)",
                    available=True,
                    data_freshness="CACHED",
                )
            return build_dns_payload(
                servers=[],
                interface=preferred_interface,
                method=None,
                source="netsh interface ip show dns",
                available=False,
                data_freshness="STALE",
            )
        ips = _IP_RE.findall(value)
        if ips:
            return build_dns_payload(
                servers=ips,
                interface=preferred_interface,
                method=None,
                source="normalized_string",
                available=True,
                data_freshness="CACHED",
            )
        if value.strip().lower() in ("dns no disponible", "sin datos disponibles"):
            return get_live_dns_info(preferred_interface=preferred_interface)
        return get_live_dns_info(preferred_interface=preferred_interface)

    if isinstance(value, dict):
        if value.get("servers") and isinstance(value["servers"], list):
            servers = [str(s) for s in value["servers"] if _IP_RE.fullmatch(str(s).strip())]
            if servers:
                return build_dns_payload(
                    servers=servers,
                    interface=value.get("interface") or preferred_interface,
                    method=value.get("method"),
                    source=value.get("source") or "normalized_dict",
                    available=value.get("available", True),
                    data_freshness=value.get("data_freshness") or "CACHED",
                    observed_at=value.get("timestamp") or value.get("observed_at_utc"),
                )
        raw = value.get("raw_excerpt")
        if raw and isinstance(raw, str):
            blocks = parse_netsh_dns_output(raw, preferred_interface=preferred_interface or value.get("interface"))
            block = _pick_block(blocks)
            if block and block.get("servers"):
                return build_dns_payload(
                    servers=block["servers"],
                    interface=block.get("interface"),
                    method=block.get("method"),
                    source="netsh interface ip show dns (parsed_legacy)",
                    available=True,
                    data_freshness="CACHED",
                )
        if value.get("display") and not _looks_like_raw_os_text(str(value.get("display"))):
            ips = _IP_RE.findall(str(value.get("display")))
            if ips:
                return build_dns_payload(
                    servers=ips,
                    interface=value.get("interface") or preferred_interface,
                    method=value.get("method"),
                    source=value.get("source") or "normalized_display",
                    available=True,
                    data_freshness=value.get("data_freshness") or "CACHED",
                )
        return get_live_dns_info(preferred_interface=preferred_interface or value.get("interface"))

    return get_live_dns_info(preferred_interface=preferred_interface)


def dns_display(value: Any, *, preferred_interface: Optional[str] = None) -> str:
    return normalize_dns_value(value, preferred_interface=preferred_interface).get("display") or "DNS no disponible"


def client_dns_struct(value: Any, *, preferred_interface: Optional[str] = None) -> Dict[str, Any]:
    """Estructura segura para API/UI — sin campos raw."""
    n = normalize_dns_value(value, preferred_interface=preferred_interface)
    return {k: v for k, v in n.items() if k != "raw_excerpt"}


_CLIENT_CONTEXT_STRIP = frozenset({
    "raw_excerpt",
    "dns_audit_note",
    "error",
    "scan_cache",
})


def sanitize_network_context_for_client(ctx: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Elimina stdout crudo y normaliza DNS antes de enviar a UI/API."""
    if not isinstance(ctx, dict):
        return {}
    out: Dict[str, Any] = {}
    iface = ctx.get("interface") or ctx.get("adapter")
    for key, val in ctx.items():
        if key in _CLIENT_CONTEXT_STRIP:
            continue
        if key == "dns_servers":
            out["dns"] = client_dns_struct(val, preferred_interface=iface)
            continue
        if isinstance(val, str) and _looks_like_raw_os_text(val):
            out[key] = UNAVAILABLE
            continue
        out[key] = val
    if "dns" not in out:
        out["dns"] = client_dns_struct(ctx.get("dns_servers") or ctx.get("dns"), preferred_interface=iface)
    return out


def sanitize_identification_for_client(idn: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(idn, dict):
        return {}
    out = dict(idn)
    iface = out.get("connection_type") or out.get("interface")
    dns_norm = normalize_dns_value(out.get("dns") or out.get("dns_servers"), preferred_interface=iface)
    out["dns"] = dns_norm.get("display") or "DNS no disponible"
    out["dns_structured"] = client_dns_struct(dns_norm)
    out.pop("raw_excerpt", None)
    for k, v in list(out.items()):
        if isinstance(v, str) and _looks_like_raw_os_text(v):
            out[k] = UNAVAILABLE
    return out
