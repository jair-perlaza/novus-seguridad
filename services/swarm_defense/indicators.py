"""
Extracción de indicadores reales desde eventos de defensa (sin inventar IOCs).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def extract_indicators(event_payload: Dict[str, Any]) -> Dict[str, List[str]]:
    """Solo extrae lo presente en el payload/evidencia. Listas vacías si no hay dato."""
    evidence = event_payload.get("evidence") if isinstance(event_payload.get("evidence"), dict) else {}
    blobs: List[str] = []
    for key in ("detail", "threat_type", "action", "finding_id", "motor"):
        val = event_payload.get(key)
        if val:
            blobs.append(str(val))
    for key, val in evidence.items():
        if val is None:
            continue
        if isinstance(val, (str, int, float)):
            blobs.append(f"{key}={val}")
        elif isinstance(val, (list, tuple)):
            blobs.extend(str(x) for x in val[:50])
        elif isinstance(val, dict):
            blobs.append(str(val)[:2000])

    text = "\n".join(blobs)
    ips: Set[str] = set(_IPV4.findall(text))
    domains: Set[str] = set(d.lower() for d in _DOMAIN.findall(text) if "." in d)
    # Filtrar dominios que son IPs mal parseadas / extensiones comunes de archivo
    domains = {d for d in domains if not _IPV4.fullmatch(d) and not d.endswith((".exe", ".dll", ".bat"))}
    urls = set(_URL.findall(text))
    sha256 = set(_SHA256.findall(text))
    md5 = set(_MD5.findall(text))
    cves = set(c.upper() for c in _CVE.findall(text))

    # Campos estructurados tienen prioridad
    for key in ("ip", "src_ip", "dst_ip", "remote_ip", "attacker_ip"):
        v = evidence.get(key) or event_payload.get(key)
        if v and _IPV4.fullmatch(str(v).strip()):
            ips.add(str(v).strip())
    for key in ("domain", "host", "hostname"):
        v = evidence.get(key)
        if v:
            domains.add(str(v).strip().lower())
    for key in ("url", "uri"):
        v = evidence.get(key)
        if v:
            urls.add(str(v).strip())
    for key in ("sha256", "hash", "file_hash"):
        v = evidence.get(key)
        if v and (_SHA256.fullmatch(str(v)) or _MD5.fullmatch(str(v))):
            (sha256 if len(str(v)) == 64 else md5).add(str(v))
    if evidence.get("cve"):
        cves.add(str(evidence["cve"]).upper())

    pid = evidence.get("pid") or evidence.get("process_id")
    process_name = evidence.get("process") or evidence.get("process_name") or evidence.get("image")

    return {
        "ips": sorted(ips)[:20],
        "domains": sorted(domains)[:20],
        "urls": sorted(urls)[:20],
        "sha256": sorted(sha256)[:20],
        "md5": sorted(md5)[:20],
        "cves": sorted(cves)[:20],
        "pids": [str(pid)] if pid is not None else [],
        "processes": [str(process_name)] if process_name else [],
    }


def correlation_keys(indicators: Dict[str, List[str]], event_payload: Dict[str, Any]) -> List[str]:
    keys: List[str] = []
    fid = event_payload.get("finding_id")
    if fid:
        keys.append(f"finding:{fid}")
    for ip in indicators.get("ips") or []:
        keys.append(f"ip:{ip}")
    for d in indicators.get("domains") or []:
        keys.append(f"domain:{d}")
    for h in indicators.get("sha256") or []:
        keys.append(f"sha256:{h}")
    for h in indicators.get("md5") or []:
        keys.append(f"md5:{h}")
    for c in indicators.get("cves") or []:
        keys.append(f"cve:{c}")
    return keys[:40]
