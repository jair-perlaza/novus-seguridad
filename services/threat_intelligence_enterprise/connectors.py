#!/usr/bin/env python3
"""
Conectores modulares de Threat Intelligence externa.
Cada conector es independiente; agregar/eliminar sin tocar Kernel.
Sin datos estáticos, sin listas falsas, sin feeds simulados.
Si no hay conexión → "NO DISPONIBLE".
"""
from __future__ import annotations

import hashlib
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

from services.threat_intelligence_enterprise.store import NA, store_feed_result, store_ioc
from utils.logger import logger

TIMEOUT = int(os.environ.get("NOVUS_TI_TIMEOUT", "10"))


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _has_internet() -> bool:
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3).close()
        return True
    except OSError:
        return False


def _safe_get(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = TIMEOUT) -> Optional[Dict[str, Any]]:
    try:
        import requests

        r = requests.get(url, headers=headers or {}, timeout=timeout)
        if r.status_code == 200:
            return r.json()
        return {"_error": f"HTTP {r.status_code}", "_url": url}
    except Exception as exc:
        return {"_error": str(exc)[:300], "_url": url}


# ────────────────────────────────────────────────────────────
# CONECTOR: abuse.ch URLhaus (gratuito, sin API key)
# ────────────────────────────────────────────────────────────
def fetch_urlhaus_recent(limit: int = 25) -> Dict[str, Any]:
    t0 = time.perf_counter()
    if not _has_internet():
        return {"connector": "urlhaus", "status": NA, "reason": "sin_conexion", "iocs": []}
    try:
        import requests

        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data={"limit": str(limit)},
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return {"connector": "urlhaus", "status": NA, "reason": f"HTTP {r.status_code}", "iocs": []}
        data = r.json()
        urls = data.get("urls") or []
        iocs: List[Dict[str, Any]] = []
        for u in urls[:limit]:
            ioc = {
                "type": "url",
                "value": u.get("url"),
                "threat_type": u.get("threat") or u.get("url_status"),
                "tags": u.get("tags") or [],
                "source": "urlhaus",
                "first_seen": u.get("date_added"),
                "last_seen": u.get("last_online"),
                "confidence": 0.7 if u.get("url_status") == "online" else 0.5,
                "country": u.get("country"),
                "reporter": u.get("reporter"),
                "fetched_at_utc": _utc(),
                "invented": False,
            }
            iocs.append(ioc)
            store_ioc(ioc)
        result = {
            "connector": "urlhaus",
            "status": "ok",
            "iocs_fetched": len(iocs),
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "fetched_at_utc": _utc(),
        }
        store_feed_result(result)
        return {**result, "iocs": iocs}
    except Exception as exc:
        return {"connector": "urlhaus", "status": NA, "reason": str(exc)[:300], "iocs": []}


# ────────────────────────────────────────────────────────────
# CONECTOR: abuse.ch Feodo Tracker (botnet C2, gratuito)
# ────────────────────────────────────────────────────────────
def fetch_feodo_tracker(limit: int = 25) -> Dict[str, Any]:
    t0 = time.perf_counter()
    if not _has_internet():
        return {"connector": "feodo_tracker", "status": NA, "reason": "sin_conexion", "iocs": []}
    try:
        import requests

        r = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return {"connector": "feodo_tracker", "status": NA, "reason": f"HTTP {r.status_code}", "iocs": []}
        entries = r.json() if isinstance(r.json(), list) else []
        iocs: List[Dict[str, Any]] = []
        for e in entries[:limit]:
            ioc = {
                "type": "ip",
                "value": e.get("ip_address") or e.get("dst_ip"),
                "threat_type": "botnet_c2",
                "malware_family": e.get("malware") or NA,
                "port": e.get("dst_port") or e.get("port"),
                "source": "feodo_tracker",
                "first_seen": e.get("first_seen"),
                "last_seen": e.get("last_online"),
                "confidence": 0.85,
                "country": e.get("country"),
                "asn": e.get("as_number"),
                "as_name": e.get("as_name"),
                "fetched_at_utc": _utc(),
                "invented": False,
            }
            iocs.append(ioc)
            store_ioc(ioc)
        result = {
            "connector": "feodo_tracker",
            "status": "ok",
            "iocs_fetched": len(iocs),
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "fetched_at_utc": _utc(),
        }
        store_feed_result(result)
        return {**result, "iocs": iocs}
    except Exception as exc:
        return {"connector": "feodo_tracker", "status": NA, "reason": str(exc)[:300], "iocs": []}


# ────────────────────────────────────────────────────────────
# CONECTOR: abuse.ch ThreatFox (IOC gratuito — malware/botnets)
# ────────────────────────────────────────────────────────────
def fetch_threatfox_recent(limit: int = 25) -> Dict[str, Any]:
    t0 = time.perf_counter()
    if not _has_internet():
        return {"connector": "threatfox", "status": NA, "reason": "sin_conexion", "iocs": []}
    try:
        import requests

        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return {"connector": "threatfox", "status": NA, "reason": f"HTTP {r.status_code}", "iocs": []}
        data = r.json()
        entries = data.get("data") or []
        if not isinstance(entries, list):
            entries = []
        iocs: List[Dict[str, Any]] = []
        for e in entries[:limit]:
            ioc_type = str(e.get("ioc_type") or "").lower()
            if "ip" in ioc_type:
                typ = "ip"
            elif "domain" in ioc_type:
                typ = "domain"
            elif "url" in ioc_type:
                typ = "url"
            elif "hash" in ioc_type or "md5" in ioc_type or "sha" in ioc_type:
                typ = "hash"
            else:
                typ = ioc_type or "unknown"
            ioc = {
                "type": typ,
                "value": e.get("ioc"),
                "threat_type": e.get("threat_type") or e.get("malware"),
                "malware_family": (e.get("malware_printable") or e.get("malware") or NA),
                "tags": e.get("tags") or [],
                "source": "threatfox",
                "first_seen": e.get("first_seen_utc"),
                "last_seen": e.get("last_seen_utc"),
                "confidence": min(1.0, (e.get("confidence_level") or 50) / 100.0),
                "reporter": e.get("reporter"),
                "reference": e.get("reference"),
                "mitre_attack": e.get("malware_malpedia"),
                "fetched_at_utc": _utc(),
                "invented": False,
            }
            iocs.append(ioc)
            store_ioc(ioc)
        result = {
            "connector": "threatfox",
            "status": "ok",
            "iocs_fetched": len(iocs),
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
        }
        store_feed_result(result)
        return {**result, "iocs": iocs}
    except Exception as exc:
        return {"connector": "threatfox", "status": NA, "reason": str(exc)[:300], "iocs": []}


# ────────────────────────────────────────────────────────────
# CONECTOR: abuse.ch MalwareBazaar (hashes de malware, gratuito)
# ────────────────────────────────────────────────────────────
def fetch_malwarebazaar_recent(limit: int = 20) -> Dict[str, Any]:
    t0 = time.perf_counter()
    if not _has_internet():
        return {"connector": "malwarebazaar", "status": NA, "reason": "sin_conexion", "iocs": []}
    try:
        import requests

        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": "time"},
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return {"connector": "malwarebazaar", "status": NA, "reason": f"HTTP {r.status_code}", "iocs": []}
        data = r.json()
        entries = data.get("data") or []
        if not isinstance(entries, list):
            entries = []
        iocs: List[Dict[str, Any]] = []
        for e in entries[:limit]:
            ioc = {
                "type": "hash",
                "value": e.get("sha256_hash") or e.get("md5_hash"),
                "md5": e.get("md5_hash"),
                "sha256": e.get("sha256_hash"),
                "sha1": e.get("sha1_hash"),
                "threat_type": "malware",
                "malware_family": e.get("signature") or NA,
                "tags": e.get("tags") or [],
                "source": "malwarebazaar",
                "file_type": e.get("file_type"),
                "file_size": e.get("file_size"),
                "first_seen": e.get("first_seen"),
                "country": e.get("origin_country"),
                "confidence": 0.9,
                "reporter": e.get("reporter"),
                "fetched_at_utc": _utc(),
                "invented": False,
            }
            iocs.append(ioc)
            store_ioc(ioc)
        result = {
            "connector": "malwarebazaar",
            "status": "ok",
            "iocs_fetched": len(iocs),
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
        }
        store_feed_result(result)
        return {**result, "iocs": iocs}
    except Exception as exc:
        return {"connector": "malwarebazaar", "status": NA, "reason": str(exc)[:300], "iocs": []}


# ────────────────────────────────────────────────────────────
# CONECTOR: VirusTotal (requiere API key)
# ────────────────────────────────────────────────────────────
def lookup_virustotal(indicator: str, indicator_type: str = "hash") -> Dict[str, Any]:
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
    if not vt_key:
        return {"connector": "virustotal", "status": NA, "reason": "API_KEY_NO_CONFIGURADA", "indicator": indicator}
    if not _has_internet():
        return {"connector": "virustotal", "status": NA, "reason": "sin_conexion", "indicator": indicator}
    try:
        import requests

        type_map = {"hash": "files", "ip": "ip_addresses", "domain": "domains", "url": "urls"}
        endpoint = type_map.get(indicator_type, "files")
        val = indicator
        if indicator_type == "url":
            val = hashlib.sha256(indicator.encode()).hexdigest()
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{quote_plus(val)}"
        r = requests.get(url, headers={"x-apikey": vt_key}, timeout=TIMEOUT)
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats") or {}
            result = {
                "connector": "virustotal",
                "status": "ok",
                "indicator": indicator,
                "indicator_type": indicator_type,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation"),
                "tags": attrs.get("tags") or [],
                "last_analysis_date": attrs.get("last_analysis_date"),
                "country": attrs.get("country"),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "fetched_at_utc": _utc(),
                "invented": False,
            }
            store_ioc({
                "type": indicator_type,
                "value": indicator,
                "source": "virustotal",
                "malicious": result["malicious"],
                "confidence": min(1.0, (result["malicious"] or 0) / max(1, (result["malicious"] or 0) + (result["harmless"] or 1))),
                "fetched_at_utc": _utc(),
                "invented": False,
            })
            return result
        return {"connector": "virustotal", "status": NA, "reason": f"HTTP {r.status_code}", "indicator": indicator}
    except Exception as exc:
        return {"connector": "virustotal", "status": NA, "reason": str(exc)[:300], "indicator": indicator}


# ────────────────────────────────────────────────────────────
# Registro de conectores — agregar/eliminar sin tocar Kernel
# ────────────────────────────────────────────────────────────
FEED_CONNECTORS = {
    "urlhaus": fetch_urlhaus_recent,
    "feodo_tracker": fetch_feodo_tracker,
    "threatfox": fetch_threatfox_recent,
    "malwarebazaar": fetch_malwarebazaar_recent,
}

LOOKUP_CONNECTORS = {
    "virustotal": lookup_virustotal,
}

ALL_CONNECTORS = list(FEED_CONNECTORS.keys()) + list(LOOKUP_CONNECTORS.keys())


def fetch_all_feeds(limit_per_feed: int = 20) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    total_iocs = 0
    for name, fn in FEED_CONNECTORS.items():
        try:
            r = fn(limit=limit_per_feed)
            results[name] = {k: v for k, v in r.items() if k != "iocs"}
            results[name]["iocs_count"] = len(r.get("iocs") or [])
            total_iocs += results[name]["iocs_count"]
        except Exception as exc:
            results[name] = {"status": NA, "reason": str(exc)[:300]}
    return {
        "fetched_at_utc": _utc(),
        "connectors": results,
        "total_iocs": total_iocs,
        "internet_available": _has_internet(),
        "invented": False,
    }


def enrich_indicator(indicator: str, indicator_type: str = "hash") -> Dict[str, Any]:
    results: Dict[str, Any] = {"indicator": indicator, "type": indicator_type, "sources": {}}
    for name, fn in LOOKUP_CONNECTORS.items():
        try:
            results["sources"][name] = fn(indicator, indicator_type)
        except Exception as exc:
            results["sources"][name] = {"status": NA, "reason": str(exc)[:300]}
    # Also check local IOC store
    iocs = store_ioc.__module__  # just to import
    from services.threat_intelligence_enterprise.store import load_iocs
    local = [i for i in load_iocs(limit=1000) if i.get("value") == indicator]
    results["local_matches"] = len(local)
    results["local_hits"] = local[:5]
    results["fetched_at_utc"] = _utc()
    results["invented"] = False
    return results
