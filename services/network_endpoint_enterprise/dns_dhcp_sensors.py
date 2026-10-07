"""
Sensores DNS (caché del cliente) y DHCP rogue — datos reales del host/OS.
"""
from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "network_endpoint_enterprise"
DNS_CACHE_PATH = DATA_DIR / "dns_cache_snapshot.json"
DHCP_BASELINE_PATH = DATA_DIR / "dhcp_baseline.json"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def inspect_dns_client_cache() -> Dict[str, Any]:
    """
    Inspección DNS en vuelo vía caché del cliente Windows (respuestas reales vistas por el SO).
    No inventa registros; si la caché está vacía lo reporta.
    """
    result: Dict[str, Any] = {
        "collected_at_utc": _utc(),
        "source": "Get-DnsClientCache",
        "entries": [],
        "ok": False,
    }
    if platform.system() != "Windows":
        result["error"] = "dns_cache_windows_only"
        return result
    try:
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-DnsClientCache | Select-Object Entry,Name,Type,Data,TTL,Status | "
                    "ConvertTo-Json -Compress"
                ),
            ],
            timeout=15,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        raw = (out or "").strip()
        if not raw:
            result["ok"] = True
            result["entries"] = []
            result["note"] = "dns_cache_empty"
            return result
        data = json.loads(raw)
        rows = data if isinstance(data, list) else [data]
        entries = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            entries.append(
                {
                    "entry": r.get("Entry") or r.get("Name"),
                    "name": r.get("Name"),
                    "type": r.get("Type"),
                    "data": r.get("Data"),
                    "ttl": r.get("TTL"),
                    "status": r.get("Status"),
                }
            )
        result["entries"] = entries[:500]
        result["count"] = len(entries)
        result["ok"] = True
    except Exception as exc:
        result["error"] = str(exc)[:240]
        logger.debug("dns cache inspect: %s", exc)
    return result


def diff_dns_cache(prev: Optional[Dict[str, Any]], cur: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not prev or not cur.get("ok"):
        return []
    prev_keys = {
        (e.get("name"), e.get("type"), e.get("data"))
        for e in (prev.get("entries") or [])
        if e.get("data")
    }
    cur_keys = {
        (e.get("name"), e.get("type"), e.get("data"))
        for e in (cur.get("entries") or [])
        if e.get("data")
    }
    added = list(cur_keys - prev_keys)[:40]
    removed = list(prev_keys - cur_keys)[:40]
    changes = []
    if added:
        changes.append(
            {
                "change_type": "dns_resolution_new",
                "added": [{"name": a[0], "type": a[1], "data": a[2]} for a in added],
                "detected_at_utc": _utc(),
            }
        )
    if removed:
        changes.append(
            {
                "change_type": "dns_resolution_expired",
                "removed": [{"name": a[0], "type": a[1], "data": a[2]} for a in removed],
                "detected_at_utc": _utc(),
            }
        )
    return changes


def snapshot_dns_cache() -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    prev = None
    if DNS_CACHE_PATH.is_file():
        try:
            prev = json.loads(DNS_CACHE_PATH.read_text(encoding="utf-8"))
        except Exception:
            prev = None
    cur = inspect_dns_client_cache()
    changes = diff_dns_cache(prev, cur)
    if cur.get("ok"):
        DNS_CACHE_PATH.write_text(json.dumps(cur, indent=2, ensure_ascii=False), encoding="utf-8")
    return cur, changes


def analyze_dhcp_servers(current_servers: List[str], gateway: Optional[str] = None) -> Dict[str, Any]:
    """
    Analizador rogue DHCP: compara servidores DHCP observados vs baseline del host.
    Marca como sospechoso un servidor nuevo no visto en baseline y distinto del gateway histórico.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    baseline: Dict[str, Any] = {"known_servers": [], "first_seen": {}, "last_seen": {}}
    if DHCP_BASELINE_PATH.is_file():
        try:
            baseline = json.loads(DHCP_BASELINE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass

    known = set(baseline.get("known_servers") or [])
    now = _utc()
    alerts: List[Dict[str, Any]] = []
    observed = [s for s in (current_servers or []) if s]

    for srv in observed:
        baseline.setdefault("last_seen", {})[srv] = now
        if srv not in known:
            if known:
                # Solo alerta si ya había baseline (no en primer arranque)
                alerts.append(
                    {
                        "alert_id": f"ROGUE-DHCP-{hashlib.sha256(srv.encode()).hexdigest()[:10]}",
                        "type": "unexpected_dhcp_server",
                        "dhcp_server": srv,
                        "gateway": gateway,
                        "known_servers": sorted(known),
                        "severity": "high",
                        "evidence": "Nuevo DHCPServer en Win32_NetworkAdapterConfiguration no presente en baseline",
                        "verified": True,
                    }
                )
            known.add(srv)
            baseline.setdefault("first_seen", {})[srv] = now

    baseline["known_servers"] = sorted(known)
    baseline["updated_at_utc"] = now
    DHCP_BASELINE_PATH.write_text(json.dumps(baseline, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "ok": True,
        "observed_servers": observed,
        "known_servers": sorted(known),
        "alerts": alerts,
        "source": "Win32_NetworkAdapterConfiguration+baseline",
    }
