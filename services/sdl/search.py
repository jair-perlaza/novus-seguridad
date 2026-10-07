#!/usr/bin/env python3
"""Busqueda SIEM del Security Data Lake — filtros combinados sobre indices."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from services.sdl.limitations import NA
from services.sdl.store import search_sql, log_query


def _parse_since(days: Optional[int] = None, since: Optional[str] = None) -> Optional[str]:
    if since:
        return since
    if days is not None:
        dt = datetime.now(timezone.utc) - timedelta(days=int(days))
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def search(
    *,
    q: Optional[str] = None,
    engine: Optional[str] = None,
    record_type: Optional[str] = None,
    asset: Optional[str] = None,
    user_ref: Optional[str] = None,
    ioc: Optional[str] = None,
    cve: Optional[str] = None,
    mitre: Optional[str] = None,
    campaign: Optional[str] = None,
    malware: Optional[str] = None,
    ransomware: Optional[str] = None,
    apt: Optional[str] = None,
    incident_id: Optional[str] = None,
    playbook_id: Optional[str] = None,
    risk: Optional[str] = None,
    client_ref: Optional[str] = None,
    device: Optional[str] = None,
    network: Optional[str] = None,
    server_ref: Optional[str] = None,
    endpoint_ref: Optional[str] = None,
    branch: Optional[str] = None,
    severity: Optional[str] = None,
    days: Optional[int] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    where: List[str] = []
    params: List[Any] = []

    def eq(col, val):
        if val is None or val == "":
            return
        where.append(f"{col} = ?")
        params.append(val)

    def like(col, val):
        if val is None or val == "":
            return
        where.append(f"{col} LIKE ?")
        params.append(f"%{val}%")

    eq("engine", engine)
    eq("record_type", record_type)
    like("asset", asset)
    like("user_ref", user_ref)
    like("ioc", ioc)
    like("cve", cve)
    like("mitre", mitre)
    like("campaign", campaign)
    like("malware", malware)
    like("ransomware", ransomware)
    like("apt", apt)
    like("incident_id", incident_id)
    like("playbook_id", playbook_id)
    like("risk", risk)
    like("client_ref", client_ref)
    like("device", device)
    like("network", network)
    like("server_ref", server_ref)
    like("endpoint_ref", endpoint_ref)
    like("branch", branch)
    like("severity", severity)

    since_ts = _parse_since(days, since)
    if since_ts:
        where.append("timestamp_utc >= ?")
        params.append(since_ts)
    if until:
        where.append("timestamp_utc <= ?")
        params.append(until)

    if q:
        # free-text across key columns + payload
        where.append(
            "(uuid LIKE ? OR asset LIKE ? OR user_ref LIKE ? OR ioc LIKE ? OR cve LIKE ? "
            "OR mitre LIKE ? OR malware LIKE ? OR ransomware LIKE ? OR apt LIKE ? "
            "OR incident_id LIKE ? OR playbook_id LIKE ? OR campaign LIKE ? OR payload_json LIKE ? "
            "OR severity LIKE ? OR engine LIKE ? OR record_type LIKE ?)"
        )
        like_q = f"%{q}%"
        params.extend([like_q] * 16)

    rows, total = search_sql(where, params, limit=min(max(1, limit), 1000), offset=max(0, offset))
    # Strip nothing — return real rows; mark NA fields already stored as NA
    result = {
        "ok": True,
        "total": total,
        "count": len(rows),
        "limit": limit,
        "offset": offset,
        "filters": {
            "q": q, "engine": engine, "record_type": record_type, "asset": asset,
            "user_ref": user_ref, "ioc": ioc, "cve": cve, "mitre": mitre,
            "days": days, "since": since_ts, "severity": severity,
            "ransomware": ransomware, "malware": malware, "apt": apt,
            "incident_id": incident_id, "playbook_id": playbook_id,
        },
        "records": rows,
        "invented": False,
        "message": NA if total == 0 else None,
    }
    log_query({"filters": result["filters"], "total": total, "count": len(rows)})
    return result


def correlate(keys: Dict[str, Any], limit: int = 100) -> Dict[str, Any]:
    """Correlacion historica: une por IOC/CVE/asset/usuario/incidente reales."""
    buckets = {}
    for field in ("ioc", "cve", "asset", "user_ref", "incident_id", "malware", "mitre"):
        val = keys.get(field)
        if not val:
            continue
        r = search(**{field: val, "limit": limit})
        buckets[field] = {"value": val, "total": r["total"], "records": r["records"]}
    if not buckets:
        return {"ok": True, "correlated": {}, "message": NA, "invented": False}
    return {"ok": True, "correlated": buckets, "invented": False}
