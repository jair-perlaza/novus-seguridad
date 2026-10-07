#!/usr/bin/env python3
"""
Identity Engine — descubre identidades y observa telemetría real.
NO inventa identidades ni actividad.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from services.identity_intelligence.limitations import NA
from services.identity_intelligence.store import (
    load_identities, save_identities, new_uuid, save_observation, ensure_dir,
)


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _upsert_identity(bucket: Dict[str, Any], key: str, itype: str, label: str, attrs: Dict[str, Any]) -> str:
    identities = bucket.setdefault("identities", {})
    # Find existing by natural key
    for iid, rec in identities.items():
        if rec.get("type") == itype and rec.get("natural_key") == key:
            rec["label"] = label or rec.get("label")
            rec["attrs"] = {**(rec.get("attrs") or {}), **{k: v for k, v in attrs.items() if v not in (None, "", NA)}}
            rec["last_seen_utc"] = _utc()
            rec["observation_count"] = int(rec.get("observation_count") or 0) + 1
            return iid
    iid = new_uuid()
    identities[iid] = {
        "uuid": iid,
        "type": itype,
        "natural_key": key,
        "label": label or key,
        "attrs": attrs,
        "first_seen_utc": _utc(),
        "last_seen_utc": _utc(),
        "observation_count": 1,
        "invented": False,
    }
    return iid


def collect_observations() -> Dict[str, Any]:
    """Recolecta observaciones reales de fuentes NOVUS (solo lectura)."""
    ensure_dir()
    bucket = load_identities()
    observations: List[Dict[str, Any]] = []
    sources_ok = {}
    sources_na = {}

    # 1) Login sessions -> user identities
    try:
        from services.login_session_audit_service import list_login_sessions
        from services.tenant_scope_service import get_platform_tenant_id

        sessions = list_login_sessions(limit=100, tenant_id=get_platform_tenant_id())
        sources_ok["login_sessions"] = len(sessions)
        for s in sessions:
            email = s.get("user_email")
            if not email:
                continue
            uid = _upsert_identity(bucket, f"user:{email}", "usuario", email, {
                "user_id": s.get("user_id"),
                "last_ip": s.get("ip_address"),
                "os_name": s.get("os_name"),
                "browser": s.get("browser"),
                "device_type": s.get("device_type"),
            })
            obs = {
                "kind": "authentication",
                "identity_uuid": uid,
                "identity_type": "usuario",
                "login_at": s.get("login_at"),
                "logout_at": s.get("logout_at"),
                "duration_seconds": s.get("duration_seconds"),
                "ip": s.get("ip_address"),
                "device_type": s.get("device_type"),
                "os_name": s.get("os_name"),
                "browser": s.get("browser"),
                "session_id": s.get("id") or s.get("session_id"),
                "source": "login_session_audit_service",
                "invented": False,
            }
            observations.append(obs)
            save_observation(obs)
    except Exception as exc:
        sources_na["login_sessions"] = str(exc)[:160]

    # 2) ASM host -> equipo
    try:
        from services.asm.store import load_inventory
        inv = load_inventory() or {}
        host = inv.get("local_host") or {}
        if host:
            key = f"host:{host.get('hostname') or host.get('ip') or 'local'}"
            hid = _upsert_identity(bucket, key, "equipo", host.get("hostname") or key, {
                "ip": host.get("ip"),
                "mac": host.get("mac"),
                "gateway": host.get("gateway"),
                "dns": host.get("dns") or host.get("dns_servers"),
                "os": host.get("os"),
                "classification": host.get("classification"),
            })
            obs = {
                "kind": "host_inventory",
                "identity_uuid": hid,
                "identity_type": "equipo",
                "ip": host.get("ip"),
                "mac": host.get("mac"),
                "gateway": host.get("gateway"),
                "dns": host.get("dns") or host.get("dns_servers"),
                "source": "asm",
                "invented": False,
            }
            observations.append(obs)
            save_observation(obs)
            sources_ok["asm"] = 1
        else:
            sources_na["asm"] = NA
    except Exception as exc:
        sources_na["asm"] = str(exc)[:160]

    # 3) Device connection events
    try:
        from services.device_connection_monitor import list_events
        events = list_events(limit=50)
        sources_ok["device_events"] = len(events)
        for ev in events:
            mac = ev.get("mac") or ev.get("hostname") or ev.get("ip")
            if not mac:
                continue
            did = _upsert_identity(bucket, f"device:{mac}", "equipo", str(mac), {
                "ip": ev.get("ip"), "mac": ev.get("mac"), "hostname": ev.get("hostname"),
            })
            obs = {
                "kind": "device_event",
                "identity_uuid": did,
                "identity_type": "equipo",
                "ip": ev.get("ip"),
                "mac": ev.get("mac"),
                "event": ev.get("event") or ev.get("type"),
                "source": "device_connection_monitor",
                "invented": False,
            }
            observations.append(obs)
            save_observation(obs)
    except Exception as exc:
        sources_na["device_events"] = str(exc)[:160]

    # 4) Live processes (psutil) -> proceso/aplicacion identities
    try:
        import psutil
        procs = []
        for p in psutil.process_iter(["pid", "name", "username", "create_time"]):
            try:
                info = p.info
                name = info.get("name")
                if not name:
                    continue
                procs.append(info)
            except Exception:
                continue
        # Persist only summary counts + unique names (real observation)
        names = sorted({(p.get("name") or "").lower() for p in procs if p.get("name")})
        sources_ok["processes"] = len(names)
        for name in names[:200]:
            pid_key = f"process:{name}"
            prid = _upsert_identity(bucket, pid_key, "proceso_persistente", name, {"name": name})
            # Also as aplicacion label
            _upsert_identity(bucket, f"app:{name}", "aplicacion", name, {"name": name})
            obs = {
                "kind": "process_sighting",
                "identity_uuid": prid,
                "identity_type": "proceso_persistente",
                "process_name": name,
                "source": "psutil",
                "invented": False,
            }
            observations.append(obs)
            save_observation(obs)
    except Exception as exc:
        sources_na["processes"] = str(exc)[:160]

    # 5) Network connections (psutil)
    try:
        import psutil
        conns = []
        for c in psutil.net_connections(kind="inet"):
            try:
                if c.status == "LISTEN" or c.raddr:
                    conns.append({
                        "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                        "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                        "status": c.status,
                    })
            except Exception:
                continue
        sources_ok["network_connections"] = len(conns)
        # Aggregate volume only — store observation of connection count (no invent)
        obs = {
            "kind": "network_snapshot",
            "connection_count": len(conns),
            "sample": conns[:20],
            "source": "psutil.net_connections",
            "invented": False,
        }
        observations.append(obs)
        save_observation(obs)
    except Exception as exc:
        sources_na["network_connections"] = str(exc)[:160]

    # 6) Service accounts — only if Windows services reveal account names (real)
    try:
        import psutil, platform
        if platform.system() == "Windows":
            # username on processes that look like services
            svc_users = set()
            for p in psutil.process_iter(["name", "username"]):
                try:
                    u = (p.info.get("username") or "")
                    if u and ("$" in u or u.lower().startswith("nt ") or "service" in u.lower()):
                        svc_users.add(u)
                except Exception:
                    continue
            sources_ok["service_accounts"] = len(svc_users)
            for u in list(svc_users)[:50]:
                sid = _upsert_identity(bucket, f"svc:{u}", "cuenta_servicio", u, {"username": u})
                obs = {
                    "kind": "service_account_sighting",
                    "identity_uuid": sid,
                    "identity_type": "cuenta_servicio",
                    "username": u,
                    "source": "psutil",
                    "invented": False,
                }
                observations.append(obs)
                save_observation(obs)
        else:
            sources_na["service_accounts"] = NA
    except Exception as exc:
        sources_na["service_accounts"] = str(exc)[:160]

    # 7) Enrichment links from IMCM/SDL (read-only) — relate incidents to users if present
    try:
        from services.imcm import search_incidents
        incs = search_incidents(limit=30)
        sources_ok["imcm"] = len(incs)
        for inc in incs:
            user = inc.get("user")
            if user:
                uid = _upsert_identity(bucket, f"user:{user}", "usuario", str(user), {})
                obs = {
                    "kind": "incident_link",
                    "identity_uuid": uid,
                    "incident_id": inc.get("id"),
                    "severity": inc.get("severity"),
                    "threat_type": inc.get("threat_type"),
                    "source": "imcm",
                    "invented": False,
                }
                observations.append(obs)
                save_observation(obs)
    except Exception as exc:
        sources_na["imcm"] = str(exc)[:160]

    save_identities(bucket)
    return {
        "ok": True,
        "observations": len(observations),
        "identities": len(bucket.get("identities") or {}),
        "sources_ok": sources_ok,
        "sources_na": sources_na,
        "invented": False,
        "timestamp_utc": _utc(),
    }


def list_identities(itype: Optional[str] = None) -> List[Dict[str, Any]]:
    data = load_identities()
    out = list((data.get("identities") or {}).values())
    if itype:
        out = [i for i in out if i.get("type") == itype]
    return out


def get_identity(uuid: str) -> Optional[Dict[str, Any]]:
    return (load_identities().get("identities") or {}).get(uuid)
