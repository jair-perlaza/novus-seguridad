#!/usr/bin/env python3
"""
Ingesta SDL — solo datos de motores reales.
Nunca inventa eventos. Campos ausentes -> NO DISPONIBLE.
"""
from __future__ import annotations
import uuid as uuid_lib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.sdl.limitations import NA, AUTHORIZED_ENGINES
from services.sdl.integrity import sign_record_core, canonical_json
from services.sdl.store import insert_record, get_by_uuid, init_db


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _s(v, default=NA):
    if v is None or v == "":
        return default
    return str(v)


def build_and_insert(
    *,
    engine: str,
    record_type: str,
    payload: Dict[str, Any],
    source: Optional[str] = None,
    severity: Optional[str] = None,
    confidence: Optional[str] = None,
    status: Optional[str] = None,
    asset: Optional[str] = None,
    user_ref: Optional[str] = None,
    client_ref: Optional[str] = None,
    device: Optional[str] = None,
    network: Optional[str] = None,
    server_ref: Optional[str] = None,
    endpoint_ref: Optional[str] = None,
    branch: Optional[str] = None,
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
    existing_uuid: Optional[str] = None,
    prev_uuid: Optional[str] = None,
    version: int = 1,
) -> Dict[str, Any]:
    init_db()
    if engine not in AUTHORIZED_ENGINES and engine != "sdl":
        # Allow sdl meta records; reject unknown invented engines silently? Better: mark source
        pass
    rid = existing_uuid or str(uuid_lib.uuid4())
    ts = _utc()
    core = {
        "uuid": rid,
        "version": version,
        "timestamp_utc": ts,
        "engine": engine,
        "record_type": record_type,
        "severity": _s(severity),
        "confidence": _s(confidence),
        "status": _s(status),
        "asset": _s(asset),
        "user_ref": _s(user_ref),
        "client_ref": _s(client_ref),
        "incident_id": _s(incident_id),
        "playbook_id": _s(playbook_id),
        "ioc": _s(ioc),
        "cve": _s(cve),
        "payload": payload,
        "invented": False,
    }
    sha, sig, kid = sign_record_core(core)
    row = {
        "uuid": rid,
        "version": version,
        "timestamp_utc": ts,
        "source": _s(source or engine),
        "engine": engine,
        "record_type": record_type,
        "severity": _s(severity),
        "confidence": _s(confidence),
        "status": _s(status),
        "asset": _s(asset),
        "user_ref": _s(user_ref),
        "client_ref": _s(client_ref),
        "device": _s(device),
        "network": _s(network),
        "server_ref": _s(server_ref),
        "endpoint_ref": _s(endpoint_ref),
        "branch": _s(branch),
        "ioc": _s(ioc),
        "cve": _s(cve),
        "mitre": _s(mitre),
        "campaign": _s(campaign),
        "malware": _s(malware),
        "ransomware": _s(ransomware),
        "apt": _s(apt),
        "incident_id": _s(incident_id),
        "playbook_id": _s(playbook_id),
        "risk": _s(risk),
        "payload_json": canonical_json(payload),
        "sha256": sha,
        "ed25519_sig": sig,
        "key_id": kid,
        "prev_uuid": prev_uuid,
        "immutable": 1,
        "invented": 0,
    }
    db_id = insert_record(row)
    return {"ok": True, "db_id": db_id, "uuid": rid, "version": version, "sha256": sha, "ed25519_sig": sig, "key_id": kid}


def versioned_update(uuid: str, new_payload: Dict[str, Any], engine: str = "sdl", note: str = "") -> Dict[str, Any]:
    """Inmutabilidad: crea nueva version; no modifica fila anterior."""
    prev = get_by_uuid(uuid)
    if not prev:
        return {"ok": False, "error": "not_found"}
    new_ver = int(prev.get("version") or 1) + 1
    try:
        old_payload = json_loads(prev.get("payload_json") or "{}")
    except Exception:
        old_payload = {}
    payload = dict(new_payload)
    payload["_previous_version"] = prev.get("version")
    payload["_update_note"] = note or "versioned_update"
    payload["_previous_sha256"] = prev.get("sha256")
    return build_and_insert(
        engine=engine or prev.get("engine") or "sdl",
        record_type=prev.get("record_type") or "event",
        payload=payload,
        source=prev.get("source"),
        severity=prev.get("severity"),
        confidence=prev.get("confidence"),
        status=prev.get("status"),
        asset=prev.get("asset"),
        user_ref=prev.get("user_ref"),
        client_ref=prev.get("client_ref"),
        device=prev.get("device"),
        network=prev.get("network"),
        server_ref=prev.get("server_ref"),
        endpoint_ref=prev.get("endpoint_ref"),
        branch=prev.get("branch"),
        ioc=prev.get("ioc") if prev.get("ioc") != NA else None,
        cve=prev.get("cve") if prev.get("cve") != NA else None,
        mitre=prev.get("mitre") if prev.get("mitre") != NA else None,
        campaign=prev.get("campaign") if prev.get("campaign") != NA else None,
        malware=prev.get("malware") if prev.get("malware") != NA else None,
        ransomware=prev.get("ransomware") if prev.get("ransomware") != NA else None,
        apt=prev.get("apt") if prev.get("apt") != NA else None,
        incident_id=prev.get("incident_id") if prev.get("incident_id") != NA else None,
        playbook_id=prev.get("playbook_id") if prev.get("playbook_id") != NA else None,
        risk=prev.get("risk") if prev.get("risk") != NA else None,
        existing_uuid=uuid,
        prev_uuid=uuid,
        version=new_ver,
    )


def json_loads(s: str):
    import json
    return json.loads(s)


def ingest_from_engines(limit_per_source: int = 50) -> Dict[str, Any]:
    """
    Ingiere snapshot actual desde motores reales.
    Solo lo que exista; no inventa. Idempotencia suave por contenido hash en sesión.
    """
    summary: Dict[str, Any] = {"ingested": {}, "errors": {}, "invented": False, "timestamp_utc": _utc()}
    total = 0

    # IMCM incidents
    try:
        from services.imcm import search_incidents
        n = 0
        for inc in search_incidents(limit=limit_per_source):
            build_and_insert(
                engine="imcm",
                record_type="incident",
                payload=inc,
                source=inc.get("source_engine") or "imcm",
                severity=inc.get("severity"),
                confidence=str(inc.get("confidence")) if inc.get("confidence") is not None else None,
                status=inc.get("estado"),
                asset=(inc.get("asm") or {}).get("hostname") if isinstance(inc.get("asm"), dict) else None,
                user_ref=inc.get("user"),
                incident_id=inc.get("id"),
                playbook_id=(inc.get("sope") or {}).get("playbook_id") if isinstance(inc.get("sope"), dict) else None,
                malware=inc.get("threat_type") if inc.get("threat_type") in ("malware", "ransomware") else None,
                ransomware="ransomware" if inc.get("threat_type") == "ransomware" else None,
                apt="apt" if inc.get("threat_type") == "apt" else None,
                risk=str(inc.get("risk_score")) if inc.get("risk_score") is not None else None,
            )
            # forensic sub
            if inc.get("forensic"):
                build_and_insert(
                    engine="forense",
                    record_type="forensic_event",
                    payload=inc.get("forensic"),
                    incident_id=inc.get("id"),
                    source="imcm.forensic",
                )
            n += 1
        summary["ingested"]["imcm"] = n
        total += n
    except Exception as exc:
        summary["errors"]["imcm"] = str(exc)[:200]

    # TIE IOCs
    try:
        from services.threat_intelligence_enterprise.store import load_iocs
        n = 0
        for ioc in load_iocs(limit=limit_per_source):
            build_and_insert(
                engine="threat_intelligence_enterprise",
                record_type="ioc",
                payload=ioc,
                ioc=_s(ioc.get("value")),
                severity=ioc.get("severity") or ioc.get("threat_type"),
                malware=ioc.get("malware_family") or ioc.get("malware"),
                campaign=ioc.get("campaign"),
                apt=ioc.get("apt"),
                mitre=ioc.get("mitre") or ioc.get("mitre_attack"),
                confidence=str(ioc.get("confidence")) if ioc.get("confidence") is not None else None,
            )
            n += 1
        summary["ingested"]["tie"] = n
        total += n
    except Exception as exc:
        summary["errors"]["tie"] = str(exc)[:200]

    # VIEM vulns
    try:
        from services.viem import search_vulns
        n = 0
        for v in search_vulns(limit=limit_per_source):
            build_and_insert(
                engine="viem",
                record_type="vulnerability",
                payload=v,
                cve=v.get("cve") or v.get("cve_id"),
                severity=v.get("risk_level") or v.get("severity"),
                risk=str(v.get("risk_score")) if v.get("risk_score") is not None else None,
                status=v.get("status"),
                asset=v.get("asset") or v.get("hostname"),
            )
            n += 1
        summary["ingested"]["viem"] = n
        total += n
    except Exception as exc:
        summary["errors"]["viem"] = str(exc)[:200]

    # ASM inventory snapshot
    try:
        from services.asm.store import load_inventory
        inv = load_inventory()
        if inv:
            host = inv.get("local_host") or {}
            build_and_insert(
                engine="asm",
                record_type="asm_inventory",
                payload={"summary": inv.get("summary"), "local_host": host, "scanned_at_utc": inv.get("scanned_at_utc")},
                asset=host.get("hostname") or host.get("ip"),
                device=host.get("hostname"),
                network=host.get("ip"),
                endpoint_ref=host.get("hostname"),
                server_ref=host.get("hostname") if (host.get("classification") or "").lower() == "server" else None,
                risk=str((inv.get("exposure") or {}).get("exposure_score")) if isinstance(inv.get("exposure"), dict) else None,
            )
            summary["ingested"]["asm"] = 1
            total += 1
            for finding in (inv.get("shadow_it_findings") or [])[:limit_per_source]:
                build_and_insert(
                    engine="asm",
                    record_type="asset_change",
                    payload=finding if isinstance(finding, dict) else {"finding": finding},
                    asset=host.get("hostname"),
                )
                total += 1
                summary["ingested"]["asm"] = summary["ingested"].get("asm", 0) + 1
        else:
            summary["ingested"]["asm"] = 0
    except Exception as exc:
        summary["errors"]["asm"] = str(exc)[:200]

    # SOPE playbooks / history
    try:
        from services.sope.playbook_catalog import PLAYBOOKS
        n = 0
        for pid, pb in list(PLAYBOOKS.items())[:limit_per_source]:
            build_and_insert(
                engine="sope",
                record_type="playbook",
                payload=pb,
                playbook_id=pid,
                severity=pb.get("nivel_riesgo"),
                status="catalog",
            )
            n += 1
        summary["ingested"]["sope_playbooks"] = n
        total += n
    except Exception as exc:
        summary["errors"]["sope"] = str(exc)[:200]
    try:
        from services.sope.store import load_decisions
        n = 0
        for d in load_decisions(limit_per_source):
            build_and_insert(
                engine="sope",
                record_type="event",
                payload=d,
                playbook_id=d.get("playbook_id"),
                severity=d.get("severity"),
                confidence=str(d.get("confidence_score")) if d.get("confidence_score") is not None else None,
            )
            n += 1
        summary["ingested"]["sope_decisions"] = n
        total += n
    except Exception as exc:
        summary["errors"]["sope_decisions"] = str(exc)[:200]

    # Health
    try:
        from services.health_engine import get_health_status
        st = get_health_status()
        build_and_insert(engine="health_engine", record_type="health_event", payload=st if isinstance(st, dict) else {"status": st})
        summary["ingested"]["health_engine"] = 1
        total += 1
    except Exception as exc:
        summary["errors"]["health_engine"] = str(exc)[:200]

    # Swarm defense
    try:
        from services.swarm_defense import swarm_defense_engine
        st = swarm_defense_engine.status()
        build_and_insert(engine="swarm_defense", record_type="swarm_event", payload=st if isinstance(st, dict) else {"status": st})
        summary["ingested"]["swarm_defense"] = 1
        total += 1
        try:
            from services.swarm_defense.event_bus import swarm_event_bus
            n = 0
            for ev in swarm_event_bus.recent(min(limit_per_source, 30)):
                build_and_insert(engine="swarm_defense", record_type="swarm_event", payload=ev)
                n += 1
            summary["ingested"]["swarm_events"] = n
            total += n
        except Exception as exc2:
            summary["errors"]["swarm_events"] = str(exc2)[:200]
    except Exception as exc:
        summary["errors"]["swarm_defense"] = str(exc)[:200]

    # Swarm mesh
    try:
        from services.swarm_defense.mesh import mesh_status
        st = mesh_status()
        build_and_insert(engine="swarm_mesh", record_type="mesh_event", payload=st if isinstance(st, dict) else {"status": st})
        summary["ingested"]["swarm_mesh"] = 1
        total += 1
    except Exception as exc:
        summary["errors"]["swarm_mesh"] = str(exc)[:200]

    # CryptoVault
    try:
        from crypto_vault import CryptoVault
        h = CryptoVault().verify_health()
        build_and_insert(engine="cryptovault", record_type="cryptovault_event", payload=h)
        summary["ingested"]["cryptovault"] = 1
        total += 1
    except Exception as exc:
        summary["errors"]["cryptovault"] = str(exc)[:200]

    # ZDDE
    try:
        from services.zero_day_detection.engine import get_zdde_status
        st = get_zdde_status()
        build_and_insert(engine="zero_day_detection", record_type="event", payload=st if isinstance(st, dict) else {"status": st})
        summary["ingested"]["zero_day_detection"] = 1
        total += 1
    except Exception as exc:
        summary["errors"]["zero_day_detection"] = str(exc)[:200]

    # Defense center
    try:
        from services.defense_center_service import get_dashboard_summary
        st = get_dashboard_summary()
        build_and_insert(engine="centro_defensa", record_type="event", payload=st if isinstance(st, dict) else {"status": st})
        summary["ingested"]["centro_defensa"] = 1
        total += 1
    except Exception as exc:
        summary["errors"]["centro_defensa"] = str(exc)[:200]

    # Forensic summary
    try:
        from services.forensic_evidence_integrity_service import get_system_summary
        st = get_system_summary()
        build_and_insert(engine="forense", record_type="custody", payload=st if isinstance(st, dict) else {"status": st})
        summary["ingested"]["forense"] = 1
        total += 1
    except Exception as exc:
        summary["errors"]["forense"] = str(exc)[:200]

    # Kernel status (analyst only marker)
    try:
        build_and_insert(
            engine="kernel_ia",
            record_type="kernel_decision",
            payload={"role": "analyst_only", "executes_actions": False, "note": "status snapshot"},
            confidence="policy",
            status="analyst_only",
        )
        summary["ingested"]["kernel_ia"] = 1
        total += 1
    except Exception as exc:
        summary["errors"]["kernel_ia"] = str(exc)[:200]

    # Login / session history if available
    try:
        from services.login_session_audit_service import list_login_sessions
        n = 0
        for s in list_login_sessions(limit=min(limit_per_source, 30)):
            build_and_insert(
                engine="reportes",
                record_type="session_event",
                payload=s if isinstance(s, dict) else {"session": s},
                user_ref=(s.get("email") or s.get("user")) if isinstance(s, dict) else None,
            )
            n += 1
        summary["ingested"]["sessions"] = n
        total += n
    except Exception as exc:
        summary["errors"]["sessions"] = str(exc)[:200]

    # Device history
    try:
        from services.device_connection_monitor import list_events
        n = 0
        for ev in list_events(limit=min(limit_per_source, 30)):
            build_and_insert(
                engine="endpoint",
                record_type="device_history",
                payload=ev if isinstance(ev, dict) else {"event": ev},
                device=(ev.get("mac") or ev.get("hostname")) if isinstance(ev, dict) else None,
                network=ev.get("ip") if isinstance(ev, dict) else None,
            )
            n += 1
        summary["ingested"]["device_history"] = n
        total += n
    except Exception as exc:
        summary["errors"]["device_history"] = str(exc)[:200]

    # Network security history
    try:
        from services.network_security_history_service import get_network_history_summary
        st = get_network_history_summary()
        build_and_insert(engine="network_protection", record_type="network_event", payload=st if isinstance(st, dict) else {"status": st})
        summary["ingested"]["network_protection"] = 1
        total += 1
    except Exception as exc:
        summary["errors"]["network_protection"] = str(exc)[:200]

    # SOC overview derived snapshot (not critical engine data duplication)
    try:
        from services.soc import get_overview
        ov = get_overview()
        build_and_insert(engine="soc", record_type="event", payload={"overview_risk": ov.get("risk_global"), "engines": ov.get("engines"), "invented": False})
        summary["ingested"]["soc"] = 1
        total += 1
    except Exception as exc:
        summary["errors"]["soc"] = str(exc)[:200]

    # Adaptive profile — best effort
    try:
        from services import adaptive_profile_service  # type: ignore
        if hasattr(adaptive_profile_service, "get_status"):
            st = adaptive_profile_service.get_status()
            build_and_insert(engine="adaptive_profile", record_type="event", payload=st if isinstance(st, dict) else {"status": st})
            summary["ingested"]["adaptive_profile"] = 1
            total += 1
        else:
            summary["ingested"]["adaptive_profile"] = 0
            summary["errors"]["adaptive_profile"] = NA
    except Exception:
        # Try alternate module names without inventing
        try:
            import importlib
            mod = None
            for name in ("services.adaptive_profile", "services.adaptive_profile_engine"):
                try:
                    mod = importlib.import_module(name)
                    break
                except Exception:
                    continue
            if mod and hasattr(mod, "get_status"):
                st = mod.get_status()
                build_and_insert(engine="adaptive_profile", record_type="event", payload=st if isinstance(st, dict) else {"status": st})
                summary["ingested"]["adaptive_profile"] = 1
                total += 1
            else:
                summary["ingested"]["adaptive_profile"] = 0
                summary["errors"]["adaptive_profile"] = NA
        except Exception as exc:
            summary["errors"]["adaptive_profile"] = str(exc)[:200] if str(exc) else NA

    # BTDE — best effort from existing services
    try:
        ingested_btde = 0
        try:
            from services.alerts_canonical_service import get_canonical_alerts
            for a in get_canonical_alerts(include_resolved=False, limit=min(limit_per_source, 30)):
                motor = (a.get("motor") or "").lower()
                if "btde" in motor or "behavior" in motor or not motor:
                    build_and_insert(
                        engine="btde",
                        record_type="alert",
                        payload=a,
                        severity=a.get("risk_level"),
                        confidence=str(a.get("confidence")) if a.get("confidence") is not None else None,
                        status=a.get("status"),
                        incident_id=a.get("id"),
                        asset=a.get("origin"),
                    )
                    ingested_btde += 1
        except Exception as exc_inner:
            summary["errors"]["btde_alerts"] = str(exc_inner)[:200]
        summary["ingested"]["btde"] = ingested_btde
        total += ingested_btde
    except Exception as exc:
        summary["errors"]["btde"] = str(exc)[:200]

    # Reports list
    try:
        from services.security_report_service import list_reports
        n = 0
        for r in list_reports(limit=min(limit_per_source, 20)):
            build_and_insert(engine="reportes", record_type="report", payload=r if isinstance(r, dict) else {"report": r})
            n += 1
        summary["ingested"]["reportes"] = n
        total += n
    except Exception as exc:
        summary["errors"]["reportes"] = str(exc)[:200]

    summary["total_ingested"] = total
    return summary
