#!/usr/bin/env python3
"""Integracion DPE — solo ante interaccion REAL; APIs publicas existentes."""
from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from services.deception_platform.limitations import NA, NI, POLICY, NAMESPACE
from services.deception_platform.store import save_event, save_ioc, save_seal


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _seal(kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    core = {"kind": kind, "payload": payload, "invented": False, "namespace": NAMESPACE}
    digest = hashlib.sha256(_canonical(core).encode()).hexdigest()
    sig, kid = NA, NA
    try:
        from services.forensic_evidence_keys import load_signing_keypair
        pk, kid = load_signing_keypair()
        sig = pk.sign(digest.encode()).hex()
    except Exception:
        pass
    entry = {
        "kind": kind,
        "sha256": digest,
        "ed25519_sig": sig,
        "key_id": kid,
        "chain_of_custody": {"phase": "dpe_interaction", "ref": digest},
        "invented": False,
    }
    save_seal(entry)
    return entry


def _bump_honeyfile_opens(uid: str) -> None:
    # Opens se reflejan en events.jsonl; no contaminar honeyfiles.jsonl
    return


def handle_decoy_interaction(
    resource_type: str,
    resource_id: str,
    action: str,
    evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Pipeline ante interaccion REAL con recurso senuelo.
    No inventa atacantes ni telemetria falsa.
    """
    if POLICY.get("invent_events"):
        return {"ok": False, "error": "policy_blocks_invented_events"}

    evidence = evidence or {}
    event_id = f"DPE-{uuid.uuid4().hex[:12].upper()}"
    now = _utc()

    # Anonymize potential PII before any outbound share
    safe_evidence = dict(evidence)
    for k in list(safe_evidence.keys()):
        if k in ("password", "token", "cookie", "email", "nombre", "documento"):
            safe_evidence[k] = "[REDACTED]"

    event = {
        "event_id": event_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "action": action,
        "evidence": safe_evidence,
        "namespace": NAMESPACE,
        "simulated": False,
        "invented": False,
        "timestamp_utc": now,
    }
    save_event(event)
    seal = _seal("decoy_interaction", {"event_id": event_id, "resource_type": resource_type, "resource_id": resource_id})

    if resource_type == "honeyfile":
        _bump_honeyfile_opens(resource_id)

    # IOC local
    ioc_value = f"dpe:{resource_type}:{resource_id}:{action}"
    ioc = {
        "ioc_id": f"IOC-DPE-{uuid.uuid4().hex[:10].upper()}",
        "ioc_type": "deception_interaction",
        "ioc_value": ioc_value,
        "source_engine": "dpe",
        "severity": "ALTO",
        "event_id": event_id,
        "invented": False,
        "timestamp_utc": now,
    }
    save_ioc(ioc)

    pipeline: Dict[str, Any] = {
        "ioc_local": ioc,
        "imcm": NA,
        "threat_intelligence": NA,
        "sdl": NA,
        "sdace": NA,
        "ueba": NA,
        "iapa": NA,
        "sope": NA,
        "kernel": NA,
        "soc": NA,
        "forensic": seal,
        "swarm": NA,
    }

    # TIE — public API
    try:
        from services.threat_intelligence_enterprise.internal_intel import ingest_internal_detection
        from services.threat_intelligence_enterprise.store import store_ioc
        tie_entry = ingest_internal_detection(
            ioc_type="deception_interaction",
            ioc_value=hashlib.sha256(ioc_value.encode()).hexdigest()[:32],
            source_engine="dpe",
            severity="ALTO",
            metadata={
                "event_id": event_id,
                "resource_type": resource_type,
                "action": action,
                "namespace": NAMESPACE,
            },
        )
        store_ioc({
            "ioc_type": "deception_interaction",
            "ioc_value": tie_entry.get("ioc_value"),
            "source_engine": "dpe",
            "severity": "ALTO",
            "timestamp_utc": now,
            "invented": False,
        })
        pipeline["threat_intelligence"] = {"ok": True, "ioc": tie_entry.get("ioc_value")}
    except Exception as exc:
        pipeline["threat_intelligence"] = {"status": NA, "error": str(exc)[:200]}

    # IMCM — public create_incident
    try:
        from services.imcm.engine import create_incident
        inc = create_incident(
            source_engine="dpe",
            threat_type="deception_interaction",
            title=f"Interaccion senuelo DPE: {resource_type}/{action}",
            severity="ALTO",
            evidence={
                "event_id": event_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "ioc": ioc.get("ioc_id"),
                "simulated": False,
            },
        )
        pipeline["imcm"] = {"ok": True, "incident_id": inc.get("id")}
    except Exception as exc:
        pipeline["imcm"] = {"status": NA, "error": str(exc)[:200]}

    # SOPE — recommend only
    try:
        from services.sope.playbook_catalog import PLAYBOOKS
        reco = NA
        for pid in ("credential_theft", "critical_threat", "compromised_device", "lateral_movement"):
            if pid in PLAYBOOKS:
                reco = {
                    "playbook_id": pid,
                    "nombre": PLAYBOOKS[pid].get("nombre"),
                    "mode": "recommend_only",
                    "executes": False,
                }
                break
        pipeline["sope"] = reco
    except Exception as exc:
        pipeline["sope"] = {"status": NA, "error": str(exc)[:200]}

    # Kernel explain (analyst only)
    try:
        from services.deception_platform.kernel_console import explain_interaction
        pipeline["kernel"] = explain_interaction(event, pipeline)
    except Exception as exc:
        pipeline["kernel"] = {"status": NA, "error": str(exc)[:200], "executes_actions": False}

    # SDL / SDACE / UEBA / IAPA / SOC — no engine mutation; honest next-cycle visibility
    pipeline["sdl"] = {
        "status": NI,
        "message": "Sin push DPE a SDL (no se altera el Data Lake). Visible via IMCM/TIE en proximo ingest si fuentes lo incluyen.",
    }
    pipeline["sdace"] = {
        "status": "next_cycle",
        "message": "SDACE correlacionara en proximo ciclo si lee IMCM/TIE; DPE no modifica SDACE.",
    }
    pipeline["ueba"] = {
        "status": "next_cycle",
        "message": "UEBA no se altera. Identidades senuelo viven en namespace DPE separado.",
    }
    pipeline["iapa"] = {
        "status": "next_cycle",
        "message": "IAPA no se altera. Rutas se actualizan cuando lean incidente IMCM en rebuild.",
    }
    pipeline["soc"] = {
        "status": "visible_via_imcm",
        "message": "SOC puede mostrar el incidente IMCM; DPE no modifica el modulo SOC.",
    }

    # Swarm anonymous summary only
    try:
        from services.deception_platform.swarm_share import swarm_anonymous_summary
        pipeline["swarm"] = swarm_anonymous_summary()
    except Exception as exc:
        pipeline["swarm"] = {"status": NA, "error": str(exc)[:200]}

    result = {
        "ok": True,
        "event": event,
        "ioc": ioc,
        "pipeline": pipeline,
        "simulated": False,
        "invented": False,
        "executes_actions": False,
    }
    return result
