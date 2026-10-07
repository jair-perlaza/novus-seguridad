#!/usr/bin/env python3
"""Motor DPE — dashboard y orquestacion (sin telemetria falsa)."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List

from services.deception_platform.limitations import LIMITATIONS, POLICY, NA, NC
from services.deception_platform.honeypots import list_honeypots
from services.deception_platform.honeytokens import list_honeytokens
from services.deception_platform.honeyfiles import list_honeyfiles
from services.deception_platform.honeycredentials import list_honeycredentials
from services.deception_platform.honeyshares import list_honeyshares
from services.deception_platform.honeydatabase import list_honeydatabases
from services.deception_platform.decoy_servers import list_decoy_servers
from services.deception_platform.segregation import segregation_report
from services.deception_platform.swarm_share import swarm_anonymous_summary
from services.deception_platform.store import load_events, load_iocs, load_seals, load_queries, log_query, save_seal
import hashlib
import json


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sources_status() -> Dict[str, Any]:
    status = {}
    probes = {
        "imcm": ("services.imcm.engine", "create_incident"),
        "tie": ("services.threat_intelligence_enterprise.internal_intel", "ingest_internal_detection"),
        "sope": ("services.sope.playbook_catalog", "PLAYBOOKS"),
        "sdl": ("services.sdl", None),
        "sdace": ("services.sdace", None),
        "ueba": ("services.identity_intelligence", None),
        "iapa": ("services.iapa", None),
        "soc": ("services.soc", None),
        "forensic_keys": ("services.forensic_evidence_keys", "load_signing_keypair"),
        "swarm": ("services.deception_platform.swarm_share", "swarm_anonymous_summary"),
        "kernel": ("services.deception_platform.kernel_console", "ask_kernel"),
    }
    for name, (mod, attr) in probes.items():
        try:
            m = __import__(mod, fromlist=["*"])
            ok = True
            if attr and not hasattr(m, attr):
                ok = False
            status[name] = {"available": ok, "module": mod}
        except Exception as exc:
            status[name] = {"available": False, "status": NA, "error": str(exc)[:120]}
    return status


def get_dashboard() -> Dict[str, Any]:
    pots = list_honeypots()
    tokens = list_honeytokens(100)
    files = list_honeyfiles(100)
    creds = list_honeycredentials(100)
    shares = list_honeyshares()
    dbs = list_honeydatabases()
    decoys = list_decoy_servers()
    events = load_events(50)
    iocs = load_iocs(50)
    seg = segregation_report()
    sources = _sources_status()

    # Honest claims
    claims = {
        "honeypots_activos": pots.get("counts", {}).get("activo", 0),
        "ataques_detectados": len(events),
        "afirma_ataques_sin_evidencia": False,
        "afirma_honeypots_activos_sin_listener": False,
    }
    if claims["honeypots_activos"] == 0:
        claims["honeypots_label"] = NC if pots.get("counts", {}).get("no_configurado") else "sin_listeners_verificados"
    else:
        claims["honeypots_label"] = "ACTIVO_verificado"

    seal_payload = {
        "events": len(events),
        "iocs": len(iocs),
        "tokens": tokens.get("count"),
        "activo": claims["honeypots_activos"],
    }
    digest = hashlib.sha256(json.dumps(seal_payload, sort_keys=True).encode()).hexdigest()
    sig, kid = NA, NA
    try:
        from services.forensic_evidence_keys import load_signing_keypair
        pk, kid = load_signing_keypair()
        sig = pk.sign(digest.encode()).hex()
    except Exception:
        pass
    seal = {"kind": "dashboard", "sha256": digest, "ed25519_sig": sig, "key_id": kid, "invented": False}
    save_seal(seal)
    log_query({"action": "dashboard"})

    sope_reco = NA
    try:
        from services.sope.playbook_catalog import PLAYBOOKS
        for pid in ("credential_theft", "critical_threat"):
            if pid in PLAYBOOKS:
                sope_reco = {"playbook_id": pid, "mode": "recommend_only", "executes": False}
                break
    except Exception:
        pass

    return {
        "generated_at_utc": _utc(),
        "invented": False,
        "simulated_attacks": False,
        "sources_status": sources,
        "honeypots": pots,
        "honeytokens": {"count": tokens.get("count"), "recent": (tokens.get("tokens") or [])[:10]},
        "honeyfiles": {"count": files.get("count"), "recent": (files.get("files") or [])[:10]},
        "honeycredentials": {"count": creds.get("count"), "recent": (creds.get("credentials") or [])[:10]},
        "honeyshares": shares,
        "honeydatabases": dbs,
        "decoy_servers": decoys,
        "events": events or [],
        "events_count": len(events),
        "iocs": iocs or [],
        "iocs_count": len(iocs),
        "timeline": events[:30] if events else NA,
        "claims": claims,
        "segregation": seg,
        "sope_recommendation": sope_reco,
        "swarm": swarm_anonymous_summary(),
        "seal": seal,
        "seals": load_seals(5),
        "queries": load_queries(10),
        "limitations": LIMITATIONS,
        "policy": POLICY,
    }


def get_status() -> Dict[str, Any]:
    pots = list_honeypots()
    return {
        "honeypots": pots.get("counts"),
        "active_protocols": pots.get("active_protocols"),
        "auto_start": False,
        "events": len(load_events(5000)),
        "iocs": len(load_iocs(5000)),
        "tokens": list_honeytokens(5000).get("count"),
        "honeyfiles": list_honeyfiles(5000).get("count"),
        "policy": POLICY,
        "invented": False,
        "simulated_attacks": False,
    }


def stats() -> Dict[str, Any]:
    return get_status()


def search(q: str, limit: int = 50) -> Dict[str, Any]:
    log_query({"action": "search", "q": q})
    ql = (q or "").lower()
    hits: List[Dict[str, Any]] = []
    for e in load_events(500):
        blob = json.dumps(e, default=str).lower()
        if ql in blob:
            hits.append({"kind": "event", "item": e})
    for i in load_iocs(500):
        blob = json.dumps(i, default=str).lower()
        if ql in blob:
            hits.append({"kind": "ioc", "item": i})
    for t in (list_honeytokens(500).get("tokens") or []):
        if ql in json.dumps(t, default=str).lower():
            hits.append({"kind": "honeytoken", "item": t})
    for f in (list_honeyfiles(500).get("files") or []):
        if ql in json.dumps(f, default=str).lower():
            hits.append({"kind": "honeyfile", "item": f})
    return {
        "ok": True,
        "q": q,
        "hits": hits[:limit],
        "count": min(len(hits), limit),
        "invented": False,
        "message": None if hits else NA,
    }
