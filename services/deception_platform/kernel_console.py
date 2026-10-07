#!/usr/bin/env python3
"""Kernel IA console DPE — solo analisis; executes_actions=false."""
from __future__ import annotations
from typing import Any, Dict

from services.deception_platform.limitations import NA
from services.deception_platform.store import load_events, load_iocs
from services.deception_platform.honeypots import list_honeypots
from services.deception_platform.honeytokens import list_honeytokens
from services.deception_platform.honeyfiles import list_honeyfiles


def explain_interaction(event: Dict[str, Any], pipeline: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "question": "explain_interaction",
        "answer": (
            f"Interaccion real detectada en {event.get('resource_type')}/{event.get('resource_id')} "
            f"accion={event.get('action')}. IOC={ (pipeline.get('ioc_local') or {}).get('ioc_id') }. "
            f"IMCM={ (pipeline.get('imcm') or {}) }. SOPE={ (pipeline.get('sope') or {}) }."
        ),
        "role": "analyst_only",
        "executes_actions": False,
        "invented": False,
    }


def ask_kernel(question: str) -> Dict[str, Any]:
    q = (question or "").lower()
    evidence: Dict[str, Any] = {}
    parts = []

    events = load_events(100)
    iocs = load_iocs(100)
    pots = list_honeypots()
    tokens = list_honeytokens(50)
    files = list_honeyfiles(50)

    if "senuelo" in q or "señuelo" in q or "recurso" in q or "tocado" in q:
        touched = [e for e in events if e.get("action")]
        parts.append(f"Recursos senuelo tocados (eventos reales): {len(touched)}. Ultimo={touched[0] if touched else NA}")
        evidence["touched"] = touched[:5] if touched else NA

    if "honeytoken" in q or "token" in q or "atacante" in q:
        token_events = [e for e in events if e.get("resource_type") == "honeytoken"]
        parts.append(f"Interacciones honeytoken: {len(token_events)}. Tokens emitidos={tokens.get('count')}")
        evidence["honeytoken_events"] = token_events[:5] if token_events else NA

    if "incidente" in q or "honeypot" in q:
        pot_events = [e for e in events if e.get("resource_type") == "honeypot"]
        parts.append(
            f"Eventos honeypot: {len(pot_events)}. "
            f"Honeypots ACTIVO={pots.get('counts', {}).get('activo', 0)} "
            f"(nunca se afirma activo sin listener verificado)."
        )
        evidence["honeypot_events"] = pot_events[:5] if pot_events else NA
        evidence["honeypot_counts"] = pots.get("counts")

    if "ioc" in q:
        parts.append(f"IOC DPE generados: {len(iocs)}. Ultimo={iocs[0] if iocs else NA}")
        evidence["iocs"] = iocs[:5] if iocs else NA

    if "playbook" in q or "sope" in q:
        sope_reco = NA
        try:
            from services.sope.playbook_catalog import PLAYBOOKS
            for pid in ("credential_theft", "critical_threat", "compromised_device"):
                if pid in PLAYBOOKS:
                    sope_reco = {"playbook_id": pid, "nombre": PLAYBOOKS[pid].get("nombre"), "mode": "recommend_only"}
                    break
        except Exception:
            sope_reco = NA
        parts.append(f"SOPE recomienda (sin ejecutar): {sope_reco}")
        evidence["sope"] = sope_reco

    if not parts:
        parts.append(
            f"DPE status: honeypots_activo={pots.get('counts', {}).get('activo', 0)}, "
            f"tokens={tokens.get('count')}, honeyfiles={files.get('count')}, "
            f"eventos_reales={len(events)}, iocs={len(iocs)}"
        )
        evidence["summary"] = {
            "events": len(events),
            "iocs": len(iocs),
            "tokens": tokens.get("count"),
            "files": files.get("count"),
        }

    return {
        "question": question,
        "answer": " ".join(str(p) for p in parts),
        "evidence": evidence,
        "role": "analyst_only",
        "executes_actions": False,
        "invented": False,
    }
