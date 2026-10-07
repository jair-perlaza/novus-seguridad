#!/usr/bin/env python3
"""Scenario runner CSV/BAS — escenarios controlados no destructivos."""
from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.csv_bas.limitations import NA, NI, NAMESPACE, POLICY
from services.csv_bas.scenario_catalog import get_scenario, list_scenarios, SCENARIOS
from services.csv_bas.validation_engine import validate_controls
from services.csv_bas.attack_chain import build_attack_chain
from services.csv_bas.coverage_engine import compute_coverage
from services.csv_bas.store import save_run, save_result, save_seal


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
        "chain_of_custody": {"phase": "csv_bas_validation", "ref": digest},
        "invented": False,
        "destructive": False,
    }
    save_seal(entry)
    return entry


def _emit_validation_signals(scenario: Dict[str, Any], run_id: str, marker: str) -> Dict[str, Any]:
    """Emite senales de validacion etiquetadas via APIs publicas. No exploits."""
    out: Dict[str, Any] = {
        "threat_intelligence": NA,
        "imcm": NA,
        "sope": NA,
        "sdl": NA,
        "sdace": NA,
        "ueba": NA,
        "iapa": NA,
        "soc": NA,
        "forensic": NA,
        "kernel": NA,
    }

    ioc_value = hashlib.sha256(f"{marker}|{run_id}".encode()).hexdigest()[:32]

    # TIE
    try:
        from services.threat_intelligence_enterprise.internal_intel import ingest_internal_detection
        from services.threat_intelligence_enterprise.store import store_ioc
        tie = ingest_internal_detection(
            ioc_type="csv_bas_validation",
            ioc_value=ioc_value,
            source_engine="csv_bas",
            severity="BAJO",
            metadata={
                "run_id": run_id,
                "scenario_id": scenario.get("id"),
                "signal": scenario.get("signal"),
                "marker": marker,
                "csv_bas_validation": True,
                "destructive": False,
                "real_attack": False,
                "namespace": NAMESPACE,
            },
        )
        store_ioc({
            "ioc_type": "csv_bas_validation",
            "ioc_value": ioc_value,
            "source_engine": "csv_bas",
            "severity": "BAJO",
            "run_id": run_id,
            "marker": marker,
            "csv_bas_validation": True,
            "invented": False,
            "timestamp_utc": _utc(),
        })
        out["threat_intelligence"] = {"ok": True, "ioc_value": ioc_value, "entry": tie.get("ioc_value")}
    except Exception as exc:
        out["threat_intelligence"] = {"status": NA, "error": str(exc)[:200]}

    # IMCM
    try:
        from services.imcm.engine import create_incident
        inc = create_incident(
            source_engine="csv_bas",
            threat_type="csv_bas_validation",
            title=f"CSV/BAS validation: {scenario.get('id')} [{run_id}]",
            severity="BAJO",
            evidence={
                "run_id": run_id,
                "scenario_id": scenario.get("id"),
                "marker": marker,
                "signal": scenario.get("signal"),
                "csv_bas_validation": True,
                "destructive": False,
                "real_attack": False,
                "mitre": scenario.get("mitre"),
            },
        )
        out["imcm"] = {"ok": True, "incident_id": inc.get("id")}
    except Exception as exc:
        out["imcm"] = {"status": NA, "error": str(exc)[:200]}

    # SOPE recommend only
    try:
        from services.sope.playbook_catalog import select_playbook, get_playbook, PLAYBOOKS
        threat = scenario.get("sope_threat") or "critical_threat"
        pb_id = select_playbook(threat) if threat in ("ransomware", "credential_theft", "phishing", "lateral_movement", "compromised_device", "critical_threat") or threat in PLAYBOOKS else select_playbook("critical_threat")
        # select_playbook may map unknown to critical_threat
        if threat in PLAYBOOKS:
            pb_id = threat
        else:
            pb_id = select_playbook(threat)
        pb = get_playbook(pb_id)
        out["sope"] = {
            "playbook_id": pb_id,
            "nombre": (pb or {}).get("nombre") if isinstance(pb, dict) else NA,
            "mode": "recommend_only",
            "executes": False,
        }
    except Exception as exc:
        out["sope"] = {"status": NA, "error": str(exc)[:200]}

    # Forensic seal
    out["forensic"] = _seal("scenario_run", {"run_id": run_id, "scenario_id": scenario.get("id"), "marker": marker})

    # Kernel explain
    try:
        from services.csv_bas.kernel_console import explain_run
        out["kernel"] = explain_run(scenario, run_id)
    except Exception as exc:
        out["kernel"] = {"status": NA, "error": str(exc)[:200], "executes_actions": False}

    # Honest next-cycle notes — no engine mutation
    out["sdl"] = {
        "status": NI if POLICY.get("modify_sdl") is False else NA,
        "message": "SDL no se altera. Proximo ingest puede incluir IMCM/TIE si fuentes lo cubren.",
    }
    out["sdace"] = {"status": "next_cycle", "message": "SDACE no modificado."}
    out["ueba"] = {"status": "next_cycle", "message": "UEBA no modificado."}
    out["iapa"] = {"status": "next_cycle", "message": "IAPA no modificado."}
    out["soc"] = {"status": "visible_via_imcm", "message": "SOC puede reflejar incidente IMCM; modulo SOC no modificado."}
    out["summary"] = {
        "imcm": (out.get("imcm") or {}).get("incident_id") if isinstance(out.get("imcm"), dict) else NA,
        "tie": (out.get("threat_intelligence") or {}).get("ok") if isinstance(out.get("threat_intelligence"), dict) else False,
        "sope": (out.get("sope") or {}).get("playbook_id") if isinstance(out.get("sope"), dict) else NA,
    }
    return out


def run_scenario(scenario_id: str) -> Dict[str, Any]:
    if POLICY.get("destructive") or POLICY.get("exploit_payloads") or POLICY.get("malware"):
        return {"ok": False, "error": "policy_blocks_destructive_run"}

    scenario = get_scenario(scenario_id)
    if not scenario:
        return {"ok": False, "error": f"scenario_not_found:{scenario_id}", "available": list(SCENARIOS.keys())}

    run_id = f"CSV-{uuid.uuid4().hex[:12].upper()}"
    marker = f"{scenario['signal']}|{run_id}"
    started = _utc()

    save_run({
        "run_id": run_id,
        "scenario_id": scenario_id,
        "status": "started",
        "marker": marker,
        "destructive": False,
        "real_attack": False,
        "started_at_utc": started,
    })

    integration = _emit_validation_signals(scenario, run_id, marker)
    validation = validate_controls(marker, run_id)
    chain = build_attack_chain(scenario, run_id, validation.get("detections") or [], integration)

    result = {
        "ok": True,
        "run_id": run_id,
        "scenario_id": scenario_id,
        "scenario_name": scenario.get("name"),
        "marker": marker,
        "started_at_utc": started,
        "finished_at_utc": _utc(),
        "destructive": False,
        "real_attack": False,
        "csv_bas_validation": True,
        "mitre": scenario.get("mitre") or NA,
        "integration": integration,
        "availability": validation.get("availability"),
        "detections": validation.get("detections"),
        "attack_chain": chain.get("attack_chain"),
        "attack_timeline": chain.get("attack_timeline"),
        "missed_detections": chain.get("missed_detections"),
        "not_implemented": chain.get("not_implemented"),
        "not_verified": chain.get("not_verified"),
        "evidence": chain.get("evidence"),
        "recommendations": chain.get("recommendations"),
        "seal": integration.get("forensic"),
        "invented": False,
        "policy": {
            "destructive": False,
            "exploit_payloads": False,
            "malware": False,
            "kernel_executes": False,
        },
    }
    save_result(result)
    save_run({
        "run_id": run_id,
        "scenario_id": scenario_id,
        "status": "completed",
        "marker": marker,
        "finished_at_utc": result["finished_at_utc"],
        "imcm": (integration.get("imcm") or {}).get("incident_id") if isinstance(integration.get("imcm"), dict) else NA,
    })
    compute_coverage()
    return result


def run_all(limit: Optional[int] = None) -> Dict[str, Any]:
    ids = list(SCENARIOS.keys())
    if limit:
        ids = ids[: int(limit)]
    results = []
    for sid in ids:
        results.append(run_scenario(sid))
    return {
        "ok": True,
        "ran": len(results),
        "results": results,
        "coverage": compute_coverage(),
        "invented": False,
        "destructive": False,
    }
