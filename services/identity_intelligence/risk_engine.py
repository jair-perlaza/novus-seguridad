#!/usr/bin/env python3
"""
Risk Engine — Identity Risk Score explicable con pesos documentados.
Sin RNG. Sin IA generativa.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.identity_intelligence.limitations import NA, RISK_WEIGHTS, MIN_BASELINE_OBS
from services.identity_intelligence.store import (
    load_baselines, load_observations, load_identities, save_anomaly, save_risk, save_seal,
    load_process_freeze,
)
from services.identity_intelligence.behavior_baseline import get_baseline, _parse_hour
import hashlib
import json


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _seal(kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    core = {"kind": kind, "payload": payload, "invented": False}
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
        "chain_of_custody": {"phase": "iiueba_risk", "ref": digest},
        "invented": False,
    }
    save_seal(entry)
    return entry


def _is_shell(name: str) -> Optional[str]:
    n = (name or "").lower()
    mapping = {
        "powershell.exe": "PowerShell",
        "pwsh.exe": "PowerShell",
        "cmd.exe": "CMD",
        "wmic.exe": "WMI",
        "wmiprvse.exe": "WMI",
        "psexec.exe": "PsExec",
        "psexesvc.exe": "PsExec",
        "mstsc.exe": "RDP",
        "rdpclip.exe": "RDP",
    }
    return mapping.get(n)


def detect_anomalies_for_identity(identity_uuid: str) -> Dict[str, Any]:
    """Detecta desviaciones del baseline con explicación explícita."""
    baseline = get_baseline(identity_uuid)
    if not baseline.get("sufficient"):
        return {
            "identity_uuid": identity_uuid,
            "anomalies": [],
            "status": "insufficient_baseline",
            "message": NA,
            "invented": False,
            "note": f"Se requieren >= {MIN_BASELINE_OBS} observaciones reales.",
        }

    obs = [o for o in load_observations(800) if o.get("identity_uuid") == identity_uuid]
    anomalies: List[Dict[str, Any]] = []
    usual_hours = baseline.get("usual_hours") if isinstance(baseline.get("usual_hours"), dict) else {}
    usual_ips = baseline.get("usual_ips") if isinstance(baseline.get("usual_ips"), dict) else {}
    usual_devices = baseline.get("usual_devices") if isinstance(baseline.get("usual_devices"), dict) else {}
    usual_gw = baseline.get("usual_gateways") if isinstance(baseline.get("usual_gateways"), dict) else {}
    usual_dns = baseline.get("usual_dns") if isinstance(baseline.get("usual_dns"), dict) else {}
    usual_procs = baseline.get("usual_processes") if isinstance(baseline.get("usual_processes"), dict) else {}

    # Latest auth
    auths = [o for o in obs if o.get("kind") == "authentication"]
    if auths:
        latest = auths[-1]
        hour = _parse_hour(latest.get("login_at"))
        if hour is not None and usual_hours:
            hour_keys = set()
            for k in usual_hours.keys():
                try:
                    hour_keys.add(int(k))
                except Exception:
                    pass
            if hour not in hour_keys:
                anomalies.append({
                    "type": "unusual_login_hour",
                    "factor": "unusual_login_hour",
                    "explanation": f"Login a la hora {hour} observada; horas habituales={sorted(hour_keys)}.",
                    "evidence": {"login_at": latest.get("login_at"), "hour": hour, "usual_hours": usual_hours},
                    "invented": False,
                })
        ip = latest.get("ip")
        if ip and usual_ips and str(ip) not in usual_ips:
            anomalies.append({
                "type": "new_network",
                "factor": "new_network",
                "explanation": f"IP {ip} no aparece en IPs habituales {list(usual_ips.keys())[:10]}.",
                "evidence": {"ip": ip, "usual_ips": list(usual_ips.keys())[:10]},
                "invented": False,
            })
        dev = latest.get("device_type")
        if dev and usual_devices and str(dev) not in usual_devices:
            anomalies.append({
                "type": "new_device",
                "factor": "new_device",
                "explanation": f"device_type={dev} no está en dispositivos habituales {list(usual_devices.keys())}.",
                "evidence": {"device_type": dev, "usual_devices": usual_devices},
                "invented": False,
            })

    # Host inventory deviations
    hosts = [o for o in obs if o.get("kind") == "host_inventory"]
    if hosts:
        latest_h = hosts[-1]
        gw = latest_h.get("gateway")
        if gw and usual_gw and str(gw) not in usual_gw:
            anomalies.append({
                "type": "new_gateway",
                "factor": "new_gateway",
                "explanation": f"Gateway {gw} distinto de habituales {list(usual_gw.keys())}.",
                "evidence": {"gateway": gw, "usual_gateways": usual_gw},
                "invented": False,
            })
        dns = latest_h.get("dns")
        dns_list = dns if isinstance(dns, list) else ([dns] if dns else [])
        for d in dns_list:
            if usual_dns and str(d) not in usual_dns:
                anomalies.append({
                    "type": "new_dns",
                    "factor": "new_dns",
                    "explanation": f"DNS {d} no visto en baseline {list(usual_dns.keys())}.",
                    "evidence": {"dns": d, "usual_dns": usual_dns},
                    "invented": False,
                })
                break

    # Process / shell never seen vs frozen prior baseline (not same-cycle)
    freeze = load_process_freeze()
    frozen = set(freeze.get("processes") or [])
    live_procs = []
    try:
        import psutil
        for p in psutil.process_iter(["name"]):
            try:
                n = (p.info.get("name") or "").lower()
                if n:
                    live_procs.append(n)
            except Exception:
                continue
    except Exception:
        live_procs = [str(o.get("process_name")).lower() for o in obs if o.get("kind") == "process_sighting" and o.get("process_name")]

    if frozen:
        for name in sorted(set(live_procs)):
            if name not in frozen:
                shell = _is_shell(name)
                if shell:
                    anomalies.append({
                        "type": "shell_never_seen",
                        "factor": "shell_never_seen",
                        "explanation": f"{shell} ({name}) no estaba en el freeze de procesos del ciclo anterior.",
                        "evidence": {"process": name, "shell": shell, "freeze_size": len(frozen)},
                        "invented": False,
                    })
                else:
                    anomalies.append({
                        "type": "new_process",
                        "factor": "new_process",
                        "explanation": f"Proceso {name} no aparece en freeze previo ({len(frozen)} procesos conocidos).",
                        "evidence": {"process": name, "freeze_size": len(frozen)},
                        "invented": False,
                    })
    # Freeze se actualiza en run_cycle() tras el scoring, no aqui.

    # Incident / IOC links (from observations)
    for o in obs:
        if o.get("kind") == "incident_link":
            anomalies.append({
                "type": "related_incident",
                "factor": "related_incident",
                "explanation": f"Identidad vinculada a incidente real {o.get('incident_id')} (severidad={o.get('severity')}).",
                "evidence": {"incident_id": o.get("incident_id"), "severity": o.get("severity")},
                "invented": False,
            })

    # Traffic spike vs traffic baseline (global)
    data = load_baselines()
    traffic = data.get("traffic_baseline")
    if isinstance(traffic, dict) and traffic.get("avg_connections"):
        snaps = [o for o in load_observations(200) if o.get("kind") == "network_snapshot"]
        if snaps:
            latest_c = snaps[-1].get("connection_count")
            avg = float(traffic["avg_connections"])
            if latest_c is not None and avg > 0 and float(latest_c) > avg * 3:
                anomalies.append({
                    "type": "traffic_spike",
                    "factor": "traffic_spike",
                    "explanation": f"Conexiones actuales={latest_c} > 3x promedio baseline={avg:.1f}.",
                    "evidence": {"current": latest_c, "avg": avg},
                    "invented": False,
                })

    # Location: only if objective field exists — typically NA
    location_status = NA

    # Multi-host: if same user has auths from >1 distinct device_type/ip in close observations
    ips_auth = {str(o.get("ip")) for o in auths if o.get("ip")}
    if len(ips_auth) > 1:
        anomalies.append({
            "type": "multi_host_simultaneous",
            "factor": "multi_host_simultaneous",
            "explanation": f"Misma identidad con autenticaciones desde multiples IPs observadas: {sorted(ips_auth)[:8]}.",
            "evidence": {"ips": sorted(ips_auth)},
            "invented": False,
        })

    for a in anomalies:
        a["identity_uuid"] = identity_uuid
        save_anomaly(a)

    return {
        "identity_uuid": identity_uuid,
        "anomalies": anomalies,
        "count": len(anomalies),
        "location": location_status,
        "invented": False,
    }


def compute_risk_score(identity_uuid: str) -> Dict[str, Any]:
    """Score = suma de pesos de factores detectados (cap 100). Explicable."""
    det = detect_anomalies_for_identity(identity_uuid)
    if det.get("status") == "insufficient_baseline":
        return {
            "identity_uuid": identity_uuid,
            "score": NA,
            "confidence": "low",
            "factors": [],
            "status": "insufficient_baseline",
            "message": NA,
            "weights_document": RISK_WEIGHTS,
            "invented": False,
        }

    factors = []
    seen = set()
    score = 0
    for a in det.get("anomalies") or []:
        factor = a.get("factor")
        if not factor or factor in seen:
            continue
        if factor not in RISK_WEIGHTS:
            continue
        seen.add(factor)
        w = RISK_WEIGHTS[factor]
        score += w
        factors.append({
            "factor": factor,
            "weight": w,
            "explanation": a.get("explanation"),
            "evidence": a.get("evidence"),
        })

    score = min(100, score)
    confidence = "high" if len(factors) >= 3 else ("medium" if factors else "low")
    result = {
        "identity_uuid": identity_uuid,
        "score": score,
        "confidence": confidence,
        "factors": factors,
        "weights_document": RISK_WEIGHTS,
        "formula": "min(100, sum(weight for each unique triggered factor))",
        "rng": False,
        "generative_ai": False,
        "invented": False,
        "timestamp_utc": _utc(),
    }
    save_risk(result)
    result["seal"] = _seal("identity_risk", {"identity_uuid": identity_uuid, "score": score, "factors": [f["factor"] for f in factors]})
    return result


def rank_identities_by_risk(limit: int = 20) -> Dict[str, Any]:
    data = load_baselines()
    baselines = data.get("baselines") or {}
    ranked = []
    for iid, b in baselines.items():
        if b.get("identity_type") != "usuario" and b.get("identity_type") not in ("equipo", "cuenta_servicio", None):
            # still score users preferentially but include all with sufficient baseline
            pass
        if not b.get("sufficient"):
            continue
        r = compute_risk_score(iid)
        if r.get("score") == NA:
            continue
        ranked.append({
            "identity_uuid": iid,
            "label": b.get("label"),
            "type": b.get("identity_type"),
            "score": r.get("score"),
            "confidence": r.get("confidence"),
            "factor_count": len(r.get("factors") or []),
        })
    ranked.sort(key=lambda x: (x.get("score") or 0), reverse=True)
    return {"ok": True, "ranked": ranked[:limit], "invented": False, "weights_document": RISK_WEIGHTS}
