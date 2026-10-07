"""
Política de respuesta Swarm — solo acciones con motor real cableado.
AUTO: acciones no destructivas de registro/monitoreo.
APPROVAL: bloqueos, kill, aislamiento, playbooks.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from utils.logger import logger

_LOCK = threading.Lock()
_AUDIT_DIR = os.path.join("data", "swarm_defense")
_AUDIT_PATH = os.path.join(_AUDIT_DIR, "action_audit.jsonl")

# Acciones que el enjambre puede ejecutar automáticamente (no destructivas)
AUTO_ALLOWED = {
    "preserve_evidence",
    "increase_monitoring",
    "create_incident",
    "generate_report",
}

# Acciones que existen parcialmente vía motores reales pero REQUIEREN aprobación
APPROVAL_REQUIRED = {
    "block_ip",
    "block_domain",
    "kill_process",
    "revoke_sessions",
    "isolate_host",
    "trigger_playbook",
}

# Limitaciones explícitas (honestas)
LIMITATIONS = [
    "trigger_playbook: requiere playbook_id real y rol autorizado; NO auto-dispara playbooks (seguridad).",
    "Colmena multi-nodo: Swarm Mesh HTTP peer-to-peer (Ed25519 + AES-256-GCM + trust/revocation); bus local sigue in-process.",
    "Swarm no inventa IOCs ni rellena evidencia faltante.",
    "Kernel IA nunca ejecuta acciones; solo analiza/prioriza/propone — la decisión final es del Swarm.",
]


def action_policy(action_id: str) -> Dict[str, Any]:
    if action_id in AUTO_ALLOWED:
        return {"mode": "auto", "requires_approval": False, "decision_tier": _decision_tier(action_id)}
    if action_id in APPROVAL_REQUIRED:
        return {"mode": "approval", "requires_approval": True, "decision_tier": _decision_tier(action_id)}
    return {"mode": "unknown", "requires_approval": True, "decision_tier": "ESCALATE"}


def _decision_tier(action_id: str) -> str:
    """Map swarm action_id → MONITOR/ALERT/… vocabulary (honest capability)."""
    mapping = {
        "preserve_evidence": "MONITOR",
        "increase_monitoring": "MONITOR",
        "generate_report": "ALERT",
        "create_incident": "ESCALATE",
        "block_ip": "BLOCK",
        "block_domain": "BLOCK",
        "kill_process": "CONTAIN",
        "revoke_sessions": "CONTAIN",
        "isolate_host": "CONTAIN",
        "trigger_playbook": "REMEDIATE",
    }
    return mapping.get(action_id, "ESCALATE")


def verification_status_for_result(result: Any) -> str:
    """Honest post-action verification label — never SUCCESS without proof."""
    if result is None:
        return "NOT_VERIFIED"
    if isinstance(result, dict):
        if result.get("not_implemented") or result.get("status") == "NOT_IMPLEMENTED":
            return "NOT_IMPLEMENTED"
        if result.get("verified") is True or result.get("resolved") is True:
            return "SUCCESS"
        if result.get("verified") is False or result.get("still_present") is True:
            return "FAILED"
        if result.get("partial"):
            return "PARTIAL"
        st = str(result.get("status") or "").upper()
        if st in ("SUCCESS", "FAILED", "PARTIAL", "NOT_VERIFIED", "NOT_IMPLEMENTED"):
            return st
        if st in ("OK", "DONE", "EXECUTED") and result.get("verified") is not True:
            return "NOT_VERIFIED"
    return "NOT_VERIFIED"


def _ensure_dir() -> None:
    os.makedirs(_AUDIT_DIR, exist_ok=True)


def _seal_decision(entry: Dict[str, Any], correlation: Dict[str, Any], origin_event: Dict[str, Any]) -> None:
    """Toda decisión Swarm → forense (hash/firma/cadena)."""
    try:
        from services.forensic_custody_phase1 import seal_swarm_evidence
        import os as _os

        seal_swarm_evidence(
            node_id=_os.environ.get("NODE_ID"),
            action_id=str(entry.get("action_id") or "decision"),
            risk_level=str(
                ((correlation.get("priority") or {}).get("level"))
                or ((correlation.get("confidence") or {}).get("level"))
                or "medium"
            ),
            response={
                "status": entry.get("status"),
                "audit_id": entry.get("audit_id"),
                "result_summary": str(entry.get("result"))[:500],
            },
            correlation=correlation,
            origin_event=origin_event,
            user_email=entry.get("user_email"),
        )
    except Exception as exc:
        logger.debug("swarm forensic seal: %s", exc)


def _publish_action(entry: Dict[str, Any]) -> None:
    try:
        from services.swarm_defense.event_bus import TOPIC_ACTION, swarm_event_bus

        swarm_event_bus.publish(TOPIC_ACTION, entry)
    except Exception:
        pass


def _audit(entry: Dict[str, Any], *, correlation: Optional[Dict[str, Any]] = None, origin_event: Optional[Dict[str, Any]] = None) -> str:
    audit_id = entry.get("audit_id") or f"SWARM-ACT-{uuid.uuid4().hex[:12]}"
    entry["audit_id"] = audit_id
    entry.setdefault("ts", datetime.now(timezone.utc).isoformat())
    try:
        _ensure_dir()
        with _LOCK:
            with open(_AUDIT_PATH, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.warning("swarm action audit write: %s", exc)
    _publish_action(entry)
    if correlation is not None:
        _seal_decision(entry, correlation, origin_event or {})
    return audit_id


def execute_swarm_action(
    action_id: str,
    *,
    correlation: Dict[str, Any],
    origin_event: Dict[str, Any],
    user_email: Optional[str] = None,
    confirmed: bool = False,
    reason: str = "",
    params: Optional[dict] = None,
) -> Dict[str, Any]:
    """Ejecuta o declara transparenciamente por qué no puede ejecutarse."""
    params = params or {}
    policy = action_policy(action_id)
    collaborating = [
        c.get("module_id")
        for c in (correlation.get("contributions") or [])
        if c.get("found")
    ]
    base_audit = {
        "action_id": action_id,
        "user_email": user_email or "swarm_defense_engine",
        "reason": reason,
        "origin_motor": origin_event.get("motor"),
        "origin_action": origin_event.get("action"),
        "collaborating_modules": collaborating,
        "confidence": (correlation.get("confidence") or {}),
        "classification": (correlation.get("classification") or {}),
        "indicators_used": correlation.get("indicators") or {},
        "policy": policy,
    }

    if policy["requires_approval"] and not confirmed:
        msg = f"Acción «{action_id}» requiere aprobación explícita (política Swarm)."
        audit_id = _audit(
            {**base_audit, "status": "needs_approval", "result": msg},
            correlation=correlation,
            origin_event=origin_event,
        )
        return {"ok": False, "status": "needs_approval", "message": msg, "audit_id": audit_id}

    try:
        result = _dispatch(action_id, correlation, origin_event, user_email, params)
        if isinstance(result, dict):
            result.setdefault("verification_status", verification_status_for_result(result))
            # Honesty: "executed" without verified≠True is NOT_VERIFIED
            if result.get("status") == "executed" and result.get("verified") is not True:
                if result.get("verification_status") == "SUCCESS":
                    pass
                else:
                    result["verification_status"] = result.get("verification_status") or "NOT_VERIFIED"
        audit_id = _audit(
            {
                **base_audit,
                "status": result.get("status"),
                "result": result,
                "verification_status": (result or {}).get("verification_status"),
                "decision_tier": policy.get("decision_tier"),
            },
            correlation=correlation,
            origin_event=origin_event,
        )
        result["audit_id"] = audit_id
        return result
    except Exception as exc:
        msg = f"Acción «{action_id}» falló: {exc}"
        audit_id = _audit(
            {**base_audit, "status": "error", "result": msg, "verification_status": "FAILED"},
            correlation=correlation,
            origin_event=origin_event,
        )
        return {"ok": False, "status": "error", "message": msg, "audit_id": audit_id, "verification_status": "FAILED"}


def _dispatch(
    action_id: str,
    correlation: Dict[str, Any],
    origin_event: Dict[str, Any],
    user_email: Optional[str],
    params: dict,
) -> Dict[str, Any]:
    if action_id == "preserve_evidence":
        # Persist correlation snapshot as defense audit event (real evidence = correlation facts)
        from services.defense_coordinator import record_detection

        evidence = {
            "verified": True,
            "swarm": True,
            "confidence": correlation.get("confidence"),
            "classification": correlation.get("classification"),
            "supporting_modules": (correlation.get("classification") or {}).get("supporting_modules"),
            "indicators": correlation.get("indicators"),
            "origin_finding_id": origin_event.get("finding_id"),
        }
        rec = record_detection(
            motor="swarm_defense_engine",
            action="swarm.preserve_correlation",
            evidence=evidence,
            phase="audit",
            outcome="preserved",
            threat_type=origin_event.get("threat_type"),
            finding_id=origin_event.get("finding_id"),
            detail="Correlación Swarm preservada",
            confidence=(correlation.get("confidence") or {}).get("level"),
            user_email=user_email,
        )
        return {"ok": True, "status": "executed", "message": "Evidencia de correlación preservada", "details": rec}

    if action_id == "increase_monitoring":
        from services.defense_coordinator import record_detection

        rec = record_detection(
            motor="swarm_defense_engine",
            action="swarm.increase_monitoring",
            evidence={
                "verified": True,
                "swarm": True,
                "indicators": correlation.get("indicators"),
                "modules": (correlation.get("classification") or {}).get("supporting_modules"),
            },
            phase="detect",
            outcome="monitoring_elevated",
            threat_type=origin_event.get("threat_type"),
            finding_id=origin_event.get("finding_id"),
            detail="Monitoreo elevado por correlación Swarm",
            confidence=(correlation.get("confidence") or {}).get("level"),
            user_email=user_email,
        )
        return {"ok": True, "status": "executed", "message": "Monitoreo elevado registrado", "details": rec}

    if action_id == "create_incident":
        from services.defense_coordinator import notify_kernel_incident

        conf = correlation.get("confidence") or {}
        cls = correlation.get("classification") or {}
        finding_id = origin_event.get("finding_id") or origin_event.get("event_id")
        correlation_id = (
            origin_event.get("correlation_id")
            or (origin_event.get("evidence") or {}).get("correlation_id")
            or correlation.get("correlation_id")
        )
        detail = (
            f"Swarm correlation category={cls.get('category')} "
            f"confidence={conf.get('level')}/{conf.get('score')} "
            f"modules={cls.get('supporting_modules')}"
        )
        evidence = {
            "verified": True,
            "swarm": True,
            "source": "swarm_defense_engine",
            "finding_id": finding_id,
            "correlation_id": correlation_id,
            "indicators": correlation.get("indicators"),
            "confidence": conf,
            "classification": cls,
            "origin_event": {
                k: origin_event.get(k)
                for k in ("threat_type", "severity", "timestamp", "motor")
                if origin_event.get(k) is not None
            },
        }

        try:
            from services.imcm.store import find_incident_by_keys
            from services.imcm.engine import create_incident

            from services.tenant_scope_service import get_platform_tenant_id

            _swarm_tid = get_platform_tenant_id()
            if evidence.get("tenant_id"):
                _swarm_tid = str(evidence["tenant_id"])
            existing = find_incident_by_keys(
                tenant_id=_swarm_tid,
                finding_id=str(finding_id) if finding_id else None,
                correlation_id=str(correlation_id) if correlation_id else None,
                source_engine="swarm_defense_engine",
            )
            if existing:
                notify_kernel_incident(
                    motor="swarm_defense_engine",
                    evento="SWARM_IMCM_DEDUP",
                    detail=f"Incidente existente {existing.get('id')} — no duplicar",
                    incident_id=existing.get("id"),
                    severity="medium",
                    evidence=evidence,
                )
                return {
                    "ok": True,
                    "status": "deduplicated",
                    "message": "Incidente IMCM ya existía para este evento",
                    "imcm_incident_id": existing.get("id"),
                }

            sev_raw = conf.get("level") or origin_event.get("severity") or "medium"
            sev = str(sev_raw).upper()
            if sev in ("HIGH", "CRITICAL", "CRITICO"):
                imcm_sev = "CRITICO"
            elif sev in ("MEDIUM", "MEDIO", "ALTO"):
                imcm_sev = "ALTO"
            else:
                imcm_sev = "MEDIO"

            title = f"Swarm: {cls.get('category') or origin_event.get('threat_type') or 'correlación detectada'}"
            inc = create_incident(
                source_engine="swarm_defense_engine",
                threat_type=str(origin_event.get("threat_type") or cls.get("category") or "swarm_correlated"),
                title=title[:200],
                severity=imcm_sev,
                evidence=evidence,
                tenant_id=_swarm_tid,
            )
            notify_kernel_incident(
                motor="swarm_defense_engine",
                evento="SWARM_CORRELATED_INCIDENT",
                detail=detail,
                incident_id=inc.get("id"),
                severity=str(sev_raw),
                evidence=evidence,
            )
            return {
                "ok": True,
                "status": "executed",
                "message": "Incidente IMCM creado desde Swarm",
                "imcm_incident_id": inc.get("id"),
            }
        except Exception as exc:
            logger.warning("swarm create_incident imcm bridge: %s", exc)
            notify_kernel_incident(
                motor="swarm_defense_engine",
                evento="SWARM_CORRELATED_INCIDENT",
                detail=detail,
                incident_id=str(finding_id) if finding_id else None,
                severity="high" if conf.get("level") == "high" else "medium",
                evidence=evidence,
            )
            return {
                "ok": True,
                "status": "partial",
                "message": "Kernel notificado; IMCM no disponible",
                "error": str(exc)[:160],
            }

    if action_id == "generate_report":
        # Informe = snapshot persistido en learning store (dato real de correlación)
        from services.swarm_defense.learning import record_confirmed_incident

        path = record_confirmed_incident(correlation, origin_event, source="generate_report")
        return {
            "ok": True,
            "status": "executed",
            "message": "Informe de correlación Swarm persistido",
            "details": {"path": path},
        }

    if action_id == "block_ip":
        ips = params.get("ips") or (correlation.get("indicators") or {}).get("ips") or []
        if not ips:
            return {
                "ok": False,
                "status": "insufficient_evidence",
                "message": "No hay IP en indicadores reales para bloquear",
            }
        ip = str(ips[0])
        from services.auth_protection_service import apply_ip_block_from_scan

        result = apply_ip_block_from_scan(
            ip,
            evidence={
                "verified": True,
                "swarm": True,
                "source": "swarm_defense_engine",
                "confidence": correlation.get("confidence"),
                "collaborators": (correlation.get("classification") or {}).get("supporting_modules"),
            },
            threat_type=str(origin_event.get("threat_type") or "swarm_correlated"),
        )
        return {
            "ok": True,
            "status": "executed",
            "message": f"IP {ip} enviada a bloqueo vía auth_protection_service",
            "details": result if isinstance(result, dict) else {"result": str(result)},
        }

    if action_id == "kill_process":
        pids = params.get("pids") or (correlation.get("indicators") or {}).get("pids") or []
        if not pids:
            return {
                "ok": False,
                "status": "insufficient_evidence",
                "message": "No hay PID real en indicadores",
            }
        import psutil

        pid = int(pids[0])
        proc = psutil.Process(pid)
        name = proc.name()
        proc.terminate()
        return {
            "ok": True,
            "status": "executed",
            "message": f"Proceso {pid} ({name}) terminate() vía psutil",
            "details": {"pid": pid, "name": name},
        }

    if action_id == "trigger_playbook":
        playbook_id = params.get("playbook_id")
        if not playbook_id:
            return {
                "ok": False,
                "status": "insufficient_evidence",
                "message": "Falta playbook_id real; Swarm no elige playbooks automáticamente",
            }
        from services.playbook_service import execute_playbook

        result = execute_playbook(str(playbook_id), user_email=user_email or "swarm_defense_engine")
        return {
            "ok": True,
            "status": "executed",
            "message": f"Playbook {playbook_id} ejecutado",
            "details": result if isinstance(result, dict) else {"result": str(result)},
        }

    if action_id == "block_domain":
        domains = params.get("domains") or (correlation.get("indicators") or {}).get("domains") or []
        if not domains:
            return {
                "ok": False,
                "status": "insufficient_evidence",
                "message": "No hay dominio en indicadores reales para bloquear",
            }
        from services.swarm_defense.domain_block import block_domain

        results = []
        for d in list(domains)[:5]:
            results.append(
                block_domain(
                    str(d),
                    reason="swarm_coordinated_block_domain",
                    actor=user_email or "swarm_defense_engine",
                )
            )
        ok_any = any(r.get("ok") for r in results)
        return {
            "ok": ok_any,
            "status": "executed" if ok_any else "failed",
            "message": "Dominio(s) añadidos a blacklist Web Shield" if ok_any else "Bloqueo de dominio falló",
            "details": results,
            "motor": "web_shield_config.blacklist_domains",
        }

    if action_id == "isolate_host":
        ips = params.get("ips") or (correlation.get("indicators") or {}).get("ips") or []
        host = params.get("host") or params.get("hostname")
        if not ips and not host:
            return {
                "ok": False,
                "status": "insufficient_evidence",
                "message": "No hay IP/host en indicadores para aislar",
            }
        from services.swarm_defense.host_isolate import isolate_host_by_ip

        target_ip = str((ips or [host])[0])
        result = isolate_host_by_ip(
            target_ip,
            actor=user_email or "swarm_defense_engine",
            reason="swarm_coordinated_isolate_host",
        )
        return {
            "ok": bool(result.get("ok")),
            "status": result.get("status"),
            "message": result.get("message") or f"Aislamiento AIE para {target_ip}",
            "details": result,
            "motor": "asset_intelligence_engine",
        }

    if action_id == "revoke_sessions":
        email = (
            params.get("user_email")
            or origin_event.get("user_email")
            or (origin_event.get("evidence") or {}).get("user_email")
        )
        session_id = params.get("session_id") or (origin_event.get("evidence") or {}).get("session_id")
        from services.swarm_defense.session_revoke import revoke_user_sessions

        result = revoke_user_sessions(
            user_email=email,
            session_id=session_id,
            reason="swarm_coordinated_revoke_sessions",
            actor=user_email or "swarm_defense_engine",
        )
        return {
            "ok": bool(result.get("ok")),
            "status": result.get("status"),
            "message": "Sesiones revocadas" if result.get("ok") else result.get("message"),
            "details": result,
            "motor": "session_revocation",
        }

    return {
        "ok": False,
        "status": "unknown",
        "message": f"Acción desconocida: {action_id}",
    }


def apply_auto_responses(
    correlation: Dict[str, Any],
    origin_event: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Ejecuta solo AUTO_ALLOWED según confianza."""
    results = []
    conf_level = (correlation.get("confidence") or {}).get("level")
    if conf_level in (None, "insufficient_evidence"):
        return [
            {
                "ok": False,
                "status": "skipped",
                "message": "Evidencia insuficiente — Swarm no ejecuta respuestas automáticas",
            }
        ]

    # Siempre preservar evidencia de correlación si hay al menos low+
    for action_id in ("preserve_evidence", "increase_monitoring"):
        results.append(
            execute_swarm_action(
                action_id,
                correlation=correlation,
                origin_event=origin_event,
                user_email="swarm_defense_engine",
                confirmed=True,
                reason="auto_policy",
            )
        )

    if conf_level in ("medium", "high"):
        results.append(
            execute_swarm_action(
                "create_incident",
                correlation=correlation,
                origin_event=origin_event,
                user_email="swarm_defense_engine",
                confirmed=True,
                reason="auto_policy_confidence",
            )
        )
    if conf_level == "high":
        results.append(
            execute_swarm_action(
                "generate_report",
                correlation=correlation,
                origin_event=origin_event,
                user_email="swarm_defense_engine",
                confirmed=True,
                reason="auto_policy_high_confidence",
            )
        )
    return results


def recent_action_audits(limit: int = 50) -> List[Dict[str, Any]]:
    if not os.path.isfile(_AUDIT_PATH):
        return []
    rows = []
    try:
        with open(_AUDIT_PATH, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return []
    return rows[-limit:]
