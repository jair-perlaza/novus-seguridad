#!/usr/bin/env python3
"""Kernel IA console for SOC — solo analisis. executes_actions=false."""
from __future__ import annotations
from typing import Any, Dict, List
from services.soc.limitations import NA


def ask_kernel(question: str, *, tenant_id: str) -> Dict[str, Any]:
    q = (question or "").strip().lower()
    tid = str(tenant_id or "").strip()
    answer_parts: List[str] = []
    evidence: Dict[str, Any] = {}
    confidence = NA

    # Critical incident
    if "incidente" in q and ("crítico" in q or "critico" in q or "mayor" in q):
        try:
            from services.imcm import get_dashboard, get_incident
            dash = get_dashboard(tenant_id=tid)
            recent = dash.get("recent_incidents") or []
            critical = [i for i in recent if str(i.get("severity", "")).upper() in ("CRITICO", "CRITICAL", "CRITICA")]
            pool = critical or recent
            if pool:
                top = pool[0]
                answer_parts.append(f"Incidente mas critico observado: {top.get('id')} — {top.get('title')} (severidad={top.get('severity')}, estado={top.get('estado')}).")
                evidence["incident"] = {"id": top.get("id"), "severity": top.get("severity"), "source": top.get("source_engine")}
                confidence = "basada en IMCM reciente"
            else:
                answer_parts.append(f"No hay incidentes en IMCM. {NA}")
        except Exception as exc:
            answer_parts.append(f"IMCM no disponible: {exc}")

    # Highest risk asset
    if "activo" in q and ("riesgo" in q or "mayor" in q or "compromet"):
        try:
            from services.asm import get_dashboard
            dash = get_dashboard(tenant_id=tid)
            evidence["asm"] = {"available": True, "summary_keys": list(dash.keys())[:8] if isinstance(dash, dict) else []}
            host = (dash.get("local_host") or dash.get("host") or {}) if isinstance(dash, dict) else {}
            exposure = dash.get("exposure") if isinstance(dash, dict) else None
            if host or exposure:
                answer_parts.append(
                    f"Activo local ASM: hostname={host.get('hostname', NA)}, ip={host.get('ip', NA)}, "
                    f"exposure={exposure if exposure is not None else NA}."
                )
                confidence = "basada en ASM"
            else:
                answer_parts.append(f"ASM sin inventario suficiente. {NA}")
        except Exception as exc:
            answer_parts.append(f"ASM no disponible: {exc}")

    # CVE exploitation
    if "cve" in q or "vulnerabilidad" in q or "explotad" in q:
        try:
            from services.viem import get_dashboard, search_vulns
            dash = get_dashboard(tenant_id=tid)
            vulns = search_vulns(risk_level="CRITICO", limit=5) or search_vulns(limit=5)
            if vulns:
                v = vulns[0]
                answer_parts.append(
                    f"Vulnerabilidad de mayor riesgo en VIEM: {v.get('title') or v.get('id') or NA} "
                    f"(risk={v.get('risk_level') or v.get('risk_score', NA)})."
                )
                evidence["viem"] = {"top": {"id": v.get("id"), "risk": v.get("risk_level") or v.get("risk_score")}}
                confidence = "basada en VIEM"
            else:
                answer_parts.append(f"VIEM sin vulnerabilidades registradas. {NA}")
            evidence["viem_dashboard"] = dash.get("summary") if isinstance(dash, dict) else NA
        except Exception as exc:
            answer_parts.append(f"VIEM no disponible: {exc}")

    # User who started activity
    if "usuario" in q:
        try:
            from services.imcm import get_dashboard
            dash = get_dashboard(tenant_id=tid)
            recent = dash.get("recent_incidents") or []
            users = [i.get("user") for i in recent if i.get("user")]
            if users:
                answer_parts.append(f"Usuarios asociados a incidentes recientes: {', '.join(str(u) for u in users[:5])}.")
                evidence["users"] = users[:5]
                confidence = "basada en IMCM"
            else:
                answer_parts.append(f"Ningun usuario asociado en incidentes IMCM. {NA}")
        except Exception as exc:
            answer_parts.append(f"IMCM no disponible: {exc}")

    # Propagation
    if "propaga" in q or "lateral" in q:
        try:
            from services.imcm import search_incidents
            laterals = search_incidents(threat_type="lateral_movement", limit=5, tenant_id=tid)
            if laterals:
                answer_parts.append(
                    f"Incidentes con potencial de propagacion (lateral_movement): "
                    + ", ".join(i.get("id", "") for i in laterals)
                )
                evidence["lateral"] = [i.get("id") for i in laterals]
                confidence = "basada en IMCM threat_type"
            else:
                answer_parts.append(f"Sin incidentes de movimiento lateral en IMCM. {NA}")
        except Exception as exc:
            answer_parts.append(f"IMCM no disponible: {exc}")

    # Playbook recommendation
    if "playbook" in q or "recomienda" in q:
        try:
            from services.imcm import get_dashboard
            from services.sope import get_automation_level
            dash = get_dashboard(tenant_id=tid)
            recent = dash.get("recent_incidents") or []
            if recent:
                top = recent[0]
                sope = top.get("sope") or {}
                answer_parts.append(
                    f"Para {top.get('id')} SOPE sugiere playbook={sope.get('playbook_nombre') or sope.get('playbook_id') or NA} "
                    f"(nivel automatizacion={get_automation_level()}). Kernel NO ejecuta acciones."
                )
                evidence["sope"] = sope
                confidence = "basada en SOPE+IMCM"
            else:
                answer_parts.append(f"Sin incidentes para recomendar playbook. {NA}")
        except Exception as exc:
            answer_parts.append(f"SOPE/IMCM no disponible: {exc}")

    if not answer_parts:
        # Generic: summarize risk from IMCM + VIEM without inventing
        try:
            from services.imcm import stats as imcm_stats
            st = imcm_stats(tenant_id=tid)
            answer_parts.append(f"Contexto IMCM: total={st.get('total')}, nuevo={st.get('nuevo')}, cerrado={st.get('cerrado')}.")
            evidence["imcm_stats"] = st
            confidence = "basada en IMCM stats"
        except Exception:
            answer_parts.append(f"No se pudo interpretar la pregunta con motores disponibles. {NA}")

    return {
        "question": question,
        "answer": " ".join(answer_parts),
        "evidence": evidence,
        "confidence": confidence,
        "role": "analyst_only",
        "executes_actions": False,
        "invented": False,
    }
