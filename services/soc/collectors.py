#!/usr/bin/env python3
"""
Colectores SOC — envuelven motores reales.
Si falla o no hay datos: NO DISPONIBLE. Nunca inventa.
"""
from __future__ import annotations
from typing import Any, Dict, Optional
from services.soc.limitations import NA


def _safe(label: str, fn) -> Dict[str, Any]:
    try:
        data = fn()
        if data is None:
            return {"source": label, "status": NA, "available": False}
        if isinstance(data, dict) and not data:
            return {"source": label, "status": NA, "available": False, "data": {}}
        return {"source": label, "status": "ok", "available": True, "data": data}
    except Exception as exc:
        return {"source": label, "status": NA, "available": False, "error": str(exc)[:200]}


def collect_imcm(*, tenant_id: str) -> Dict[str, Any]:
    def _fn():
        from services.imcm import stats, get_dashboard

        return {"stats": stats(tenant_id=tenant_id), "dashboard": get_dashboard(tenant_id=tenant_id)}

    return _safe("imcm", _fn)


def collect_asm() -> Dict[str, Any]:
    def _fn():
        from services.asm import stats, get_dashboard
        return {"stats": stats(), "dashboard": get_dashboard()}
    return _safe("asm", _fn)


def collect_viem() -> Dict[str, Any]:
    def _fn():
        from services.viem import stats, get_dashboard
        return {"stats": stats(), "dashboard": get_dashboard()}
    return _safe("viem", _fn)


def collect_tie() -> Dict[str, Any]:
    def _fn():
        from services.threat_intelligence_enterprise import stats, get_dashboard
        return {"stats": stats(), "dashboard": get_dashboard()}
    return _safe("threat_intelligence_enterprise", _fn)


def collect_sope() -> Dict[str, Any]:
    def _fn():
        from services.sope import stats, get_dashboard, get_automation_level
        return {"stats": stats(), "dashboard": get_dashboard(), "automation_level": get_automation_level()}
    return _safe("sope", _fn)


def collect_health() -> Dict[str, Any]:
    def _fn():
        from services.health_engine import get_health_status_response
        return get_health_status_response(trigger_refresh=False)
    return _safe("health_engine", _fn)


def collect_swarm_defense() -> Dict[str, Any]:
    def _fn():
        from services.swarm_defense import swarm_defense_engine
        return swarm_defense_engine.status()
    return _safe("swarm_defense", _fn)


def collect_swarm_mesh() -> Dict[str, Any]:
    def _fn():
        from services.swarm_defense.mesh import mesh_status
        return mesh_status()
    return _safe("swarm_mesh", _fn)


def collect_cryptovault() -> Dict[str, Any]:
    def _fn():
        from crypto_vault import CryptoVault
        return CryptoVault().verify_health()
    return _safe("cryptovault", _fn)


def collect_compliance() -> Dict[str, Any]:
    def _fn():
        from services.compliance_center_service import list_audits
        audits = list_audits(limit=5)
        if not audits:
            return {"audits": [], "note": NA}
        return {"audits": audits, "latest": audits[-1] if audits else NA}
    return _safe("compliance", _fn)


def collect_defense_center() -> Dict[str, Any]:
    def _fn():
        from services.defense_center_service import get_dashboard_summary
        return get_dashboard_summary()
    return _safe("centro_defensa", _fn)


def collect_zdde() -> Dict[str, Any]:
    def _fn():
        from services.zero_day_detection.engine import get_zdde_status
        return get_zdde_status()
    return _safe("zero_day_detection", _fn)


def collect_forensic() -> Dict[str, Any]:
    def _fn():
        try:
            from services.forensic_evidence_integrity_service import get_system_summary
            return get_system_summary()
        except Exception:
            return {"status": NA}
    return _safe("forense", _fn)


def collect_kernel_status() -> Dict[str, Any]:
    def _fn():
        try:
            from services.ai_kernel import ai_kernel
            return {
                "role": "analyst_only",
                "executes_actions": False,
                "available": ai_kernel is not None,
                "logs_snippet": (ai_kernel.get_logs()[:200] if ai_kernel and hasattr(ai_kernel, "get_logs") else NA),
            }
        except Exception:
            return {"role": "analyst_only", "executes_actions": False, "available": False, "status": NA}
    return _safe("kernel_ia", _fn)


def collect_all(*, tenant_id: str) -> Dict[str, Dict[str, Any]]:
    return {
        "imcm": collect_imcm(tenant_id=tenant_id),
        "asm": collect_asm(),
        "viem": collect_viem(),
        "tie": collect_tie(),
        "sope": collect_sope(),
        "health_engine": collect_health(),
        "swarm_defense": collect_swarm_defense(),
        "swarm_mesh": collect_swarm_mesh(),
        "cryptovault": collect_cryptovault(),
        "compliance": collect_compliance(),
        "centro_defensa": collect_defense_center(),
        "zero_day_detection": collect_zdde(),
        "forense": collect_forensic(),
        "kernel_ia": collect_kernel_status(),
    }
