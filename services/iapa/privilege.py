#!/usr/bin/env python3
"""Privilege analysis — solo con evidencia objetiva."""
from __future__ import annotations
from typing import Any, Dict, List

from services.iapa.limitations import NA, NI
from services.iapa.readers import peek_sources


def privilege_analysis() -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    unavailable: List[str] = []

    # UEBA identities
    try:
        from services.identity_intelligence import list_identities, compute_risk_score, get_baseline
        idents = list_identities()
        admins = []
        service_accounts = []
        inactive = []
        for i in idents:
            label = (i.get("label") or "").lower()
            itype = i.get("type")
            if itype == "cuenta_servicio":
                service_accounts.append({"uuid": i.get("uuid"), "label": i.get("label")})
            if "admin" in label or "administrador" in label or "root" in label:
                admins.append({"uuid": i.get("uuid"), "label": i.get("label"), "type": itype})
            # inactive: no recent observation — only if observation_count and last_seen suggest stale
            # Without authoritative HR/AD source, mark inheritance/inactive as NI unless weak signal
            if itype == "usuario" and int(i.get("observation_count") or 0) < 2:
                inactive.append({"uuid": i.get("uuid"), "label": i.get("label"), "note": "pocas observaciones UEBA"})

        for a in admins:
            findings.append({
                "type": "administrador",
                "identity": a,
                "explanation": f"Etiqueta/nombre indica administrador: {a.get('label')}.",
                "invented": False,
            })
        for s in service_accounts:
            findings.append({
                "type": "cuenta_servicio",
                "identity": s,
                "explanation": "Identidad tipo cuenta_servicio observada por UEBA/psutil.",
                "invented": False,
            })

        # Identity risk from UEBA
        risks = []
        for u in [i for i in idents if i.get("type") == "usuario"][:10]:
            r = compute_risk_score(u["uuid"])
            risks.append({
                "uuid": u["uuid"],
                "label": u.get("label"),
                "score": r.get("score"),
                "confidence": r.get("confidence"),
                "status": r.get("status"),
            })

        excessive = NA  # requires IAM policy source
        inheritance = NI
        unavailable.append(f"privilegios_excesivos: {NI} (sin fuente IAM/AD de permisos)")
        unavailable.append(f"herencia_permisos: {inheritance}")

        return {
            "ok": True,
            "findings": findings,
            "admins": admins or NA,
            "service_accounts": service_accounts or NA,
            "inactive_candidates": inactive or NA,
            "identity_risks": risks or NA,
            "excessive_privileges": excessive,
            "permission_inheritance": inheritance,
            "unavailable": unavailable,
            "invented": False,
        }
    except Exception as exc:
        return {
            "ok": True,
            "findings": [],
            "message": NA,
            "error": str(exc)[:160],
            "unavailable": [f"UEBA: {NA}"],
            "invented": False,
        }
