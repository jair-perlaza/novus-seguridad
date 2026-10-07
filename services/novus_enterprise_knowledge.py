"""
NOVUS Enterprise Knowledge — taxonomía y vocabulario para IA Kernel.

SOLO conocimiento / clasificación / recomendación.
Las acciones de mitigación se enrutan a motores REALES de NOVUS cuando existen;
de lo contrario se marcan NOT_IMPLEMENTED (sin simulación).
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

# --- Vocabulario canónico (subset representativo; extensible) ---

_MITRE_TACTICS = {
    "initial_access": {"mitre_id": "TA0001", "category": "MITRE_TACTIC"},
    "execution": {"mitre_id": "TA0002", "category": "MITRE_TACTIC"},
    "persistence": {"mitre_id": "TA0003", "category": "MITRE_TACTIC"},
    "privilege_escalation": {"mitre_id": "TA0004", "category": "MITRE_TACTIC"},
    "defense_evasion": {"mitre_id": "TA0005", "category": "MITRE_TACTIC"},
    "credential_access": {"mitre_id": "TA0006", "category": "MITRE_TACTIC"},
    "discovery": {"mitre_id": "TA0007", "category": "MITRE_TACTIC"},
    "lateral_movement": {"mitre_id": "TA0008", "category": "MITRE_TACTIC"},
    "collection": {"mitre_id": "TA0009", "category": "MITRE_TACTIC"},
    "exfiltration": {"mitre_id": "TA0010", "category": "MITRE_TACTIC"},
    "command_and_control": {"mitre_id": "TA0011", "category": "MITRE_TACTIC"},
    "impact": {"mitre_id": "TA0040", "category": "MITRE_TACTIC"},
}

_MALWARE_FAMILIES = {
    "emotet": {"category": "MALWARE", "severity": "high"},
    "trickbot": {"category": "MALWARE", "severity": "high"},
    "ryuk": {"category": "RANSOMWARE", "severity": "critical"},
    "lockbit": {"category": "RANSOMWARE", "severity": "critical"},
    "qakbot": {"category": "MALWARE", "severity": "high"},
    "cobalt_strike": {"category": "C2_FRAMEWORK", "severity": "critical"},
}

_IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b[a-z0-9][a-z0-9.-]+\.[a-z]{2,}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
}

_SECTOR_TERMS = {
    "fintech": {"category": "SECTOR", "threats": ["ato", "wire_fraud", "api_abuse"]},
    "logistics": {"category": "SECTOR", "threats": ["supply_chain", "gps_spoofing"]},
    "healthcare": {"category": "SECTOR", "threats": ["phi_exfiltration", "ransomware"]},
    "retail": {"category": "SECTOR", "threats": ["pos_malware", "skimming"]},
}

_SECURITY_TERMS = {
    "phishing": {"category": "ATTACK", "mitre": "initial_access"},
    "spear_phishing": {"category": "ATTACK", "mitre": "initial_access"},
    "brute_force": {"category": "ATTACK", "mitre": "credential_access"},
    "sql_injection": {"category": "ATTACK", "mitre": "initial_access"},
    "xss": {"category": "ATTACK", "mitre": "initial_access"},
    "ddos": {"category": "ATTACK", "mitre": "impact"},
    "arp_spoofing": {"category": "NETWORK", "mitre": "credential_access"},
    "mitm": {"category": "NETWORK", "mitre": "collection"},
    "ransomware": {"category": "MALWARE", "mitre": "impact"},
    "zero_trust": {"category": "CONCEPT"},
    "siem": {"category": "CONCEPT"},
    "xdr": {"category": "CONCEPT"},
    "ueba": {"category": "CONCEPT"},
    "forensics": {"category": "CONCEPT"},
    "aes_gcm": {"category": "CRYPTO"},
    "tls": {"category": "PROTOCOL"},
    "oauth": {"category": "AUTH"},
    "mfa": {"category": "AUTH"},
}


def _build_term_index() -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}
    for name, meta in _MITRE_TACTICS.items():
        idx[name.replace("_", " ")] = {**meta, "term": name}
        idx[name] = {**meta, "term": name}
    for name, meta in _MALWARE_FAMILIES.items():
        idx[name] = {**meta, "term": name}
    for name, meta in _SECTOR_TERMS.items():
        idx[name] = {**meta, "term": name}
    for name, meta in _SECURITY_TERMS.items():
        idx[name.replace("_", " ")] = {**meta, "term": name}
        idx[name] = {**meta, "term": name}
    return idx


class NOVUSVocabularyRegistry:
    """Registro de términos — NO ejecuta acciones."""

    def __init__(self) -> None:
        self.term_index = _build_term_index()
        self.threat_vectors = list(_MALWARE_FAMILIES.keys())
        self.term_count = len(self.term_index)

    def match_terms(self, text: str) -> List[Dict[str, Any]]:
        if not text:
            return []
        low = text.lower()
        hits: List[Dict[str, Any]] = []
        seen = set()
        for term, meta in self.term_index.items():
            if term in low and term not in seen:
                seen.add(term)
                hits.append({"term": term, "meta": meta})
                if len(hits) >= 30:
                    break
        for ioc_type, pat in _IOC_PATTERNS.items():
            for m in pat.findall(text):
                key = f"{ioc_type}:{m}"
                if key not in seen:
                    seen.add(key)
                    hits.append({"term": m, "meta": {"category": "IOC", "ioc_type": ioc_type}})
        return hits


# Acciones documentadas en taxonomía enterprise — verificar existencia REAL en NOVUS
_DOCUMENTED_ACTIONS = frozenset({
    "block_ip",
    "isolate_host",
    "isolate_asset",
    "scan_network",
    "scan_vulnerabilities",
    "record_detection",
    "execute_rate_limit_and_mfa_enforcement",
    "isolate_transaction_pipeline_and_verify_signatures",
    "trigger_biometric_stepup_auth",
    "block_bin_range_and_enable_3ds2",
})


def _real_action_handlers() -> Dict[str, Callable[..., Dict[str, Any]]]:
    """Solo handlers que existen en el codebase NOVUS."""

    def _block_ip(ctx: Dict[str, Any]) -> Dict[str, Any]:
        ip = ctx.get("ip") or ctx.get("origin_ip")
        if not ip:
            return {"status": "error", "message": "IP requerida", "implemented": True}
        from services.os_firewall_service import block_ip_os

        return {**block_ip_os(str(ip)), "implemented": True, "action": "block_ip"}

    def _isolate_asset(ctx: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = ctx.get("asset_id") or ctx.get("ip") or ctx.get("device_ip")
        if not asset_id:
            return {"status": "error", "message": "asset_id/IP requerido", "implemented": True}
        from services.asset_intelligence_engine import apply_admin_action

        return {
            **apply_admin_action(str(asset_id), action="isolate", reason=ctx.get("reason") or "kernel_knowledge"),
            "implemented": True,
            "action": "isolate_asset",
            "note": "Marca en inventario AIE — no aislamiento OS garantizado",
        }

    def _scan_network(ctx: Dict[str, Any]) -> Dict[str, Any]:
        from services.network_scan_coordinator import schedule_network_discovery

        schedule_network_discovery(consumer="enterprise_knowledge", force=False)
        return {"status": "scheduled", "implemented": True, "action": "scan_network"}

    def _record_detection(ctx: Dict[str, Any]) -> Dict[str, Any]:
        from services.defense_coordinator import record_detection

        record_detection(
            source=ctx.get("source") or "enterprise_knowledge",
            threat_type=ctx.get("threat_type") or ctx.get("type") or "knowledge_match",
            severity=ctx.get("severity") or "medium",
            message=ctx.get("message") or "Enterprise knowledge correlation",
            details=ctx.get("details") or {},
        )
        return {"status": "recorded", "implemented": True, "action": "record_detection"}

    return {
        "block_ip": _block_ip,
        "isolate_host": _isolate_asset,
        "isolate_asset": _isolate_asset,
        "scan_network": _scan_network,
        "record_detection": _record_detection,
    }


class NOVUSCoreDispatcher:
    """
    Analiza eventos con vocabulario enterprise.
    NO simula mitigaciones — asyncio.sleep eliminado por diseño.
    """

    def __init__(self, registry: Optional[NOVUSVocabularyRegistry] = None) -> None:
        self.registry = registry or NOVUSVocabularyRegistry()
        self._handlers = _real_action_handlers()

    def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        text = " ".join(
            str(event.get(k) or "")
            for k in ("message", "description", "type", "source", "module", "raw", "indicator")
        ).strip()
        sector = (event.get("sector") or event.get("sector_target") or "INFRASTRUCTURE").upper()
        matches = self.registry.match_terms(text)
        score = min(100, 10 + len(matches) * 8)

        mitigations: List[Dict[str, Any]] = []
        for m in matches[:5]:
            cat = (m.get("meta") or {}).get("category")
            if cat in ("MALWARE", "RANSOMWARE", "ATTACK"):
                mitigations.append({
                    "action": "record_detection",
                    "execution_mode": "RECOMMENDATION_ONLY",
                    "reason": f"Match {m.get('term')}",
                })
                mitigations.append({
                    "action": "isolate_asset",
                    "execution_mode": "RECOMMENDATION_ONLY",
                    "reason": "Evaluar aislamiento en inventario si hay activo identificado",
                })

        playbook = None
        if any((m.get("meta") or {}).get("category") == "RANSOMWARE" for m in matches):
            playbook = "ransomware_containment_v1"
            score = max(score, 75)

        return {
            "status": "ok" if matches else "no_match",
            "sector": sector,
            "matches": matches,
            "ANALYTICAL_SCORE": score,
            "risk_score": score,
            "threat_vector": matches[0].get("term") if matches else None,
            "playbook": playbook,
            "mitigations": mitigations,
            "actions": mitigations,
            "invented": False,
        }

    def execute_action(self, action: str, context: Dict[str, Any], *, authorized: bool = False) -> Dict[str, Any]:
        """
        Ejecuta SOLO si authorized=True y existe handler real.
        Acciones fintech/documentadas sin handler → NOT_IMPLEMENTED.
        """
        action = (action or "").strip().lower()
        if action not in _DOCUMENTED_ACTIONS:
            return {"status": "NOT_IMPLEMENTED", "action": action, "implemented": False}
        handler = self._handlers.get(action)
        if handler is None:
            return {
                "status": "NOT_IMPLEMENTED",
                "action": action,
                "implemented": False,
                "message": "Acción documentada en taxonomía pero sin motor/enforcer en NOVUS",
            }
        if not authorized:
            return {
                "status": "RECOMMENDATION_ONLY",
                "action": action,
                "implemented": True,
                "message": "Requiere confirmación explícita del operador",
            }
        try:
            return handler(context)
        except Exception as exc:
            return {"status": "error", "action": action, "implemented": True, "message": str(exc)[:200]}

    async def _execute_automated_mitigation(self, action: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Compatibilidad async — delega a execute_action sin sleep/simulación."""
        return self.execute_action(action, context, authorized=bool(context.get("authorized")))
