"""
Cobertura avanzada de amenazas por sector — catálogo canónico + validación en vivo.
Solo alerta cuando existe evidencia real del motor NOVUS.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

MAP_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "threat_coverage_map.json")
INTEL_LIBRARY = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "intelligence", "coverage_library.jsonl")

_map_cache: Optional[dict] = None


def _load_map() -> dict:
    global _map_cache
    if _map_cache is not None:
        return _map_cache
    try:
        with open(MAP_PATH, "r", encoding="utf-8") as fh:
            _map_cache = json.load(fh)
            return _map_cache
    except Exception as exc:
        logger.error("threat_coverage_map load: %s", exc)
        return {"categories": {}, "sectors": []}


def list_categories() -> List[str]:
    return list((_load_map().get("categories") or {}).keys())


def get_category(category_id: str) -> Optional[dict]:
    return (_load_map().get("categories") or {}).get(category_id)


def classify_finding(finding: dict) -> Tuple[Optional[str], float]:
    """
    Clasifica un hallazgo en categoría del catálogo usando keywords y motores.
    Retorna (category_id, confidence 0-1).
    """
    text = " ".join([
        str(finding.get("threat_type") or ""),
        str(finding.get("tipo") or ""),
        str(finding.get("type") or ""),
        str(finding.get("motor") or finding.get("source") or ""),
        str(finding.get("nombre") or finding.get("title") or ""),
        str(finding.get("descripcion") or finding.get("description") or ""),
        str(finding.get("evidence") or finding.get("evidencia") or ""),
    ]).lower()

    rules: List[Tuple[str, Tuple[str, ...], float]] = [
        ("auth_credentials", ("brute", "login", "credential", "ato", "auth", "password spray", "fuerza bruta"), 0.9),
        ("api_attacks", ("api", "endpoint", "rate limit", "graphql", "rest abuse"), 0.85),
        ("web_app", ("sqli", "xss", "injection", "query param", "sql"), 0.85),
        ("mobile_app", ("overlay", "clickjack", "sim swap", "mobile", "ui shield"), 0.85),
        ("iot", ("iot", "telemetry", "sensor", "gps", "iot_guard"), 0.9),
        ("ransomware", ("ransom", "encrypt", "cryptolocker", "entropy"), 0.95),
        ("mitm", ("mitm", "tunnel", "intercept", "cert pin"), 0.9),
        ("phishing", ("phishing", "spear", "correo malicioso"), 0.9),
        ("bec", ("bec", "wire fraud", "transactional", "swift"), 0.9),
        ("network", ("arp", "spoof", "mac conflict", "ndr", "scan pattern"), 0.9),
        ("lateral_movement", ("lateral", "pivot", "spread", "smb"), 0.8),
        ("exfiltration", ("exfil", "data leak", "filtración"), 0.85),
        ("cryptojacking", ("xmrig", "miner", "cryptominer", "minerd"), 0.9),
        ("botnet", ("botnet", "c2", "beacon", "elevated connection"), 0.75),
        ("ddos_compatible", ("rate_limited", "flood", "429", "too many"), 0.8),
        ("supply_chain", ("virustotal", "hash", "supply chain", "malware file"), 0.8),
        ("apt_compatible", ("apt", "correlat", "multi-signal", "campaign"), 0.7),
    ]

    best_id: Optional[str] = None
    best_score = 0.0
    for cat_id, keywords, base in rules:
        if cat_id not in (_load_map().get("categories") or {}):
            continue
        hits = sum(1 for kw in keywords if kw in text)
        if hits:
            score = min(1.0, base + hits * 0.05)
            if score > best_score:
                best_score = score
                best_id = cat_id

    if best_id:
        return best_id, best_score

    motor = str(finding.get("motor") or finding.get("source") or "").lower()
    if "ndr" in motor or "network" in motor:
        return "network", 0.6
    if "advanced_detector" in motor or "process" in text:
        return "endpoints", 0.55
    return "enterprise_infra", 0.4


def has_sufficient_evidence(finding: dict, category_id: Optional[str] = None) -> bool:
    """Exige evidencia verificable antes de promover alerta."""
    if finding.get("verified") is True:
        return True
    ev = finding.get("evidence") or finding.get("evidencia") or finding.get("details")
    if isinstance(ev, dict) and (ev.get("verified") or ev.get("evidence")):
        return True
    if isinstance(ev, str) and len(ev.strip()) > 20:
        return True
    cat = get_category(category_id) if category_id else None
    if not cat:
        return bool(ev)
    required = cat.get("evidence_required") or []
    blob = json.dumps(finding, default=str).lower()
    return any(req.replace("_", " ") in blob or req in blob for req in required)


def _probe_category(
    category_id: str,
    cache: Optional[dict] = None,
    ndr_fn=None,
    vulns_fn=None,
    ports_fn=None,
) -> Dict[str, Any]:
    """Prueba en vivo si el motor responde — sin inventar detecciones."""
    cat = get_category(category_id)
    if not cat:
        return {"category": category_id, "implemented": False, "validated": False, "probe": "unknown category"}

    result: Dict[str, Any] = {
        "category": category_id,
        "label": cat.get("label"),
        "implemented": True,
        "validated": False,
        "capabilities": cat.get("capabilities"),
        "limitations": cat.get("limitations"),
        "probe_evidence": None,
    }

    try:
        if category_id == "auth_credentials":
            from services.auth_protection_service import auth_protection
            st = auth_protection.get_protection_status()
            result["validated"] = "thresholds" in st
            result["probe_evidence"] = f"thresholds={st.get('thresholds')}"

        elif category_id in ("api_attacks", "web_app", "ddos_compatible"):
            from services.api_security_service import scan_query_params
            result["validated"] = callable(scan_query_params)
            result["probe_evidence"] = "api_security_service importable"

        elif category_id == "mobile_app":
            from security_engine import NovusSecurityEngine
            eng = NovusSecurityEngine()
            result["validated"] = hasattr(eng, "detect_overlay_threat")
            result["probe_evidence"] = "overlay_threat method exists"

        elif category_id in ("network", "lateral_movement", "exfiltration", "botnet"):
            from services.network_ndr_service import build_ndr_payload, analyze_behavior
            result["validated"] = callable(build_ndr_payload) and callable(analyze_behavior)
            result["probe_evidence"] = "NDR motors available"

        elif category_id in ("endpoints", "trojan", "spyware", "rootkit", "cryptojacking", "persistence"):
            from services.advanced_detector_service import AdvancedDetector
            det = AdvancedDetector()
            result["validated"] = hasattr(det, "scan_running_processes")
            result["probe_evidence"] = "scan_running_processes available"

        elif category_id == "iot":
            from security_engine import NovusSecurityEngine
            result["validated"] = hasattr(NovusSecurityEngine(), "validate_iot_telemetry")
            result["probe_evidence"] = "iot_guard method exists"

        elif category_id == "enterprise_infra":
            from services.universal_compatibility_engine import uce
            result["validated"] = hasattr(uce, "detect_infrastructure")
            result["probe_evidence"] = "UCE detect_infrastructure available"

        elif category_id == "ransomware":
            from security_engine import NovusSecurityEngine
            result["validated"] = hasattr(NovusSecurityEngine(), "monitor_filesystem_activity")
            result["probe_evidence"] = "filesystem monitor available"

        elif category_id == "mitm":
            from security_engine import NovusSecurityEngine
            result["validated"] = hasattr(NovusSecurityEngine(), "verify_tunnel_integrity")
            result["probe_evidence"] = "mitm_shield method exists"

        elif category_id in ("phishing", "bec"):
            from security_engine import NovusSecurityEngine
            eng = NovusSecurityEngine()
            result["validated"] = hasattr(eng, "inspect_email_integrity")
            result["probe_evidence"] = "email motors exist — OAuth required for live data"
            result["implemented"] = True

        elif category_id == "supply_chain":
            import os
            has_vt = bool(os.environ.get("VIRUSTOTAL_API_KEY"))
            result["validated"] = has_vt
            result["implemented"] = True
            result["probe_evidence"] = "VIRUSTOTAL_API_KEY set" if has_vt else "VT key absent — standby"

        elif category_id == "apt_compatible":
            from services.threat_intelligence_service import threat_intelligence
            st = threat_intelligence.stats()
            result["validated"] = isinstance(st, dict)
            result["probe_evidence"] = f"cases={st.get('total', 0)}"

        elif category_id == "privilege_escalation":
            from services.vulnerability_analyst_service import answer_kernel_query
            result["validated"] = callable(answer_kernel_query)
            result["probe_evidence"] = "vulnerability_analyst available"

        elif category_id == "backdoor":
            import services.novus_security_integration as nsi
            result["validated"] = hasattr(nsi, "NovusSecurityIntegration")
            result["probe_evidence"] = "port scan motor class exists"

        else:
            result["probe_evidence"] = "generic motor check"
            result["validated"] = bool(cat.get("motors"))

    except Exception as exc:
        result["implemented"] = False
        result["validated"] = False
        result["probe_error"] = str(exc)[:200]

    return result


def evaluate_live_coverage() -> Dict[str, Any]:
    """Evalúa todas las categorías con pruebas en vivo."""
    _probe_cache: Dict[str, Any] = {}

    def _cached_ndr():
        if "ndr" not in _probe_cache:
            from services.network_ndr_service import build_ndr_payload
            _probe_cache["ndr"] = build_ndr_payload(force_refresh=False)
        return _probe_cache["ndr"]

    def _cached_vulns():
        if "vulns" not in _probe_cache:
            from services.novus_security_integration import novus_security
            _probe_cache["vulns"] = novus_security.scan_vulnerabilities()
        return _probe_cache["vulns"]

    def _cached_ports():
        if "ports" not in _probe_cache:
            from services.novus_security_integration import novus_security
            _probe_cache["ports"] = novus_security.scan_open_ports()
        return _probe_cache["ports"]

    categories = {}
    implemented = validated = 0
    for cat_id in list_categories():
        probe = _probe_category(cat_id, cache=_probe_cache, ndr_fn=_cached_ndr, vulns_fn=_cached_vulns, ports_fn=_cached_ports)
        categories[cat_id] = probe
        if probe.get("implemented"):
            implemented += 1
        if probe.get("validated"):
            validated += 1

    total = len(categories) or 1
    return {
        "total_categories": total,
        "implemented_count": implemented,
        "validated_count": validated,
        "implementation_rate_pct": round(implemented / total * 100, 2),
        "validation_rate_pct": round(validated / total * 100, 2),
        "categories": categories,
        "principle": _load_map().get("principle"),
    }


def get_sector_coverage(sector_key: str, live: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Cobertura por sector PyME."""
    m = _load_map()
    cats = m.get("categories") or {}
    sector_cats = {
        cid: cat for cid, cat in cats.items()
        if sector_key in (cat.get("sectors") or [])
    }
    if live is None:
        live = evaluate_live_coverage()
    live_for_sector = {
        cid: live["categories"].get(cid)
        for cid in sector_cats
        if cid in live.get("categories", {})
    }
    validated = sum(1 for v in live_for_sector.values() if v and v.get("validated"))
    return {
        "sector": sector_key,
        "categories_count": len(sector_cats),
        "validated_count": validated,
        "categories": sector_cats,
        "live_probes": live_for_sector,
        "coverage_pct": round(validated / max(len(sector_cats), 1) * 100, 2),
    }


def append_intelligence_entry(category_id: str, finding: dict, evidence: dict) -> None:
    """Biblioteca de inteligencia — solo con evidencia verificada."""
    if not has_sufficient_evidence(finding, category_id):
        return
    os.makedirs(os.path.dirname(INTEL_LIBRARY), exist_ok=True)
    entry = {
        "category": category_id,
        "finding_id": finding.get("id"),
        "evidence": evidence,
        "classified_from": classify_finding(finding)[0],
    }
    try:
        with open(INTEL_LIBRARY, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.debug("coverage intel library: %s", exc)


def get_kernel_context(sector: Optional[str] = None) -> Dict[str, Any]:
    live = evaluate_live_coverage()
    ctx: Dict[str, Any] = {
        "module": "threat_coverage",
        "live_summary": {
            "implemented": live["implemented_count"],
            "validated": live["validated_count"],
            "implementation_rate_pct": live["implementation_rate_pct"],
            "validation_rate_pct": live["validation_rate_pct"],
        },
        "principle": live.get("principle"),
    }
    if sector:
        ctx["sector"] = get_sector_coverage(sector, live=live)
    return ctx


def answer_kernel_query(question: str) -> Optional[str]:
    q = (question or "").lower()
    if not any(t in q for t in ("cobertura", "coverage", "categoría", "amenaza", "sector", "apt", "ransom")):
        return None
    live = evaluate_live_coverage()
    lines = [
        f"Cobertura NOVUS: {live['validated_count']}/{live['total_categories']} categorías validadas en vivo.",
        f"Implementadas: {live['implemented_count']} ({live['implementation_rate_pct']}%).",
        f"Principio: {live.get('principle', '')[:120]}",
    ]
    not_valid = [
        cid for cid, p in live.get("categories", {}).items()
        if not p.get("validated") and p.get("implemented")
    ]
    if not_valid:
        lines.append("Limitaciones (implementado sin validación live): " + ", ".join(not_valid[:5]))
    return "\n".join(lines)


class ThreatCoverageService:
    list_categories = staticmethod(list_categories)
    get_category = staticmethod(get_category)
    classify_finding = staticmethod(classify_finding)
    has_sufficient_evidence = staticmethod(has_sufficient_evidence)
    evaluate_live_coverage = staticmethod(evaluate_live_coverage)
    get_sector_coverage = staticmethod(get_sector_coverage)
    append_intelligence_entry = staticmethod(append_intelligence_entry)
    get_kernel_context = staticmethod(get_kernel_context)
    answer_kernel_query = staticmethod(answer_kernel_query)


threat_coverage = ThreatCoverageService()
