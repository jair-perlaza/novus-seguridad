"""
Puente entre IA Kernel y novus_enterprise_knowledge (taxonomía / vocabulario).
Singleton — no reinicializa 1000+ términos por request.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from utils.logger import logger

_lock = threading.Lock()
_registry = None
_dispatcher = None
_load_error: Optional[str] = None
_MODULE_PATH = "services.novus_enterprise_knowledge"


def _load_module():
    global _registry, _dispatcher, _load_error
    with _lock:
        if _registry is not None or _load_error:
            return
        try:
            import importlib

            mod = importlib.import_module(_MODULE_PATH.replace("/", ".").replace("\\", "."))
            if hasattr(mod, "NOVUSVocabularyRegistry"):
                _registry = mod.NOVUSVocabularyRegistry()
            if hasattr(mod, "NOVUSCoreDispatcher"):
                _dispatcher = mod.NOVUSCoreDispatcher()
            if _registry is None and _dispatcher is None:
                _load_error = "novus_enterprise_knowledge: no registry/dispatcher exported"
        except ImportError as exc:
            _load_error = f"Module not found: {_MODULE_PATH} ({exc})"
            logger.info("Enterprise knowledge module not loaded: %s", _load_error)
        except Exception as exc:
            _load_error = str(exc)
            logger.warning("Enterprise knowledge load failed: %s", exc)


def get_knowledge_status() -> Dict[str, Any]:
    _load_module()
    term_count = 0
    vector_count = 0
    if _registry is not None:
        idx = getattr(_registry, "term_index", None) or {}
        term_count = len(idx) if isinstance(idx, dict) else getattr(_registry, "term_count", 0)
        vectors = getattr(_registry, "threat_vectors", None) or getattr(_registry, "vectors", None)
        if vectors is not None:
            vector_count = len(vectors) if hasattr(vectors, "__len__") else 0
    return {
        "loaded": _load_error is None and (_registry is not None or _dispatcher is not None),
        "error": _load_error,
        "module": _MODULE_PATH,
        "term_count": term_count,
        "vector_count": vector_count,
    }


def analyze_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analiza evento real de NOVUS con vocabulario enterprise.
    NO ejecuta mitigaciones simuladas como acciones reales.
    """
    _load_module()
    if _load_error or (_registry is None and _dispatcher is None):
        return {
            "status": "NOT_IMPLEMENTED",
            "message": _load_error or "Enterprise knowledge module not available",
            "recommendations": [],
            "actions_executed": [],
            "actions_recommendation_only": [],
            "invented": False,
        }

    text = " ".join(
        str(event.get(k) or "")
        for k in ("message", "description", "type", "source", "module", "raw")
    ).strip()
    sector = (event.get("sector") or event.get("sector_target") or "INFRASTRUCTURE").upper()

    matches: List[Dict[str, Any]] = []
    risk_score = None
    threat_vector = None
    playbook = None

    try:
        if _registry is not None and hasattr(_registry, "match_terms"):
            matches = _registry.match_terms(text) or []
        elif _registry is not None and hasattr(_registry, "term_index"):
            low = text.lower()
            for term, meta in (getattr(_registry, "term_index", {}) or {}).items():
                if term.lower() in low:
                    matches.append({"term": term, "meta": meta})
                    if len(matches) >= 20:
                        break
    except Exception as exc:
        logger.debug("knowledge term match: %s", exc)

    recommendations: List[Dict[str, Any]] = []
    executed: List[Dict[str, Any]] = []
    recommendation_only: List[Dict[str, Any]] = []

    if _dispatcher is not None and hasattr(_dispatcher, "analyze"):
        try:
            import asyncio

            result = _dispatcher.analyze(event)
            if asyncio.iscoroutine(result):
                loop = asyncio.new_event_loop()
                try:
                    result = loop.run_until_complete(result)
                finally:
                    loop.close()
            if isinstance(result, dict):
                risk_score = result.get("risk_score") or result.get("ANALYTICAL_SCORE")
                threat_vector = result.get("threat_vector")
                playbook = result.get("playbook")
                for action in result.get("mitigations") or result.get("actions") or []:
                    entry = action if isinstance(action, dict) else {"action": str(action)}
                    mode = entry.get("execution_mode") or entry.get("status") or "RECOMMENDATION_ONLY"
                    if mode in ("EXECUTED", "APPROVED", "REAL"):
                        executed.append({**entry, "note": "verify authorization layer"})
                    else:
                        recommendation_only.append({**entry, "mode": "RECOMMENDATION_ONLY"})
        except Exception as exc:
            logger.debug("dispatcher analyze: %s", exc)

    if not recommendations and matches:
        recommendations = [
            {"term": m.get("term"), "type": "KNOWLEDGE_MATCH", "mode": "RECOMMENDATION_ONLY"}
            for m in matches[:10]
        ]
        recommendation_only.extend(recommendations)

    return {
        "status": "ok" if matches or risk_score is not None else "no_match",
        "sector": sector,
        "matches": matches[:20],
        "match_count": len(matches),
        "risk_score": risk_score,
        "threat_vector": threat_vector,
        "playbook": playbook,
        "recommendations": recommendations,
        "actions_executed": executed,
        "actions_recommendation_only": recommendation_only,
        "source": "enterprise_knowledge_bridge",
        "invented": False,
    }
