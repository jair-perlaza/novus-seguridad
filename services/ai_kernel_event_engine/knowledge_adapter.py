"""Adaptador de aprendizaje — retroalimentación admin persistida por MAC."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from utils.logger import logger

_FEEDBACK_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data",
    "ai_kernel_feedback",
)
_FEEDBACK_FILE = os.path.join(_FEEDBACK_DIR, "feedback.json")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_store() -> Dict[str, Any]:
    os.makedirs(_FEEDBACK_DIR, exist_ok=True)
    if not os.path.exists(_FEEDBACK_FILE):
        return {"learned_exceptions": {}, "risk_modifiers": {}, "history": []}
    try:
        with open(_FEEDBACK_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault("learned_exceptions", {})
        data.setdefault("risk_modifiers", {})
        data.setdefault("history", [])
        return data
    except Exception as exc:
        logger.debug("knowledge_adapter load: %s", exc)
        return {"learned_exceptions": {}, "risk_modifiers": {}, "history": []}


def _save_store(data: Dict[str, Any]) -> None:
    os.makedirs(_FEEDBACK_DIR, exist_ok=True)
    with open(_FEEDBACK_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


class NOVUSKnowledgeAdapter:
    """Memoria de retroalimentación — ajusta modificadores de riesgo por MAC."""

    def __init__(self):
        self._store = _load_store()

    def learn_from_feedback(
        self,
        mac: str,
        original_verdict: str,
        admin_action: str,
        reason: str,
    ) -> Dict[str, Any]:
        mac_key = (mac or "").upper()
        if not mac_key:
            return {"status": "error", "message": "MAC requerida", "executes_actions": False}

        entry = {
            "mac": mac_key,
            "original_verdict": original_verdict,
            "admin_action": admin_action,
            "reason": reason[:500],
            "learned_at": _utc_now(),
        }

        if admin_action in ("OVERRIDE_UNBLOCK", "approve", "corporate", "temporary"):
            self._store["learned_exceptions"][mac_key] = {
                "whitelisted": True,
                "reason": reason[:500],
                "learned_at": entry["learned_at"],
            }
            self._store["risk_modifiers"][mac_key] = 0.5
            logger.info("[AI KERNEL LEARNING] Umbral reducido para activo %s", mac_key)

        elif admin_action in ("CONFIRM_ATTACK", "isolate", "block", "reject"):
            self._store["risk_modifiers"][mac_key] = 1.5
            self._store["learned_exceptions"].pop(mac_key, None)
            logger.info("[AI KERNEL LEARNING] Umbral elevado para activo %s", mac_key)

        history = self._store.setdefault("history", [])
        history.append(entry)
        self._store["history"] = history[-200:]
        _save_store(self._store)

        return {
            "status": "learned",
            "mac": mac_key,
            "risk_modifier": self.get_risk_modifier(mac_key),
            "executes_actions": False,
            "verified": True,
            "invented": False,
        }

    def get_risk_modifier(self, mac: str) -> float:
        mac_key = (mac or "").upper()
        if not mac_key:
            return 1.0
        if mac_key in self._store.get("learned_exceptions", {}):
            return float(self._store.get("risk_modifiers", {}).get(mac_key, 0.5))
        return float(self._store.get("risk_modifiers", {}).get(mac_key, 1.0))

    def is_whitelisted(self, mac: str) -> bool:
        mac_key = (mac or "").upper()
        exc = self._store.get("learned_exceptions", {}).get(mac_key)
        return bool(exc and exc.get("whitelisted"))

    def snapshot(self) -> Dict[str, Any]:
        return {
            "exceptions_n": len(self._store.get("learned_exceptions") or {}),
            "modifiers_n": len(self._store.get("risk_modifiers") or {}),
            "history_n": len(self._store.get("history") or []),
        }


_adapter: Optional[NOVUSKnowledgeAdapter] = None


def get_knowledge_adapter() -> NOVUSKnowledgeAdapter:
    global _adapter
    if _adapter is None:
        _adapter = NOVUSKnowledgeAdapter()
    return _adapter
