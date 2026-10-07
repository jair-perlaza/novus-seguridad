"""
Registro central de Knowledge Packs, Action Packs y Engines.
Crecimiento ilimitado: register_* no requiere reinicio de lógica legacy.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Type

from services.kernel_enterprise_v2.base import BaseActionPack, BaseEngine, BaseKnowledgePack
from utils.logger import logger


class PackRegistry:
    """Registro thread-safe de paquetes y motores V2."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._knowledge: Dict[str, BaseKnowledgePack] = {}
        self._actions: Dict[str, BaseActionPack] = {}
        self._engines: Dict[str, BaseEngine] = {}
        self._bootstrapped = False

    def register_knowledge(self, pack: BaseKnowledgePack, *, replace: bool = True) -> None:
        with self._lock:
            if pack.pack_id in self._knowledge and not replace:
                raise ValueError(f"Knowledge pack already registered: {pack.pack_id}")
            self._knowledge[pack.pack_id] = pack
            logger.debug("KE-V2 knowledge registered: %s v%s", pack.pack_id, pack.version)

    def register_action(self, pack: BaseActionPack, *, replace: bool = True) -> None:
        with self._lock:
            if pack.action_id in self._actions and not replace:
                raise ValueError(f"Action pack already registered: {pack.action_id}")
            self._actions[pack.action_id] = pack
            logger.debug("KE-V2 action registered: %s v%s", pack.action_id, pack.version)

    def register_engine(self, engine: BaseEngine, *, replace: bool = True) -> None:
        with self._lock:
            if engine.engine_id in self._engines and not replace:
                raise ValueError(f"Engine already registered: {engine.engine_id}")
            self._engines[engine.engine_id] = engine
            logger.debug("KE-V2 engine registered: %s v%s", engine.engine_id, engine.version)

    def get_knowledge(self, pack_id: str) -> Optional[BaseKnowledgePack]:
        with self._lock:
            return self._knowledge.get(pack_id)

    def get_action(self, action_id: str) -> Optional[BaseActionPack]:
        with self._lock:
            return self._actions.get(action_id)

    def get_engine(self, engine_id: str) -> Optional[BaseEngine]:
        with self._lock:
            return self._engines.get(engine_id)

    def list_knowledge(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = [p.meta() for p in self._knowledge.values()]
        if category:
            items = [i for i in items if i.get("category") == category]
        return sorted(items, key=lambda x: x["pack_id"])

    def list_actions(self, category: Optional[str] = None, wired_only: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            items = [p.meta() for p in self._actions.values()]
        if category:
            items = [i for i in items if i.get("category") == category]
        if wired_only:
            items = [i for i in items if i.get("wired")]
        return sorted(items, key=lambda x: x["action_id"])

    def list_engines(self) -> List[Dict[str, Any]]:
        with self._lock:
            items = [e.meta() for e in self._engines.values()]
        return sorted(items, key=lambda x: x["engine_id"])

    def match_knowledge(self, text: str, limit: int = 8) -> List[BaseKnowledgePack]:
        with self._lock:
            packs = list(self._knowledge.values())
        scored = []
        t = (text or "").lower()
        for p in packs:
            hits = sum(1 for k in p.keywords if k.lower() in t)
            if hits:
                scored.append((hits, p))
        scored.sort(key=lambda x: (-x[0], x[1].pack_id))
        return [p for _, p in scored[:limit]]

    def match_actions(self, text: str, limit: int = 8) -> List[BaseActionPack]:
        with self._lock:
            packs = list(self._actions.values())
        scored = []
        t = (text or "").lower()
        for p in packs:
            hits = sum(1 for k in p.keywords if k.lower() in t)
            if hits:
                scored.append((hits, p))
        scored.sort(key=lambda x: (-x[0], x[1].action_id))
        return [p for _, p in scored[:limit]]

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "architecture": "Kernel IA Enterprise V2.0",
                "modular": True,
                "unlimited_growth": True,
                "knowledge_packs": len(self._knowledge),
                "action_packs": len(self._actions),
                "engines": len(self._engines),
                "wired_actions": sum(1 for a in self._actions.values() if a.is_wired()),
                "bootstrapped": self._bootstrapped,
            }

    def mark_bootstrapped(self) -> None:
        with self._lock:
            self._bootstrapped = True


pack_registry = PackRegistry()


def ensure_bootstrapped() -> PackRegistry:
    """Carga perezosa de catálogos — idempotente."""
    if pack_registry._bootstrapped:
        return pack_registry
    with pack_registry._lock:
        if pack_registry._bootstrapped:
            return pack_registry
        from services.kernel_enterprise_v2.knowledge_packs.catalog import register_all_knowledge_packs
        from services.kernel_enterprise_v2.action_packs.catalog import register_all_action_packs
        from services.kernel_enterprise_v2.engines import register_all_engines

        register_all_knowledge_packs(pack_registry)
        register_all_action_packs(pack_registry)
        register_all_engines(pack_registry)
        pack_registry.mark_bootstrapped()
        logger.info(
            "Kernel Enterprise V2 bootstrapped: %s",
            pack_registry.summary(),
        )
    return pack_registry
