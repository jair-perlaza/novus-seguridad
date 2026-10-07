"""
Contratos base Kernel IA Enterprise V2.0 — packs y engines independientes.
No sustituye motores existentes; solo define interfaces extensibles.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EvidenceResult:
    """Resultado de evidencia verificable. Nunca inventar campos."""

    pack_id: str
    found: bool
    sources: List[str] = field(default_factory=list)
    facts: List[Dict[str, Any]] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    message: str = ""
    collected_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "found": self.found,
            "sources": list(self.sources),
            "facts": list(self.facts),
            "gaps": list(self.gaps),
            "message": self.message,
            "collected_at": self.collected_at,
            "evidence_policy": "real_data_only",
        }


@dataclass
class ActionResult:
    action_id: str
    ok: bool
    status: str  # executed | denied | needs_confirm | not_wired | error | insufficient_evidence
    message: str
    audit_id: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "ok": self.ok,
            "status": self.status,
            "message": self.message,
            "audit_id": self.audit_id,
            "evidence": self.evidence,
            "details": self.details or {},
        }


class BaseKnowledgePack(ABC):
    """Paquete de conocimiento actualizable de forma independiente."""

    pack_id: str = "base"
    label: str = "Base Knowledge Pack"
    category: str = "general"
    version: str = "1.0.0"
    keywords: Sequence[str] = ()
    description: str = ""
    # Fuentes reales NOVUS (nombres lógicos); vacío = solo metadatos + gap explícito
    evidence_source_ids: Sequence[str] = ()

    def meta(self) -> Dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "label": self.label,
            "category": self.category,
            "version": self.version,
            "keywords": list(self.keywords),
            "description": self.description,
            "evidence_source_ids": list(self.evidence_source_ids),
            "updatable": True,
        }

    def matches(self, text: str) -> bool:
        t = (text or "").lower()
        return any(k.lower() in t for k in self.keywords)

    @abstractmethod
    def collect_evidence(self, query: str = "", context: Optional[dict] = None) -> EvidenceResult:
        ...


class BaseActionPack(ABC):
    """Acción autorizada — RBAC + auditoría + evidencia."""

    action_id: str = "base.action"
    label: str = "Base Action"
    category: str = "general"
    version: str = "1.0.0"
    # Roles mínimos (vacío = denegar siempre)
    allowed_roles: Sequence[str] = ()
    requires_confirm: bool = True
    # Capacidad existente en capability_registry, o None si no está cableada
    capability_id: Optional[str] = None
    description: str = ""
    keywords: Sequence[str] = ()

    def meta(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "label": self.label,
            "category": self.category,
            "version": self.version,
            "allowed_roles": list(self.allowed_roles),
            "requires_confirm": self.requires_confirm,
            "capability_id": self.capability_id,
            "wired": self.is_wired(),
            "description": self.description,
            "keywords": list(self.keywords),
        }

    def is_wired(self) -> bool:
        return bool(self.capability_id) or self._has_handler()

    def _has_handler(self) -> bool:
        return type(self).execute is not BaseActionPack.execute

    def matches(self, text: str) -> bool:
        t = (text or "").lower()
        return any(k.lower() in t for k in self.keywords)

    @abstractmethod
    def execute(
        self,
        *,
        user_email: Optional[str],
        user_role: Optional[str],
        params: Optional[dict] = None,
        confirmed: bool = False,
        reason: str = "",
    ) -> ActionResult:
        ...


class BaseEngine(ABC):
    engine_id: str = "base"
    label: str = "Base Engine"
    version: str = "1.0.0"

    def meta(self) -> Dict[str, Any]:
        return {
            "engine_id": self.engine_id,
            "label": self.label,
            "version": self.version,
            "modular": True,
        }

    @abstractmethod
    def run(self, request: Dict[str, Any]) -> Dict[str, Any]:
        ...


# Tipo de colector de evidencia pluggable
EvidenceCollector = Callable[[str, Optional[dict]], Tuple[bool, List[Dict[str, Any]], List[str], List[str]]]
