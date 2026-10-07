"""
Contexto operativo de sesión del Kernel IA — memoria de trabajo (no persistente).

Recuerda durante la sesión: última pregunta, escaneo, informe, anomalías, acciones.
"""
from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# TTL para reutilizar motores sin repetir escaneo completo (segundos)
ENGINE_REUSE_TTL = 120


class KernelSessionContext:
    """Memoria operativa por session_id — solo en RAM."""

    def __init__(self):
        self._sessions: Dict[str, dict] = {}

    def _empty(self) -> dict:
        return {
            "last_message": "",
            "last_intent": "",
            "last_intent_label": "",
            "last_scan_profile": None,
            "last_report_summary": "",
            "last_risk_level": "",
            "anomalies": [],
            "actions_executed": [],
            "engines_recent": {},  # cap_id -> {ts, data_hash}
            "history_snippets": [],
            "last_operation_id": None,
            "updated_at": None,
        }

    def get(self, session_id: str) -> dict:
        if not session_id:
            return self._empty()
        self._evict_idle(max_sessions=int(__import__("os").environ.get("NOVUS_KERNEL_SESSION_MAX", "256")))
        if session_id not in self._sessions:
            self._sessions[session_id] = self._empty()
        return self._sessions[session_id]

    def _evict_idle(self, *, max_sessions: int = 256, idle_sec: float = 1800.0) -> None:
        # Cap session map — FIFO on insertion order (dict preserves order on 3.7+)
        if len(self._sessions) <= max_sessions:
            return
        extra = list(self._sessions.keys())[: max(0, len(self._sessions) - max_sessions)]
        for sid in extra:
            self._sessions.pop(sid, None)

    def enrich_from_history(self, session_id: str, history: Optional[List[dict]]) -> dict:
        ctx = self.get(session_id)
        if not history:
            return ctx
        snippets = []
        for turn in history[-8:]:
            role = turn.get("role", "")
            content = (turn.get("content") or "")[:200]
            if content:
                snippets.append(f"{role}: {content}")
        ctx["history_snippets"] = snippets
        if history:
            last_user = next((h for h in reversed(history) if h.get("role") == "user"), None)
            if last_user and not ctx.get("last_message"):
                ctx["last_message"] = last_user.get("content", "")
        return ctx

    def resolve_message(self, message: str, session_id: str) -> str:
        """Resuelve referencias contextuales: 'este problema', 'eso', 'analiza esto'."""
        msg = (message or "").strip()
        ctx = self.get(session_id)
        ref = re.search(
            r"\b(este|esta|ese|esa|esto|aquello|el\s+problema|la\s+anomal[ií]a|"
            r"analiza\s+este|revisa\s+eso|sobre\s+eso|mismo\s+tema)\b",
            msg,
            re.I,
        )
        if not ref or not ctx.get("last_message"):
            return msg
        prefix = f"[Contexto: consulta previa «{ctx['last_message'][:80]}» — intención {ctx.get('last_intent_label') or ctx.get('last_intent', 'N/D')}] "
        return prefix + msg

    def should_skip_engine(self, session_id: str, capability: str, force_refresh: bool) -> bool:
        if force_refresh:
            return False
        ctx = self.get(session_id)
        recent = ctx.get("engines_recent", {}).get(capability)
        if not recent:
            return False
        return (time.time() - recent.get("ts", 0)) < ENGINE_REUSE_TTL

    def record_engines(self, session_id: str, capabilities: List[str]):
        ctx = self.get(session_id)
        now = time.time()
        for cap in capabilities or []:
            ctx.setdefault("engines_recent", {})[cap] = {"ts": now}

    def update_before_plan(
        self,
        session_id: str,
        message: str,
        intent_id: str,
        intent_label: str,
    ):
        ctx = self.get(session_id)
        ctx["last_message"] = message
        ctx["last_intent"] = intent_id
        ctx["last_intent_label"] = intent_label
        ctx["updated_at"] = datetime.now().isoformat()

    def update_after_operation(
        self,
        session_id: str,
        operation_id: str,
        intent_id: str,
        engines: List[str],
        risk_level: str,
        anomalies: Optional[List[str]] = None,
        report_summary: str = "",
        scan_profile: Optional[str] = None,
        actions: Optional[List[str]] = None,
    ):
        ctx = self.get(session_id)
        ctx["last_operation_id"] = operation_id
        ctx["last_intent"] = intent_id
        ctx["last_risk_level"] = risk_level or ctx.get("last_risk_level", "")
        ctx["last_report_summary"] = report_summary[:500] if report_summary else ctx.get("last_report_summary", "")
        if scan_profile:
            ctx["last_scan_profile"] = scan_profile
        self.record_engines(session_id, engines)
        if anomalies:
            existing = {a[:80] for a in ctx.get("anomalies", [])}
            for a in anomalies:
                if a[:80] not in existing:
                    ctx.setdefault("anomalies", []).append(a)
            ctx["anomalies"] = ctx["anomalies"][-20:]
        if actions:
            ctx.setdefault("actions_executed", []).extend(actions)
            ctx["actions_executed"] = ctx["actions_executed"][-30:]
        ctx["updated_at"] = datetime.now().isoformat()

    def planning_hints(self, session_id: str) -> List[str]:
        ctx = self.get(session_id)
        hints = []
        if ctx.get("last_intent"):
            hints.append(f"Consulta anterior: {ctx.get('last_intent_label') or ctx['last_intent']}")
        if ctx.get("anomalies"):
            hints.append(f"Anomalías previas en sesión: {len(ctx['anomalies'])}")
        if ctx.get("last_scan_profile"):
            hints.append(f"Último escaneo: perfil {ctx['last_scan_profile']}")
        return hints


kernel_session_context = KernelSessionContext()
