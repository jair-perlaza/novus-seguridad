"""
Kernel IA Enterprise V2.0 — fachada operativa.
Compatible con Kernel existente: no reemplaza AIKernel ni motores.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from services.kernel_enterprise_v2.registry import ensure_bootstrapped, pack_registry
from utils.logger import logger

# Señal para activar el cerebro V2 sin interceptar todas las consultas legacy
_V2_TRIGGER = re.compile(
    r"\b(kernel\s*enterprise|enterprise\s*v2|knowledge\s*pack|action\s*pack|"
    r"motor\s+de\s+razonamiento|reasoning\s+engine|automation\s+engine|"
    r"learning\s+engine|paquetes?\s+de\s+conocimiento|arquitectura\s+modular|"
    r"kev2|ke-v2)\b",
    re.I,
)

_HELP_TRIGGER = re.compile(
    r"\b(qu[eé]\s+puedes\s+hacer|capacidades\s+enterprise|lista(r)?\s+packs|"
    r"packs\s+disponibles|engines?\s+disponibles)\b",
    re.I,
)


class KernelEnterpriseV2:
    """Cerebro modular — coordina packs/engines sobre evidencia real."""

    VERSION = "2.0.0"

    def bootstrap(self) -> Dict[str, Any]:
        reg = ensure_bootstrapped()
        return reg.summary()

    def status(self) -> Dict[str, Any]:
        reg = ensure_bootstrapped()
        return {
            "ok": True,
            "version": self.VERSION,
            "compatible_with_legacy_kernel": True,
            "replaces_existing_engines": False,
            "evidence_policy": "real_data_only",
            **reg.summary(),
            "engines": reg.list_engines(),
        }

    def list_knowledge(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        return ensure_bootstrapped().list_knowledge(category=category)

    def list_actions(self, category: Optional[str] = None, wired_only: bool = False) -> List[Dict[str, Any]]:
        return ensure_bootstrapped().list_actions(category=category, wired_only=wired_only)

    def collect_knowledge(self, pack_id: str, query: str = "", context: Optional[dict] = None) -> Dict[str, Any]:
        reg = ensure_bootstrapped()
        pack = reg.get_knowledge(pack_id)
        if not pack:
            return {
                "found": False,
                "gaps": [f"Knowledge pack no registrado: {pack_id}"],
                "message": "Evidencia insuficiente: el paquete no existe en el registro.",
            }
        return pack.collect_evidence(query, context).to_dict()

    def execute_action(
        self,
        action_id: str,
        *,
        user_email: Optional[str],
        user_role: Optional[str],
        params: Optional[dict] = None,
        confirmed: bool = False,
        reason: str = "",
    ) -> Dict[str, Any]:
        reg = ensure_bootstrapped()
        pack = reg.get_action(action_id)
        if not pack:
            return {
                "ok": False,
                "status": "error",
                "action_id": action_id,
                "message": f"Action pack no registrado: {action_id}",
            }
        return pack.execute(
            user_email=user_email,
            user_role=user_role,
            params=params,
            confirmed=confirmed,
            reason=reason,
        ).to_dict()

    def run_engine(self, engine_id: str, request: Optional[dict] = None) -> Dict[str, Any]:
        reg = ensure_bootstrapped()
        engine = reg.get_engine(engine_id)
        if not engine:
            return {
                "ok": False,
                "message": f"Engine no registrado: {engine_id}. Engines: {[e['engine_id'] for e in reg.list_engines()]}",
            }
        payload = dict(request or {})
        payload["registry"] = reg
        try:
            return engine.run(payload)
        except Exception as exc:
            logger.warning("KE-V2 engine %s failed: %s", engine_id, exc)
            return {
                "ok": False,
                "engine": engine_id,
                "message": f"Error del engine (no oculto): {exc}",
            }

    def answer_kernel_query(
        self,
        message: str,
        user_email: Optional[str] = None,
        user_role: Optional[str] = None,
        context: Optional[dict] = None,
    ) -> Optional[str]:
        """
        Hook para kernel_agent. Retorna None si no aplica (deja pasar a flujo legacy).
        Solo responde cuando el mensaje apunta a la arquitectura V2 / packs / engines.
        """
        text = (message or "").strip()
        if not text:
            return None
        if not (_V2_TRIGGER.search(text) or _HELP_TRIGGER.search(text)):
            return None

        reg = ensure_bootstrapped()
        lines: List[str] = [
            "## Kernel IA Enterprise V2.0",
            "Arquitectura modular activa. No reemplaza motores existentes.",
            "Política: solo evidencia verificable. Sin datos simulados.",
            "",
        ]

        if _HELP_TRIGGER.search(text) or re.search(r"\b(estado|status|resumen)\b", text, re.I):
            s = reg.summary()
            lines.append(f"- Knowledge Packs: **{s['knowledge_packs']}**")
            lines.append(f"- Action Packs: **{s['action_packs']}** (cableados: {s['wired_actions']})")
            lines.append(f"- Engines: **{s['engines']}**")
            lines.append("")
            lines.append("Engines: " + ", ".join(e["engine_id"] for e in reg.list_engines()))
            lines.append("")
            lines.append(
                "Ejemplos: «razonamiento XDR», «knowledge pack ransomware», "
                "«ejecutar action pack scan.network» (requiere API + RBAC)."
            )
            return "\n".join(lines)

        # Consulta de conocimiento
        matched_k = reg.match_knowledge(text, limit=3)
        if matched_k:
            lines.append("### Evidencia (Knowledge Packs)")
            for pack in matched_k:
                ev = pack.collect_evidence(text, context)
                lines.append(f"**{pack.label}** (`{pack.pack_id}` v{pack.version})")
                lines.append(f"- {ev.message}")
                if ev.sources:
                    lines.append(f"- Fuentes: {', '.join(ev.sources)}")
                if ev.gaps:
                    lines.append(f"- Gaps: {'; '.join(ev.gaps[:3])}")
                lines.append("")

        # Acciones relacionadas (solo catálogo — no auto-ejecuta)
        matched_a = reg.match_actions(text, limit=5)
        if matched_a:
            lines.append("### Action Packs relacionados (no ejecutados automáticamente)")
            for a in matched_a:
                wired = "cableado" if a.is_wired() else "registrado / no cableado"
                lines.append(
                    f"- `{a.action_id}` — {a.label} [{wired}] "
                    f"(confirmación={'sí' if a.requires_confirm else 'no'})"
                )
            lines.append("")
            lines.append(
                "Para ejecutar: `POST /api/ai/enterprise/v2/actions/<action_id>/execute` "
                "con rol autorizado, motivo y `confirmed=true`."
            )

        # Razonamiento breve
        reasoning = self.run_engine(
            "reasoning",
            {"query": text, "context": context, "user_email": user_email, "user_role": user_role},
        )
        if reasoning.get("sufficient_evidence"):
            lines.append("### Correlación")
            for c in reasoning.get("correlated_packs") or []:
                if c.get("found"):
                    lines.append(
                        f"- {c['label']}: {c['fact_count']} hecho(s) desde {', '.join(c.get('sources') or [])}"
                    )
        else:
            lines.append(
                "### Correlación\n"
                "Evidencia insuficiente para una correlación completa. "
                "Kernel IA no inventa conclusiones."
            )

        if len(lines) <= 5:
            return None
        return "\n".join(lines)


kernel_enterprise_v2 = KernelEnterpriseV2()
