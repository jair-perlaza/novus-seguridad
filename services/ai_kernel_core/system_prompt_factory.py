"""Prompt maestro consolidado — taxonomía 11 módulos con capacidades verificables."""
from __future__ import annotations

from services.ai_kernel_brain.kernel_prompt import get_kernel_brain


class NOVUSSystemPromptFactory:
    """Capa 2: instrucciones maestras alineadas con motores reales NOVUS."""

    @staticmethod
    def get_time_greeting() -> str:
        return get_kernel_brain().get_time_based_greeting()

    @classmethod
    def build_system_prompt(cls) -> str:
        greeting = cls.get_time_greeting()
        base = get_kernel_brain().get_system_prompt()
        modules = f"""
TAXONOMÍA DE MÓDULOS (referencia operativa — no implica ejecución autónoma):
- M1 Cortesía: saludo horario ({greeting}).
- M2 Conocimiento: consultas ciberseguridad vía kernel_operator/kernel_agent con telemetría real.
- M3 Escaneo: endpoint_enterprise.yara_engine (yara-x) + heurísticas BTDE — señales, no veredicto malware.
- M4 Radar: network_ndr_service + AIE + network_device_defense.
- M5 Aprendizaje: ai_kernel_event_engine/knowledge_adapter (data/ai_kernel_feedback/).
- M6 Barreras: executes_actions=false; aislamiento recomendado → AIE/Swarm, no netsh/iptables autónomo.
- M7 C2/Exfiltración: network_endpoint_enterprise + NDR — solo con evidencia verificada.
- M8 Reglas defensivas: YARA en rules/*.yar; Sigma NO DISPONIBLE hasta regla proporcionada.
- M9 Playbooks: SOPE/playbook_catalog — recomendación por defecto.
- M10 Auditoría: evidence_center + audit log ai_kernel_core.
- M11 Simulación: CSV/BAS enterprise — escenarios con evidencia LIVE en data/csv_bas/.
""".strip()
        return f"{base}\n\n{modules}"

    @classmethod
    def module_status(cls) -> dict:
        return {
            "M1_courtesy": "integrated",
            "M2_knowledge": "integrated",
            "M3_yara_scan": "integrated_yara_x",
            "M4_radar": "integrated",
            "M5_learning": "integrated",
            "M6_barriers": "recommendation_only",
            "M7_c2_exfil": "partial_ndr_nee",
            "M8_sigma_yara": "yara_partial_sigma_not_provided",
            "M9_playbooks": "integrated_sope",
            "M10_audit": "integrated",
            "M11_simulation": "integrated_csv_bas",
            "executes_network_block": False,
        }
