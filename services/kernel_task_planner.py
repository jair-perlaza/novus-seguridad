"""
Task Planner — convierte intención en lista numerada de tareas para agentes especializados.
Cada consulta genera un plan distinto; sin plantillas genéricas.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from services.kernel_planner import ExecutionPlan, GREETING
from services.kernel_agents.registry import agent_for_capability


@dataclass
class KernelTask:
    task_id: int
    label: str
    agent_id: str
    capability: Optional[str] = None
    action: Optional[str] = None  # orchestrator action name
    status: str = "pending"  # pending | running | completed | failed | skipped
    result_summary: str = ""


# Escaneo integral portátil — secuencia visible al operador
FULL_PORTABLE_SEQUENCE = [
    ("soc", "Inicializando análisis...", None),
    ("endpoint", "Detectando sistema operativo...", "system.metrics"),
    ("endpoint", "Detectando hardware...", "security.system_health"),
    ("soc", "Preparando motores...", None),
    ("soc", "Iniciando análisis profundo...", None),
    ("endpoint", "Analizando procesos...", "process.scanner"),
    ("endpoint", "Analizando memoria...", "advanced_detector.processes"),
    ("endpoint", "Analizando servicios...", None),
    ("endpoint", "Analizando drivers...", None),
    ("endpoint", "Analizando tareas programadas...", None),
    ("endpoint", "Analizando inicio automático...", None),
    ("network", "Analizando conexiones...", "connections.active"),
    ("firewall", "Analizando firewall...", "firewall.ports"),
    ("endpoint", "Analizando registros...", None),
    ("threat", "Analizando archivos críticos...", "advanced_detector.malware"),
    ("endpoint", "Analizando extensiones del navegador...", None),
    ("endpoint", "Analizando dispositivos USB...", None),
    ("email", "Analizando correo...", "gmail.analyzer"),
    ("soc", "Correlacionando evidencias...", None),
    ("threat", "Evaluando amenazas y política de mitigación...", "security.threats"),
    ("report", "Generando informe...", "reports.manager"),
    ("soc", "Escaneo finalizado.", None),
]

NETWORK_SEQUENCE = [
    ("soc", "Inicializando análisis de red...", None),
    ("network", "Escaneo ARP / Radar...", "network.radar"),
    ("network", "Inventario de dispositivos...", "network.scanner"),
    ("network", "Analizando conexiones activas...", "connections.active"),
    ("network", "Analizando tráfico...", "traffic.stats"),
    ("firewall", "Analizando puertos y firewall...", "firewall.ports"),
    ("topology", "Construyendo topología...", "topology.view"),
    ("soc", "Correlacionando evidencias de red...", None),
    ("report", "Generando informe...", None),
    ("soc", "Análisis de red finalizado.", None),
]

MALWARE_SEQUENCE = [
    ("soc", "Iniciando caza de amenazas...", None),
    ("threat", "Escaneando procesos sospechosos...", "advanced_detector.processes"),
    ("xdr", "Motor XDR / Threat Engine...", "security.threats"),
    ("threat", "Análisis antimalware heurístico...", "advanced_detector.malware"),
    ("threat", "Escaneo de vulnerabilidades asociadas...", "security.vulnerabilities"),
    ("soc", "Correlacionando indicadores...", None),
    ("threat", "Evaluando mitigación según política...", None),
    ("report", "Generando informe...", None),
    ("soc", "Análisis de amenazas finalizado.", None),
]

VULN_SEQUENCE = [
    ("soc", "Iniciando análisis de vulnerabilidades...", None),
    ("threat", "Motor de vulnerabilidades...", "security.vulnerabilities"),
    ("threat", "Escáner del sistema...", "vulnerability.scanner"),
    ("firewall", "Puertos expuestos...", "advanced_detector.ports"),
    ("xdr", "Correlación XDR...", "security.threats"),
    ("report", "Generando informe detallado...", "reports.manager"),
    ("soc", "Análisis finalizado.", None),
]

DAILY_SEQUENCE = [
    ("siem", "Recopilando eventos del día...", "siem.logs"),
    ("siem", "Revisando incidentes...", "incidents.manager"),
    ("network", "Eventos de red...", "network.events"),
    ("xdr", "Amenazas del periodo...", "security.threats"),
    ("soc", "Sintetizando actividad del día...", None),
    ("report", "Generando resumen...", None),
]

EMAIL_SEQUENCE = [
    ("email", "Conectando motor Gmail...", "gmail.analyzer"),
    ("threat", "Correlación con Threat Engine...", "security.threats"),
    ("soc", "Análisis de correo finalizado.", None),
]

PROCESS_SEQUENCE = [
    ("endpoint", "Inventario de procesos...", "process.scanner"),
    ("endpoint", "Detector avanzado...", "advanced_detector.processes"),
    ("endpoint", "Métricas de sistema...", "system.metrics"),
    ("soc", "Correlacionando...", None),
    ("report", "Informe de procesos.", None),
]

GENERIC_SEQUENCE = [
    ("soc", "Comprendiendo solicitud...", None),
    ("soc", "Ejecutando motores requeridos...", None),
    ("soc", "Correlacionando evidencias...", None),
    ("report", "Generando informe...", None),
]


def build_task_list(plan: ExecutionPlan, message: str) -> List[KernelTask]:
    """Genera tareas numeradas según intención — plan único por consulta."""
    if plan.skip_engines:
        return []

    seq: List[tuple] = GENERIC_SEQUENCE

    if plan.workflow_profile == "full" or plan.intent_id in ("deep_scan", "full_computer_analysis"):
        seq = FULL_PORTABLE_SEQUENCE
    elif plan.workflow_profile == "network" or plan.intent_id in ("network_status", "wifi_intrusion"):
        seq = NETWORK_SEQUENCE
    elif plan.workflow_profile == "malware" or plan.intent_id == "malware":
        seq = MALWARE_SEQUENCE
    elif plan.workflow_profile == "vulnerabilities" or plan.intent_id == "vulnerabilities":
        seq = VULN_SEQUENCE
    elif plan.intent_id == "daily_summary":
        seq = DAILY_SEQUENCE
    elif plan.intent_id in ("gmail", "email_analysis") or plan.inline_action == "gmail":
        seq = EMAIL_SEQUENCE
    elif plan.intent_id in ("processes", "performance_slow") or plan.workflow_profile == "processes":
        seq = PROCESS_SEQUENCE
    elif plan.workflow_profile == "connections":
        seq = [
            ("network", "Analizando conexiones...", "connections.active"),
            ("network", "Gateway y DNS...", "network.scanner"),
            ("firewall", "Puertos...", "firewall.ports"),
            ("soc", "Correlacionando...", None),
            ("report", "Informe.", None),
        ]
    elif plan.request_type == "clean_threats":
        seq = [
            ("threat", "Buscando amenazas activas...", "security.threats"),
            ("threat", "Vulnerabilidades relacionadas...", "security.vulnerabilities"),
            ("xdr", "Indicadores XDR...", "advanced_detector.malware"),
            ("threat", "Evaluando remediación...", None),
        ]
    elif plan.capabilities:
        # Plan dinámico desde capacidades — sin plantilla fija
        seq = [("soc", "Planificando motores...", None)]
        for cap in plan.capabilities[:12]:
            aid = agent_for_capability(cap)
            seq.append((aid, f"Ejecutando {cap}...", cap))
        seq.append(("soc", "Correlacionando evidencias...", None))
        seq.append(("report", "Generando informe...", None))

    tasks: List[KernelTask] = []
    for i, (agent_id, label, cap) in enumerate(seq, 1):
        tasks.append(KernelTask(task_id=i, label=label, agent_id=agent_id, capability=cap))
    return tasks


def tasks_to_dict(tasks: List[KernelTask]) -> List[Dict[str, Any]]:
    return [
        {
            "task_id": t.task_id,
            "label": t.label,
            "agent_id": t.agent_id,
            "capability": t.capability,
            "status": t.status,
            "result_summary": t.result_summary,
        }
        for t in tasks
    ]
