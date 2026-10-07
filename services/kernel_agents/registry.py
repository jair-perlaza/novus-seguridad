"""
Agentes especializados del Kernel IA — cada uno envuelve motores reales existentes.
El Kernel coordina; los agentes ejecutan.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from services.ai_capability_registry import capability_registry
from utils.logger import logger


@dataclass
class AgentTaskResult:
    success: bool
    data: Any = None
    message: str = ""
    agent_id: str = ""


class BaseKernelAgent:
    agent_id: str = "base"
    label: str = "Base Agent"
    capabilities: List[str] = []
    implemented: bool = True
    note: str = ""

    def execute(self, capability: str, user_id: Optional[int] = None, force_refresh: bool = True) -> AgentTaskResult:
        try:
            data, module = capability_registry._run_capability(capability, user_id, force_refresh)
            return AgentTaskResult(success=True, data=data, message=f"{self.label}: {capability} OK", agent_id=self.agent_id)
        except Exception as exc:
            logger.warning(f"Agent {self.agent_id} failed {capability}: {exc}")
            return AgentTaskResult(success=False, data=None, message=str(exc), agent_id=self.agent_id)


class SOCAgent(BaseKernelAgent):
    agent_id = "soc"
    label = "SOC Agent"
    capabilities = []


class NetworkAgent(BaseKernelAgent):
    agent_id = "network"
    label = "Network Agent"
    capabilities = ["network.scanner", "network.radar", "network.events", "traffic.stats", "connections.active"]


class ThreatAgent(BaseKernelAgent):
    agent_id = "threat"
    label = "Threat Agent / XDR"
    capabilities = ["security.threats", "advanced_detector.malware", "security.vulnerabilities"]


class EndpointAgent(BaseKernelAgent):
    agent_id = "endpoint"
    label = "Endpoint Agent"
    capabilities = ["process.scanner", "advanced_detector.processes", "endpoints.live", "system.metrics", "security.system_health"]


class TopologyAgent(BaseKernelAgent):
    agent_id = "topology"
    label = "Topology Agent"
    capabilities = ["topology.view"]
    note = "Datos derivados de ARP; UI completa en /topology"


class EmailSecurityAgent(BaseKernelAgent):
    agent_id = "email"
    label = "Email Security Agent"
    capabilities = ["gmail.analyzer"]
    note = "SPF/DKIM/DMARC completo y VirusTotal requieren desarrollo adicional"


class FirewallAgent(BaseKernelAgent):
    agent_id = "firewall"
    label = "Firewall Agent"
    capabilities = ["firewall.ports", "advanced_detector.ports"]


class PlaybookAgent(BaseKernelAgent):
    agent_id = "playbook"
    label = "Playbook Agent"
    capabilities = ["playbooks.manager"]
    note = "Ejecución de playbooks desde chat requiere integración adicional"


class CryptoAgent(BaseKernelAgent):
    agent_id = "crypto"
    label = "Crypto Agent"
    capabilities = ["security.vault"]


class ReportAgent(BaseKernelAgent):
    agent_id = "report"
    label = "Report Agent"
    capabilities = ["reports.manager"]


class AutomationAgent(BaseKernelAgent):
    agent_id = "automation"
    label = "Automation Agent"
    capabilities = ["playbooks.manager"]
    implemented = True
    note = "Automatización vía Kernel Enterprise V2 Action Packs + playbook_service (sin reemplazar motores)"


class XDRAgent(BaseKernelAgent):
    agent_id = "xdr"
    label = "XDR Agent"
    capabilities = ["security.threats", "advanced_detector.malware"]


class SIEMAgent(BaseKernelAgent):
    agent_id = "siem"
    label = "SIEM Agent"
    capabilities = ["siem.logs", "incidents.manager"]


class SectorAgent(BaseKernelAgent):
    agent_id = "sector"
    label = "Sector Shield Agent"
    capabilities = ["security.sector_shield"]


AGENT_REGISTRY: Dict[str, BaseKernelAgent] = {
    "soc": SOCAgent(),
    "network": NetworkAgent(),
    "threat": ThreatAgent(),
    "endpoint": EndpointAgent(),
    "topology": TopologyAgent(),
    "email": EmailSecurityAgent(),
    "firewall": FirewallAgent(),
    "playbook": PlaybookAgent(),
    "crypto": CryptoAgent(),
    "report": ReportAgent(),
    "automation": AutomationAgent(),
    "xdr": XDRAgent(),
    "siem": SIEMAgent(),
    "sector": SectorAgent(),
}


def get_agent(agent_id: str) -> Optional[BaseKernelAgent]:
    return AGENT_REGISTRY.get(agent_id)


def agent_for_capability(capability: str) -> str:
    for aid, agent in AGENT_REGISTRY.items():
        if capability in agent.capabilities:
            return aid
    return "soc"
