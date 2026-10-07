"""
Catálogo de Knowledge Packs — cada uno actualizable de forma independiente.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from services.kernel_enterprise_v2.base import BaseKnowledgePack, EvidenceResult
from services.kernel_enterprise_v2.evidence_collectors import COLLECTORS
from services.kernel_enterprise_v2.registry import PackRegistry


class DeclarativeKnowledgePack(BaseKnowledgePack):
    def __init__(
        self,
        pack_id: str,
        label: str,
        category: str,
        keywords: Sequence[str],
        description: str,
        collector_id: str = "none",
        version: str = "1.0.0",
        evidence_source_ids: Optional[Sequence[str]] = None,
    ):
        self.pack_id = pack_id
        self.label = label
        self.category = category
        self.keywords = tuple(keywords)
        self.description = description
        self.version = version
        self.collector_id = collector_id
        self.evidence_source_ids = tuple(evidence_source_ids or ())

    def collect_evidence(self, query: str = "", context: Optional[dict] = None) -> EvidenceResult:
        collector = COLLECTORS.get(self.collector_id, COLLECTORS["none"])
        found, facts, gaps, sources = collector(query, context)
        if found:
            msg = f"Evidencia verificable encontrada para «{self.label}» desde fuentes reales NOVUS."
        else:
            msg = (
                f"Evidencia insuficiente para «{self.label}». "
                "Kernel IA no inventa datos. "
                + ("; ".join(gaps) if gaps else "Sin fuentes locales disponibles.")
            )
        return EvidenceResult(
            pack_id=self.pack_id,
            found=found,
            sources=sources,
            facts=_truncate_facts(facts),
            gaps=gaps,
            message=msg,
        )


def _truncate_facts(facts: List[Dict[str, Any]], max_items: int = 12) -> List[Dict[str, Any]]:
    """Evita payloads enormes en respuestas Kernel; el dato completo vive en motores."""
    out = []
    for fact in facts[:max_items]:
        item = dict(fact)
        data = item.get("data")
        if isinstance(data, dict) and len(str(data)) > 4000:
            item["data"] = {
                "_truncated": True,
                "keys": list(data.keys())[:40],
                "note": "Resumen; detalle completo en el motor fuente",
            }
        elif isinstance(data, list) and len(data) > 20:
            item["data"] = data[:20]
            item["truncated_count"] = len(data)
        out.append(item)
    return out


# (pack_id, label, category, keywords, description, collector_id, evidence_sources)
_PACK_SPECS = [
    ("os.general", "Sistema Operativo", "os", ["sistema operativo", "os ", "operating system"], "Conocimiento general de SO vía telemetría endpoint", "endpoint", ["endpoints.live", "system.metrics"]),
    ("os.windows", "Windows", "os", ["windows", "powershell", "active directory", "registry"], "Windows — procesos, servicios, registro vía motores endpoint", "endpoint", ["process.scanner", "advanced_detector.processes"]),
    ("os.linux", "Linux", "os", ["linux", "systemd", "selinux"], "Linux — sin corpus local dedicado; evidencia solo si hay sensores", "none", []),
    ("net.networks", "Redes", "network", ["redes", "network", "lan", "wan", "tcp", "udp"], "Redes — escáner ARP, eventos, NDR", "network", ["network.scanner", "network.events"]),
    ("threat.malware", "Malware", "threat", ["malware", "troyano", "trojan", "worm"], "Malware — detector avanzado y XDR", "threats", ["advanced_detector.malware", "security.threats"]),
    ("threat.virus", "Virus", "threat", ["virus", "antivirus"], "Virus — amenazas runtime", "threats", ["security.threats"]),
    ("threat.ransomware", "Ransomware", "threat", ["ransomware", "cifrado malicioso", "encryptor"], "Ransomware — correlación con amenazas y defensa", "threats", ["security.threats"]),
    ("threat.botnets", "Botnets", "threat", ["botnet", "c2", "command and control"], "Botnets — requiere evidencia de red/amenazas", "network", ["network.events", "security.threats"]),
    ("threat.apt", "APT", "threat", ["apt", "amenaza persistente", "advanced persistent"], "APT — inteligencia operacional si existe", "threats", ["threat_intelligence.center", "security.threats"]),
    ("framework.mitre", "MITRE ATT&CK", "framework", ["mitre", "att&ck", "attack technique", "tactics"], "MITRE — mapeo solo con evidencia local (sin inventar técnicas)", "threats", ["security.threats"]),
    ("framework.cve", "CVE", "framework", ["cve-", "cve ", "vulnerabilidad conocida"], "CVE — motor de vulnerabilidades", "vulnerabilities", ["security.vulnerabilities", "vulnerability.scanner"]),
    ("framework.cwe", "CWE", "framework", ["cwe-", "cwe ", "weakness"], "CWE — vía hallazgos de vulnerabilidades si existen", "vulnerabilities", ["security.vulnerabilities"]),
    ("framework.capec", "CAPEC", "framework", ["capec", "patrones de ataque"], "CAPEC — pack registrado; corpus local no cableado", "none", []),
    ("framework.owasp", "OWASP", "framework", ["owasp", "top 10", "web app security"], "OWASP — Web Shield / apps si hay evidencia", "mail_web", ["web_shield"]),
    ("compliance.nist", "NIST", "compliance", ["nist", "nist csf", "800-53"], "NIST — Compliance Center", "compliance", ["compliance_center"]),
    ("compliance.iso27001", "ISO 27001", "compliance", ["iso 27001", "iso27001", "isms"], "ISO 27001 — Compliance Center", "compliance", ["compliance_center"]),
    ("compliance.pci_dss", "PCI DSS", "compliance", ["pci dss", "pci-dss", "pci"], "PCI DSS — Compliance Center", "compliance", ["compliance_center"]),
    ("compliance.soc2", "SOC 2", "compliance", ["soc 2", "soc2", "trust services"], "SOC 2 — Compliance Center", "compliance", ["compliance_center"]),
    ("compliance.ley1581", "Ley 1581", "compliance", ["ley 1581", "1581", "habeas data", "protección de datos colombia"], "Ley 1581 — Compliance Center", "compliance", ["compliance_center"]),
    ("compliance.gdpr", "GDPR", "compliance", ["gdpr", "rgpd", "protección de datos ue"], "GDPR — Compliance Center", "compliance", ["compliance_center"]),
    ("compliance.iso27701", "ISO 27701", "compliance", ["iso 27701", "iso27701", "privacy information"], "ISO 27701 — Compliance Center", "compliance", ["compliance_center"]),
    ("sector.fintech", "Fintech", "sector", ["fintech", "banca", "pagos", "pci"], "Fintech — ASPE / Compliance / sector shield", "compliance", ["aspe", "compliance_center"]),
    ("sector.logistics", "Logística", "sector", ["logística", "logistica", "supply chain"], "Logística — perfiles sectoriales si existen", "compliance", ["aspe"]),
    ("tech.mobile", "Aplicaciones móviles", "tech", ["móvil", "mobile", "android", "ios", "apk"], "Mobile — pack modular; evidencia solo si hay sensores", "none", []),
    ("cloud.general", "Cloud", "cloud", ["cloud", "nube", "saas", "iaas"], "Cloud — pack modular", "none", []),
    ("cloud.containers", "Containers", "cloud", ["container", "contenedor", "oci"], "Containers — pack modular", "none", []),
    ("cloud.docker", "Docker", "cloud", ["docker", "dockerfile"], "Docker — pack modular", "none", []),
    ("cloud.kubernetes", "Kubernetes", "cloud", ["kubernetes", "k8s", "helm"], "Kubernetes — pack modular", "none", []),
    ("cloud.azure", "Azure", "cloud", ["azure", "microsoft cloud"], "Azure — pack modular", "none", []),
    ("cloud.aws", "AWS", "cloud", ["aws", "amazon web services", "ec2", "s3"], "AWS — pack modular", "none", []),
    ("cloud.gcp", "Google Cloud", "cloud", ["gcp", "google cloud", "gke"], "Google Cloud — pack modular", "none", []),
    ("ot.iot", "IoT", "ot", ["iot", "dispositivo inteligente"], "IoT — correlación con inventario/red si hay evidencia", "network", ["network.scanner"]),
    ("ot.industrial", "Industrial", "ot", ["industrial", "planta", "ot "], "Industrial / OT — pack modular", "none", []),
    ("ot.scada", "SCADA", "ot", ["scada", "ics", "modbus"], "SCADA — pack modular", "none", []),
    ("ot.ot", "OT", "ot", ["operational technology", "tecnología operacional"], "OT — pack modular", "none", []),
    ("sec.email", "Correo", "security", ["correo", "email", "phishing", "mail shield", "spf", "dkim"], "Correo — Mail Shield / Gmail analyzer", "mail_web", ["mail_shield", "gmail.analyzer"]),
    ("sec.dns", "DNS", "security", ["dns", "resolución", "domain name"], "DNS — eventos de red si existen", "network", ["network.events"]),
    ("sec.firewall", "Firewall", "security", ["firewall", "puertos", "acl"], "Firewall — detector de puertos", "endpoint", ["firewall.ports", "advanced_detector.ports"]),
    ("sec.vpn", "VPN", "security", ["vpn", "túnel", "ipsec", "wireguard"], "VPN — pack modular; evidencia si hay sensores", "none", []),
    ("sec.siem", "SIEM", "security", ["siem", "correlación de logs", "security information"], "SIEM — logs/incidentes vía capacidades", "security_summary", ["siem.logs", "incidents.manager"]),
    ("sec.xdr", "XDR", "security", ["xdr", "detección y respuesta extendida"], "XDR — motor de amenazas", "threats", ["security.threats"]),
    ("sec.ndr", "NDR", "security", ["ndr", "network detection", "detección de red"], "NDR — network_ndr_service", "network", ["network.ndr"]),
    ("sec.endpoint", "Endpoint", "security", ["endpoint", "estación", "workstation", "edr"], "Endpoint — telemetría real", "endpoint", ["endpoints.live", "process.scanner"]),
    ("sec.zero_trust", "Zero Trust", "security", ["zero trust", "confianza cero", "ztna"], "Zero Trust — pack + auth/access si hay evidencia", "security_summary", ["auth_protection"]),
    ("forensic.digital", "Forense Digital", "forensic", ["forense", "forensic", "pcap", "cadena de custodia"], "Forense — evidencias y PCAP", "forensic", ["defense_evidence_registry", "forensic_pcap"]),
    ("forensic.custody", "Cadena de Custodia", "forensic", ["cadena de custodia", "custody", "integridad evidencia"], "Cadena de custodia — registry + integridad", "forensic", ["defense_evidence_registry"]),
    ("gov.compliance", "Cumplimiento", "governance", ["cumplimiento", "compliance", "normativa"], "Cumplimiento — Compliance Center", "compliance", ["compliance_center"]),
    ("gov.risk", "Gestión de Riesgos", "governance", ["riesgo", "risk management", "riesgos"], "Gestión de riesgos — compliance + amenazas", "compliance", ["compliance_center", "security.threats"]),
    ("gov.continuity", "Continuidad", "governance", ["continuidad", "bcp", "business continuity"], "Continuidad — pack modular", "none", []),
    ("gov.backup", "Respaldo", "governance", ["respaldo", "backup", "copia de seguridad"], "Respaldo — pack modular", "none", []),
    ("gov.recovery", "Recuperación", "governance", ["recuperación", "recovery", "drp", "disaster recovery"], "Recuperación — pack modular", "none", []),
    ("learn.history", "Historial Kernel", "learning", ["aprendizaje", "historial kernel", "memoria kernel"], "Aprendizaje verificable — kernel_memory", "kernel_memory", ["kernel_memory"]),
    ("ops.reports", "Reportes", "ops", ["reportes", "informe", "pdf"], "Reportes empresariales", "reports", ["reports.manager"]),
]


def register_all_knowledge_packs(registry: PackRegistry) -> int:
    count = 0
    for spec in _PACK_SPECS:
        pack_id, label, category, keywords, description, collector_id, sources = spec
        registry.register_knowledge(
            DeclarativeKnowledgePack(
                pack_id=pack_id,
                label=label,
                category=category,
                keywords=keywords,
                description=description,
                collector_id=collector_id,
                evidence_source_ids=sources,
            )
        )
        count += 1
    return count
