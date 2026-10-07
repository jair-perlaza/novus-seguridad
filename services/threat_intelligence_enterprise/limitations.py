#!/usr/bin/env python3
"""Límites honestos del Threat Intelligence Enterprise."""

LIMITATIONS = [
    "Feeds externos requieren conexión a internet; sin conexión → 'NO DISPONIBLE'.",
    "IOC de feeds gratuitos pueden tener falsos positivos; confidence_score lo refleja.",
    "VirusTotal requiere API key; sin configurar → resultados de VT = 'NO DISPONIBLE'.",
    "La inteligencia propia se genera por correlación interna, no por firma de malware.",
    "IOC compartidos vía Swarm Mesh son anonimizados: nunca documentos/correos/contraseñas.",
    "Kernel IA usa TI como un factor más, nunca como única evidencia de decisión.",
    "No se inventan IOC, reputaciones, ni feeds simulados.",
]

POLICY = {
    "fake_feeds": False,
    "static_ioc_lists": False,
    "invented_reputations": False,
    "simulated_feeds": False,
    "kernel_sole_evidence": False,
    "share_personal_data": False,
    "share_documents": False,
    "share_passwords": False,
    "share_tokens": False,
    "share_cookies": False,
    "allowed_share": ["ioc_hash", "ioc_domain", "ioc_ip", "ioc_url", "technical_metadata"],
}

PRIVACY_NEVER_SHARE = frozenset([
    "documents", "files", "users", "emails", "passwords",
    "tokens", "cookies", "personal_info", "session_data",
])

PRIVACY_ALLOWED_SHARE = frozenset([
    "ioc_hash", "ioc_domain", "ioc_ip", "ioc_url",
    "ioc_certificate_fingerprint", "technical_metadata_anonymized",
])
