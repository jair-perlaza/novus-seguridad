#!/usr/bin/env python3
"""Catálogo canónico de componentes monitoreados por Health Engine."""

COMPONENT_IDS = (
    "kernel_ia",
    "swarm_defense",
    "swarm_mesh",
    "behavioral_threat_detection",
    "adaptive_profile",
    "cryptovault",
    "defense_center",
    "forensic",
    "endpoint",
    "network_protection",
    "web_security",
    "authentication",
    "compliance",
    "reports",
    "automatic_response",
    "database",
    "web_server",
    "api_rest",
    "scheduler",
    "background_workers",
)

COMPONENT_LABELS = {
    "kernel_ia": "Kernel IA",
    "swarm_defense": "Swarm Defense",
    "swarm_mesh": "Swarm Mesh",
    "behavioral_threat_detection": "Behavioral Threat Detection",
    "adaptive_profile": "Adaptive Profile",
    "cryptovault": "CryptoVault",
    "defense_center": "Centro de Defensa",
    "forensic": "Forense",
    "endpoint": "Endpoint",
    "network_protection": "Protección de Red",
    "web_security": "Web Security",
    "authentication": "Authentication",
    "compliance": "Compliance",
    "reports": "Reportes",
    "automatic_response": "Respuesta Automática",
    "database": "Base de Datos",
    "web_server": "Servidor Web",
    "api_rest": "API REST",
    "scheduler": "Scheduler",
    "background_workers": "Background Workers",
}

STATUS_ACTIVE = "activo"
STATUS_DEGRADED = "degradado"
STATUS_STOPPED = "detenido"
STATUS_UNAVAILABLE = "no_disponible"

NA = "NO DISPONIBLE"
