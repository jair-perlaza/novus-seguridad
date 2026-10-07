#!/usr/bin/env python3
"""Limites y politicas del SOC Enterprise."""
LIMITATIONS = [
    "NO usa datos simulados, graficos estaticos ni porcentajes inventados.",
    "Toda informacion proviene exclusivamente de motores reales.",
    "Si un motor no tiene datos -> 'NO DISPONIBLE'.",
    "Kernel IA solo analiza/propone; executes_actions=false.",
    "No dibuja relaciones inexistentes en el mapa tactico.",
    "No genera evidencia forense ficticia.",
    "Cache solo de datos derivados; nunca informacion critica.",
]
POLICY = {
    "invent_data": False,
    "static_charts": False,
    "fake_percentages": False,
    "fake_evidence": False,
    "kernel_executes": False,
    "cache_critical": False,
}
NA = "NO DISPONIBLE"
AUTHORIZED_SOURCES = [
    "btde", "zero_day_detection", "swarm_defense", "swarm_mesh",
    "threat_intelligence_enterprise", "asm", "viem", "imcm", "sope",
    "kernel_ia", "adaptive_profile", "endpoint", "network_protection",
    "health_engine", "cryptovault", "forense", "compliance", "centro_defensa",
]
