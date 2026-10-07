#!/usr/bin/env python3
"""Limitaciones CSV/BAS — Continuous Security Validation / Breach & Attack Simulation."""
LIMITATIONS = [
    "CSV/BAS NO es pentest destructivo, exploit framework, malware ni ataque real.",
    "Solo escenarios controlados, reproducibles, reversibles y no destructivos.",
    "No inventa detecciones: DETECTED / NOT DETECTED / NOT IMPLEMENTED / NOT VERIFIED.",
    "No modifica motores existentes; solo APIs publicas.",
    "No altera el Data Lake ni auditorias oficiales.",
    "Cobertura solo con conteos observados (sin porcentajes inventados).",
    "MITRE: mapeo del catalogo cuando exista; si no, NA.",
    "Kernel IA solo analiza; executes_actions=false.",
    "Marcadores CSV-BAS estan etiquetados como validacion (no telemetria de ataque falsa).",
]
POLICY = {
    "destructive": False,
    "exploit_payloads": False,
    "malware": False,
    "real_attacks": False,
    "invent_detections": False,
    "modify_engines": False,
    "modify_sdl": False,
    "kernel_executes": False,
    "rng_coverage": False,
}
NA = "NO DISPONIBLE"
NI = "NOT IMPLEMENTED"
ND = "NOT DETECTED"
NV = "NOT VERIFIED"
DETECTED = "DETECTED"

CONTROL_ENGINES = [
    "btde",
    "zdde",
    "threat_intelligence",
    "swarm_defense",
    "swarm_mesh",
    "ueba",
    "asm",
    "viem",
    "imcm",
    "sope",
    "cryptovault",
    "forense",
    "kernel_ia",
    "soc",
    "sdl",
    "sdace",
    "iapa",
    "health_engine",
    "adaptive_profile",
]

NAMESPACE = "csv.bas.validation"
