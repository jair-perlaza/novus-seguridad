#!/usr/bin/env python3
"""Limites IAPA — Attack Path Intelligence (solo evidencia real)."""
LIMITATIONS = [
    "NO inventa relaciones, grafos ni rutas.",
    "NO modifica motores, SDL, SDACE, UEBA, IMCM, SOPE ni Kernel.",
    "Solo consume lecturas de motores existentes.",
    "Sin evidencia -> NO DISPONIBLE / NO IMPLEMENTADO.",
    "Scores explicables con pesos documentados; sin RNG.",
    "Kernel IA solo analiza; executes_actions=false.",
    "Swarm solo agregados anonimizados.",
]
POLICY = {
    "invent_edges": False,
    "modify_engines": False,
    "modify_sdl": False,
    "rng_score": False,
    "kernel_executes": False,
    "swarm_pii": False,
}
NA = "NO DISPONIBLE"
NI = "NO IMPLEMENTADO"

# Pesos documentados Attack Path Score (suma 100)
PATH_WEIGHTS = {
    "path_length_short": 15,      # rutas cortas = mas criticas
    "reaches_critical_asset": 20,
    "has_cve_or_vuln": 15,
    "has_ioc": 10,
    "has_privileged_identity": 15,
    "has_lateral_evidence": 10,
    "has_incident": 10,
    "multi_engine_evidence": 5,
}
