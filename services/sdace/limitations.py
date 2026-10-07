#!/usr/bin/env python3
"""Limites SDACE — solo consumo; nunca inventa correlaciones."""
LIMITATIONS = [
    "NO crea datos simulados, IOC falsos ni correlaciones inventadas.",
    "NO modifica motores existentes ni el Security Data Lake.",
    "Solo consume informacion existente (SDL + lecturas de motores).",
    "Si una relacion no se demuestra -> NO DISPONIBLE / NA.",
    "Kernel IA solo analiza; executes_actions=false.",
    "Swarm solo recibe resumenes analiticos anonimizados.",
    "Sellos forenses se guardan en data/sdace (no mutan el SDL).",
]
POLICY = {
    "invent_correlations": False,
    "modify_sdl": False,
    "modify_engines": False,
    "kernel_executes": False,
    "swarm_private_data": False,
}
NA = "NO DISPONIBLE"
