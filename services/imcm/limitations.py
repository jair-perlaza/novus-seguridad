#!/usr/bin/env python3
"""Limites y politicas del IMCM."""
LIMITATIONS = [
    "NO crea incidentes ficticios ni datos simulados.",
    "Toda informacion proviene de motores existentes.",
    "Kernel IA solo analiza/propone; executes_actions=false.",
    "Si un dato no existe -> 'NO DISPONIBLE'.",
    "No duplica codigo; consume servicios directamente.",
]
POLICY = {
    "invent_incidents": False, "fake_ioc": False, "fake_cve": False,
    "fake_campaigns": False, "fake_evidence": False, "fake_timeline": False,
    "kernel_executes": False,
}
STATES = ["nuevo", "investigando", "confirmado", "contenido", "erradicado", "recuperado", "cerrado", "reabierto"]
NA = "NO DISPONIBLE"
