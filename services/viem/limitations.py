#!/usr/bin/env python3
"""Limites y politicas del VIEM."""
LIMITATIONS = [
    "NO inventa CVE, CPE, CVSS, exploits, parches, software ni versiones.",
    "Vulnerabilidades se detectan por version de software real vs bases publicas.",
    "Sin conexion a internet, CVE lookup = 'NO DISPONIBLE'.",
    "No aplica parches automaticamente; solo propone, documenta, verifica.",
    "Kernel IA consulta VIEM como contexto; no ejecuta remediaciones.",
]
POLICY = {
    "invent_cve": False, "invent_cpe": False, "invent_cvss": False,
    "invent_exploits": False, "invent_patches": False,
    "auto_patch": False, "na_when_unavailable": "NO DISPONIBLE",
}
NA = "NO DISPONIBLE"
