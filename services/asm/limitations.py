#!/usr/bin/env python3
"""Limites y politicas del Asset Intelligence & Attack Surface Management."""

LIMITATIONS = [
    "Todo activo se descubre del sistema o red real; nunca se inventa.",
    "Si una informacion no puede obtenerse -> 'NO DISPONIBLE'.",
    "Descubrimiento de red depende de ARP y permisos del SO.",
    "Software instalado se lee del registro/SO; no se simula.",
    "Certificados se leen del almacen del SO; sin acceso -> 'NO DISPONIBLE'.",
    "IoT y camaras IP dependen de respuesta ARP/mDNS en la red local.",
    "Kernel IA usa ASM como contexto; no ejecuta cambios.",
]

POLICY = {
    "invent_assets": False,
    "create_fictitious_devices": False,
    "simulate_software": False,
    "simulate_ports": False,
    "simulate_certificates": False,
    "static_data": False,
    "na_when_unavailable": "NO DISPONIBLE",
}

NA = "NO DISPONIBLE"
