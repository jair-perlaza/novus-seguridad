#!/usr/bin/env python3
"""Limites Identity Intelligence & UEBA Enterprise."""
LIMITATIONS = [
    "NO usa datos simulados ni perfiles precargados.",
    "Baseline solo desde telemetria real observada.",
    "Sin baseline suficiente -> anomalías NO DISPONIBLE / insuficiente.",
    "NO modifica datos de motores externos; solo lectura + enriquecimiento local.",
    "Risk score con pesos documentados; sin RNG ni IA generativa.",
    "Kernel IA solo analiza; executes_actions=false.",
    "Swarm solo recibe agregados anonimizados.",
]
POLICY = {
    "invent_behavior": False,
    "static_only_rules": False,
    "preloaded_profiles": False,
    "modify_engines": False,
    "kernel_executes": False,
    "swarm_pii": False,
    "rng_score": False,
}
NA = "NO DISPONIBLE"

# Pesos documentados del Identity Risk Score (suman 100)
RISK_WEIGHTS = {
    "unusual_login_hour": 12,
    "new_device": 10,
    "new_network": 10,
    "new_gateway": 8,
    "new_dns": 6,
    "new_process": 10,
    "shell_never_seen": 12,
    "traffic_spike": 8,
    "multi_host_simultaneous": 10,
    "related_incident": 8,
    "related_ioc": 6,
}
# Min observations before baseline is considered usable
MIN_BASELINE_OBS = 3
