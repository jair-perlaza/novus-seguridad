#!/usr/bin/env python3
"""Limites y politicas del Security Data Lake Enterprise."""
LIMITATIONS = [
    "NO inventa eventos, telemetria ni registros simulados.",
    "Toda ingesta proviene de motores reales o de escrituras explicitas con fuente verificable.",
    "Registros inmutables: cambios crean nueva version + hash + firma.",
    "Kernel IA / consumidores leen el lake; SDL no ejecuta acciones ofensivas.",
    "Almacenamiento local (SQLite + JSONL archive). NO es un data lake distribuido petabyte.",
    "Campos ausentes en motores -> 'NO DISPONIBLE' (nunca inventados).",
    "Sucursal/cliente multi-tenant: solo si el motor origen lo aporta.",
]
POLICY = {
    "invent_events": False,
    "fake_telemetry": False,
    "silent_mutate": False,
    "kernel_executes": False,
    "distributed_cluster": False,  # no implementado
}
NA = "NO DISPONIBLE"
RECORD_TYPES = [
    "incident", "alert", "event", "ioc", "ioa", "cve", "mitre", "ttp",
    "playbook", "kernel_decision", "swarm_event", "mesh_event", "threat_intel",
    "vulnerability", "asm_inventory", "asset_change", "user_history",
    "device_history", "config_change", "auth_event", "session_event",
    "network_event", "endpoint_event", "health_event", "cryptovault_event",
    "forensic_event", "hash", "custody", "evidence", "timeline", "report",
]
AUTHORIZED_ENGINES = [
    "swarm_defense", "swarm_mesh", "btde", "zero_day_detection",
    "threat_intelligence_enterprise", "asm", "viem", "imcm", "sope",
    "health_engine", "endpoint", "network_protection", "adaptive_profile",
    "kernel_ia", "cryptovault", "centro_defensa", "forense", "reportes", "soc",
]
