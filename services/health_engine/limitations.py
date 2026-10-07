#!/usr/bin/env python3
"""Límites honestos del Health Monitoring & Self-Healing Engine."""

LIMITATIONS = [
    "Métricas por hilo/worker individuales pueden ser NO DISPONIBLE si el SO no las expone.",
    "Deadlocks de SQLite se detectan por síntomas (lock timeouts / errores), no por debugger de locks.",
    "Fugas de memoria se infieren por tendencia de RSS del proceso NOVUS, no por heap profiling completo.",
    "Loops infinitos se detectan por CPU sostenida + falta de progreso, no por análisis estático de código.",
    "Self-healing NUNCA elimina evidencias forenses ni altera custody chain.",
    "Kernel IA solo analiza/explica/propone; no ejecuta recuperaciones destructivas.",
    "Telemetría estática o inventada está prohibida; ausencia = NO DISPONIBLE.",
]

POLICY = {
    "fake_telemetry": False,
    "invent_alerts": False,
    "delete_forensic_evidence": False,
    "destructive_auto_heal": False,
    "kernel_executes": False,
}
