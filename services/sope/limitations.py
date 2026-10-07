#!/usr/bin/env python3
"""Límites y políticas del Security Orchestration & Playbook Engine."""

LIMITATIONS = [
    "SOPE no detecta amenazas; decide cómo responder a las ya detectadas.",
    "Ninguna acción destructiva se ejecuta sin configuración y autorización del cliente.",
    "Nivel de automatización por defecto: 1 (solo observar y registrar).",
    "Kernel IA solo analiza/correlaciona/propone/justifica; nunca ejecuta playbooks.",
    "Swarm solo valida consistencia y aporta IOC/evidencias; nunca ejecuta acciones.",
    "Toda acción genera evidencia forense (cadena de custodia, hash, firma, cronología).",
    "Self-healing nunca elimina archivos, procesos, sesiones ni evidencia forense.",
]

POLICY = {
    "destructive_by_default": False,
    "execute_without_evidence": False,
    "block_equipment": False,
    "delete_files": False,
    "kill_processes": False,
    "isolate_equipment": False,
    "revoke_sessions": False,
    "block_domains": False,
    "modify_firewall": False,
    "change_configurations": False,
    "kernel_executes_playbooks": False,
    "swarm_executes_actions": False,
    "default_automation_level": 1,
}

AUTOMATION_LEVELS = {
    1: {
        "name": "Observar",
        "description": "Solo observar, registrar, generar evidencia.",
        "actions_allowed": ["observe", "log", "evidence"],
        "requires_approval": False,
        "auto_execute": False,
    },
    2: {
        "name": "Recomendar",
        "description": "Observar, recomendar, mostrar acciones, esperar aprobación.",
        "actions_allowed": ["observe", "log", "evidence", "recommend", "show_actions"],
        "requires_approval": True,
        "auto_execute": False,
    },
    3: {
        "name": "Semi-automático",
        "description": "Ejecutar solo acciones previamente autorizadas por el cliente.",
        "actions_allowed": ["observe", "log", "evidence", "recommend", "execute_authorized"],
        "requires_approval": False,
        "auto_execute": True,
        "only_pre_authorized": True,
    },
    4: {
        "name": "Automático completo",
        "description": "Automatización completa, solo si el cliente la habilita explícitamente.",
        "actions_allowed": ["observe", "log", "evidence", "recommend", "execute_all"],
        "requires_approval": False,
        "auto_execute": True,
        "only_pre_authorized": False,
    },
}
