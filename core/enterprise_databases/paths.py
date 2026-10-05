"""Rutas físicas de las bases de datos empresariales NOVUS (dominios separados)."""
from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(ROOT, "data", "databases")

DB_CLIENTS = os.path.join(DATA_DIR, "novus_clients.db")
DB_SECURITY_EVENTS = os.path.join(DATA_DIR, "novus_security_events.db")
DB_HISTORY = os.path.join(DATA_DIR, "novus_history.db")
DB_KERNEL = os.path.join(DATA_DIR, "novus_kernel_learning.db")
DB_EVIDENCE = os.path.join(DATA_DIR, "novus_evidence.db")
DB_STUDY_CASES = os.path.join(DATA_DIR, "novus_study_cases.db")
DB_AUDIT = os.path.join(DATA_DIR, "novus_audit.db")

LEGACY_MONOLITH = os.path.join(ROOT, "novus_vault_v2.db")

DOMAIN_LABELS = {
    "clients": ("Clientes", DB_CLIENTS),
    "security_events": ("Eventos de seguridad", DB_SECURITY_EVENTS),
    "history": ("Histórico", DB_HISTORY),
    "kernel": ("Kernel IA", DB_KERNEL),
    "evidence": ("Evidencias", DB_EVIDENCE),
    "study_cases": ("Casos de estudio NOVUS", DB_STUDY_CASES),
    "audit": ("Auditoría", DB_AUDIT),
}


def ensure_data_dir() -> str:
    os.makedirs(DATA_DIR, exist_ok=True)
    return DATA_DIR
