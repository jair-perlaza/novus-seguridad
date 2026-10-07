#!/usr/bin/env python3
"""
Zero-Day Detection Engine Enterprise (ZDDE).
Correlación multicapa de comportamientos anómalos / amenazas desconocidas.
NO es antivirus. NO usa firmas como método principal. NO inventa zero-days.
"""
from services.zero_day_detection.orchestrator import (
    get_zdde_orchestrator_status,
    run_zdde_orchestrator_cycle,
    start_zdde,
    stop_zdde,
)
from services.zero_day_detection.engine import (
    get_zdde_dashboard,
    get_zdde_status,
    run_zdde_cycle,
)
from services.zero_day_detection.limitations import CLASSIFICATION, LIMITATIONS

__all__ = [
    "start_zdde",
    "stop_zdde",
    "run_zdde_cycle",
    "run_zdde_orchestrator_cycle",
    "get_zdde_status",
    "get_zdde_dashboard",
    "get_zdde_orchestrator_status",
    "LIMITATIONS",
    "CLASSIFICATION",
]
