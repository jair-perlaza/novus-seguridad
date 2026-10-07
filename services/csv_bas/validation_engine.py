#!/usr/bin/env python3
"""Validation engine — orquesta probes de controles."""
from __future__ import annotations
from typing import Any, Dict, List

from services.csv_bas.limitations import CONTROL_ENGINES
from services.csv_bas.control_validator import verify_detection, check_engine_availability


def validate_controls(marker: str, run_id: str, engines: List[str] | None = None) -> Dict[str, Any]:
    engines = engines or CONTROL_ENGINES
    detections: List[Dict[str, Any]] = []
    availability: Dict[str, Any] = {}
    for eng in engines:
        availability[eng] = check_engine_availability(eng)
        detections.append(verify_detection(eng, marker, run_id))
    return {
        "engines_probed": len(engines),
        "availability": availability,
        "detections": detections,
        "invented": False,
    }
