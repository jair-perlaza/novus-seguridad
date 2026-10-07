"""Reglas de detección enterprise — integradas en Endpoint/BTDE (no motor aislado)."""
from services.endpoint_enterprise.detection_rules.office_child_process import detect_office_suspicious_children
from services.endpoint_enterprise.detection_rules.process_masquerading import detect_process_masquerading

__all__ = ["detect_office_suspicious_children", "detect_process_masquerading"]
