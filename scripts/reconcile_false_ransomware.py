"""Reconcilia alertas ransomware históricas sin evidencia activa del motor."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.alert_reconciliation_service import reconcile_stale_security_alerts


if __name__ == "__main__":
    result = reconcile_stale_security_alerts()
    print("Reconciliación completada:", result)
