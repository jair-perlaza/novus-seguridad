"""NOVUS Vulnerability Intelligence & Exposure Management (VIEM)."""
from services.viem.engine import (
    run_full_scan, get_dashboard, stats, search_vulns,
    propose_remediation, verify_remediation,
)
