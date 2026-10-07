"""NOVUS Continuous Security Validation / Breach & Attack Simulation (CSV/BAS)."""
from services.csv_bas.engine import get_dashboard, stats, search, history, engines_status
from services.csv_bas.scenario_catalog import list_scenarios, get_scenario, SCENARIOS
from services.csv_bas.scenario_runner import run_scenario, run_all
from services.csv_bas.coverage_engine import compute_coverage
from services.csv_bas.kernel_console import ask_kernel
from services.csv_bas.limitations import LIMITATIONS, POLICY, NA, NI, ND, NV, DETECTED, CONTROL_ENGINES
