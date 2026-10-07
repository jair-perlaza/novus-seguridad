"""NOVUS Deception Platform Enterprise (DPE)."""
from services.deception_platform.engine import get_dashboard, get_status, stats, search
from services.deception_platform.honeypots import list_honeypots, configure_honeypot, activate_honeypot
from services.deception_platform.honeytokens import list_honeytokens, mint_honeytoken
from services.deception_platform.honeyfiles import list_honeyfiles, create_honeyfile, mark_opened
from services.deception_platform.honeycredentials import list_honeycredentials, create_honeycredential
from services.deception_platform.honeyshares import list_honeyshares, configure_honeyshare
from services.deception_platform.honeydatabase import list_honeydatabases, configure_honeydatabase
from services.deception_platform.decoy_servers import list_decoy_servers, configure_decoy_server
from services.deception_platform.segregation import segregation_report
from services.deception_platform.kernel_console import ask_kernel
from services.deception_platform.swarm_share import swarm_anonymous_summary
from services.deception_platform.integration import handle_decoy_interaction
from services.deception_platform.limitations import LIMITATIONS, POLICY, NA, NI, NC, CFG, ACT
