#!/usr/bin/env python3
"""Perfil in-process por componente (subprocess aislado) — RSS delta por import/función."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_release_candidate" / "NOVUS_RAM_INPROCESS_PROFILE.json"

SNIPPETS = {
    "import_flask_app": "from core.app import app; _=app",
    "import_novus_security": "from services.novus_security_integration import novus_security; _=novus_security",
    "threat_cache_read": "from services.novus_security_integration import novus_security; _=novus_security._threat_cache",
    "scan_vulnerabilities": "from services.novus_security_integration import novus_security; _=novus_security.scan_vulnerabilities()",
    "detect_threats": "from services.novus_security_integration import novus_security; _=novus_security.detect_threats_realtime(force=False)",
    "network_scanner_cache": "from services.network_scanner import network_scanner; _=network_scanner.get_cached_nodes()",
    "arp_light": "from services.network_scanner import network_scanner; _=network_scanner.scan_arp_light()",
    "platform_counters": "from services.platform_metrics_service import get_platform_counters; _=get_platform_counters()",
    "reports_list": "from services.security_report_service import list_reports; _=list_reports(limit=50)",
    "reports_center": "from services.reports_center_service import get_reports_center_payload; _=get_reports_center_payload(reports_limit=40)",
    "global_search": "from services.global_search_index import search_live; _=search_live('alert', tenant_id='QA-NOVUS-2026')",
    "canonical_alerts": "from services.alerts_canonical_service import get_canonical_alerts; _=get_canonical_alerts(limit=50)",
}


WORKER = r"""
import json, sys, psutil, os, gc
os.chdir(r'{root}')
sys.path.insert(0, r'{root}')
proc = psutil.Process()
gc.collect()
base = proc.memory_info().rss
code = {code!r}
try:
    exec(code, {{'__name__': '__main__'}})
    gc.collect()
    after = proc.memory_info().rss
    print(json.dumps({{'ok': True, 'rss_delta_mb': round((after-base)/(1024*1024),1), 'rss_after_mb': round(after/(1024*1024),1)}}))
except Exception as e:
    print(json.dumps({{'ok': False, 'error': str(e)[:200]}}))
"""


def run_case(name: str, code: str) -> dict:
    script = WORKER.format(root=str(ROOT), code=code)
    r = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(ROOT),
    )
    row = {"component": name, "stdout": (r.stdout or "").strip()[:500], "stderr": (r.stderr or "").strip()[:200]}
    try:
        row.update(json.loads((r.stdout or "").strip().splitlines()[-1]))
    except Exception:
        row["ok"] = False
    row["exit_code"] = r.returncode
    return row


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = [run_case(k, v) for k, v in SNIPPETS.items()]
    rows.sort(key=lambda x: x.get("rss_delta_mb") or 0, reverse=True)
    OUT.write_text(json.dumps({"components": rows}, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(OUT), "top": rows[:5]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
