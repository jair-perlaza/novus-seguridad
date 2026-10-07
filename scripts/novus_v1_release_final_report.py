#!/usr/bin/env python3
"""Genera NOVUS_V1_RELEASE_FINAL.md/json con evidencia de regresión."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "novus_release_candidate"
OUT_JSON = OUT_DIR / "NOVUS_V1_RELEASE_FINAL.json"
OUT_MD = OUT_DIR / "NOVUS_V1_RELEASE_FINAL.md"
PYTHON = sys.executable


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_cmd(label: str, cmd: List[str], timeout: int = 600) -> Dict[str, Any]:
    try:
        proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=timeout)
        return {
            "label": label,
            "cmd": cmd,
            "exit_code": proc.returncode,
            "verdict": "PASS" if proc.returncode == 0 else "FAIL",
            "stdout_tail": (proc.stdout or "")[-2000:],
            "stderr_tail": (proc.stderr or "")[-1000:],
        }
    except Exception as exc:
        return {"label": label, "cmd": cmd, "verdict": "FAIL", "error": str(exc)}


def load_json(path: Path) -> Dict[str, Any]:
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    regressions = [
        run_cmd("py_compile", [PYTHON, "-m", "py_compile"] + [
            str(p) for p in [
                ROOT / "services" / "production_runtime_guard.py",
                ROOT / "services" / "tenant_scope_service.py",
                ROOT / "services" / "platform_metrics_service.py",
                ROOT / "services" / "adaptive_defense_engine.py",
                ROOT / "services" / "topology_service.py",
                ROOT / "services" / "enterprise_snapshot_service.py",
                ROOT / "services" / "novus_security_integration.py",
                ROOT / "main.py",
            ]
        ]),
        run_cmd("tenant_isolation_service", [PYTHON, str(ROOT / "scripts" / "tenant_isolation_service_test.py")]),
        run_cmd("tenant_isolation_imcm_soc", [PYTHON, str(ROOT / "scripts" / "tenant_isolation_imcm_soc_search_test.py")]),
        run_cmd("clean_tenant_e2e", [PYTHON, str(ROOT / "scripts" / "novus_v1_clean_tenant_e2e.py")]),
        run_cmd("network_discovery_audit", [PYTHON, str(ROOT / "scripts" / "network_discovery_real_data_audit.py")]),
        run_cmd("mfa_admin_policy", [PYTHON, str(ROOT / "scripts" / "mfa_admin_policy_test.py")]),
    ]

    ram = load_json(OUT_DIR / "NOVUS_V1_RAM_PROFILE.json")
    clean = load_json(OUT_DIR / "NOVUS_V1_CLEAN_TENANT_E2E.json")
    quarantine = load_json(ROOT / "data" / "lab_quarantine" / "quarantine_manifest.json")

    modules = {
        "authentication": "REAL",
        "mfa": "REAL",
        "tenant_isolation": "REAL",
        "dashboard": "REAL_LIMITED",
        "ssot_metrics": "REAL",
        "network_discovery": "REAL_LIMITED",
        "network_nodes": "REAL_LIMITED",
        "network_topology": "REAL_LIMITED",
        "threat_detection": "REAL_LIMITED",
        "vulnerability_detection": "REAL_LIMITED",
        "endpoints": "REAL_LIMITED",
        "reports": "REAL",
        "evidence": "REAL",
        "sessions": "REAL",
        "health": "REAL_LIMITED",
        "deception_bas_ai": "NOT_IMPLEMENTED_MVP",
        "imcm_enterprise": "NOT_IMPLEMENTED_MVP",
        "soc_enterprise": "NOT_IMPLEMENTED_MVP",
    }

    reg_pass = all(r.get("verdict") == "PASS" for r in regressions)
    tenant_iso = all(
        r.get("verdict") == "PASS"
        for r in regressions
        if r.get("label", "").startswith("tenant_isolation")
    )
    clean_ok = clean.get("overall") == "VERIFIED"
    ram_summary = ram.get("summary") or {}
    ram_ok = not ram_summary.get("runaway_suspected") if ram_summary else False

    blockers = []
    if not reg_pass:
        blockers.append("regression_tests_failed")
    if not clean_ok:
        blockers.append("clean_tenant_contamination")
    if ram_summary and ram_summary.get("runaway_suspected"):
        blockers.append("ram_runaway")
    if not ram:
        blockers.append("ram_profile_missing")

    go = not blockers
    report = {
        "generated_at_utc": utc(),
        "A_functionalities": modules,
        "B_simulated_data_in_mvp": {"count_visible": 0, "note": "Floors topology/protection removed; deception excluded from MVP"},
        "C_qa_contamination": {
            "runtime_default": "blocked_without_NOVUS_ALLOW_LAB_RUNTIME",
            "quarantine_manifest": quarantine,
            "clean_tenant_e2e": clean,
        },
        "D_tenant_isolation": [r for r in regressions if "tenant_isolation" in r.get("label", "")],
        "E_mfa": [r for r in regressions if "mfa" in r.get("label", "")],
        "F_network_discovery": [r for r in regressions if "network_discovery" in r.get("label", "")],
        "G_ram": ram,
        "H_http_e2e": clean,
        "I_regression": regressions,
        "J_verdict": "GO" if go else "NO-GO",
        "blockers": blockers,
    }

    OUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    md_lines = [
        "# NOVUS V1 — Release Final",
        "",
        f"**Generado:** {report['generated_at_utc']}",
        "",
        f"## J. Verdict: **{report['J_verdict']}**",
        "",
    ]
    if blockers:
        md_lines.append("### Bloqueadores")
        for b in blockers:
            md_lines.append(f"- {b}")
        md_lines.append("")

    md_lines.extend([
        "## A. Funcionalidades MVP",
        "",
        "| Módulo | Clasificación |",
        "|--------|---------------|",
    ])
    for k, v in modules.items():
        md_lines.append(f"| {k} | {v} |")

    md_lines.extend([
        "",
        "## B. Datos simulados en MVP",
        "",
        f"**Objetivo:** 0 visibles en funcionalidades REAL del MVP.",
        "",
        "## C. QA contamination",
        "",
        f"- Clean tenant E2E: **{clean.get('overall', 'NOT_RUN')}**",
        f"- Quarantine actions: {len((quarantine.get('actions') or []))}",
        "",
        "## D–I. Regresión",
        "",
    ])
    for r in regressions:
        md_lines.append(f"- {r['label']}: **{r.get('verdict')}** (exit={r.get('exit_code')})")

    if ram_summary:
        md_lines.extend([
            "",
            "## G. RAM",
            "",
            f"- RSS growth: {ram_summary.get('rss_growth_mb')} MB",
            f"- Runaway suspected: {ram_summary.get('runaway_suspected')}",
        ])

    OUT_MD.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(json.dumps({"verdict": report["J_verdict"], "blockers": blockers}, indent=2))
    return 0 if go else 1


if __name__ == "__main__":
    sys.exit(main())
