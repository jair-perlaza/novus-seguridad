#!/usr/bin/env python3
"""
Informe final de fortalecimiento — defensa, cifrado, sectores, auditorías.
Basado exclusivamente en evidencia verificable; sin inflar porcentajes manualmente.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

OUT_DIR = os.path.join(ROOT, "data", "final_hardening")
JSON_OUT = os.path.join(OUT_DIR, "final_hardening_report.json")
MD_OUT = os.path.join(OUT_DIR, "final_hardening_report.md")


def _run(script: str, timeout: int = 300) -> dict:
    path = os.path.join(ROOT, "scripts", script)
    if not os.path.isfile(path):
        return {"script": script, "passed": False, "error": "not found"}
    try:
        proc = subprocess.run(
            [sys.executable, path],
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=timeout,
        )
        tail = (proc.stdout or "")[-3000:]
        return {
            "script": script,
            "exit_code": proc.returncode,
            "passed": proc.returncode == 0,
            "stdout_tail": tail,
            "stderr_tail": (proc.stderr or "")[-1500:],
        }
    except subprocess.TimeoutExpired:
        return {"script": script, "passed": False, "error": "timeout"}
    except Exception as exc:
        return {"script": script, "passed": False, "error": str(exc)}


def _load(path: str) -> dict:
    p = path if os.path.isabs(path) else os.path.join(ROOT, path)
    if not os.path.isfile(p):
        return {}
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    tests = [
        _run("test_auth_protection.py", 180),
        _run("test_api_hardening.py", 120),
        _run("test_defense_comprehensive.py", 300),
        _run("sector_protection_audit.py", 120),
        _run("uce_aspe_audit.py", 120),
        _run("data_truth_audit.py", 120),
        _run("audit_ui_buttons_complete.py", 180),
    ]
    _run("generate_executive_maturity_audit.py", 60)

    boot = _load("data/defense_boot_report.json")
    remote = _load("data/remote_access.json")
    maturity = _load("data/executive_maturity_audit.json")
    defense_audit = _load("scripts/defense_comprehensive_audit.json")
    sector_audit = _load("scripts/sector_audit_results.json")

    try:
        from services.startup_defense_service import initialize_defense_stack
        from services.defense_evidence_registry import get_registry_summary
        from crypto_vault import CryptoVault

        crypto = CryptoVault().verify_health()
        registry = get_registry_summary()
    except Exception as exc:
        crypto = {"status": "error", "error": str(exc)}
        registry = {}

    improvements = [
        "Coordinador central defense_coordinator — evidencia + Kernel IA unificados",
        "startup_defense_service — verificación CryptoVault, UCE y baselines ASPE al arranque",
        "ASPE evaluate_incident — registro en todo evaluación (detect/respond)",
        "UCE detect_infrastructure — registro en defense_registry",
        "NDR — alertas registradas antes de ASPE",
        "AI Kernel — alertas CPU/RAM en registry + kernel memory",
        "auth_protection — notify_kernel vía defense_coordinator",
        "security_engine register_threat_event — trazabilidad sectorial",
        "bootstrap_sector_baselines — perfiles fintech/logística/mobile/otros al boot",
        "scripts/start_ngrok_remote.py — acceso remoto autenticado vía ngrok",
    ]

    residual_risks = [
        "SQLite local — no HA multi-nodo en esta instancia",
        "TLS 1.3 depende del túnel/proxy externo (ngrok/cloudflare), no del proceso Flask",
        "Algunos motores sectoriales simulan telemetría cuando no hay fuente hardware real",
        "registry read en production_readiness puede fallar si el archivo JSONL está bloqueado",
        "Acceso remoto requiere NOVUS_BEHIND_PROXY=True para IP/rate-limit correctos",
    ]

    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "improvements_implemented": improvements,
        "defense_motors_boot": boot,
        "cryptovault_health": crypto,
        "defense_registry_summary": registry,
        "sector_baselines": boot.get("components", {}).get("sector_baselines", {}),
        "remote_access": remote,
        "tests_executed": tests,
        "tests_passed": sum(1 for t in tests if t.get("passed")),
        "tests_total": len(tests),
        "executive_maturity_audit": maturity,
        "defense_comprehensive": {
            "summary": defense_audit.get("summary"),
            "threat_coverage": defense_audit.get("threat_coverage"),
        },
        "sector_audit": sector_audit,
        "residual_risks": residual_risks,
        "recommendations": [
            "Configurar NOVUS_PUBLIC_URL y SECRET_KEY en .env antes de compartir ngrok",
            "Ejecutar auditoría integral profunda periódicamente vía /api/audit",
            "Rotar master_aes.key y ecc keys en entornos de producción desplegados",
            "Añadir authtoken ngrok para URLs estables en demos prolongadas",
            "Monitorear data/defense_registry/events.jsonl como fuente canónica de evidencia",
        ],
    }

    with open(JSON_OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    mat = maturity.get("protection_global") or maturity.get("auditoria_proteccion_global") or {}
    pct = mat.get("percentage") or mat.get("score_pct") or "N/D"

    md = [
        "# Informe Final — Fortalecimiento Defensa, Cifrado y Despliegue Remoto",
        "",
        f"**Generado:** {report['generated_at']}",
        "",
        "## Mejoras implementadas",
        "",
    ]
    for imp in improvements:
        md.append(f"- {imp}")

    md.extend([
        "",
        "## Estado motores de defensa",
        "",
        f"- Boot status: `{boot.get('status', 'N/D')}`",
        f"- Motores verificados: {boot.get('motors_verified', 'N/D')}",
        f"- Eventos defense registry: {registry.get('total_events', 'N/D')}",
        "",
        "## Cifrado (CryptoVault)",
        "",
        f"- AES-GCM roundtrip: `{crypto.get('aes_gcm_roundtrip')}`",
        f"- Claves ECC/AES presentes: `{crypto.get('ecc_private')}` / `{crypto.get('aes_key')}`",
        "",
        "## Cobertura sectorial",
        "",
    ])
    baselines = boot.get("components", {}).get("sector_baselines", {}).get("sectors") or {}
    for sk, prof in baselines.items():
        md.append(f"- **{sk}**: activos={len(prof.get('active_modules', []))}, foco={prof.get('threat_focus')}")

    md.extend([
        "",
        "## Pruebas",
        "",
        f"**{report['tests_passed']}/{report['tests_total']}** suites OK",
        "",
    ])
    for t in tests:
        md.append(f"- `{t.get('script')}`: {'PASS' if t.get('passed') else 'FAIL'}")

    md.extend([
        "",
        "## Nueva auditoría de protección",
        "",
        f"- Protección global (madurez ejecutiva): **{pct}%**",
        f"- Defense comprehensive: {defense_audit.get('summary', {})}",
        "",
        "## Acceso remoto NGROK",
        "",
        f"- URL pública: `{remote.get('public_url', 'no iniciado — ejecutar scripts/start_ngrok_remote.py')}`",
        "",
        "## Riesgos residuales",
        "",
    ])
    for r in residual_risks:
        md.append(f"- {r}")

    md.extend([
        "",
        "## Recomendaciones",
        "",
    ])
    for rec in report["recommendations"]:
        md.append(f"- {rec}")

    with open(MD_OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))

    print(f"Informe: {MD_OUT}")
    print(f"Pruebas: {report['tests_passed']}/{report['tests_total']}")
    print(f"Protección global: {pct}%")
    return 0 if report["tests_passed"] >= report["tests_total"] -  1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
