#!/usr/bin/env python3
"""
Auditoría independiente de endurecimiento 2026-07-20.
No modifica auditorías anteriores. Porcentaje solo desde compute_protection_score().
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

OUT_DIR = os.path.join(ROOT, "data", "security_hardening_audit_20260720")
MD_OUT = os.path.join(OUT_DIR, "security_hardening_audit.md")
JSON_OUT = os.path.join(OUT_DIR, "protection_score_snapshot.json")
VERIFY_OUT = os.path.join(OUT_DIR, "verify_hardening_result.txt")

IMPROVEMENTS = [
    {
        "layer": "Datos sensibles",
        "items": [
            "services/sensitive_operations_audit.py — log JSONL operaciones críticas",
            "services/cryptovault_key_rotation.py — rotación AES con backup (schedule vía aes_key_max_age_days)",
            "startup_defense_service — verificación CryptoVault + política de rotación al boot",
        ],
    },
    {
        "layer": "Malware",
        "items": [
            "services/malware_behavior_engine.py — heurísticas LOLBin, PowerShell, mineros, hollowing hint",
            "advanced_detector_service.scan_running_processes — fusión con malware_behavior_engine",
        ],
    },
    {
        "layer": "Red",
        "items": [
            "services/network_baseline_service.py — baseline MAC LAN",
            "network_ndr_service.build_ndr_payload — network_baseline en payload NDR",
        ],
    },
    {
        "layer": "Web",
        "items": [
            "web_shield_analyzer — javascript:/data URLs y enlaces comprimidos/ejecutables",
        ],
    },
    {
        "layer": "Correo",
        "items": [
            "mail_shield_analyzer.analyze_graph_message — SPF/DKIM/DMARC desde headers Graph, Reply-To mismatch",
            "mail_shield_service — Web Shield en URLs solo con OAuth/config existente",
        ],
    },
    {
        "layer": "Ataques masivos (aplicación)",
        "items": [
            "services/http_abuse_guard.py — flood HTTP, circuit breaker, bots, slowloris parcial",
            "core/security.py — run_pre_request_checks en before_request",
            "hostile_hardening_config — defaults flood/circuit/bot/slowloris",
        ],
    },
    {
        "layer": "Zero Trust / sesión",
        "items": [
            "services/zero_trust_session_service.py — riesgo sesión desde eventos auth",
            "auth_protection_service.check_login_allowed — adjunta zero_trust en verificación de login",
        ],
    },
    {
        "layer": "Kernel IA",
        "items": [
            "services/kernel_threat_explainer.py — explicaciones desde campos del hallazgo",
            "module_kernel_context._ctx_xdr — threat_explanations en contexto consulta",
        ],
    },
    {
        "layer": "Métricas",
        "items": [
            "services/platform_protection_score_service.py — puntuación binaria verificable",
            "GET /api/system/protection-score",
        ],
    },
]

MODIFIED_FILES = [
    "services/advanced_detector_service.py",
    "services/network_ndr_service.py",
    "services/web_shield_analyzer.py",
    "services/startup_defense_service.py",
    "services/module_kernel_context.py",
    "services/mail_shield_analyzer.py",
    "services/hostile_hardening_config.py",
    "core/security.py",
    "api/system.py",
    "services/auth_protection_service.py",

NEW_FILES = [
    "services/sensitive_operations_audit.py",
    "services/cryptovault_key_rotation.py",
    "services/malware_behavior_engine.py",
    "services/network_baseline_service.py",
    "services/http_abuse_guard.py",
    "services/zero_trust_session_service.py",
    "services/kernel_threat_explainer.py",
    "services/platform_protection_score_service.py",
    "scripts/verify_security_hardening.py",
]

API_CHANGES = [
    "GET /api/system/protection-score — puntuación calculada (login requerido)",
]

LIMITATIONS = [
    "Sin mitigación de DDoS volumétrico a nivel ISP/CDN — solo rate limiting y circuit breaker HTTP en la app Flask.",
    "Rotación AES automática desactivada por defecto (aes_key_max_age_days=0); tokens cifrados con clave anterior no se re-cifran solos.",
    "Mail Shield Microsoft365 requiere internetMessageHeaders en Graph para auth completa.",
    "Baseline LAN se crea en el primer escaneo NDR con nodos visibles; no sustituye inventario NAC empresarial.",
    "malware_behavior_engine depende de cmdline/procesos visibles — sin kernel driver propio.",
    "VirusTotal y OAuth correo son checks opcionales en la puntuación global.",
]

RESIDUAL_RISKS = [
    "Instancia single-node SQLite — sin HA.",
    "Protección web limitada a heurísticas URL/certificados disponibles sin proxy transparente.",
    "Bot block desactivado por defecto (bot_block_enabled=false) — solo detección/registro.",
]


def _run_verify() -> dict:
    script = os.path.join(ROOT, "scripts", "verify_security_hardening.py")
    proc = subprocess.run(
        [sys.executable, script],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(VERIFY_OUT, "w", encoding="utf-8") as fh:
        fh.write(proc.stdout or "")
        if proc.stderr:
            fh.write("\n--- stderr ---\n")
            fh.write(proc.stderr)
    return {"exit_code": proc.returncode, "passed": proc.returncode == 0}


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    verify = _run_verify()

    from services.platform_protection_score_service import compute_protection_score

    score = compute_protection_score()
    with open(JSON_OUT, "w", encoding="utf-8") as fh:
        json.dump({"generated_at": datetime.now().isoformat(), "score": score, "verify": verify}, fh, indent=2)

    core_pct = score.get("core_protection_percent")
    overall_pct = score.get("overall_protection_percent")

    md = [
        "# Auditoría independiente — Endurecimiento de seguridad NOVUS",
        "",
        f"**Generado:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "> Auditoría nueva. No modifica informes en `data/official_defense_technical_audit_*` ni `data/final_hardening/`.",
        "",
        "## Puntuación de protección (calculada, no manual)",
        "",
        f"- **Core (checks obligatorios):** {core_pct}% ({score.get('core_passed')}/{score.get('core_total')})",
        f"- **Overall (incl. opcionales VT/OAuth/baseline):** {overall_pct}%",
        f"- DDoS volumétrico infra: **{score.get('ddos_volumetric_mitigation')}**",
        "",
        "## Verificación automatizada",
        "",
        f"- `scripts/verify_security_hardening.py`: **{'PASS' if verify.get('passed') else 'FAIL'}** (exit {verify.get('exit_code')})",
        "",
        "## Mejoras implementadas por capa",
        "",
    ]
    for block in IMPROVEMENTS:
        md.append(f"### {block['layer']}")
        for item in block["items"]:
            md.append(f"- {item}")
        md.append("")

    md.extend([
        "## Archivos nuevos",
        "",
    ])
    for f in NEW_FILES:
        md.append(f"- `{f}`")

    md.extend([
        "",
        "## Archivos modificados",
        "",
    ])
    for f in MODIFIED_FILES:
        md.append(f"- `{f}`")

    md.extend([
        "",
        "## APIs modificadas o añadidas",
        "",
    ])
    for a in API_CHANGES:
        md.append(f"- {a}")

    md.extend([
        "",
        "## Motores reforzados",
        "",
        "- advanced_detector_service (procesos + behavior engine)",
        "- network_ndr_service (baseline LAN)",
        "- web_shield_analyzer",
        "- mail_shield_analyzer (Graph headers)",
        "- http_abuse_guard + core/security before_request",
        "- startup_defense_service (CryptoVault + rotación programada)",
        "- module_kernel_context / kernel_threat_explainer",
        "",
        "## Limitaciones documentadas",
        "",
    ])
    for lim in LIMITATIONS:
        md.append(f"- {lim}")

    md.extend([
        "",
        "## Riesgos residuales",
        "",
    ])
    for r in RESIDUAL_RISKS:
        md.append(f"- {r}")

    md.extend([
        "",
        "## Detalle de checks",
        "",
        "| Check | OK | Opcional | Evidencia |",
        "|-------|----|----------|-----------|",
    ])
    for c in score.get("checks") or []:
        md.append(
            f"| {c.get('check')} | {c.get('passed')} | {c.get('optional')} | {c.get('evidence')} |"
        )

    with open(MD_OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))

    print(f"Auditoría: {MD_OUT}")
    print(f"Core: {core_pct}% | Overall: {overall_pct}%")
    return 0 if verify.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
