#!/usr/bin/env python3
"""Auditoría independiente — monitoreo automático post-login."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "continuous_monitoring_audit_20260721")
MD = os.path.join(OUT, "continuous_monitoring_audit.md")


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "verify_continuous_monitoring.py")],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )
    verify_ok = proc.returncode == 0

    lines = [
        "# Auditoría — Monitoreo automático y reportes ejecutivos",
        "",
        f"**Generado:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "> Informe nuevo. No modifica auditorías en `data/security_hardening_audit_*` ni `executive_operational_maturity_audit_*`.",
        "",
        f"**Verificación:** `scripts/verify_continuous_monitoring.py` — {'PASS' if verify_ok else 'FAIL'}",
        "",
        "## Mecanismos activos tras login",
        "",
        "- `services/continuous_monitoring_orchestrator.ensure_continuous_monitors` — network_monitor_engine, endpoint_realtime_monitor, network_scanner",
        "- `services/login_session_audit_service._run_post_login_check_async` — dispara orquestador",
        "",
        "## Análisis al iniciar sesión",
        "",
        "- **Fase 1:** `run_phase1_immediate_analysis` — sistema, CryptoVault, procesos, puertos, conexiones, red (caché), auth, amenazas XDR, vulnerabilidades",
        "- **Fase 2:** `deep_scan_engine.start_scan(profile=login_session)` en hilo daemon",
        "",
        "## Monitoreo continuo",
        "",
        "- `network_monitor_engine` (arranque en main.py / scanner)",
        "- `endpoint_realtime_monitor` (ciclos `run_monitor_cycle`)",
        "- `device_connection_monitor` / NDR (existentes, no duplicados)",
        "",
        "## Informes",
        "",
        "- `services/auto_monitoring_report_builder.build_executive_auto_report`",
        "- Persistencia: `services/security_report_service.save_report` → `data/reports/` + índice",
        "- ID informe: `AUTO-{session_audit_id}`",
        "",
        "## API / UI",
        "",
        "- `GET /api/monitoring/status` — progreso fase 1/2",
        "- `static/js/novus-continuous-monitor.js` en dashboard",
        "",
        "## Respuesta automática",
        "",
        "- Solo hallazgos `high/critical` en procesos: `defense_coordinator.record_detection` (registro, sin eventos ficticios)",
        "",
        "## Limitaciones",
        "",
        "- Correo: solo si OAuth Mail Shield ya configurado (no forzado en este flujo)",
        "- Escaneo memoria/kernel-mode limitado a capacidades de `deep_scan_engine` en Windows",
        "- DDoS volumétrico / IDS DNS no forman parte de este orquestador",
        "- Informe fase 1 puede mostrar «No analizado» hasta completar fase 2",
        "",
        "## Riesgos residuales",
        "",
        "- Contención automática limitada a registro en registry (no bloqueo OS sin playbook)",
        "- Un login concurrente por email evita duplicar hilos; segundo login no reinicia escaneo",
        "",
        "## Archivos tocados",
        "",
        "- `services/continuous_monitoring_orchestrator.py` (nuevo)",
        "- `services/auto_monitoring_report_builder.py` (nuevo)",
        "- `services/login_session_audit_service.py`",
        "- `services/deep_scan_engine.py` (perfil login_session)",
        "- `api/monitoring.py`, `core/app.py`",
        "- `templates/dashboard.html`, `static/js/novus-continuous-monitor.js`",
        "",
    ]
    with open(MD, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    with open(os.path.join(OUT, "verify_output.txt"), "w", encoding="utf-8") as fh:
        fh.write(proc.stdout or "")
        fh.write(proc.stderr or "")

    print(MD)
    return 0 if verify_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
