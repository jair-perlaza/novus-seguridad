"""
Genera informe de implementación de protección avanzada contra accesos no autorizados.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

OUT_DIR = os.path.join(ROOT, "data", "auth_protection")
JSON_OUT = os.path.join(OUT_DIR, "implementation_report.json")
MD_OUT = os.path.join(OUT_DIR, "implementation_report.md")


def _run_test(script: str) -> dict:
    path = os.path.join(ROOT, "scripts", script)
    try:
        proc = subprocess.run(
            [sys.executable, path],
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=180,
        )
        return {
            "script": script,
            "exit_code": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-2000:] if proc.stderr else "",
            "passed": proc.returncode == 0,
        }
    except Exception as exc:
        return {"script": script, "passed": False, "error": str(exc)}


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    from services.auth_protection_service import (
        LEVEL1_THRESHOLD,
        LEVEL2_THRESHOLD,
        LEVEL3_THRESHOLD,
        FAILURE_WINDOW_MINUTES,
        BASE_BLOCK_MINUTES,
        auth_protection,
    )

    tests = [
        _run_test("test_auth_protection.py"),
        _run_test("test_production_readiness.py"),
        _run_test("test_api_hardening.py"),
    ]

    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mechanism": {
            "name": "Auth Protection Service",
            "module": "services/auth_protection_service.py",
            "scope": "Bloqueo/limitación por origen (IP, dispositivo, sesión) — NO bloqueo global de API",
            "levels": {
                "level1": {
                    "threshold": LEVEL1_THRESHOLD,
                    "action": "Registro + monitoreo elevado",
                },
                "level2": {
                    "threshold": LEVEL2_THRESHOLD,
                    "action": "Bloqueo temporal del origen + incidente + Kernel IA + evidencia",
                    "block_minutes_base": BASE_BLOCK_MINUTES,
                },
                "level3": {
                    "threshold": LEVEL3_THRESHOLD,
                    "action": "Bloqueo progresivo + Adaptive Defense + contención",
                },
            },
            "criteria": {
                "failure_window_minutes": FAILURE_WINDOW_MINUTES,
                "signals": ["ip", "device_fingerprint", "session_id", "email", "frequency", "timestamp"],
                "evidence_store": ["auth_access_events", "auth_origin_sanctions", "incidents.jsonl", "defense_registry"],
            },
            "integration": [
                "routes/auth.py — login y sector_auth",
                "core/security.py — verificación previa en POST /login",
                "services/module_kernel_context.py — contexto auth_protection",
                "api/system.py — /auth-protection/status e /incidents",
                "services/novus_security_integration.py — escaneo background",
            ],
        },
        "current_status": auth_protection.get_protection_status(),
        "recent_incidents": auth_protection.list_incidents(limit=10),
        "tests_executed": tests,
        "tests_summary": {
            "total": len(tests),
            "passed": sum(1 for t in tests if t.get("passed")),
            "failed": sum(1 for t in tests if not t.get("passed")),
        },
    }

    with open(JSON_OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    md_lines = [
        "# Informe — Protección Avanzada contra Accesos No Autorizados",
        "",
        f"**Generado:** {report['generated_at']}",
        "",
        "## Implementación",
        "",
        f"- **Módulo:** `{report['mechanism']['module']}`",
        f"- **Alcance:** {report['mechanism']['scope']}",
        "",
        "### Respuesta escalonada",
        "",
        f"| Nivel | Umbral | Acción |",
        f"|-------|--------|--------|",
        f"| 1 | {LEVEL1_THRESHOLD} fallos | Monitoreo elevado + registro |",
        f"| 2 | {LEVEL2_THRESHOLD} fallos | Bloqueo temporal del origen + incidente + Kernel IA |",
        f"| 3 | {LEVEL3_THRESHOLD} fallos | Bloqueo progresivo + Adaptive Defense |",
        "",
        "### Criterios analizados",
        "",
        "- IP, sesión, dispositivo (fingerprint), usuario, frecuencia, hora y patrón en ventana de "
        f"{FAILURE_WINDOW_MINUTES} minutos.",
        "",
        "## Pruebas ejecutadas",
        "",
    ]
    for t in tests:
        status = "PASS" if t.get("passed") else "FAIL"
        md_lines.append(f"- `{t.get('script')}`: **{status}** (exit {t.get('exit_code', 'N/A')})")
    md_lines.extend([
        "",
        f"**Resumen:** {report['tests_summary']['passed']}/{report['tests_summary']['total']} suites OK",
        "",
        "## Estado actual",
        "",
        f"- Fallos recientes (ventana): {report['current_status'].get('recent_failures_window')}",
        f"- Orígenes bloqueados: {report['current_status'].get('active_blocks')}",
        f"- Monitoreo elevado: {report['current_status'].get('elevated_monitoring')}",
        f"- Incidentes registrados: {report['current_status'].get('incidents_total')}",
        "",
        "## Resultado",
        "",
        "El bloqueo se aplica únicamente al origen del ataque (IP/dispositivo/sesión). "
        "Usuarios legítimos desde otros orígenes mantienen acceso normal a la API.",
    ])

    with open(MD_OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md_lines))

    print(f"Informe JSON: {JSON_OUT}")
    print(f"Informe MD: {MD_OUT}")
    print(f"Pruebas: {report['tests_summary']['passed']}/{report['tests_summary']['total']} OK")
    return 0 if report["tests_summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
