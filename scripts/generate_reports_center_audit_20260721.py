#!/usr/bin/env python3
"""Auditoría Centro de Reportes y corrección de errores visibles — 2026-07-21."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "reports_center_audit_20260721")
sys.path.insert(0, ROOT)


def _run(name: str) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", name)],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rc1, out1 = _run("verify_reports_center.py")
    rc2, out2 = _run("verify_no_visible_errors.py")

    import urllib.request

    login_ok = False
    try:
        login_ok = urllib.request.urlopen("http://127.0.0.1:5000/login", timeout=12).status == 200
    except Exception as exc:
        login_note = str(exc)
    else:
        login_note = "HTTP 200"

    md = [
        "# Auditoría — Centro de Reportes y manejo de errores",
        "",
        f"**Generado:** {ts}",
        "",
        "## Errores encontrados y corregidos",
        "",
        "| Problema | Corrección |",
        "|----------|------------|",
        "| `Cannot set properties of null (setting 'disabled')` en Reportes (`novus-btn-details` inexistente) | Uso de `NovusRemediation._setReportButtons` / `NovusDom.setDisabled` con IDs reales del modal |",
        "| Mensajes técnicos (`error.message`, TypeError) en generación de reportes | Fases UX: Preparando / Analizando / Generando / Informe listo + recuperación |",
        "| Exportación limitada | PDF, HTML, JSON, CSV y **Excel (xlsx)** vía `export_report` |",
        "",
        "## Módulos revisados",
        "",
        "- `templates/reportes.html` — Centro de Reportes, historial red, export Excel",
        "- `services/reports_center_service.py` — catálogo e historial verificable",
        "- `api/reports.py` — `/center`, export historial red",
        "- `static/js/novus-dom-safe.js` — acceso DOM seguro (global)",
        "- `core/recovery_middleware.py` + `novus-recovery-client.js` — sin errores HTTP visibles",
        "",
        "## Validación automática",
        "",
        f"- `verify_reports_center.py`: **{'PASS' if rc1 == 0 else 'FAIL'}**",
        f"- `verify_no_visible_errors.py`: **{'PASS' if rc2 == 0 else 'FAIL'}**",
        f"- Servidor `/login`: **{'OK' if login_ok else 'NO RESPONDE'}** ({login_note})",
        "",
        "## Evidencia",
        "",
        "```",
        out1.strip()[-600:],
        "```",
        "",
        "```",
        out2.strip()[-400:],
        "```",
    ]
    path = os.path.join(OUT, "reports_center_audit.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    with open(os.path.join(OUT, "reports_center_audit.json"), "w", encoding="utf-8") as fh:
        json.dump(
            {"generated_at": ts, "verify_reports": rc1 == 0, "verify_errors": rc2 == 0, "login_ok": login_ok},
            fh,
            indent=2,
        )
    print("Wrote", path)
    return 0 if rc1 == 0 and rc2 == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
