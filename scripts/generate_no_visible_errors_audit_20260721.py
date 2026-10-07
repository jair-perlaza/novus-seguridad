#!/usr/bin/env python3
"""Genera auditoría de eliminación de páginas de error visibles."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "no_visible_errors_audit_20260721")
sys.path.insert(0, ROOT)


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "verify_no_visible_errors.py")],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    ok = proc.returncode == 0

    md = [
        "# Auditoría — Sin páginas de error visibles",
        "",
        f"**Generado:** {ts}",
        "",
        f"**verify_no_visible_errors.py:** {'PASS' if ok else 'FAIL'}",
        "",
        "## Implementación",
        "",
        "- `services/novus_recovery_service.py` — registro interno (`data/novus_recovery/recovery_events.jsonl`), reinicio selectivo de módulos.",
        "- `core/recovery_middleware.py` — `after_request` normaliza HTTP ≥400 a recuperación (200).",
        "- `core/error_handlers.py` — excepciones → `novus_recovery.html` o JSON `status: recovering`.",
        "- `templates/novus_recovery.html` — animación + reintentos automáticos.",
        "- `static/js/novus-recovery-client.js` — fetch/XHR, overlay, reintentos.",
        "- `templates/export_error.html` — redirige (legacy); no muestra mensajes de error.",
        "",
        "## Logs administrativos",
        "",
        "- `data/novus_recovery/recovery_events.jsonl` — fecha, usuario, módulo, excepción, stack, acciones, ms.",
        "- `data/remote_access/http_errors.jsonl` — errores HTTP normalizados.",
        "",
        "## Alcance",
        "",
        "- Flask (rutas HTML + APIs REST bajo `/api/`).",
        "- Cliente: fetch, XMLHttpRequest, errores JS globales → overlay de recuperación.",
        "- Jobs en background: excepciones siguen en logs del motor; no se propagan al navegador.",
        "- WebSocket FastAPI (`realtime_engine.py`): proceso separado; conexiones fallidas no renderizan traceback en Flask UI.",
        "",
        "## Verificación automática",
        "",
        "```",
        (proc.stdout or proc.stderr or "").strip()[-1200:],
        "```",
    ]
    md_path = os.path.join(OUT, "no_visible_errors_audit.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))

    with open(os.path.join(OUT, "no_visible_errors_audit.json"), "w", encoding="utf-8") as fh:
        json.dump({"generated_at": ts, "verify_pass": ok}, fh, indent=2)

    print("Wrote", md_path)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
