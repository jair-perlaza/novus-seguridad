#!/usr/bin/env python3
"""Genera auditoría de historial de seguridad + monitoreo continuo (2026-07-21)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "network_security_history_audit_20260721")
sys.path.insert(0, ROOT)


def _run(script: str) -> tuple[int, str]:
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", script)],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    v1_code, v1_out = _run("verify_continuous_monitoring.py")
    v2_code, v2_out = _run("verify_network_security_history.py")

    from services.continuous_monitoring_orchestrator import activate_all_defense_motors_on_login
    from services.network_security_history_service import get_network_history_summary

    motors = activate_all_defense_motors_on_login(None)
    summary = get_network_history_summary()

    md_lines = [
        "# Auditoría — Historial de Seguridad de la Red y Monitoreo Continuo",
        "",
        f"**Generado:** {ts}",
        "",
        "## Validación automática",
        "",
        f"- `verify_continuous_monitoring.py`: **{'PASS' if v1_code == 0 else 'FAIL'}**",
        f"- `verify_network_security_history.py`: **{'PASS' if v2_code == 0 else 'FAIL'}**",
        "",
        "## Mecanismos activos tras `activate_all_defense_motors_on_login`",
        "",
    ]
    for m in motors.get("motors") or []:
        md_lines.append(f"- {m}")
    md_lines.extend([
        "",
        "## Monitoreo continuo",
        "",
        "- Fase 1 inmediata post-login (`run_phase1_immediate_analysis`) — sistema, firewall, AV, procesos, conexiones, red local.",
        "- Fase 2 en segundo plano (`deep_scan_engine` perfil `login_session`) — escaneo profundo sin bloquear UI.",
        "- Motores de fondo: `network_monitor_engine`, `endpoint_realtime_monitor`, `network_scanner`, Web Shield, Kernel IA, NDR (`build_ndr_payload`).",
        "- Mail Shield solo si OAuth Gmail/M365 está configurado y autorizado.",
        "",
        "## Datos de red (observación real)",
        "",
        f"- Gateway: `{summary.get('network_context', {}).get('gateway')}`",
        f"- Subred: `{summary.get('network_context', {}).get('subnet')}`",
        f"- Dispositivos visibles (cache escaneo): {summary.get('network_context', {}).get('visible_devices_count')}",
        f"- Eventos en historial actual: {summary.get('event_count')}",
        "",
        "## Historial de Seguridad",
        "",
        f"- Módulo UI: `/historial-seguridad-red`",
        f"- API: `/api/network-security-history/summary`, `/events`",
        f"- Almacenamiento: `data/network_security_history/{{scope_id}}/events.jsonl`",
        f"- Aviso: {summary.get('disclaimer') or '(pendiente primer monitoreo)'}",
        "",
        "## Limitaciones (sin datos inventados)",
        "",
        "- No se afirma histórico de red anterior a la primera observación NOVUS en ese alcance (gateway+subred).",
        "- Dispositivos y puertos dependen de escaneo ARP/DNS legítimo desde el host donde corre NOVUS.",
        "- Correo y navegador requieren integraciones/extensiones autorizadas; sin ellas no se generan eventos ficticios.",
        "- Vulnerabilidades y procesos provienen de motores locales; ausencia de hallazgos no implica red limpia global.",
        "",
        "## Riesgos residuales",
        "",
        "- Amenazas fuera del segmento visible o cifradas end-to-end pueden no detectarse.",
        "- Monitoreo continuo depende de que el proceso NOVUS permanezca activo.",
        "- ngrok/túnel público amplía superficie de ataque si credenciales son débiles.",
        "",
        "## Evidencia de verificación",
        "",
        "```",
        v1_out.strip()[-800:],
        "```",
        "",
        "```",
        v2_out.strip()[-800:],
        "```",
    ])

    md_path = os.path.join(OUT, "network_security_history_audit.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md_lines))

    json_path = os.path.join(OUT, "network_security_history_audit.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "generated_at": ts,
                "verify_continuous": v1_code == 0,
                "verify_network_history": v2_code == 0,
                "motors": motors,
                "summary_snapshot": {
                    "scope_id": summary.get("scope_id"),
                    "event_count": summary.get("event_count"),
                    "disclaimer": summary.get("disclaimer"),
                },
            },
            fh,
            indent=2,
            ensure_ascii=False,
        )

    print("Wrote", md_path)
    return 0 if v1_code == 0 and v2_code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
