#!/usr/bin/env python3
"""Genera informe final de integración NOVUS."""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_full_integration_report"
AUDIT = ROOT / "data" / "novus_master_capability_audit"
PERF = ROOT / "data" / "novus_performance_forensic_audit"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(p: Path):
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return {}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    cap = load_json(AUDIT / "CAPABILITY_MATRIX.json")
    api = load_json(OUT / "API_STATUS.json")
    modules = cap.get("modules") or []

    by_status = {}
    for m in modules:
        st = m.get("status", "?")
        by_status.setdefault(st, []).append(m.get("module"))

    repaired = [
        "Autenticación enterprise unificada (Flask-Login _user_id)",
        "security_snapshot_service — /api/security/summary non-blocking",
        "network_snapshot_service — nodes/ndr/topology snapshot-first",
        "topology_service — NDR cache sin ARP sync en GET",
        "network_security_history — sin scan_arp_light sincrónico",
        "enterprise_snapshot_service — warmup extendido + módulos ASM/VIEM/SOC/etc",
        "novus_enterprise_knowledge.py — vocabulario + dispatcher sin simulación",
        "threats API — performance_cache TTL",
        "reports /list alias",
    ]

    remaining_recovering = [r["path"] for r in (api.get("critical_probes") or []) if r.get("recovering")]
    remaining_timeout = [r["path"] for r in (api.get("critical_probes") or []) if r.get("error")]

    payload = {
        "generated_at_utc": utc(),
        "operativos": by_status.get("🟢 OPERATIVO VERIFICADO", []),
        "operativos_limitaciones": by_status.get("🟢 OPERATIVO CON LIMITACIONES", []),
        "reparados_en_esta_sesion": repaired,
        "recovering_restantes": remaining_recovering,
        "timeout_restantes": remaining_timeout,
        "simulacion": by_status.get("⚫ SIMULACIÓN / DEMOSTRACIÓN INTENCIONAL", []),
        "no_implementado_acciones_fintech": [
            "execute_rate_limit_and_mfa_enforcement",
            "isolate_transaction_pipeline_and_verify_signatures",
            "trigger_biometric_stepup_auth",
            "block_bin_range_and_enable_3ds2",
        ],
    }

    OUT.joinpath("MODULE_STATUS.json").write_text(
        json.dumps({"modules": modules, "counts": cap.get("counts")}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    OUT.joinpath("ENTERPRISE_MODULE_STATUS.json").write_text(
        json.dumps({m["module_id"]: m for m in modules if m["module_id"] in (
            "tie", "asm", "viem", "soc", "sope", "imcm", "sdl", "sdace", "deception", "iapa", "csv_bas", "identity_intel", "health_center"
        )}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    OUT.joinpath("IA_KERNEL_STATUS.json").write_text(
        (AUDIT / "IA_KERNEL_CAPABILITIES.json").read_text(encoding="utf-8") if (AUDIT / "IA_KERNEL_CAPABILITIES.json").is_file() else "{}",
        encoding="utf-8",
    )
    OUT.joinpath("NETWORK_STATUS.json").write_text(
        (AUDIT / "NETWORK_CAPABILITIES.json").read_text(encoding="utf-8") if (AUDIT / "NETWORK_CAPABILITIES.json").is_file() else "{}",
        encoding="utf-8",
    )
    OUT.joinpath("XDR_STATUS.json").write_text(
        json.dumps(load_json(AUDIT / "SECURITY_MODULES.json"), indent=2),
        encoding="utf-8",
    )
    OUT.joinpath("PLAYBOOK_STATUS.json").write_text(
        json.dumps({"note": "Playbooks DEFINIDOS en data/playbooks; ejecución vía SOPE/remediation con confirmación", "defined": True, "auto_execute_kernel": False}, indent=2),
        encoding="utf-8",
    )
    OUT.joinpath("DATA_TRUTH_STATUS.json").write_text(
        (AUDIT / "DATA_TRUTH.json").read_text(encoding="utf-8") if (AUDIT / "DATA_TRUTH.json").is_file() else "{}",
        encoding="utf-8",
    )
    OUT.joinpath("ERRORS_REMAINING.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    before = load_json(PERF / "LIVE_VERIFICATION.json") if (PERF / "LIVE_VERIFICATION.json").is_file() else {}
    after = load_json(AUDIT / "LIVE_VERIFICATION.json")
    OUT.joinpath("PERFORMANCE_BEFORE_AFTER.json").write_text(
        json.dumps({"before_audit": before, "after_audit": after, "critical_probes": api}, indent=2),
        encoding="utf-8",
    )

    md = f"""# NOVUS — Informe Final de Integración

Generado: {utc()}

## Reparaciones aplicadas (código)

{chr(10).join('- ' + x for x in repaired)}

## Causa raíz principal identificada

1. **APIs enterprise** usaban `_auth()` con claves de sesión legacy → HTTP 401 → middleware `recovering`.
2. **`get_connected_network_context`** ejecutaba `scan_arp_light()` sincrónicamente → timeout historial/red.
3. **Topology/NDR** en cache miss ejecutaban agregación pesada en hilo HTTP.

## Estado post-reparación (requiere reinicio servidor)

Ejecutar `py scripts/novus_full_integration_verify.py` tras reiniciar NOVUS.

### Recovering restantes (última probe)

{remaining_recovering or '— re-verificar tras reinicio'}

### Timeout restantes (última probe)

{remaining_timeout or '— re-verificar tras reinicio'}

## IA Kernel + Enterprise Knowledge

- Módulo: `services/novus_enterprise_knowledge.py` (vocabulario MITRE/malware/IoC)
- Bridge: `services/enterprise_knowledge_bridge.py`
- Acciones fintech documentadas **sin motor** → NOT_IMPLEMENTED (no simulación)
- Acciones reales: block_ip (os_firewall), isolate_asset (AIE), scan_network, record_detection

## Trabajo pendiente

- Reiniciar servidor y re-ejecutar auditoría live
- Verificar que `/api/network/nodes` responde <500ms con snapshot pending
- Confirmar 0 recovering en módulos enterprise tras fix `_user_id`
- Playbook ejecución end-to-end SOPE → enforcer
"""
    OUT.joinpath("FINAL_STATUS.md").write_text(md, encoding="utf-8")
    print("Wrote", OUT)


if __name__ == "__main__":
    main()
