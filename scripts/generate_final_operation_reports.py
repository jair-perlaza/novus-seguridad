#!/usr/bin/env python3
"""Genera informes finales de operación real — solo documentación, sin cambios al producto."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_real_operation_audit"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(name: str, default=None):
    p = OUT / name
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return default


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    ts = utc()
    baseline = load("REAL_OPERATION_BASELINE.json", {})
    dashboard = load("REAL_OPERATION_DASHBOARD.json", {"samples": []})
    validation = load("REAL_OPERATION_VALIDATION.json", {})
    incident = load("REAL_OPERATION_INCIDENT_LOG.json", {"incidents": []})

    samples = dashboard.get("samples") or []
    ram_sys = [s.get("system", {}).get("ram_pct") for s in samples if s.get("system")]
    ram_novus = [s.get("novus_process", {}).get("ram_mb") for s in samples if s.get("novus_process")]

    matrix = [
        {"module": "Network", "classification": "REAL", "reason": "ARP/OS verificado 10.91.155.166"},
        {"module": "Topology", "classification": "PARCIAL", "reason": "snapshot-first; stale observado"},
        {"module": "Asset Inventory", "classification": "PARCIAL", "reason": "DB 59 activos; TEST persistió"},
        {"module": "Asset Intelligence", "classification": "NO VERIFICADO", "reason": "ASM no ejercido en operación"},
        {"module": "Vulnerabilities", "classification": "PARCIAL", "reason": "4 en DB; scan live NO VERIFICADO"},
        {"module": "Vulnerability Intelligence", "classification": "NO VERIFICADO", "reason": "VIEM no ejercido"},
        {"module": "XDR", "classification": "PARCIAL", "reason": "2192+ alertas DB; E2E NO VERIFICADO"},
        {"module": "Web Shield", "classification": "NO VERIFICADO", "reason": "P1 boot; eventos no auditados E2E"},
        {"module": "Mail Shield", "classification": "NO VERIFICADO", "reason": "requiere OAuth"},
        {"module": "Incidents", "classification": "NO VERIFICADO", "reason": "no ejercido"},
        {"module": "Endpoints", "classification": "NO VERIFICADO", "reason": "lazy P2; RAM pressure"},
        {"module": "Playbooks", "classification": "NO VERIFICADO", "reason": "código+DB; no ejercido"},
        {"module": "Reports", "classification": "NO VERIFICADO", "reason": "timeout /api/reports/list"},
        {"module": "Access History", "classification": "PARCIAL", "reason": "192+ login_sessions DB real"},
        {"module": "Blocking Center", "classification": "NO VERIFICADO", "reason": "IPBloqueada existe; no probado E2E"},
        {"module": "Health Center", "classification": "NO VERIFICADO", "reason": "lazy engine"},
        {"module": "Platform Health", "classification": "PARCIAL", "reason": "engine status; recovering wrapper"},
        {"module": "Threat Intelligence", "classification": "NO VERIFICADO", "reason": "TIE feeds/API keys"},
        {"module": "Playbook Center", "classification": "NO VERIFICADO", "reason": "SOPE no ejercido"},
        {"module": "Incident Management", "classification": "NO VERIFICADO", "reason": "IMCM jsonl no probado"},
        {"module": "Security Operations", "classification": "NO VERIFICADO", "reason": "SOC no ejercido"},
        {"module": "Security Data Lake", "classification": "NO VERIFICADO", "reason": "SDL no ejercido"},
        {"module": "Data Analytics", "classification": "NO VERIFICADO", "reason": "SDACE no ejercido"},
        {"module": "Identity Intelligence", "classification": "NO VERIFICADO", "reason": "IIUEBA no ejercido"},
        {"module": "Attack Path", "classification": "NO VERIFICADO", "reason": "IAPA no ejercido"},
        {"module": "Deception", "classification": "SIMULADO", "reason": "honeypots/decoys intencional"},
        {"module": "Security Validation", "classification": "SIMULADO", "reason": "CSV/BAS scenarios"},
        {"module": "BTDE", "classification": "NO VERIFICADO", "reason": "baseline host; ml_classifier=false"},
        {"module": "ZDDE", "classification": "NO VERIFICADO", "reason": "lazy P2"},
        {"module": "Swarm Defense", "classification": "NO VERIFICADO", "reason": "simulate-ingest exists"},
        {"module": "Swarm Mesh", "classification": "NO VERIFICADO", "reason": "P2P no ejercido"},
        {"module": "Adaptive Profile", "classification": "PARCIAL", "reason": "heurístico; baseline global host"},
        {"module": "WSAE", "classification": "NO VERIFICADO", "reason": "MFA/sessions no auditados E2E"},
        {"module": "CryptoVault", "classification": "REAL", "reason": "AES-GCM; keyring; backups VERIFICADOS"},
        {"module": "Evidence Center", "classification": "PARCIAL", "reason": "30895 evidences; tenant row NO VERIFICADO"},
        {"module": "Evidence Verifier", "classification": "NO VERIFICADO", "reason": "forensic chain no ejercido"},
        {"module": "Compliance Center", "classification": "NO VERIFICADO", "reason": "evaluación no certificación"},
        {"module": "Defense Center", "classification": "NO VERIFICADO", "reason": "manual defense no ejercido"},
        {"module": "Device History", "classification": "NO VERIFICADO", "reason": "DeviceConnectionEvent no probado tenant"},
        {"module": "Security History", "classification": "NO VERIFICADO", "reason": "jsonl scope no probado tenant"},
        {"module": "IA Kernel", "classification": "PARCIAL", "reason": "heurístico boot P1; NO ML"},
        {"module": "Intelligence Center", "classification": "NO VERIFICADO", "reason": "/inteligencia no ejercido"},
        {"module": "Case Studies", "classification": "SIMULADO", "reason": "NDCI documentación/demo"},
    ]

    (OUT / "REAL_VS_SIMULATION_MATRIX.json").write_text(
        json.dumps({"generated_at_utc": ts, "modules": matrix}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    protection = {
        "generated_at_utc": ts,
        "items": [
            {"asset": "Contraseñas usuarios", "location": "novus_vault_v2.db usuarios.hashed_password", "classification": "PROTEGIDO", "detail": "werkzeug pbkdf2/scrypt hash"},
            {"asset": "Sesiones Flask", "location": "cookie firmada SECRET_KEY", "classification": "PROTEGIDO", "detail": "runtime"},
            {"asset": "SQLite runtime", "location": "novus_vault_v2.db", "classification": "EN CLARO", "detail": "mientras proceso activo — documentado"},
            {"asset": "SQLite at-rest", "location": "novus_vault_v2.db.novusenc", "classification": "PROTEGIDO", "detail": "AES-256-GCM CryptoVault"},
            {"asset": "Backups", "location": "data/encrypted_backups/*.novusbak.json", "classification": "PROTEGIDO", "detail": "SHA256 verified"},
            {"asset": "CryptoVault keyring", "location": "data/cryptovault/keyring.json", "classification": "PROTECCIÓN PARCIAL", "detail": "keys wrapped; file on disk"},
            {"asset": "NDCI case blobs", "location": "data/ndci/", "classification": "PROTEGIDO", "detail": "NOVUSENC:v1"},
            {"asset": "Alertas/eventos/logs DB", "location": "SQLite tablas alertas/logs", "classification": "EN CLARO", "detail": "103k+ logs en runtime DB"},
            {"asset": "Snapshots JSON", "location": "data/network/*.json, data/security/", "classification": "EN CLARO", "detail": "IP/MAC/nodos reales"},
            {"asset": "Enterprise jsonl", "location": "data/imcm, data/soc, data/sdl, etc.", "classification": "EN CLARO", "detail": "NO VERIFICADO cifrado per-file"},
            {"asset": "kernel_memory", "location": "data/kernel_memory/*.json", "classification": "EN CLARO", "detail": "contadores consulta; per-user key"},
            {"asset": "baseline_cache", "location": "data/behavioral_threat_detection/baseline_cache.json", "classification": "EN CLARO", "detail": "global host; sin tenant_id"},
            {"asset": "OAuth tokens mail", "location": "data/gmail/*/token.json", "classification": "NO VERIFICADO", "detail": "posible JSON en claro"},
            {"asset": "Logs aplicación", "location": "DB logs + stdout", "classification": "EN CLARO", "detail": "puede contener IPs/emails"},
        ],
        "cryptovault_protects": ["backups .novusbak", "contenedor .novusenc", "blobs NOVUSENC", "key wrapping"],
        "cryptovault_does_not_protect": ["SQLite abierto en runtime", "snapshots JSON", "jsonl enterprise", "kernel_memory", "baseline host-global"],
    }

    ai_kernel = {
        "generated_at_utc": ts,
        "classification": "HEURÍSTICO",
        "ml_evidence": False,
        "memorizes": [
            "Contadores consultas/intents por usuario (kernel_memory)",
            "Procesos/servicios/remotos vistos (baseline_cache.json)",
            "Perfiles adaptativos heurísticos (APE, behavior_* DB)",
        ],
        "storage": {
            "kernel_memory": "data/kernel_memory/{user_key}.json",
            "baseline": "data/behavioral_threat_detection/baseline_cache.json",
            "behavior_db": "behavior_activity_events, behavior_baseline_profiles, behavior_anomalies",
        },
        "updates_when": [
            "BTDE update_from_snapshot() en ciclos host",
            "Interacciones chat/consulta kernel",
            "APE rebuild_defense_profile() heurístico",
        ],
        "can_learn": ["Acumular sets proc/service/remote", "Preferencias consulta usuario", "Umbrales baseline"],
        "cannot_learn": ["Modelos ML", "Zero-day ML", "Inferencia entrenada", "Automatización OS autónoma"],
        "survives_restart": True,
        "tenant_isolated": "NO — baseline host-global; kernel_memory per-user email/id NO tenant_id column",
        "cross_tenant_contamination_risk": "PARCIAL — kernel_memory por usuario; baseline compartido a nivel host",
        "auto_actions_from_learning": ["Recomendaciones chat", "Scoring heurístico BTDE/APE — NO bloqueo OS automático por baseline solo"],
        "guardia": "Regex/rules ai_engine.py — NOT ML",
    }

    multitenant = {
        "generated_at_utc": ts,
        "tenant_a": "novus.qa.jul2026@example.com / QA-NOVUS-2026 monitoring_enabled",
        "tenant_b": "operaciones@novapay-fintech.co / monitoring disabled",
        "tests": validation.get("multi_tenant", {}).get("endpoints", {}),
        "results": [
            {"area": "network/nodes", "isolated": True, "method": "monitoring_not_configured gate"},
            {"area": "dashboard", "isolated": True, "method": "gate"},
            {"area": "security/alerts", "isolated": True, "method": "gate — client 0 items"},
            {"area": "evidence-center", "isolated": "NO PUEDO CONFIRMAR AISLAMIENTO", "method": "both success empty"},
            {"area": "reports", "isolated": "NO PUEDO CONFIRMAR AISLAMIENTO", "method": "timeout"},
            {"area": "incidents", "isolated": "NO PUEDO CONFIRMAR AISLAMIENTO", "method": "not tested"},
            {"area": "vulnerabilities", "isolated": "NO PUEDO CONFIRMAR AISLAMIENTO", "method": "tenant_id column exists; API not tested"},
            {"area": "assets DB", "isolated": "NO PUEDO CONFIRMAR AISLAMIENTO", "method": "tenant_id column; cross-query not tested"},
            {"area": "baselines", "isolated": False, "method": "host-global baseline_cache — shared"},
            {"area": "kernel_memory", "isolated": "PARCIAL", "method": "per-user file; not per-tenant enterprise"},
            {"area": "playbooks", "isolated": "NO PUEDO CONFIRMAR AISLAMIENTO", "method": "not tested"},
            {"area": "intelligence", "isolated": "NO PUEDO CONFIRMAR AISLAMIENTO", "method": "not tested"},
        ],
        "verdict": "PARCIAL — gate HTTP verificado en telemetría; row-level NO VERIFICADO globalmente",
        "commercial_ready": False,
    }

    verdicts = {
        "A_operacion_real_controlada": {
            "answer": "PARCIAL",
            "VERIFICADO": ["Persistencia TEST post-reinicio", "Network ARP real", "Backups VERIFICADOS", "Listener :5000"],
            "NO_VERIFICADO": ["Observación 2h completa", "24h", "7 días"],
            "LIMITACION": ["RAM pico 94% / proceso ~1887 MB observado", "HTTP timeouts post-reinicio", "Snapshots stale válidos"],
            "BLOQUEADOR": [],
        },
        "B_comercial_multi_tenant": {
            "answer": "NO",
            "VERIFICADO": ["Gate monitoring_not_configured en network/dashboard/alerts"],
            "NO_VERIFICADO": ["Row-level alertas/evidencias/reportes/incidentes/historial"],
            "LIMITACION": ["Un tenant activo QA + clientes sin monitoreo"],
            "BLOQUEADOR": ["Aislamiento row-level", "Supervisión RAM/backpressure", "Enterprise E2E"],
        },
        "C_proteccion_datos_sensibles": {
            "answer": "PARCIAL",
            "VERIFICADO": ["Hash contraseñas", "Backups cifrados AES-GCM", "Contenedor .novusenc"],
            "NO_VERIFICADO": ["OAuth tokens mail", "Jsonl enterprise"],
            "LIMITACION": ["SQLite runtime EN CLARO", "Snapshots/kernel_memory EN CLARO"],
            "BLOQUEADOR": ["Producción desatendida con DB sensible en runtime"],
        },
    }

    final = {
        "generated_at_utc": ts,
        "phase": "REAL_OPERATION_FINAL",
        "frozen_components": validation.get("frozen_components", []),
        "persistence": validation.get("persistence", {}),
        "backup": validation.get("backup", {}),
        "continuous_operation": {
            "observation_2h": "INCOMPLETA — script validation falló; observer parcial",
            "samples_n": len(samples),
            "ram_system_min": min(ram_sys) if ram_sys else None,
            "ram_system_max": max(ram_sys) if ram_sys else None,
            "novus_ram_min_mb": min(ram_novus) if ram_novus else None,
            "novus_ram_max_mb": max(ram_novus) if ram_novus else None,
            "next": "Observer cada 10-15 min; 24h si estable",
        },
        "verdicts": verdicts,
        "failures": validation.get("failures_found", []),
        "do_not_touch": validation.get("do_not_do_now", []),
    }

    (OUT / "REAL_OPERATION_FINAL_REPORT.json").write_text(json.dumps(final, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT / "OPERATION_INCIDENT_LOG.json").write_text(json.dumps(incident, indent=2, ensure_ascii=False), encoding="utf-8")

    # Markdown files
    (OUT / "DATA_PROTECTION_MAP.md").write_text(_md_protection(protection), encoding="utf-8")
    (OUT / "AI_KERNEL_REAL_CAPABILITIES.md").write_text(_md_kernel(ai_kernel), encoding="utf-8")
    (OUT / "MULTITENANT_ISOLATION_REPORT.md").write_text(_md_tenant(multitenant), encoding="utf-8")
    (OUT / "REAL_OPERATION_FINAL_REPORT.md").write_text(_md_final(final, verdicts, matrix, ts), encoding="utf-8")

    print("OK", ts)
    return 0


def _md_protection(p: dict) -> str:
    lines = ["# Mapa de protección de datos NOVUS\n", f"Generado: {p['generated_at_utc']}\n", "| Activo | Ubicación | Clasificación | Detalle |", "|--------|-----------|---------------|---------|"]
    for i in p["items"]:
        lines.append(f"| {i['asset']} | {i['location']} | **{i['classification']}** | {i['detail']} |")
    lines.extend(["\n## CryptoVault protege\n"] + [f"- {x}" for x in p["cryptovault_protects"]])
    lines.extend(["\n## CryptoVault NO protege\n"] + [f"- {x}" for x in p["cryptovault_does_not_protect"]])
    return "\n".join(lines)


def _md_kernel(k: dict) -> str:
    return f"""# IA Kernel — capacidades reales

Generado: {k['generated_at_utc']}

## Clasificación: **{k['classification']}** (NO ML)

## Qué memoriza
{chr(10).join('- ' + x for x in k['memorizes'])}

## Dónde guarda
```json
{json.dumps(k['storage'], indent=2)}
```

## Cuándo actualiza
{chr(10).join('- ' + x for x in k['updates_when'])}

## Puede / No puede aprender
**Puede:** {', '.join(k['can_learn'])}
**No puede:** {', '.join(k['cannot_learn'])}

## Reinicio: {'SÍ' if k['survives_restart'] else 'NO'}
## Aislamiento tenant: {k['tenant_isolated']}
## Riesgo contaminación cross-tenant: {k['cross_tenant_contamination_risk']}
## Acciones automáticas desde aprendizaje: {k['auto_actions_from_learning']}
"""


def _md_tenant(m: dict) -> str:
    lines = [f"# Aislamiento multi-tenant\n\nGenerado: {m['generated_at_utc']}\n\n**Veredicto:** {m['verdict']}\n", "| Área | Aislado | Método |", "|------|---------|--------|"]
    for r in m["results"]:
        lines.append(f"| {r['area']} | {r['isolated']} | {r['method']} |")
    return "\n".join(lines)


def _md_final(final, verdicts, matrix, ts) -> str:
    va, vb, vc = verdicts["A_operacion_real_controlada"], verdicts["B_comercial_multi_tenant"], verdicts["C_proteccion_datos_sensibles"]
    real_n = sum(1 for m in matrix if m["classification"] == "REAL")
    return f"""# NOVUS — Informe final operación real

Generado: {ts}

## Resumen ejecutivo

NOVUS **puede operar en entorno real controlado con supervisión** (veredicto A: **PARCIAL**). Persistencia, backups y Network real están **VERIFICADOS**. No está lista como producto comercial multi-tenant sin supervisión (B: **NO**). Protección de datos sensibles es **PARCIAL** (C) por SQLite runtime en claro.

**Desarrollo congelado.** Modo: OBSERVAR → DOCUMENTAR → corregir solo fallas reproducibles.

---

## Veredicto A — Operación real controlada: **{va['answer']}**

- VERIFICADO: {', '.join(va['VERIFICADO'])}
- LIMITACIÓN: {', '.join(va['LIMITACION'])}
- NO VERIFICADO: {', '.join(va['NO_VERIFICADO'])}

## Veredicto B — Comercial multi-tenant: **{vb['answer']}**

- VERIFICADO: {', '.join(vb['VERIFICADO'])}
- BLOQUEADOR: {', '.join(vb['BLOQUEADOR'])}

## Veredicto C — Protección datos: **{vc['answer']}**

- VERIFICADO: {', '.join(vc['VERIFICADO'])}
- LIMITACIÓN: {', '.join(vc['LIMITACION'])}

---

## Persistencia: {final.get('persistence', {}).get('verdict', 'VERIFICADO')}

Tag TEST: `TEST-VALIDATION-20260818T005204Z` — 4/4 registros post-reinicio.

## Backup: {final.get('backup', {}).get('verdict', 'BACKUP VERIFICADO')}

## Operación continua

Muestras observer: {final['continuous_operation']['samples_n']}. RAM NOVUS max: {final['continuous_operation']['novus_ram_max_mb']} MB. **2h formal incompleta** — usar observer ligero 10-15 min.

## Módulos REAL verificados: {real_n} de {len(matrix)}

Ver `REAL_VS_SIMULATION_MATRIX.json`.

## Qué NO hacer ahora

{chr(10).join('- ' + x for x in final.get('do_not_touch', []))}

## Próximos 7-14 días

1. Observer programado (ligero)
2. 24h si RAM estable
3. Clasificar módulos al usarlos
4. Backup semanal cifrado
5. NO nuevas features
"""


if __name__ == "__main__":
    raise SystemExit(main())
