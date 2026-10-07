#!/usr/bin/env python3
"""Generate security_engine_capability_gate deliverables (READ-ONLY — no product code changes)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "production_closure" / "security_engine_capability_gate"
OUT.mkdir(parents=True, exist_ok=True)

ev = json.loads((OUT / "ENGINE_RUNTIME_EVIDENCE.json").read_text(encoding="utf-8"))
e2e_path = ROOT / "data" / "production_closure" / "threat_defense_capability_audit" / "E2E_DEMO_RESULTS_LATEST.json"
e2e = json.loads(e2e_path.read_text(encoding="utf-8"))
honest = ev["honest_runtime"]


def W(name: str, text: str) -> None:
    (OUT / name).write_text(text, encoding="utf-8")


def e2e_result(key: str) -> str:
    v = e2e.get(key) or {}
    if not isinstance(v, dict):
        return str(v)
    return str(v.get("result") or v.get("verdict") or v.get("status") or "NO VERIFICADO")


def e2e_conclusion(key: str) -> str:
    v = e2e.get(key) or {}
    if isinstance(v, dict):
        return str(v.get("conclusion") or "")[:400]
    return ""


# --- ENGINE_RUNTIME_STATUS.md ---
rows = [
    "| Engine | Status | Tier | Notes |",
    "|---|---|---|---|",
]
for k, v in honest.items():
    note = v.get("reason") or v.get("note") or v.get("loop") or ""
    rows.append(f"| `{k}` | **{v.get('status')}** | {v.get('tier')} | {note} |")

W(
    "ENGINE_RUNTIME_STATUS.md",
    "\n".join(
        [
            "# ENGINE RUNTIME STATUS",
            "",
            f"Generated: {ev.get('generated_at_utc')}",
            "",
            "Audit mode: **READ_ONLY** — product code changes: **NONE**",
            "",
            "## Honesty rule",
            "",
            "`ACTIVE` means real runtime activity (loop/thread/request path), **not** merely:",
            "code present, object instantiated, `active=True`, historical registry rows, or cached `last_scan`.",
            "",
            "## Automatic protection",
            "",
            "```json",
            json.dumps(ev.get("automatic_protection"), indent=2, ensure_ascii=False),
            "```",
            "",
            "## Honest runtime (primary)",
            "",
            *rows,
            "",
            "## Panel vs honesty",
            "",
            "UI panel from `defense_center_service.get_engines_panel` can diverge:",
            "- Web Shield may show `activo` while loop is inactive (status schema)",
            "- Swarm `ok` ≈ engine loaded, not live multi-node correlation",
            "- XDR ACTIVE requires threat cache `last_scan` (cache ≠ daemon)",
            "- Adaptive Defense may show `no_disponible` due to panel schema mismatch while code is IDLE/available",
            "",
            "```json",
            json.dumps(ev.get("panel_engines"), indent=2, ensure_ascii=False, default=str)[:12000],
            "```",
            "",
            "## Beta classification",
            "",
            "### CORE BETA",
            "security_engine, AdvancedDetector, YARA (lab), Network Monitor, Web Shield (platform), Swarm,",
            "BTDE, ZDDE, Defense Coordinator, Remediation Orchestrator, Adaptive Defense, XDR/NSI,",
            "Abuse Guard/auth, ransomware FS heuristics, evidence registry, AI Kernel (recommend-only), CryptoVault.",
            "",
            "### OPTIONAL / NOT_CONFIGURED",
            "Mail Shield (OAuth required).",
            "",
            "### FUTURE",
            "Cloud Shield (planned); commercial AV; trained ML; APT hunting.",
            "",
            "## Metrics",
            f"- probe_ms: {ev.get('probe_ms')}",
            f"- before: {ev.get('metrics_before')}",
            f"- after: {ev.get('metrics_after')}",
            "",
        ]
    ),
)

W(
    "MALWARE_DETECTION_CAPABILITY.md",
    f"""# Malware Detection Capability

Evidence base: E2E `{e2e.get('run_id')}` + live YARA status.

| Capacidad | Estado | Motor | Mecanismo | Fuente |
|---|---|---|---|---|
| YARA file scan (lab rules) | DETECTA (lab) | endpoint_enterprise.yara_engine | scan_file/scan_bytes | 2 `.yar` files |
| EICAR | DETECTA (TEST_FIXTURE) | NOVUS_EICAR_TestFile | string match | fixture only |
| PowerShell EncodedCommand | DETECTA (pattern) | NOVUS_PowerShell_EncodedCommand | YARA | file/bytes |
| Mimikatz strings | DETECTA (pattern) | NOVUS_Mimikatz_Strings | YARA | strings |
| Reflective DLL stub | DETECTA (heuristic) | NOVUS_Reflective_DLL_Stub | YARA | PE/strings |
| Temp script + IEX | DETECTA (heuristic) | NOVUS_Suspicious_Temp_Script | YARA | path+script |
| Keylog/screencap heuristic | DETECTA (heuristic) | NOVUS_PE_Keylogging_Screencapture_Heuristic | YARA PE APIs | PE |
| Cmdline malware heuristics | PARCIAL | malware_behavior / AdvancedDetector | cmdline patterns | host/synthetic |
| Ransomware FS behavior | PARCIAL | security_engine.monitor_filesystem_activity | entropy/burst | synthetic/host |
| Suspicious processes | PARCIAL | AdvancedDetector | process/cmdline | host |
| Hash → VirusTotal | NO DEMOSTRADO | scan_file_reputation | VT API | needs key |
| Commercial AV / malware fleet | NO IMPLEMENTADO | — | — | — |
| Universal malware detection | NO IMPLEMENTADO | — | — | — |
| Packed PE / fileless live | NO DEMOSTRADO | — | — | — |

**Do not claim:** commercial antivirus; detects all viruses; EICAR as LIVE client malware.

E2E malware conclusion: {e2e_conclusion('malware')}
""",
)

W(
    "YARA_CAPABILITY.md",
    f"""# YARA Capability

## Live engine status

```json
{json.dumps(ev.get('yara_engine_status'), indent=2, ensure_ascii=False, default=str)}
```

## Rule inventory

| File | Rules |
|---|---|
| `novus_baseline.yar` | NOVUS_EICAR_TestFile, NOVUS_PowerShell_EncodedCommand, NOVUS_Mimikatz_Strings, NOVUS_Reflective_DLL_Stub, NOVUS_Suspicious_Temp_Script |
| `novus_pe_keylogging_screencapture_heuristic.yar` | NOVUS_PE_Keylogging_Screencapture_Heuristic |

## Runtime

- Engine load: **ACTIVE** (compile OK)
- Endpoint enterprise orchestrator continuous loop: **IDLE** unless started
- Invokers: `yara_engine.scan_*`, `run_endpoint_enterprise_cycle`, async_scanner, monitoring API
- Pipeline: hit → publish_findings / `defense_coordinator.record_detection` (E2E PASS)
- EICAR often severity `info` → may not reach user bell

## Fixture policy

`TEST_FIXTURE` / `SYNTHETIC_TEST_ONLY` ≠ `LIVE_CLIENT_DATA`

E2E YARA result: **{e2e_result('yara')}**
""",
)

W(
    "RANSOMWARE_CAPABILITY.md",
    f"""# Ransomware Capability

| Stage | Status |
|---|---|
| Detection (FS burst + entropy heuristic) | PARCIAL — DEMOSTRADO on synthetic |
| Decision EMERGENCY_LOCKDOWN / READ_ONLY_MODE | IMPLEMENTED (logic labels) |
| OS lockdown effect | EXECUTED_NOT_VERIFIED |
| BLOCKED / SUCCESS verified | **NO** — do not claim |
| Notification | PARCIAL if escalated via NSI/Alerta |

E2E: **{e2e_result('ransomware')}**

{e2e_conclusion('ransomware')}

Allowed honesty labels: DETECTADO, EN INVESTIGACIÓN, RESPUESTA PROPUESTA, ACCIÓN EJECUTADA, ACCIÓN VERIFICADA, ACCIÓN FALLIDA, NOT_VERIFIABLE.
""",
)

W(
    "ATTACK_DETECTION_CAPABILITY.md",
    f"""# Attack Detection Capability

## Authentication

| Ataque | Detección | Motor | Evidencia E2E | Respuesta | Verificación | Notificación |
|---|---|---|---|---|---|---|
| Brute force | DEMOSTRADO | auth_protection_service | lab IP sanctioned | app IP block | DEMONSTRATED | PARCIAL |
| Credential stuffing | PARCIAL | hostile_environment_service | code thresholds | sanctions/MFA | NO DEMOSTRADO E2E | NO VERIFICADO |
| Password spraying | PARCIAL | hostile_environment_service | code thresholds | same | NO DEMOSTRADO E2E | NO VERIFICADO |
| Session abuse | PARCIAL | session_risk + Swarm revoke | scoring | APPROVAL revoke | NO DEMOSTRADO | NO VERIFICADO |

Brute force E2E: **{e2e_result('brute_force')}**

## Web/API (platform self-protection — NOT full WAF)

| Amenaza | Prevención | Detección | Respuesta | Estado |
|---|---|---|---|---|
| Path traversal / sensitive files | BLOCKED_PATHS | deny | HTTP deny | DEMOSTRADO (platform) |
| Rate abuse | Abuse Guard | throttle | 429 | DEMOSTRADO (platform) |
| Auth gate | Flask-Login/RBAC | 401/403 | deny | DEMOSTRADO |
| SQLi | api_security_service | reject/log | 400 | PARCIAL |
| XSS | CSP/headers | dedicated detector | headers | PARCIAL / NO DEMOSTRADO detector |
| SSRF | ssrf_guard code | deny URL | deny | NO VERIFICADO live this gate |
| Command injection | hardening catalog | — | claimed block | PARCIAL |

Web/API E2E: **{e2e_result('web_api')}** — {e2e_conclusion('web_api')}

## Network

| Capacidad | Scope | Estado |
|---|---|---|
| New device / ARP observation | HOST_GLOBAL | PARCIAL — ≠ confirmed intrusion |
| Traffic Mbps | HOST_GLOBAL | LIVE telemetry ≠ intrusion |
| MITM | HOST | NOT_VERIFIED |
| Port scan surface | HOST_GLOBAL | PARCIAL |
| Lateral movement | multi-signal lab | PARCIAL |
| Full NDR/PCAP product | — | NO IMPLEMENTADO |

## Correlation

| Component | Multi-signal | E2E |
|---|---|---|
| Swarm | YES | **{e2e_result('swarm')}** — foreign tenant dropped |
| BTDE | behavioral | IDLE loop; no ML |
| ZDDE | unknown candidate | IDLE loop; candidate ≠ CVE zero-day |
""",
)

W(
    "NETWORK_INTRUSION_CAPABILITY.md",
    f"""# Network & Intrusion Capability

## MITM

| Probe | Result |
|---|---|
| Empty metadata `{{}}` | CRITICAL SSL Stripping over-trigger (still present) |
| TLS 1.3 + cert_verify_failed | NOT_VERIFIABLE / OBSERVE |
| Secure TLS | SECURE |

**Commercial MITM claim: NOT_VERIFIED**

```json
{json.dumps(ev.get('mitm_probes'), indent=2, ensure_ascii=False)}
```

E2E MITM: **{e2e_result('mitm')}** — {e2e_conclusion('mitm')}

## Intrusion taxonomy

| Concept | Meaning | Status |
|---|---|---|
| New device | ARP/topology observation | PARCIAL |
| Malicious activity | heuristics / multi-signal | PARCIAL |
| Confirmed intrusion | policy + multi-context | NOT CONFIRMED |

NDR/ARP E2E: **{e2e_result('ndr_arp')}** — {e2e_conclusion('ndr_arp')}

Never equate new device with confirmed intrusion.
""",
)

W(
    "RESPONSE_CAPABILITY_MATRIX.md",
    f"""# Response Capability Matrix

Policy source: `services/swarm_defense/response_policy.py`

| Amenaza | Acción | Automática | Requiere aprobación | Ejecutada E2E | Verificada SUCCESS | Notificación |
|---|---|---|---|---|---|---|
| YARA/malware lab | record_detection / evidence | AUTO (record) | kill = APPROVAL | detection YES; kill NO | detection YES | PARCIAL |
| Ransomware heuristic | EMERGENCY_LOCKDOWN logic | decision AUTO | OS effect unverified | synthetic YES | OS NO | PARCIAL |
| Brute force | app IP sanction | AUTO | — | YES | app YES; OS FW NO | PARCIAL |
| MITM | TERMINATE_CONNECTION label | logic | — | over-trigger risk | NOT_VERIFIED | must not claim LIVE |
| New device / “intruso” | observe / monitoring | AUTO observe | isolate = APPROVAL | observe PARCIAL | intrusion NO | PARCIAL |
| Suspicious process | alert / recommend | AUTO alert | kill = APPROVAL | NO_KILL | NOT_VERIFIED | PARCIAL |
| Web/API abuse | 429 / deny | AUTO | — | YES platform | YES status | logs |
| Swarm correlated | INVESTIGATE / incident | AUTO subset | block/kill/isolate APPROVAL | decision YES | destructive NOT_EXECUTED | PARCIAL |

### AUTO
preserve_evidence, increase_monitoring, create_incident, generate_report

### APPROVAL_REQUIRED
kill_process, block_ip, block_domain, isolate_host, revoke_sessions, trigger_playbook

### AI Kernel
Recommends only (`executes_actions=False`). Does **not** autonomously execute defense.

Defense E2E: **{e2e_result('defense')}**

Rule: `ok=True` ≠ `SUCCESS` without VERIFY stage.
""",
)

W(
    "NOTIFICATION_CAPABILITY.md",
    f"""# Notification Capability

```
DETECTION
  → defense_coordinator / evidence registry
  ↘ NSI _log_threat → Alerta SQLite → alerts_canonical → dashboard / incidentes / XDR
  ↘ emit_notification → novus_notifications → /api/notifications → campanita
```

| Claim | Evidence |
|---|---|
| `record_detection` alone creates Alerta UI | False |
| Detection without user alert possible | True |
| Bell emit / mark-read / decrement | PASS (dashboard_security_truth_gate) |
| Every detection reaches bell | NO |
| Severity invented from missing data | Forbidden — use NOT_AVAILABLE |

Notification E2E (threat campaign): **{e2e_result('notification')}**

{e2e_conclusion('notification')}
""",
)

W(
    "TENANT_SECURITY_CAPABILITY.md",
    f"""# Tenant Security Capability

| Check | Result |
|---|---|
| TENANT_LEAKS (threat E2E regression) | {(e2e.get('security_regression') or {}).get('TENANT_LEAKS', 0)} |
| Swarm foreign tenant contribution | Dropped (E2E PASS) |
| Notification isolation (truth gate) | TENANT_LEAKS = 0 |
| HOST_GLOBAL traffic/ARP → tenant KPI | Forbidden / not attributed |

Canonical alerts require platform tenant id when configured; empty `NOVUS_PLATFORM_TENANT_ID` yields empty canonical list for non-platform callers (existing design).
""",
)

W(
    "E2E_SECURITY_DEMONSTRATIONS.md",
    f"""# E2E Security Demonstrations

Primary campaign directory: `data/production_closure/threat_defense_capability_audit/`  
Run id: `{e2e.get('run_id')}`  
This capability gate: **READ_ONLY** (no destructive re-run; live snapshot in `ENGINE_RUNTIME_EVIDENCE.json`).

| Case | Result | Notes |
|---|---|---|
| YARA | {e2e_result('yara')} | Lab rules; not commercial AV |
| Malware heuristics | {e2e_result('malware')} | Partial patterns |
| Ransomware | {e2e_result('ransomware')} | Heuristic; OS lockdown not verified |
| Suspicious process | {e2e_result('suspicious_process')} | No kill |
| NDR/ARP | {e2e_result('ndr_arp')} | Observation ≠ intrusion |
| Brute force | {e2e_result('brute_force')} | Lab IP sanctioned |
| Web/API | {e2e_result('web_api')} | Platform preventivo ≠ WAF |
| Swarm | {e2e_result('swarm')} | multi_signal; not APT |
| MITM | {e2e_result('mitm')} | NOT_VERIFIABLE |
| Mail | {e2e_result('mail_shield')} | NOT_CONFIGURED |
| Defense policy | {e2e_result('defense')} | AUTO vs APPROVAL |
| Notification | {e2e_result('notification')} | Partial wiring |
| Security regression | {e2e_result('security_regression')} | TENANT_LEAKS=0 |
""",
)

before_after = {
    "mode": "READ_ONLY",
    "code_changes": "NONE",
    "before_after": "N/A — no product code modified in this gate",
    "runtime_snapshot": {k: v.get("status") for k, v in honest.items()},
    "metrics": {
        "before": ev.get("metrics_before"),
        "after": ev.get("metrics_after"),
        "probe_ms": ev.get("probe_ms"),
    },
    "prior_e2e_run_id": e2e.get("run_id"),
    "reason_no_code_change": (
        "Capabilities already demonstrable via prior E2E + live runtime probe; "
        "panel honesty gaps documented only (READ-ONLY gate)."
    ),
}
(OUT / "SECURITY_CAPABILITY_BEFORE_AFTER.json").write_text(
    json.dumps(before_after, indent=2, ensure_ascii=False), encoding="utf-8"
)

final = {
    "MOTORES_REALMENTE_ACTIVOS": [
        "YARA engine load (rules compiled) — continuous loop IDLE unless orchestrator started",
        "Swarm defense engine (in-process started) — correlation may be IDLE; mesh may be DEGRADED",
        "defense_evidence_registry (writable append-only)",
        "CryptoVault (initialized utility, not a detector)",
        "Abuse Guard — ACTIVE only while HTTP app serves requests (NOT_VERIFIABLE in import-only probe)",
    ],
    "MOTORES_PARCIALES_LIMITADOS": [
        "security_engine / AdvancedDetector / ransomware FS — IDLE until scan",
        "Network Monitor / Web Shield / BTDE / ZDDE / Adaptive / Remediation / XDR — IDLE or panel-misleading",
        "AI Kernel / GuardIA — IDLE; recommend-only (no autonomous defense execution)",
    ],
    "MOTORES_NO_CONFIGURADOS": [
        "Mail Shield (OAuth)",
        "Cloud Shield (FUTURE / planned)",
        "XDR panel without last_scan cache",
    ],
    "CAPACIDADES_NO_IMPLEMENTADAS": [
        "Commercial antivirus",
        "Universal malware detection",
        "Trained machine learning",
        "APT hunting",
        "Full customer WAF",
        "Full continuous NDR/PCAP product",
        "R4/R5 autonomous destructive defense",
        "Verified OS ransomware lockdown SUCCESS",
        "MITM commercial E2E DEMONSTRATED",
    ],
    "MALWARE_QUE_PUEDE_DETECTAR": {
        "demostrado": [
            "YARA lab rules (EICAR fixture, PS encoded, mimikatz strings, reflective stub, temp script, keylog heuristic)",
            "cmdline heuristics (partial)",
            "FS ransomware heuristic on synthetic activity",
        ],
        "parcial": ["suspicious processes", "entropy/process indicators"],
        "no_demostrado": ["VirusTotal without key", "packed PE live", "fileless memory live"],
    },
    "ATAQUES_QUE_PUEDE_DETECTAR": {
        "demostrado": [
            "brute force (lab)",
            "Swarm multi-signal correlation (lab)",
            "platform path deny / auth gate / rate abuse",
        ],
        "parcial": [
            "credential stuffing/spraying (code)",
            "SQLi sanitize",
            "ARP/new device observation",
            "port surface",
        ],
        "no_verificado": [
            "MITM E2E",
            "dedicated XSS/command-injection E2E",
            "SSRF live probe this gate",
            "confirmed intrusion",
        ],
    },
    "COMO_RESPONDE": "DETECT → DECIDE → RESPOND → VERIFY → NOTIFY — VERIFY often missing for destructive/OS actions; NOTIFY not universal",
    "COMO_SE_ENTERA_EL_USUARIO": (
        "DETECTION → (optional Alerta via NSI) → canonical alerts → dashboard; "
        "parallel emit_notification → bell (partial wiring)"
    ),
    "QUE_PUEDE_BLOQUEAR_REALMENTE": {
        "bloqueado_y_verificado": [
            "app-layer auth IP sanction (lab)",
            "HTTP sensitive path deny",
            "Abuse Guard 429",
        ],
        "ejecutado_no_verificado": ["ransomware EMERGENCY_LOCKDOWN OS claim"],
        "requiere_aprobacion": [
            "kill process",
            "OS firewall block_ip",
            "isolate host",
            "revoke sessions",
            "playbook",
        ],
        "solo_recomendado": ["AI Kernel / GuardIA recommendations"],
        "no_implementado": ["commercial AV quarantine fleet", "guaranteed ransomware block"],
    },
    "NO_PROMETER": [
        "antivirus comercial",
        "detección universal de malware",
        "bloqueo garantizado de ransomware",
        "MITM confirmado",
        "APT hunting",
        "ML entrenado",
        "Mail Shield sin OAuth",
        "NDR completo",
        "WAF completo",
        "defensa autónoma R4/R5",
        "nuevo dispositivo = intruso",
        "ok=True = SUCCESS",
        "DETECTED = BLOCKED",
        "RECOMMENDED = EXECUTED",
        "APPROVAL = AUTO",
    ],
    "respuesta_cliente_beta": (
        "Si un cliente Beta conecta NOVUS mañana: puede detectar patrones YARA locales y heurísticas de "
        "proceso/cmdline/FS; puede sancionar fuerza bruta a nivel aplicación; puede correlacionar señales "
        "Swarm de laboratorio; puede prevenir abuso a la propia plataforma (paths, rate, auth). "
        "No tiene AV comercial, WAF/NDR de cliente completo, MITM E2E demostrado, ni contención destructiva "
        "autónoma verificada. Mail Shield no opera sin OAuth. AI Kernel recomienda, no ejecuta defensa. "
        "Notificaciones al usuario son parciales (no toda detección llega a la campanita)."
    ),
    "code_changes": "NONE",
    "TENANT_LEAKS": (e2e.get("security_regression") or {}).get("TENANT_LEAKS", 0),
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
}

W(
    "SECURITY_ENGINE_CAPABILITY_FINAL.md",
    "# SECURITY ENGINE CAPABILITY FINAL\n\n"
    + json.dumps(final, indent=2, ensure_ascii=False)
    + "\n",
)

index = {
    "dir": str(OUT.resolve()),
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "files": sorted(p.name for p in OUT.iterdir() if p.is_file()),
    "code_changes": "NONE",
    "prior_e2e": e2e.get("run_id"),
    "audit_mode": "READ_ONLY",
}
(OUT / "SECURITY_CAPABILITY_EVIDENCE_INDEX.json").write_text(
    json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
)
print("OK", len(index["files"]), "files")
for f in index["files"]:
    print(" -", f)
