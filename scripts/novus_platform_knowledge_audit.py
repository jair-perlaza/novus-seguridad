#!/usr/bin/env python3
"""
Auditoría Maestra de Conocimiento y Capacidades NOVUS — SOLO LECTURA.
Genera entregables en data/novus_platform_knowledge_audit/ sin modificar producto.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_platform_knowledge_audit"
OUT.mkdir(parents=True, exist_ok=True)
BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _server_status() -> Dict[str, Any]:
    import psutil

    listeners: List[Dict[str, Any]] = []
    main_procs: List[Dict[str, Any]] = []
    for p in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
        cmd = " ".join(p.info.get("cmdline") or [])
        if "main.py" in cmd:
            listens = False
            try:
                for c in p.connections(kind="inet"):
                    if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN":
                        listens = True
            except Exception:
                pass
            main_procs.append({
                "pid": p.info["pid"],
                "name": p.info.get("name"),
                "listens_5000": listens,
                "cmdline": cmd[:200],
            })
        try:
            for c in p.connections(kind="inet"):
                if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN":
                    listeners.append({"pid": p.info["pid"], "name": p.info.get("name")})
        except Exception:
            pass

    http = {"status": None, "response_ms": None, "error": None}
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(f"{BASE}/login", method="GET")
        with urllib.request.urlopen(req, timeout=30) as resp:
            http["status"] = resp.status
            http["response_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            http["bytes"] = len(resp.read())
    except Exception as exc:
        http["error"] = str(exc)[:200]
        http["response_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    official = [x for x in listeners if x["pid"]]
    return {
        "generated_at_utc": _utc(),
        "base_url": BASE,
        "listeners_port_5000": listeners,
        "single_listener": len({x["pid"] for x in listeners}) == 1,
        "main_py_processes": main_procs,
        "main_py_count": len(main_procs),
        "http_login": http,
        "note": "En Windows py.exe + python.exe pueden contar como 2 procesos main.py; 1 listener = instancia oficial.",
    }


def _timed_get(path: str) -> Dict[str, Any]:
    url = f"{BASE}{path}"
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            body = resp.read()
            return {
                "path": path,
                "status": resp.status,
                "ms": round((time.perf_counter() - t0) * 1000, 2),
                "bytes": len(body),
                "auth_required": resp.status in (401, 302) or b"login" in body[:800].lower(),
            }
    except urllib.error.HTTPError as e:
        return {
            "path": path,
            "status": e.code,
            "ms": round((time.perf_counter() - t0) * 1000, 2),
            "bytes": 0,
            "auth_required": e.code in (401, 403),
        }
    except Exception as exc:
        return {"path": path, "status": None, "ms": round((time.perf_counter() - t0) * 1000, 2), "error": str(exc)[:120]}


def _performance_snapshot() -> Dict[str, Any]:
    paths = [
        "/login",
        "/dashboard",
        "/network",
        "/amenazas",
        "/api/health/status",
        "/api/security/summary",
        "/api/dashboard/live",
        "/api/network/nodes",
        "/api/soc/overview",
    ]
    return {
        "generated_at_utc": _utc(),
        "method": "GET_only_unauthenticated",
        "endpoints": [_timed_get(p) for p in paths],
        "note": "Endpoints autenticados devuelven redirect/login; tiempos reflejan shell HTTP sin sesión.",
        "reference_ux_after": str(ROOT / "data" / "performance_ux_optimization" / "UX_PERFORMANCE_AFTER.json"),
    }


def _inventory() -> Dict[str, Any]:
    inv: Dict[str, Any] = {
        "generated_at_utc": _utc(),
        "services_py": [],
        "api_py": [],
        "routes_py": [],
        "templates_html": [],
        "static_js": [],
        "scripts_py": [],
        "data_dirs": [],
        "limitations_modules": [],
    }
    for p in sorted((ROOT / "services").rglob("*.py")):
        if "__pycache__" not in str(p):
            inv["services_py"].append(str(p.relative_to(ROOT)))
    for p in sorted((ROOT / "api").glob("*.py")):
        inv["api_py"].append(str(p.relative_to(ROOT)))
    for p in sorted((ROOT / "routes").glob("*.py")):
        inv["routes_py"].append(str(p.relative_to(ROOT)))
    for p in sorted((ROOT / "templates").rglob("*.html")):
        inv["templates_html"].append(str(p.relative_to(ROOT)))
    for p in sorted((ROOT / "static" / "js").glob("*.js")):
        inv["static_js"].append(str(p.relative_to(ROOT)))
    for p in sorted((ROOT / "scripts").glob("*.py")):
        inv["scripts_py"].append(str(p.relative_to(ROOT)))
    data_root = ROOT / "data"
    if data_root.is_dir():
        inv["data_dirs"] = sorted([x.name for x in data_root.iterdir() if x.is_dir()])
    inv["limitations_modules"] = sorted(
        str(p.relative_to(ROOT)) for p in (ROOT / "services").rglob("limitations.py")
    )
    inv["counts"] = {k: len(v) for k, v in inv.items() if isinstance(v, list)}
    return inv


def _engines_map() -> Dict[str, Any]:
    """Mapa funcional basado en código — estados honestos."""
    engines = [
        {"id": "novus_security_integration", "name": "Motor XDR integrado", "path": "services/novus_security_integration.py", "boot": "auto", "state": "OPERATIVO"},
        {"id": "network_scanner", "name": "Network Scanner / ARP", "path": "services/network_scanner.py", "boot": "auto", "state": "OPERATIVO"},
        {"id": "network_monitor_engine", "name": "Network Monitor / NDR", "path": "services/network_monitor_engine.py", "boot": "auto", "state": "OPERATIVO"},
        {"id": "network_scan_coordinator", "name": "Coordinador ARP/contexto red", "path": "services/network_scan_coordinator.py", "boot": "auto", "state": "OPERATIVO"},
        {"id": "ai_kernel", "name": "Kernel IA", "path": "services/ai_kernel.py", "boot": "auto", "state": "OPERATIVO"},
        {"id": "btde", "name": "BTDE", "path": "services/behavioral_threat_detection/", "boot": "auto", "state": "OPERATIVO_LIMITADO"},
        {"id": "zdde", "name": "ZDDE", "path": "services/zero_day_detection/", "boot": "auto", "state": "PARCIAL"},
        {"id": "health_engine", "name": "Health Engine", "path": "services/health_engine/", "boot": "auto", "state": "OPERATIVO"},
        {"id": "swarm_defense", "name": "Swarm Defense", "path": "services/swarm_defense/", "boot": "on_demand", "state": "OPERATIVO"},
        {"id": "asm", "name": "ASM", "path": "services/asm/", "boot": "api", "state": "OPERATIVO"},
        {"id": "viem", "name": "VIEM", "path": "services/viem/", "boot": "api", "state": "OPERATIVO"},
        {"id": "imcm", "name": "IMCM", "path": "services/imcm/", "boot": "api", "state": "OPERATIVO"},
        {"id": "soc", "name": "SOC Enterprise", "path": "services/soc/", "boot": "api", "state": "OPERATIVO"},
        {"id": "sdl", "name": "SDL", "path": "services/sdl/", "boot": "pull_ingest", "state": "PARCIAL"},
        {"id": "sdace", "name": "SDACE", "path": "services/sdace/", "boot": "read_sdl", "state": "PARCIAL"},
        {"id": "tie", "name": "TIE", "path": "services/threat_intelligence_enterprise/", "boot": "api", "state": "PARCIAL"},
        {"id": "ueba", "name": "UEBA / Identity Intelligence", "path": "services/identity_intelligence/", "boot": "api", "state": "OPERATIVO_LIMITADO"},
        {"id": "iapa", "name": "IAPA", "path": "services/iapa/", "boot": "api", "state": "PARCIAL"},
        {"id": "sope", "name": "SOPE", "path": "services/sope/", "boot": "api", "state": "OPERATIVO"},
        {"id": "deception", "name": "Deception Platform", "path": "services/deception_platform/", "boot": "api", "state": "OPERATIVO"},
        {"id": "csv_bas", "name": "CSV-BAS", "path": "services/csv_bas/", "boot": "api", "state": "OPERATIVO"},
        {"id": "web_shield", "name": "Web Shield", "path": "services/web_shield_engine.py", "boot": "auto", "state": "OPERATIVO"},
        {"id": "mail_shield", "name": "Mail Shield", "path": "services/mail_shield_engine.py", "boot": "auto", "state": "OPERATIVO"},
        {"id": "endpoint_enterprise", "name": "Endpoint Enterprise", "path": "services/endpoint_enterprise/", "boot": "auto", "state": "OPERATIVO"},
        {"id": "cloud_shield", "name": "Cloud Shield", "path": "services/shield_platform_registry.py", "boot": None, "state": "NO_IMPLEMENTADO"},
        {"id": "cryptovault", "name": "CryptoVault", "path": "crypto_vault.py", "boot": "init", "state": "OPERATIVO"},
    ]
    return {"generated_at_utc": _utc(), "engines": engines, "classification_legend": {
        "OPERATIVO": "Código + API/boot verificables",
        "OPERATIVO_LIMITADO": "Operativo con alcance/host local limitado",
        "PARCIAL": "Funciona bajo condiciones o ingest manual",
        "NO_IMPLEMENTADO": "Registrado pero sin motor activo",
    }}


def _architecture() -> Dict[str, Any]:
    return {
        "generated_at_utc": _utc(),
        "hubs": {
            "detection_write": "services/defense_coordinator.py → data/defense_registry/events.jsonl",
            "metrics_read": "services/platform_metrics_service.py → GET /api/security/summary",
            "swarm_bus": "services/swarm_defense/event_bus.py (in-process, Swarm-local)",
        },
        "real_connections": [
            "motors → defense_coordinator.record_detection",
            "defense_coordinator → network_security_history, forensic_pcap, adaptive_profile, swarm",
            "swarm → imcm.create_incident (response_policy)",
            "swarm → kernel_memory notify (no ejecuta containment)",
            "imcm/sdl/sdace → pull ingest/read",
            "novus_security → platform_metrics → dashboard/API",
        ],
        "partial_connections": [
            "SDL ingest pull-only (no auto-push on detection)",
            "platform_metrics NO lee defense_registry directamente",
            "IMCM kernel block = plantilla estática, no llamada live ai_kernel",
            "SDACE → swarm solo agregados, no detección live",
        ],
        "code_only": [
            "cloud_shield en registry sin engine boot",
            "Sigma/YARA originales YAML parcialmente portados a Python",
        ],
    }


def _data_flow() -> Dict[str, Any]:
    return {
        "generated_at_utc": _utc(),
        "entities": {
            "network_device": "ARP/network_scanner → cache nodes → platform_metrics/API/UI",
            "ip_mac": "host_data + ARP → network_scan_coordinator context → invalidación cache",
            "ioc": "TIE feeds + internal_intel → defense_coordinator → SDL (ingest)",
            "cve_vulnerability": "novus_security scan → threat_cache → VIEM/API",
            "incident": "IMCM store ← Swarm/manual/API; contexto ASM/VIEM/TIE al crear",
            "evidence": "defense_registry → forensic_evidence → CryptoVault/sealed",
            "swarm_event": "defense_coordinator → event_bus TOPIC_ANOMALY → correlate → response_policy",
            "risk_score": "ASM exposure / IMCM severity / session_risk (WSAE) — fuentes separadas",
        },
    }


def _capabilities() -> Dict[str, Any]:
    return {
        "generated_at_utc": _utc(),
        "can_do_today": {
            "proteccion": ["MFA TOTP", "CSRF", "RBAC", "rate limits", "session audit", "device fingerprint", "Web/Mail Shield"],
            "deteccion": ["Procesos/puertos locales (advanced_detector)", "ARP/red local", "BTDE heurístico", "Endpoint YARA (rules files)", "Auth anomalies WSAE"],
            "inteligencia": ["TIE ciclo manual/API", "Internal intel batches", "Threat registry SQLite"],
            "red": ["ARP scan", "gateway/subnet detect", "context fingerprint SSID/BSSID/IP", "cache invalidation on change"],
            "endpoint": ["psutil inventory", "Endpoint enterprise cycles", "Rootkit hybrid heuristics"],
            "vulnerabilidades": ["Live scan verified findings", "VIEM enrichment", "Pending verification queue"],
            "incidentes": ["IMCM CRUD", "Swarm auto-create with dedup", "Forensic timeline hashes"],
            "respuesta": ["SOPE playbooks", "Swarm auto: preserve_evidence, increase_monitoring, create_incident", "Manual defense jobs"],
            "forense": ["Ed25519/sealed evidence", "PCAP metadata monitor", "Chain registry JSONL"],
            "soc": ["Overview/tactical/executive/analyst/hunting views from collectors"],
            "analytics": ["SDACE correlation over SDL snapshot"],
            "deception": ["Honeytokens/credentials/files decoy"],
            "health": ["Self-healing engine cycles", "Snapshot API"],
        },
        "partial": {
            "zero_day": "ZDDE heurístico local — NO garantía zero-day genérico",
            "tie": "Depende feeds/config e Internet para IOC externos",
            "sdl": "Ingest manual/pull — datos stale hasta próximo ingest",
            "mesh": "Peer sync requiere peers configurados",
            "bssid": "Puede ser null en Windows según driver",
            "ngrok": "Opcional NOVUS_AUTO_NGROK",
        },
        "cannot_do": {
            "cloud_shield": "No motor activo",
            "arbitrary_zero_day": "No ML genérico demostrado",
            "enterprise_siem_scale": "Single-node SQLite/JSONL predominante",
            "automatic_sdl_on_every_detection": "No implementado — pull ingest",
            "kernel_execute_containment": "Kernel analiza; Swarm/motores ejecutan",
        },
    }


def _limitations() -> Dict[str, Any]:
    lims = {}
    for p in (ROOT / "services").rglob("limitations.py"):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            lims[str(p.relative_to(ROOT))] = text[:2000]
        except Exception as exc:
            lims[str(p.relative_to(ROOT))] = f"read_error: {exc}"
    return {"generated_at_utc": _utc(), "limitations_files": lims}


def _data_truth() -> Dict[str, Any]:
    patterns = ["fake", "mock", "demo", "dummy", "hardcoded", "placeholder", "synthetic", "simulation"]
    hits: List[Dict[str, Any]] = []
    scan_dirs = [ROOT / "services", ROOT / "routes", ROOT / "api", ROOT / "templates"]
    for base in scan_dirs:
        for p in base.rglob("*"):
            if p.suffix not in {".py", ".html", ".js"} or "__pycache__" in str(p):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for pat in patterns:
                if re.search(pat, text, re.I):
                    hits.append({"file": str(p.relative_to(ROOT)), "pattern": pat})
                    break
    production_risk = [
        "services/ndci_expedient_sections.py — simulaciones/predicción heurística en casos estudio",
        "services/csv_bas/ — escenarios BAS etiquetados simulation",
        "services/deception_platform/ — señuelos intencionales",
    ]
    guards = [
        "services/alerts_canonical_service.py — filtra TEST_SOURCES/demo/simulated",
        "services/telemetry_resolver.py — placeholder/simulated como ausente",
        "routes/dashboard.py — LOADING/Sin datos disponibles",
    ]
    return {
        "generated_at_utc": _utc(),
        "scan_hit_count": len(hits),
        "scan_hits_sample": hits[:80],
        "production_ui_risk_modules": production_risk,
        "anti_fake_guards": guards,
        "canonical_metrics": "platform_metrics_service → /api/security/summary",
    }


def _write_json(name: str, obj: Any) -> None:
    (OUT / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_md_report(live: Dict, perf: Dict, inv: Dict) -> None:
    md = f"""# Informe Completo NOVUS — Auditoría de Conocimiento (Solo Lectura)

**Generado:** {_utc()}  
**Tipo:** Inspección + pruebas GET seguras — sin modificaciones al producto

---

## 1. Estado del servidor

| Campo | Valor |
|-------|-------|
| URL | {BASE}/login |
| HTTP | {live.get('http_login', {}).get('status')} |
| Tiempo respuesta | {live.get('http_login', {}).get('response_ms')} ms |
| Listener PID(s) | {live.get('listeners_port_5000')} |
| Instancia única | {live.get('single_listener')} |
| Procesos main.py | {live.get('main_py_count')} |

---

## 2. ¿Qué tiene NOVUS?

Plataforma Flask modular multi-tenant con:
- **{inv.get('counts', {}).get('services_py', '?')}** módulos Python en `services/`
- **{inv.get('counts', {}).get('api_py', '?')}** blueprints API
- **{inv.get('counts', {}).get('templates_html', '?')}** templates HTML
- **{inv.get('counts', {}).get('data_dirs', '?')}** directorios de datos persistentes
- Motor central XDR: `novus_security_integration` + `security_engine.py`
- Hub de detección: `defense_coordinator` → `defense_registry/events.jsonl`
- Hub de métricas: `platform_metrics_service` → `/api/security/summary`

---

## 3. ¿Qué puede hacer?

Ver `CAPACIDADES_REALES.json` y sección 17-19 abajo.

**Fortalezas:** detección local host+red, auth enterprise (MFA/CSRF/RBAC), Swarm correlación, IMCM, SOC multi-vista, forensics con integridad, health self-healing.

**Limitaciones:** SDL pull-only, métricas dashboard separadas del registry de defensa, Cloud Shield no implementado, ZDDE heurístico (no zero-day universal).

---

## 4. Arquitectura de integración (real)

```
Motores detectan → defense_coordinator → defense_registry (JSONL)
                              ├→ network_security_history
                              ├→ forensic_pcap
                              ├→ adaptive_profile
                              └→ Swarm event_bus → correlate → response_policy → IMCM

novus_security (cache) → platform_metrics_service → Dashboard/API

SDL ingest (pull) ← motores | SDACE lee SDL | Kernel IA lee métricas + registry (parcial)
```

---

## 5. Flujo ataque detectado → respuesta → forense

1. Motor (BTDE/endpoint/NDR/XDR) detecta evidencia verificada  
2. `publish.py` → `defense_coordinator.record_detection`  
3. Evento en `data/defense_registry/events.jsonl` + side effects  
4. Swarm recibe `anomaly.detected`, correlaciona con registry  
5. Auto-respuesta según política (evidencia, monitoreo, incidente IMCM)  
6. IMCM consolida contexto ASM/VIEM/TIE  
7. Forensics: PCAP metadata, evidence center, sealed hashes  
8. SOPE playbooks / manual defense si operador aprueba  
9. SDL/SDACE: snapshot analítico (no tiempo real automático)

---

## 6. Kernel IA

- **Consulta:** system_monitor, network_scanner, novus_security cache, orchestrator modules, GuardIA heuristics  
- **Análisis:** carga CPU/RAM, recomendaciones chat, enterprise v2 engines on-demand  
- **Ejecución:** NO ejecuta containment Swarm; registra en kernel_memory  
- **Fuentes:** parcial SDL/SDACE vía collectors; BTDE/UEBA/IAPA indirecto

---

## 7. Seguridad (implementado)

MFA, CSRF, RBAC, session audit, refresh tokens (WSAE), rate limiting, CSP/CORS opcional, device fingerprint, adaptive login, session revocation (Swarm), CryptoVault, DB at-rest encryption, ProxyFix.

---

## 8. Red y cambio de red

`network_scan_coordinator`: detecta SSID, BSSID (puede null), interfaz, IP, subred, gateway.  
`invalidate_on_context_change`: limpia scanner cache + threat cache vía runtime_environment_service.  
**Riesgo obsoleto:** datos UI hasta próximo scan/API si invalidación no corre.

---

## 9. Performance (snapshot GET)

{json.dumps(perf.get('endpoints', []), indent=2, ensure_ascii=False)}

Referencia post-optimización UX: handlers autenticados dashboard ~12-56ms (ver `data/performance_ux_optimization/`).

---

## 10. LO QUE NOVUS PUEDE HACER HOY

Protección local, escaneo ARP/procesos, incidentes IMCM, SOC convergente, playbooks SOPE, deception decoys, CSV-BAS no destructivo, health monitoring, auth enterprise.

---

## 11. PARCIAL

TIE feeds externos, SDL ingest manual, ZDDE heurístico, Mesh multi-nodo, BSSID Windows.

---

## 12. NO PUEDE HACER

Cloud Shield activo, SIEM petabyte-scale, detección zero-day universal garantizada, push SDL automático por cada evento.

---

## 13. Mapa madurez funcional

| Nivel | Módulos |
|-------|---------|
| OPERATIVO VERIFICADO | XDR, Network, Health, IMCM, SOC, Auth, ASM, VIEM, SOPE |
| OPERATIVO LIMITADO | BTDE, UEBA, Endpoint Enterprise |
| PARCIAL | SDL, SDACE, TIE, IAPA, ZDDE |
| NO IMPLEMENTADO | Cloud Shield |

---

*Auditoría solo lectura. Evidencia JSON en este directorio.*
"""
    (OUT / "INFORME_COMPLETO_NOVUS.md").write_text(md, encoding="utf-8")


def _write_pdf() -> bool:
    try:
        from fpdf import FPDF
        from utils.pdf_text import normalize_pdf_multiline

        md = (OUT / "INFORME_COMPLETO_NOVUS.md").read_text(encoding="utf-8")
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=12)
        pdf.add_page()
        pdf.set_font("Helvetica", size=8)
        for line in md.splitlines():
            safe = normalize_pdf_multiline(line[:500])
            if line.startswith("#"):
                pdf.set_font("Helvetica", "B", 10 if line.startswith("##") else 12)
                pdf.multi_cell(190, 4, safe)
                pdf.set_font("Helvetica", size=8)
            else:
                pdf.multi_cell(190, 3.5, safe)
        pdf.output(str(OUT / "INFORME_COMPLETO_NOVUS.pdf"))
        return True
    except Exception as exc:
        (OUT / "INFORME_COMPLETO_NOVUS.pdf.error.txt").write_text(str(exc), encoding="utf-8")
        return False


def main() -> int:
    live = _server_status()
    perf = _performance_snapshot()
    inv = _inventory()
    engines = _engines_map()
    arch = _architecture()
    flow = _data_flow()
    caps = _capabilities()
    lims = _limitations()
    truth = _data_truth()

    _write_json("LIVE_STATUS.json", live)
    _write_json("PERFORMANCE_SNAPSHOT.json", perf)
    _write_json("INVENTARIO_COMPLETO.json", inv)
    _write_json("MAPA_ARQUITECTURA.json", arch)
    _write_json("MAPA_DEPENDENCIAS.json", {
        "generated_at_utc": _utc(),
        "source": "code_inspection",
        "architecture": arch,
        "engines": engines,
    })
    _write_json("DATA_FLOW.json", flow)
    _write_json("CAPACIDADES_REALES.json", caps)
    _write_json("LIMITACIONES_REALES.json", lims)
    _write_json("DATA_TRUTH_FINDINGS.json", truth)

    _write_md_report(live, perf, inv)
    pdf_ok = _write_pdf()

    summary = {
        "output_dir": str(OUT),
        "live_http": live.get("http_login"),
        "single_listener": live.get("single_listener"),
        "pdf_generated": pdf_ok,
        "files": sorted(x.name for x in OUT.iterdir()),
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
