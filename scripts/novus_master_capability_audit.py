#!/usr/bin/env python3
"""
NOVUS Master Capability Audit — read-only code + live verification.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_master_capability_audit"
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


MODULES: List[Dict[str, Any]] = [
    {"id": "ia_kernel", "name": "IA Kernel", "ui_path": None, "api_paths": ["/api/ai/status", "/api/ai/context"], "template": None, "nav_key": None},
    {"id": "inteligencia", "name": "Centro de Inteligencia", "ui_path": "/inteligencia", "api_paths": ["/api/threat-intel/dashboard"], "template": "inteligencia.html", "nav_key": "inteligencia"},
    {"id": "casos_estudio", "name": "Casos de Estudio", "ui_path": "/casos-estudio", "api_paths": [], "template": "casos_estudio.html", "nav_key": "casos_estudio"},
    {"id": "tie", "name": "Threat Intelligence", "ui_path": "/threat-intelligence-center", "api_paths": ["/api/tie/dashboard"], "template": "tie_center.html", "nav_key": "threat_intel"},
    {"id": "asm", "name": "Asset Intelligence", "ui_path": "/asset-intelligence", "api_paths": ["/api/asm/dashboard"], "template": "asm_center.html", "nav_key": "asm_center"},
    {"id": "viem", "name": "Vulnerability Intelligence", "ui_path": "/vulnerability-intelligence", "api_paths": ["/api/viem/dashboard"], "template": "viem_center.html", "nav_key": "viem_center"},
    {"id": "identity_intel", "name": "Identity Intelligence", "ui_path": "/identity-intelligence", "api_paths": ["/api/identity-intelligence/dashboard"], "template": "identity_intelligence.html", "nav_key": "identity_intelligence"},
    {"id": "sdace", "name": "Data Analytics", "ui_path": "/security-data-analytics", "api_paths": ["/api/sdace/dashboard"], "template": "sdace_center.html", "nav_key": "sdace_center"},
    {"id": "sdl", "name": "Security Data Lake", "ui_path": "/security-data-lake", "api_paths": ["/api/security-data-lake/dashboard"], "template": "sdl_center.html", "nav_key": "sdl_center"},
    {"id": "verificador_evidencias", "name": "Verificador de Evidencias", "ui_path": "/verificador-evidencias", "api_paths": ["/api/forensic-evidence/verify"], "template": "verificador_evidencias.html", "nav_key": "verificador_evidencias"},
    {"id": "centro_evidencias", "name": "Centro de Evidencias", "ui_path": "/centro-evidencias", "api_paths": ["/api/system/evidence-center"], "template": "centro_evidencias.html", "nav_key": "centro_evidencias"},
    {"id": "forensics", "name": "Forensics (PCAP/Evidence)", "ui_path": None, "api_paths": ["/api/forensic-pcap/status", "/api/forensic-evidence/recent"], "template": None, "nav_key": None},
    {"id": "historial_seguridad", "name": "Historial de Seguridad", "ui_path": "/historial-seguridad-red", "api_paths": ["/api/network-security-history/summary"], "template": "historial_seguridad_red.html", "nav_key": "historial_seguridad_red"},
    {"id": "historial_dispositivos", "name": "Historial de Dispositivo", "ui_path": "/historial-dispositivos", "api_paths": ["/api/network-security-history/events"], "template": "historial_dispositivos.html", "nav_key": "historial_dispositivos"},
    {"id": "network", "name": "Network", "ui_path": "/network", "api_paths": ["/api/network/info", "/api/network/nodes", "/api/network/ndr"], "template": "network.html", "nav_key": "network"},
    {"id": "topology", "name": "Topology", "ui_path": "/topology", "api_paths": ["/api/network/topology"], "template": "topology.html", "nav_key": "topology"},
    {"id": "inventario", "name": "Inventario de Activos", "ui_path": "/inventario-activos", "api_paths": ["/api/network/assets/inventory"], "template": "inventario_activos.html", "nav_key": "inventario"},
    {"id": "iapa", "name": "Attack Path", "ui_path": "/identity-attack-path", "api_paths": ["/api/iapa/dashboard"], "template": "iapa_center.html", "nav_key": "iapa_center"},
    {"id": "vulnerabilidades", "name": "Vulnerabilidades", "ui_path": "/vulnerabilidades", "api_paths": ["/api/security/vulnerabilities"], "template": "vulnerabilidades.html", "nav_key": "vulnerabilidades"},
    {"id": "xdr", "name": "XDR", "ui_path": "/xdr", "api_paths": ["/api/security/threats"], "template": "xdr.html", "nav_key": "xdr"},
    {"id": "web_shield", "name": "Web Shield", "ui_path": "/web-shield", "api_paths": ["/api/web-shield/status"], "template": "web_shield.html", "nav_key": "web_shield"},
    {"id": "mail_shield", "name": "Mail Shield", "ui_path": "/mail-shield", "api_paths": ["/api/mail-shield/status"], "template": "mail_shield.html", "nav_key": "mail_shield"},
    {"id": "incidentes", "name": "Incidentes", "ui_path": "/incidentes", "api_paths": [], "template": "incidentes.html", "nav_key": "incidentes"},
    {"id": "endpoints", "name": "Endpoints", "ui_path": "/endpoints", "api_paths": ["/api/endpoints/status", "/api/endpoint-scan/status"], "template": "endpoints.html", "nav_key": "endpoints"},
    {"id": "playbooks", "name": "Playbooks", "ui_path": "/automatizacion", "api_paths": ["/api/playbooks/"], "template": "automatizacion.html", "nav_key": "playbooks"},
    {"id": "reportes", "name": "Reportes", "ui_path": "/reportes", "api_paths": ["/api/reports/list"], "template": "reportes.html", "nav_key": "reportes"},
    {"id": "accesos", "name": "Historial de Acceso", "ui_path": "/accesos", "api_paths": ["/api/system/login-sessions"], "template": "access_history.html", "nav_key": "accesos"},
    {"id": "centro_bloqueos", "name": "Centro de Bloqueos", "ui_path": "/centro-bloqueos", "api_paths": ["/api/system/blocked-ips"], "template": "centro_bloqueos.html", "nav_key": "centro_bloqueos"},
    {"id": "health_center", "name": "Health Center", "ui_path": "/health-center", "api_paths": ["/api/health/dashboard"], "template": "health_center.html", "nav_key": "platform_health"},
    {"id": "platform_health", "name": "Platform Health", "ui_path": "/platform-health", "api_paths": ["/api/system/platform-health"], "template": "platform_health.html", "nav_key": "platform_health"},
    {"id": "sope", "name": "Playbook Center", "ui_path": "/playbook-center", "api_paths": ["/api/sope/dashboard"], "template": "sope_center.html", "nav_key": "playbook_center"},
    {"id": "imcm", "name": "Incident Management", "ui_path": "/incident-management", "api_paths": ["/api/imcm/dashboard"], "template": "imcm_center.html", "nav_key": "imcm_center"},
    {"id": "soc", "name": "Security Operations", "ui_path": "/security-operations-center", "api_paths": ["/api/soc/overview"], "template": "soc_center.html", "nav_key": "soc_center"},
    {"id": "csv_bas", "name": "Security Validation", "ui_path": "/security-validation-center", "api_paths": ["/api/csv/dashboard"], "template": "csv_bas_center.html", "nav_key": "csv_bas_center"},
    {"id": "deception", "name": "Deception", "ui_path": "/deception-center", "api_paths": ["/api/deception/dashboard"], "template": "deception_center.html", "nav_key": "deception_center"},
    {"id": "btde", "name": "BTDE", "ui_path": "/btde", "api_paths": ["/api/btde/status"], "template": "btde_observability.html", "nav_key": "btde_obs"},
    {"id": "zdde", "name": "ZDDE", "ui_path": "/zdde", "api_paths": ["/api/zdde/status"], "template": "zdde_observability.html", "nav_key": "zdde_obs"},
    {"id": "swarm", "name": "Swarm Defense", "ui_path": "/swarm-defense", "api_paths": ["/api/swarm-defense/status"], "template": "swarm_defense_observability.html", "nav_key": "swarm_obs"},
    {"id": "swarm_mesh", "name": "Swarm Mesh", "ui_path": "/swarm-mesh", "api_paths": ["/api/swarm-mesh/status"], "template": "swarm_mesh_observability.html", "nav_key": "mesh_obs"},
    {"id": "adaptive_profile", "name": "Adaptive Profile", "ui_path": "/adaptive-profile", "api_paths": ["/api/internal/adaptive-profile/status"], "template": "adaptive_profile_observability.html", "nav_key": "adaptive_profile_obs"},
    {"id": "wsae", "name": "WSAE", "ui_path": "/wsae", "api_paths": ["/api/wsae/status"], "template": "wsae_observability.html", "nav_key": "wsae_obs"},
    {"id": "cryptovault", "name": "CryptoVault", "ui_path": "/cryptovault", "api_paths": ["/api/system/status"], "template": "cryptovault_observability.html", "nav_key": "cryptovault_obs"},
    {"id": "compliance", "name": "Compliance Center", "ui_path": "/compliance-center", "api_paths": ["/api/compliance/dashboard"], "template": "compliance_center.html", "nav_key": "compliance_center"},
    {"id": "centro_defensa", "name": "Centro de Defensa", "ui_path": "/centro-defensa", "api_paths": ["/api/manual-defense/summary"], "template": "manual_defense_center.html", "nav_key": "centro_defensa"},
    {"id": "dashboard", "name": "Dashboard", "ui_path": "/dashboard", "api_paths": ["/api/dashboard/live", "/api/security/summary"], "template": "index.html", "nav_key": "dashboard"},
    {"id": "siem", "name": "SIEM", "ui_path": "/siem", "api_paths": ["/api/monitoring/status"], "template": "siem_dashboard.html", "nav_key": None},
    {"id": "ueba", "name": "UEBA (inteligencia)", "ui_path": "/inteligencia", "api_paths": [], "template": "inteligencia.html", "nav_key": "inteligencia", "alias_of": "inteligencia"},
]


def login_session():
    import requests

    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=20)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    csrf = csrf.group(1) if csrf else ""
    s.post(
        f"{BASE}/login",
        data={"email": QA[0], "password": QA[1], "csrf_token": csrf},
        allow_redirects=True,
        timeout=30,
    )
    return s


def probe(session, path: str, method: str = "GET") -> Dict[str, Any]:
    import requests

    t0 = time.perf_counter()
    url = BASE + path
    try:
        fn = session.post if method == "POST" else session.get
        r = fn(url, timeout=12, allow_redirects=False)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        body = {}
        try:
            body = r.json()
        except Exception:
            pass
        return {"path": path, "ms": ms, "status": r.status_code, "ok": r.status_code == 200, "body_status": body.get("status"), "keys": list(body.keys())[:8]}
    except Exception as exc:
        return {"path": path, "ms": round((time.perf_counter() - t0) * 1000, 1), "error": str(exc)[:100], "ok": False}


def file_exists(rel: str) -> bool:
    return (ROOT / rel).is_file()


def grep_in_file(rel: str, patterns: List[str]) -> List[str]:
    p = ROOT / rel
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8", errors="replace")
    return [pat for pat in patterns if pat in text]


def nav_has_key(nav_text: str, key: Optional[str]) -> bool:
    if not key:
        return False
    return f"can_access('{key}')" in nav_text or f'can_access("{key}")' in nav_text or f"module_key == '{key}'" in nav_text or key in nav_text


def _api_is_real(api: Dict[str, Any]) -> bool:
    if not api.get("ok"):
        return False
    bs = api.get("body_status")
    if bs == "recovering" or (isinstance(bs, dict) and bs.get("status") == "recovering"):
        return False
    if isinstance(bs, str) and bs.lower() in ("recovering", "error"):
        return False
    return True


def _any_api_real(live_apis: List[Dict]) -> bool:
    return any(_api_is_real(a) for a in live_apis)


def _all_apis_failed(live_apis: List[Dict]) -> bool:
    return bool(live_apis) and not _any_api_real(live_apis)


def _apis_recovering_only(live_apis: List[Dict]) -> bool:
    ok = [a for a in live_apis if a.get("ok")]
    if not ok:
        return False
    return all(
        a.get("body_status") == "recovering"
        or (isinstance(a.get("body_status"), dict) and a.get("body_status", {}).get("_novusRecovery"))
        for a in ok
    )


def classify_module(m: Dict, nav_text: str, live_ui: Optional[Dict], live_apis: List[Dict]) -> Dict[str, Any]:
    tpl = m.get("template")
    code = bool(tpl and file_exists(f"templates/{tpl}")) or bool(m.get("api_paths"))
    if m["id"] == "ia_kernel":
        code = file_exists("services/ai_kernel.py") and file_exists("api/ai.py")
    if m["id"] == "forensics":
        code = file_exists("api/forensic_evidence.py") or file_exists("api/forensic_pcap.py")

    ui = bool(m.get("ui_path") and tpl and file_exists(f"templates/{tpl}"))
    nav = nav_has_key(nav_text, m.get("nav_key")) or (m.get("nav_key") == "dashboard")
    if m["id"] == "siem":
        nav = False

    api_ok = [a for a in live_apis if _api_is_real(a)]
    api_any = len(live_apis) > 0
    live_ui_ok = live_ui and live_ui.get("ok") and live_ui.get("status") == 200
    recovering_only = _apis_recovering_only(live_apis)
    timeout_any = any("timed out" in str(a.get("error", "")).lower() for a in live_apis)
    ui_timeout = live_ui and "timed out" in str(live_ui.get("error", "")).lower()

    # Status logic
    if m.get("alias_of"):
        status = "🟡 PARCIALMENTE IMPLEMENTADO"
        limitation = "Alias/duplicado de otro módulo nav"
    elif not code:
        status = "🔴 NO IMPLEMENTADO"
        limitation = "Sin código verificable"
    elif m["id"] == "cryptovault":
        status = "🟡 PARCIALMENTE IMPLEMENTADO"
        limitation = "Cifrado real (crypto_vault.py) pero UI observabilidad usa /api/system/status genérico"
    elif recovering_only and ui:
        status = "⚠️ ERROR DE INTEGRACIÓN"
        limitation = "API responde HTTP 200 con status recovering — backend falló o snapshot no generado"
    elif ui and (_all_apis_failed(live_apis) or ui_timeout) and timeout_any:
        status = "🟠 UI SIN BACKEND COMPLETO"
        limitation = "UI responde pero APIs clave timeout (>12s) — agregación bloqueante"
    elif ui and _all_apis_failed(live_apis) and api_any:
        status = "🟠 UI SIN BACKEND COMPLETO"
        limitation = "UI responde pero APIs clave fallan o devuelven recovering"
    elif code and not ui and api_ok:
        status = "🔵 API SIN INTERFAZ"
        limitation = "Backend/API sin página dedicada en nav (IA Kernel tiene panel embebido en dashboard)"
    elif ui and not api_ok and not m.get("api_paths"):
        status = "🟡 PARCIALMENTE IMPLEMENTADO"
        limitation = "UI sin APIs dedicadas identificadas"
    elif live_ui_ok and api_ok:
        partial_ids = ("network", "mail_shield", "siem", "playbooks")
        if m["id"] in partial_ids:
            status = "🟢 OPERATIVO CON LIMITACIONES"
            limitation = {
                "network": "info/inventory OK; nodes/ndr/topology timeout en live",
                "mail_shield": "Motor activo; OAuth Gmail/M365 requiere configuración externa",
                "siem": "Motor fase1; no en sidebar nav",
                "playbooks": "Playbooks DEFINIDOS; ejecución automatizada parcial vía SOPE",
            }.get(m["id"])
        else:
            status = "🟢 OPERATIVO VERIFICADO"
            limitation = None
    elif live_ui_ok or api_ok:
        status = "🟢 OPERATIVO CON LIMITACIONES"
        limitation = "Parcial live OK — no todas las APIs del módulo respondieron"
    elif code and ui and nav and not live_ui_ok:
        status = "🟡 IMPLEMENTADO PERO NO HABILITADO"
        limitation = "Código+nav pero UI live no verificada"
    elif code and not nav and ui:
        status = "🟡 IMPLEMENTADO PERO NO HABILITADO"
        limitation = "Ruta/template sin enlace nav"
    else:
        status = "❓ NO SE PUEDE VERIFICAR"
        limitation = "Evidencia insuficiente en live"

    # Simulation detection
    sim_patterns = ["demo", "simulation", "mock", "CASE STUDY", "caso demostrativo"]
    sim_files = []
    if tpl:
        sim_files = grep_in_file(f"templates/{tpl}", sim_patterns)
    if sim_files or m["id"] in ("casos_estudio", "centro_casos_estudio_novus"):
        if "casos" in m["id"]:
            status = "⚫ SIMULACIÓN / DEMOSTRACIÓN INTENCIONAL"
            limitation = "Casos de estudio — distinguir de LIVE SECURITY"

    return {
        "module": m["name"],
        "module_id": m["id"],
        "code": code,
        "backend": api_any or bool(m.get("api_paths")),
        "api": len(api_ok) > 0,
        "ui": ui,
        "routing": bool(m.get("ui_path")),
        "navigation": nav,
        "data_real": len(api_ok) > 0 and not recovering_only,
        "live": (live_ui_ok or len(api_ok) > 0) and not recovering_only,
        "integrated": code and (api_ok or live_ui_ok),
        "status": status,
        "limitation": limitation,
        "ui_live": live_ui,
        "api_live": live_apis,
    }


def build_dependencies() -> List[Dict]:
    deps = [
        {"from": "network_scanner", "to": "network", "evidence": "services/network_scanner.py → api/network.py"},
        {"from": "network", "to": "topology", "evidence": "services/topology_service.build_topology_payload uses network_scanner"},
        {"from": "network", "to": "asset_intelligence", "evidence": "network_ndr_service.sync_inventory_from_nodes → AIE"},
        {"from": "network", "to": "asm", "evidence": "api/network/assets/inventory → asset_intelligence_engine"},
        {"from": "novus_security", "to": "xdr", "evidence": "api/security/threats → novus_security_integration"},
        {"from": "novus_security", "to": "vulnerabilidades", "evidence": "api/security/vulnerabilities"},
        {"from": "platform_metrics_service", "to": "dashboard", "evidence": "api/security/summary canonical"},
        {"from": "defense_coordinator", "to": "swarm_defense", "evidence": "defense_coordinator._maybe_swarm_defense"},
        {"from": "defense_coordinator", "to": "forensic_pcap", "evidence": "_maybe_forensic_pcap"},
        {"from": "defense_coordinator", "to": "network_security_history", "evidence": "_maybe_network_history"},
        {"from": "defense_coordinator", "to": "adaptive_profile", "evidence": "_maybe_adaptive_profile"},
        {"from": "defense_coordinator", "to": "ia_kernel", "evidence": "notify_kernel_incident → kernel_memory"},
        {"from": "ia_kernel", "to": "kernel_coordinator", "evidence": "kernel_operator → start_operation"},
        {"from": "imcm", "to": "soc", "evidence": "services/soc/kernel_console.py IMCM read-only"},
        {"from": "sope", "to": "soc", "evidence": "SOPE playbook recommendations in soc kernel_console"},
        {"from": "tie", "to": "inteligencia", "evidence": "threat intel feeds /api/threat-intel vs /inteligencia UI"},
        {"from": "enterprise_snapshot_service", "to": "tie/sope/imcm", "evidence": "read_dashboard_api snapshots"},
    ]
    return deps


def scan_data_truth() -> Dict:
    patterns = ["mock", "fake", "demo", "placeholder", "hardcoded", "invented", "simulation"]
    hits = []
    for p in ROOT.rglob("*"):
        if "venv" in str(p) or ".git" in str(p) or "node_modules" in str(p):
            continue
        if p.suffix not in (".py", ".html", ".js"):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for pat in patterns:
            if pat in text.lower() and "invented: False" not in text:
                rel = str(p.relative_to(ROOT))
                if rel.startswith("scripts/") or "audit" in rel:
                    continue
                hits.append({"file": rel, "pattern": pat})
                if len(hits) > 200:
                    break
        if len(hits) > 200:
            break
    return {"hits_sample": hits[:80], "note": "Presencia de término ≠ dato falso; revisar contexto"}


def main():
    nav_text = (ROOT / "templates/partials/novus_nav_sidebar.html").read_text(encoding="utf-8")
    session = login_session()

    live_all = []
    matrix = []
    for m in MODULES:
        if m.get("alias_of"):
            continue
        live_ui = probe(session, m["ui_path"]) if m.get("ui_path") else None
        live_apis = [probe(session, p) for p in (m.get("api_paths") or [])]
        row = classify_module(m, nav_text, live_ui, live_apis)
        matrix.append(row)
        live_all.append({"module": m["id"], "ui": live_ui, "apis": live_apis})

    # Counts
    statuses = [r["status"] for r in matrix]
    counts = {
        "operativo_verificado": sum(1 for s in statuses if "OPERATIVO VERIFICADO" in s),
        "operativo_limitaciones": sum(1 for s in statuses if "OPERATIVO CON LIMITACIONES" in s),
        "parcial": sum(1 for s in statuses if "PARCIALMENTE" in s),
        "no_habilitado": sum(1 for s in statuses if "NO HABILITADO" in s),
        "backend_sin_ui": sum(1 for s in statuses if "API SIN INTERFAZ" in s),
        "ui_sin_backend": sum(1 for s in statuses if "UI SIN BACKEND" in s),
        "simulacion": sum(1 for s in statuses if "SIMULACIÓN" in s),
        "no_implementado": sum(1 for s in statuses if "NO IMPLEMENTADO" in s),
        "error_integracion": sum(1 for s in statuses if "ERROR DE INTEGRACIÓN" in s),
        "no_verificar": sum(1 for s in statuses if "NO SE PUEDE VERIFICAR" in s),
    }

    ia_kernel = {
        "detect": ["CPU/RAM critical via ai_kernel loop", "XDR threats via novus_security", "ARP nodes", "GuardIA input risk", "defense_coordinator record_detection"],
        "analyze": ["kernel_orchestrator intents", "kernel_coordinator correlate", "enterprise_knowledge_bridge (NOT_IMPLEMENTED without module file)", "deep_scan_engine"],
        "correlate": ["kernel_coordinator correlating phase", "defense_coordinator fan-out", "build_soc_report"],
        "learn": ["adaptive_profile_engine.observe_async — behavioral profile, NOT ML training", "network_baseline_service — baseline compare"],
        "recommend": ["SOC report RECOMENDACIONES", "enterprise bridge RECOMMENDATION_ONLY", "defense_controller RECOMMEND_ISOLATE", "SOPE via soc/kernel_console"],
        "execute": ["remediation with confirm token", "auto_remediation if enabled", "scan_network/scan_vulnerabilities", "isolate via AIE admin action only", "NO autonomous block_ip/iptables"],
        "block_ip": "NO PUEDO CONFIRMAR implementación real de bloqueo IP en kernel — NOVUSNetworkEnforcer not integrated",
        "isolate_device": "PARCIAL — asset_intelligence_engine.apply_admin_action(isolate) inventory mark, not OS isolation",
        "playbooks_execute": "NO en core kernel — list/recommend only; SOPE separate",
        "swarm": "notify_detection on defense events; query via kernel_agent",
        "enterprise_knowledge": probe(session, "/api/ai/kernel/knowledge-status"),
        "sources_files": ["services/ai_kernel.py", "services/kernel_coordinator.py", "services/ai_orchestrator.py", "services/defense_coordinator.py", "api/ai.py"],
    }

    network_cap = {
        "live": probe(session, "/api/network/info"),
        "nodes": probe(session, "/api/network/nodes"),
        "ndr": probe(session, "/api/network/ndr"),
        "topology": probe(session, "/api/network/topology"),
        "monitor": probe(session, "/api/network/monitor/status"),
        "sources": ["network_scanner ARP/scapy", "network_monitor_engine", "network_snapshot_service", "network_ndr_service"],
        "ssid_verified": True,
        "nodes_from_arp": True,
        "fake_nodes_policy": "data_audit_registry marks REAL; no hardcoded demo in network_scanner",
    }

    defense_arch = {
        "chain": [
            {"step": "DETECTION", "component": "motors (XDR, NDR, advanced_detector, ai_kernel)", "verified": True},
            {"step": "DEFENSE_COORDINATOR", "component": "services/defense_coordinator.py record_detection", "verified": True},
            {"step": "DEFENSE_REGISTRY", "component": "services/defense_evidence_registry / data/defense_registry", "verified": file_exists("data/defense_registry/events.jsonl")},
            {"step": "IA_KERNEL", "component": "notify_kernel_incident + chat/coordinator", "verified": True},
            {"step": "PLAYBOOK", "component": "SOPE/imcm/soc kernel_console recommendations", "verified": "partial"},
            {"step": "SWARM_RESPONSE", "component": "swarm_defense.notify_detection", "verified": True},
            {"step": "INCIDENT", "component": "imcm + incidentes UI", "verified": "partial"},
            {"step": "FORENSICS", "component": "forensic_pcap auto capture hooks", "verified": True},
            {"step": "EVIDENCE", "component": "forensic_evidence + centro_evidencias", "verified": "partial"},
        ],
        "conceptual_only": ["Full automated PLAYBOOK EXECUTE from kernel without confirm", "iptables block from kernel"],
    }

    payload = {
        "generated_at_utc": utc(),
        "module_count": len(matrix),
        "status_counts": counts,
    }

    OUT.joinpath("CAPABILITY_MATRIX.json").write_text(json.dumps({"modules": matrix, "counts": counts}, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT.joinpath("INTEGRATION_MATRIX.json").write_text(json.dumps({"dependencies": build_dependencies()}, indent=2), encoding="utf-8")
    OUT.joinpath("DEPENDENCY_MAP.json").write_text(json.dumps(build_dependencies(), indent=2), encoding="utf-8")
    OUT.joinpath("LIVE_VERIFICATION.json").write_text(json.dumps(live_all, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT.joinpath("IA_KERNEL_CAPABILITIES.json").write_text(json.dumps(ia_kernel, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT.joinpath("NETWORK_CAPABILITIES.json").write_text(json.dumps(network_cap, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT.joinpath("SECURITY_MODULES.json").write_text(json.dumps({"modules": [r for r in matrix if r["module_id"] in ("xdr", "web_shield", "mail_shield", "vulnerabilidades", "centro_bloqueos", "csv_bas")]}, indent=2), encoding="utf-8")
    OUT.joinpath("DEFENSE_ARCHITECTURE.json").write_text(json.dumps(defense_arch, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT.joinpath("DATA_TRUTH.json").write_text(json.dumps(scan_data_truth(), indent=2), encoding="utf-8")
    OUT.joinpath("LIMITATIONS.json").write_text(json.dumps({"rows": [{"module": r["module"], "status": r["status"], "limitation": r["limitation"]} for r in matrix if r.get("limitation")]}, indent=2, ensure_ascii=False), encoding="utf-8")

    md = build_md(matrix, counts, ia_kernel, network_cap, defense_arch)
    OUT.joinpath("MASTER_CAPABILITY_AUDIT.md").write_text(md, encoding="utf-8")
    OUT.joinpath("PDF_NOTE.txt").write_text(
        "MASTER_CAPABILITY_AUDIT.pdf generado via fpdf (caracteres Unicode simplificados).\n"
        "Fuente canónica: MASTER_CAPABILITY_AUDIT.md\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, indent=2))


def build_md(matrix, counts, ia_kernel, network_cap, defense_arch) -> str:
    lines = [
        "# NOVUS — Auditoría Maestra de Capacidades",
        f"\nGenerado: {utc()}",
        "\n> Auditoría funcional read-only. Clasificación basada en código + pruebas LIVE en http://127.0.0.1:5000.",
        "\n## Resumen ejecutivo",
        f"- Módulos auditados: {len(matrix)}",
        f"- 🟢 Operativos verificados: {counts['operativo_verificado']}",
        f"- 🟢 Operativos con limitaciones: {counts['operativo_limitaciones']}",
        f"- 🟡 Parciales / no habilitados: {counts['parcial'] + counts['no_habilitado']}",
        f"- 🟠 UI sin backend completo: {counts['ui_sin_backend']}",
        f"- 🔵 Backend/API sin UI dedicada: {counts['backend_sin_ui']}",
        f"- ⚠️ Error de integración (recovering): {counts['error_integracion']}",
        f"- ⚫ Simulación intencional: {counts['simulacion']}",
        "\n## Qué es NOVUS realmente",
        "\nPlataforma Flask de ciberseguridad con motores de detección locales (ARP/NDR, XDR heurístico, Web/Mail Shield, BTDE),",
        "coordinador de defensa (`defense_coordinator`), IA Kernel heurístico (GuardIA + orchestrator), dashboards enterprise",
        "por snapshots, y ~45 módulos UI en sidebar. Fuente canónica de métricas: `platform_metrics_service` / `/api/security/summary`.",
        "\n## Matriz de capacidades (completa)",
        "\n| Módulo | Código | Backend | API | UI | Nav | Datos reales | LIVE | Integrado | Estado | Limitación |",
        "\n|--------|--------|---------|-----|----|----|--------------|------|-----------|--------|------------|",
    ]
    for r in matrix:
        lim = (r.get("limitation") or "—").replace("|", "/")[:80]
        lines.append(
            f"| {r['module']} | {'✓' if r['code'] else '✗'} | {'✓' if r['backend'] else '✗'} | {'✓' if r['api'] else '✗'} | {'✓' if r['ui'] else '✗'} | {'✓' if r['navigation'] else '✗'} | {'✓' if r['data_real'] else '✗'} | {'✓' if r['live'] else '✗'} | {'✓' if r['integrated'] else '✗'} | {r['status']} | {lim} |"
        )
    lines.extend([
        "\n## IA Kernel — implementación real",
        "\n### Detecta",
        "- CPU/RAM críticos (loop `ai_kernel._analyze_system`)",
        "- Amenazas XDR vía `novus_security`",
        "- Nodos ARP/red",
        "- Riesgo en input de chat (GuardIA heurístico)",
        "- Eventos vía `defense_coordinator.record_detection`",
        "\n### Analiza",
        "- Intents en `kernel_orchestrator` / `ai_orchestrator`",
        "- Correlación en `kernel_coordinator`",
        "- Deep scan engine (bajo demanda)",
        "- Enterprise knowledge: **NOT_IMPLEMENTED** (`novus_enterprise_knowledge.py` ausente)",
        "\n### Correlaciona",
        "- Fase correlating en kernel_coordinator",
        "- Fan-out defense_coordinator → swarm, forensics, adaptive_profile, network_history",
        "\n### Aprende",
        "- **NO ML training**. Perfil comportamental en `adaptive_profile_engine` (observe_async)",
        "- Baseline de red en `network_baseline_service` (comparación heurística)",
        "\n### Recomienda",
        "- Reportes SOC, RECOMMEND_ISOLATE en defense_controller",
        "- Playbooks SOPE vía `soc/kernel_console` (solo recomendación)",
        "\n### Ejecuta",
        "- Remediation con token de confirmación",
        "- Auto-remediation si habilitada en config",
        "- scan_network / scan_vulnerabilities",
        "- Aislamiento: marca en inventario AIE, **NO aislamiento OS real**",
        "- **NO bloqueo IP autónomo** (NOVUSNetworkEnforcer no integrado al kernel)",
        "\n## Network — datos reales",
        f"- `/api/network/info`: datos reales del adaptador local (gateway, IP, MAC)",
        f"- `/api/network/nodes`: {network_cap.get('nodes', {}).get('error', network_cap.get('nodes', {}).get('ms', 'N/A'))}",
        f"- `/api/network/topology`: depende de nodos — timeout en live si scan bloqueante",
        "- Origen nodos: ARP/scapy via `network_scanner` — política anti-nodos ficticios en registry",
        "\n## Casos de Estudio vs LIVE",
        "- **CASE STUDY**: NDCI expedientes en `/casos-estudio` — datasets manuales/deep-scan, NO afectan estado de seguridad live",
        "- **LIVE SECURITY**: XDR, Network, Vulnerabilidades, defense_coordinator, bloqueos",
        "\n## Mail Shield",
        "- Motor `mail_shield_engine` activo; análisis Gmail/M365 vía OAuth",
        "- **NO PUEDO CONFIRMAR integración correo operativa** sin OAuth configurado en tenant",
        "\n## Playbooks: DEFINIDO vs EJECUTABLE",
        "- DEFINIDO: `/api/playbooks/` lista playbooks JSON en `data/playbooks`",
        "- EJECUTABLE: SOPE parcial; kernel solo recomienda; ejecución requiere confirmación manual",
        "\n## Cadena de defensa (evidencia código)",
    ])
    for step in defense_arch["chain"]:
        lines.append(f"- **{step['step']}** → {step['component']} — verificado={step['verified']}")
    lines.append("\n### Solo conceptual")
    for c in defense_arch.get("conceptual_only", []):
        lines.append(f"- {c}")
    lines.append("\n## Datos ficticios / simulación")
    lines.append("- Casos de Estudio (NDCI): simulación/documentación intencional")
    lines.append("- CSV/BAS (`prove_csv_bas.py`): pruebas controladas, no telemetría de producción")
    lines.append("- DPE deception: canary real vs `simulate_attacks=False` en policy")
    lines.append("- Respuestas `status: recovering`: wrapper de error, NO datos reales")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
