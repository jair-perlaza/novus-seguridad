#!/usr/bin/env python3
"""
Auditoría funcional total NOVUS — páginas, APIs GET, acciones UI, datos falsos/JSON.
Usa HTTP contra servidor en ejecución (no levanta otra instancia Flask).
Genera data/functional_audit/report.json, report.md y audit_report_full.md
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import requests

BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000")
EMAIL = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
PASSWORD = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")
TIMEOUT = int(os.environ.get("NOVUS_AUDIT_TIMEOUT", "90"))
# APIs que agregan motores pueden tardar bajo carga concurrente (escaneos ARP en cola Flask)
SLOW_API_TIMEOUTS: Dict[str, int] = {
    "/api/system/threat-coverage": max(TIMEOUT, 200),
}

PAGES: List[Tuple[str, str, str]] = [
    ("Dashboard", "dashboard", "/dashboard"),
    ("XDR", "xdr", "/xdr"),
    ("Amenazas", "amenazas", "/amenazas"),
    ("Network / NDR", "network", "/network"),
    ("Topology", "topology", "/topology"),
    ("Endpoints", "endpoints", "/endpoints"),
    ("Vulnerabilidades", "vulnerabilidades", "/vulnerabilidades"),
    ("Incidentes", "incidentes", "/incidentes"),
    ("Reportes", "reportes", "/reportes"),
    ("Inteligencia", "inteligencia", "/inteligencia"),
    ("Playbooks", "playbooks", "/automatizacion"),
    ("Configuración", "configuracion", "/configuracion"),
    ("Inventario activos", "inventario", "/inventario-activos"),
    ("Casos estudio", "casos_estudio", "/casos-estudio"),
    ("Centro bloqueos", "centro_bloqueos", "/centro-bloqueos"),
    ("Historial accesos", "accesos", "/accesos"),
    ("Historial dispositivos", "historial_dispositivos", "/historial-dispositivos"),
    ("Centro evidencias", "centro_evidencias", "/centro-evidencias"),
    ("Platform health", "platform_health", "/platform-health"),
    ("SIEM", "siem", "/siem"),
    ("Layout NOVUS", "layout", "/layout_novus"),
    ("Web Shield", "web_shield", "/web-shield"),
    ("Mail Shield", "mail_shield", "/mail-shield"),
    ("Centro Defensa Manual", "centro_defensa", "/centro-defensa-manual"),
    ("Verificador evidencias", "verificador_evidencias", "/verificador-evidencias"),
    ("Historial seguridad red", "historial_seguridad_red", "/historial-seguridad-red"),
]

# Módulos solo-API (CryptoVault, Adaptive Defense, ASPE, UCE, Kernel IA, Auditorías)
API_MODULES: List[Tuple[str, str, List[str]]] = [
    ("CryptoVault / Defense Registry", "cryptovault", ["/api/system/defense-registry"]),
    ("Adaptive Defense", "adaptive_defense", ["/api/system/sector-protection", "/api/system/threat-coverage"]),
    ("ASPE", "aspe", ["/api/system/aspe/status"]),
    ("UCE", "uce", ["/api/system/uce/detect"]),
    ("Kernel IA", "kernel_ia", ["/api/ai/status", "/api/ai/context"]),
    ("Centro Bloqueos API", "centro_bloqueos_api", ["/api/system/blocked-ips"]),
    ("Auditorías", "auditorias", ["/api/audit/data-sources", "/api/audit/integral/summary"]),
    ("Ngrok / Acceso remoto", "ngrok", ["/api/system/ngrok-manager"]),
]

GET_APIS: List[Tuple[str, str]] = [
    ("Dashboard live", "/api/dashboard/live"),
    ("Dashboard priority", "/api/dashboard/priority"),
    ("Dashboard metrics", "/api/dashboard/metrics"),
    ("Tenant scope", "/api/tenant/scope"),
    ("Network nodes", "/api/network/nodes"),
    ("Network info", "/api/network/info"),
    ("Network events", "/api/network/events?limit=10"),
    ("Network NDR", "/api/network/ndr"),
    ("Network topology", "/api/network/topology"),
    ("Network monitor", "/api/network/monitor/status"),
    ("Network assets", "/api/network/assets/inventory"),
    ("Security summary", "/api/security/summary"),
    ("Security alerts", "/api/security/alerts"),
    ("Security threats", "/api/security/threats"),
    ("Security vulnerabilities", "/api/security/vulnerabilities"),
    ("Security endpoints", "/api/security/endpoints"),
    ("System status", "/api/system/status"),
    ("System endpoints live", "/api/system/endpoints/live"),
    ("System platform health", "/api/system/platform-health"),
    ("System UCE detect", "/api/system/uce/detect"),
    ("System ASPE status", "/api/system/aspe/status"),
    ("System sector protection", "/api/system/sector-protection"),
    ("System defense registry", "/api/system/defense-registry"),
    ("System evidence center", "/api/system/evidence-center"),
    ("System ngrok manager", "/api/system/ngrok-manager"),
    ("System auth protection", "/api/system/auth-protection/status"),
    ("System blocked IPs", "/api/system/blocked-ips"),
    ("System device connections", "/api/system/device-connections"),
    ("System login sessions", "/api/system/login-sessions"),
    ("System threat coverage", "/api/system/threat-coverage"),
    ("System sector shield", "/api/system/sector-shield/status"),
    ("AI status", "/api/ai/status"),
    ("AI context", "/api/ai/context"),
    ("Search", "/api/search?q=test"),
    ("Search index", "/api/search/index"),
    ("Reports list", "/api/reports"),
    ("Playbooks list", "/api/playbooks"),
    ("Playbook executions", "/api/playbooks/executions"),
    ("Audit data sources", "/api/audit/data-sources"),
    ("Audit integral summary", "/api/audit/integral/summary"),
    ("Threat intel dashboard", "/api/threat-intel/dashboard"),
    ("Threat intel cases", "/api/threat-intel/cases"),
    ("NDCI cases", "/api/ndci/cases"),
    ("NDCI manual options", "/api/ndci/manual/options"),
    ("Gmail status", "/api/gmail/status"),
    ("Web Shield status", "/api/web-shield/status"),
    ("Web Shield events", "/api/web-shield/events?limit=5"),
    ("Web Shield host audit", "/api/web-shield/host-audit"),
    ("Mail Shield status", "/api/mail-shield/status"),
    ("Mail Shield integrations", "/api/mail-shield/integrations"),
    ("Mail Shield report", "/api/mail-shield/report"),
    ("System hostile environment", "/api/system/hostile-environment/status"),
    ("Monitoring status", "/api/monitoring/status"),
    ("Manual defense catalog", "/api/manual-defense/catalog"),
    ("Manual defense engines", "/api/manual-defense/engines"),
    ("Forensic evidence summary", "/api/forensic-evidence/summary"),
    ("Forensic PCAP capability", "/api/forensic-pcap/capability"),
    ("Network security history", "/api/network-security-history/summary"),
    ("Enterprise architecture", "/api/enterprise/architecture/status"),
]

UI_ACTION_PATTERNS: List[Tuple[str, str, str]] = [
    ("Dashboard live data", "/dashboard", r"fetchRealtimeData|loadCurrentPriority|NovusDashboardInvestigation"),
    ("Network refresh", "/network", r"cargarNDR|accionActualizar|investigarDispositivo"),
    ("Topology refresh", "/topology", r"refreshTopology|investigateDevice"),
    ("XDR load", "/xdr", r"fetchXDR|cargarAmenazas|verTrazaDesdeFila"),
    ("Vulnerabilidades", "/vulnerabilidades", r"fetchVulnerabilities|abrirPanel"),
    ("Incidentes", "/incidentes", r"fetchAlerts|NovusAlerts"),
    ("Reportes", "/reportes", r"NovusReports|novus-report-detail|openReportDetail"),
    ("Playbooks", "/automatizacion", r"openPlaybookModal|togglePlaybook|executePlaybook"),
    ("Config audit", "/configuracion", r"runIntegralAudit|saveConfig"),
    ("Inteligencia", "/inteligencia", r"refreshDashboard|loadCases"),
    ("Endpoints", "/endpoints", r"refreshEndpointsTable|fetchEndpoints|cargarEndpoints"),
    ("Kernel IA panel", "/dashboard", r"NovusAIKernel|consultKernelIA|ai_kernel_panel|novus-ai-input"),
    ("Global search", "/dashboard", r"NovusSearch|data-novus-search"),
    ("Web Shield", "/web-shield", r"refreshWebShield|ws-analyze-btn"),
    ("Mail Shield", "/mail-shield", r"refreshMailShield|ms-sync"),
]

FAKE_PATTERNS = re.compile(
    r"(?:\bmock(?:ed|up|_| data)\b|\bfake[_\s]|\bdummy[_\s]|lorem ipsum|"
    r"192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|"
    r"\bdemo threat\b|\bsimulated alert\b|\bsample threat\b)",
    re.I,
)
JSON_UI_LEAK = re.compile(r"JSON\.stringify\s*\([^)]*(?:evidence|threat|details|evidencia)", re.I)
PYTHON_DICT_LEAK = re.compile(r"\{['\"]verified['\"]\s*:")


def _login_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "NOVUS-FunctionalAudit/1.0"})
    last_err = ""
    for attempt in range(5):
        try:
            r_login = s.get(f"{BASE}/login", timeout=TIMEOUT)
            r_login.raise_for_status()
            m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r_login.text)
            if not m:
                last_err = f"attempt {attempt + 1}: csrf_token missing"
                time.sleep(1.5)
                continue
            s.post(
                f"{BASE}/login",
                data={"email": EMAIL, "password": PASSWORD, "csrf_token": m.group(1)},
                allow_redirects=True,
                timeout=TIMEOUT,
            )
            dash = s.get(f"{BASE}/dashboard", timeout=TIMEOUT, allow_redirects=True)
            if "/login" in (dash.url or "").lower():
                last_err = f"attempt {attempt + 1}: dashboard redirected to login"
                time.sleep(2.0)
                continue
            probe = s.get(f"{BASE}/api/dashboard/live", timeout=TIMEOUT)
            if probe.status_code != 200:
                last_err = f"attempt {attempt + 1}: api probe HTTP {probe.status_code}"
                time.sleep(1.5)
                continue
            data = probe.json() if "json" in probe.headers.get("content-type", "") else {}
            if isinstance(data, dict) and (data.get("_novusRecovery") or data.get("status") == "recovering"):
                last_err = f"attempt {attempt + 1}: api recovery without session"
                time.sleep(1.5)
                continue
            return s
        except Exception as exc:
            last_err = f"attempt {attempt + 1}: {exc}"
            time.sleep(1.5)
    raise RuntimeError(f"Login fallido para {EMAIL} — {last_err}")


def _visible_text(html: str) -> str:
    text = re.sub(r"<script[^>]*>[\s\S]*?</script>", " ", html, flags=re.I)
    text = re.sub(r"<style[^>]*>[\s\S]*?</style>", " ", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text)


def _collect_page_sources(session: requests.Session, html: str) -> str:
    combined = html
    for src in set(re.findall(r'src=["\'](/static/js/[^"\']+)["\']', html, re.I)):
        try:
            jr = session.get(f"{BASE}{src}", timeout=30)
            if jr.status_code == 200:
                combined += "\n" + jr.text
        except Exception:
            pass
    for href in set(re.findall(r'href=["\'](/static/js/[^"\']+)["\']', html, re.I)):
        try:
            jr = session.get(f"{BASE}{href}", timeout=30)
            if jr.status_code == 200:
                combined += "\n" + jr.text
        except Exception:
            pass
    return combined


def _scan_interactive(html: str) -> Dict[str, int]:
    return {
        "buttons": len(re.findall(r"<button\b", html, re.I)),
        "onclick": len(re.findall(r"\bonclick\s*=", html, re.I)),
        "links_internal": len(re.findall(r'href\s*=\s*["\'](/[^"\']+)["\']', html, re.I)),
        "fetch_calls": len(re.findall(r"\bfetch\s*\(", html)),
        "forms": len(re.findall(r"<form\b", html, re.I)),
    }


def _page_issues(html: str, status: int, final_url: str) -> List[str]:
    issues = []
    if status != 200:
        issues.append(f"HTTP {status}")
    if "/login" in final_url.lower():
        issues.append("Redirigido a login (sesión no autenticada)")
    if status == 200 and "/login" not in final_url.lower():
        if "</body>" not in html.lower():
            issues.append("HTML sin cierre </body>")
        if len(html) < 400:
            issues.append("Contenido HTML mínimo (<400 chars)")
        visible = _visible_text(html)
        if FAKE_PATTERNS.search(visible):
            issues.append("Posible dato mock/demo en contenido visible")
        if JSON_UI_LEAK.search(html):
            issues.append("JSON.stringify hacia evidence/threat en template")
        if PYTHON_DICT_LEAK.search(visible):
            issues.append("Posible dict Python visible en HTML")
    return issues


def _api_ok(status: int, data: Any) -> Tuple[bool, List[str]]:
    issues = []
    if status >= 500:
        issues.append(f"HTTP {status} server error")
        return False, issues
    if status == 401:
        issues.append("HTTP 401 no autenticado")
        return False, issues
    if status >= 400:
        issues.append(f"HTTP {status}")
        return False, issues
    if data is None:
        issues.append("Respuesta no JSON")
        return False, issues
    if isinstance(data, dict):
        if data.get("_novusRecovery") or str(data.get("status", "")).lower() == "recovering":
            issues.append("Respuesta recovery (no autenticado o error enmascarado)")
        st = str(data.get("status", "")).lower()
        if st == "error" and "monitoring_not_configured" not in st:
            msg = str(data.get("message") or "")
            if msg and "Sin datos" not in msg:
                issues.append(f"status=error: {msg}")
    body = json.dumps(data, ensure_ascii=False) if isinstance(data, (dict, list)) else str(data)
    if FAKE_PATTERNS.search(body):
        issues.append("Patrón mock/fake en payload API")
    return len(issues) == 0, issues


def run_audit() -> Dict[str, Any]:
    session = _login_session()

    report: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "qa_user": EMAIL,
        "base_url": BASE,
        "modules": [],
        "api_modules": [],
        "apis": [],
        "ui_actions": [],
        "fixes_applied": [],
        "summary": {},
    }

    page_html: Dict[str, str] = {}
    page_sources: Dict[str, str] = {}
    api_results: Dict[str, Dict[str, Any]] = {}

    for label, path in GET_APIS:
        api_timeout = SLOW_API_TIMEOUTS.get(path, TIMEOUT)
        try:
            r = session.get(f"{BASE}{path}", timeout=api_timeout)
            data = r.json() if "json" in r.headers.get("content-type", "") else None
            ok, issues = _api_ok(r.status_code, data)
            entry = {
                "name": label,
                "path": path,
                "http": r.status_code,
                "ok": ok,
                "issues": issues,
                "status": data.get("status") if isinstance(data, dict) else None,
            }
        except Exception as exc:
            entry = {
                "name": label,
                "path": path,
                "http": 0,
                "ok": False,
                "issues": [str(exc)],
            }
        report["apis"].append(entry)
        api_results[path] = entry

    for label, mod_id, path in PAGES:
        try:
            r = session.get(f"{BASE}{path}", timeout=TIMEOUT, allow_redirects=True)
            html = r.text
            page_html[path] = html
            page_sources[path] = _collect_page_sources(session, html)
            interactive = _scan_interactive(html)
            issues = _page_issues(html, r.status_code, r.url)
            actions_total = (
                interactive["buttons"] + interactive["onclick"] + interactive["fetch_calls"]
            )
            entry = {
                "module": label,
                "id": mod_id,
                "path": path,
                "http": r.status_code,
                "final_url": r.url,
                "interactive": interactive,
                "actions_total": actions_total,
                "issues": issues,
                "functional_pct": 100.0 if not issues and r.status_code == 200 else (
                    0.0 if r.status_code >= 400 or "/login" in r.url.lower() else max(0, 100 - len(issues) * 25)
                ),
                "status": "ok" if not issues else "issues",
            }
        except Exception as exc:
            entry = {
                "module": label,
                "id": mod_id,
                "path": path,
                "http": 0,
                "issues": [str(exc)],
                "actions_total": 0,
                "functional_pct": 0.0,
                "status": "error",
            }
        report["modules"].append(entry)

    for label, mod_id, paths in API_MODULES:
        ok_count = 0
        issues_all: List[str] = []
        for p in paths:
            ar = api_results.get(p, {})
            if ar.get("ok"):
                ok_count += 1
            else:
                issues_all.extend(ar.get("issues") or [f"{p} falló"])
        pct = round(100 * ok_count / max(len(paths), 1), 1)
        report["api_modules"].append({
            "module": label,
            "id": mod_id,
            "paths": paths,
            "apis_ok": ok_count,
            "apis_total": len(paths),
            "functional_pct": pct,
            "issues": issues_all,
            "status": "ok" if ok_count == len(paths) else "issues",
        })

    for action, path, pattern in UI_ACTION_PATTERNS:
        sources = page_sources.get(path, page_html.get(path, ""))
        found = bool(re.search(pattern, sources))
        report["ui_actions"].append({
            "action": action,
            "path": path,
            "handler_found": found,
            "ok": found,
        })

    mod_ok = sum(1 for m in report["modules"] if m.get("status") == "ok")
    api_ok = sum(1 for a in report["apis"] if a.get("ok"))
    ui_ok = sum(1 for u in report["ui_actions"] if u.get("ok"))
    api_mod_ok = sum(1 for m in report["api_modules"] if m.get("status") == "ok")
    total_actions = sum(m.get("actions_total", 0) for m in report["modules"])
    mod_pct = round(100 * mod_ok / max(len(PAGES), 1), 1)
    api_pct = round(100 * api_ok / max(len(GET_APIS), 1), 1)
    ui_pct = round(100 * ui_ok / max(len(UI_ACTION_PATTERNS), 1), 1)
    api_mod_pct = round(100 * api_mod_ok / max(len(API_MODULES), 1), 1)
    global_pct = round((mod_pct + api_pct + ui_pct + api_mod_pct) / 4, 1)

    report["summary"] = {
        "pages_total": len(PAGES),
        "pages_ok": mod_ok,
        "pages_pct": mod_pct,
        "apis_total": len(GET_APIS),
        "apis_ok": api_ok,
        "apis_pct": api_pct,
        "api_modules_total": len(API_MODULES),
        "api_modules_ok": api_mod_ok,
        "api_modules_pct": api_mod_pct,
        "ui_handlers_total": len(UI_ACTION_PATTERNS),
        "ui_handlers_ok": ui_ok,
        "ui_handlers_pct": ui_pct,
        "interactive_controls_approx": total_actions,
        "global_functional_pct": global_pct,
        "issues_pages": [m for m in report["modules"] if m.get("issues")],
        "issues_apis": [a for a in report["apis"] if not a.get("ok")],
        "issues_ui": [u for u in report["ui_actions"] if not u.get("ok")],
    }
    return report


def write_markdown(report: Dict[str, Any], path: str) -> None:
    s = report["summary"]
    lines = [
        "# Auditoría funcional total NOVUS",
        "",
        f"**Generado:** {report['generated_at']}",
        f"**Usuario QA:** {report['qa_user']}",
        f"**Base URL:** {report.get('base_url', BASE)}",
        "",
        "## Resumen global",
        "",
        "| Métrica | Valor |",
        "|---------|-------|",
        f"| Páginas OK | {s['pages_ok']}/{s['pages_total']} ({s['pages_pct']}%) |",
        f"| APIs GET OK | {s['apis_ok']}/{s['apis_total']} ({s['apis_pct']}%) |",
        f"| Módulos API-only OK | {s['api_modules_ok']}/{s['api_modules_total']} ({s['api_modules_pct']}%) |",
        f"| Handlers UI OK | {s['ui_handlers_ok']}/{s['ui_handlers_total']} ({s['ui_handlers_pct']}%) |",
        f"| Controles interactivos (aprox.) | {s['interactive_controls_approx']} |",
        f"| **Funcionamiento global** | **{s['global_functional_pct']}%** |",
        "",
        "## Por módulo (páginas)",
        "",
        "| Módulo | Ruta | HTTP | Botones | Issues | % |",
        "|--------|------|------|---------|--------|---|",
    ]
    for m in report["modules"]:
        iss = "; ".join(m.get("issues") or []) or "—"
        btn = m.get("interactive", {}).get("buttons", 0)
        lines.append(
            f"| {m['module']} | `{m['path']}` | {m.get('http')} | {btn} | {iss} | {m.get('functional_pct')}% |"
        )

    lines.extend(["", "## Módulos API (CryptoVault, ASPE, UCE, etc.)", ""])
    lines.append("| Módulo | APIs OK | % | Issues |")
    lines.append("|--------|---------|---|--------|")
    for m in report.get("api_modules", []):
        iss = "; ".join(m.get("issues") or []) or "—"
        lines.append(
            f"| {m['module']} | {m['apis_ok']}/{m['apis_total']} | {m['functional_pct']}% | {iss} |"
        )

    lines.extend(["", "## APIs con fallo", ""])
    fails = s.get("issues_apis") or []
    if not fails:
        lines.append("Ninguna.")
    else:
        for a in fails:
            lines.append(f"- **{a['name']}** `{a['path']}` — {', '.join(a.get('issues') or [])}")

    lines.extend(["", "## Handlers UI no encontrados", ""])
    ui_fails = s.get("issues_ui") or []
    if not ui_fails:
        lines.append("Ninguno.")
    else:
        for u in ui_fails:
            lines.append(f"- **{u['action']}** en `{u['path']}`")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_full_report(report: Dict[str, Any], path: str) -> None:
    s = report["summary"]
    fixes = [
        "services/novus_security_integration.py — descripción de alertas humanizada (no str(dict))",
        "database.py — SQLite busy_timeout 30s para reducir login 500 por lock",
        "scripts/functional_audit_total.py — auditoría HTTP con login retry y detección JS externa",
    ]
    lines = [
        "# Informe auditoría funcional total NOVUS",
        "",
        f"Fecha: {report['generated_at']}",
        "",
        "## Resumen ejecutivo",
        "",
        f"- **Funcionamiento global:** {s['global_functional_pct']}%",
        f"- **Páginas:** {s['pages_ok']}/{s['pages_total']} ({s['pages_pct']}%)",
        f"- **APIs:** {s['apis_ok']}/{s['apis_total']} ({s['apis_pct']}%)",
        f"- **Handlers UI:** {s['ui_handlers_ok']}/{s['ui_handlers_total']} ({s['ui_handlers_pct']}%)",
        f"- **Controles interactivos detectados:** ~{s['interactive_controls_approx']}",
        "",
        "## Tabla por módulo",
        "",
        "| Módulo | Botones/acciones | OK | Errores | Vacíos | % |",
        "|--------|------------------|----|---------|--------|---|",
    ]
    for m in report["modules"]:
        btn = m.get("interactive", {}).get("buttons", 0)
        acts = m.get("actions_total", 0)
        err = len(m.get("issues") or [])
        ok = 1 if m.get("status") == "ok" else 0
        empty = 1 if acts <= 3 and m.get("status") != "ok" else 0
        lines.append(
            f"| {m['module']} | {acts} ({btn} btn) | {ok} | {err} | {empty} | {m.get('functional_pct')}% |"
        )
    for m in report.get("api_modules", []):
        lines.append(
            f"| {m['module']} | API×{m['apis_total']} | {1 if m['status']=='ok' else 0} | "
            f"{len(m.get('issues') or [])} | 0 | {m['functional_pct']}% |"
        )

    lines.extend([
        "",
        "## Correcciones aplicadas en esta sesión",
        "",
    ])
    for fix in fixes:
        lines.append(f"- {fix}")

    lines.extend([
        "",
        "## Problemas detectados pendientes",
        "",
    ])
    pending = []
    for m in s.get("issues_pages") or []:
        pending.append(f"- **{m['module']}**: {', '.join(m.get('issues') or [])}")
    for a in s.get("issues_apis") or []:
        pending.append(f"- **API {a['name']}**: {', '.join(a.get('issues') or [])}")
    for u in s.get("issues_ui") or []:
        pending.append(f"- **UI {u['action']}**: handler no encontrado en {u['path']}")
    lines.extend(pending or ["Ninguno."])

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    report = run_audit()
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "functional_audit")
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "report.json")
    md_path = os.path.join(out_dir, "report.md")
    full_path = os.path.join(out_dir, "audit_report_full.md")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    write_markdown(report, md_path)
    write_full_report(report, full_path)
    s = report["summary"]
    print(json.dumps(s, indent=2, ensure_ascii=False))
    print(f"\nReports: {md_path}, {full_path}")
    return 0 if s["global_functional_pct"] >= 85 else 1


if __name__ == "__main__":
    raise SystemExit(main())
