#!/usr/bin/env python3
"""
Auditoría completa de botones y acciones de la interfaz NOVUS.
Genera data/ui_button_audit_report.json con evidencia por botón/acción.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = "http://127.0.0.1:5000"
EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"

MODULE_PAGES = {
    "dashboard": "/dashboard",
    "inteligencia": "/inteligencia",
    "casos_estudio": "/casos-estudio",
    "network": "/network",
    "topology": "/topology",
    "vulnerabilidades": "/vulnerabilidades",
    "xdr": "/xdr",
    "incidentes": "/incidentes",
    "endpoints": "/endpoints",
    "playbooks": "/automatizacion",
    "reportes": "/reportes",
    "configuracion": "/configuracion",
    "siem": "/siem",
}

KERNEL_HANDLERS = [
    ("sidebar_consultKernelIA", r'onclick\s*=\s*["\']consultKernelIA\(\)["\']'),
    ("inline_consultModule", r"consultModule\s*\("),
    ("global_consultKernelIA_fn", r"window\.consultKernelIA\s*="),
    ("NovusAIKernel_object", r"const\s+NovusAIKernel\s*="),
    ("ai_kernel_panel_dom", r'id=["\']novus-ai-panel["\']'),
    ("novus_sidebar_rendered", r"Consultar Kernel IA"),
    ("data_novus_module", r'data-novus-module=["\']([^"\']+)["\']'),
]

ACTION_PATTERNS = [
    ("investigate_network", ("/network", r"investigarDispositivo\s*\(")),
    ("investigate_topology", ("/topology", r"investigateDevice\s*\(|consultKernel\s*\(")),
    ("refresh_topology", ("/topology", r"refreshTopology\s*\(")),
    ("xdr_trace", ("/xdr", r"verTrazaDesdeFila\s*\(")),
    ("playbook_modal", ("/automatizacion", r"openPlaybookModal\s*\(")),
    ("report_generator", ("/reportes", r"abrirGenerador\s*\(")),
    ("integral_audit_quick", ("/configuracion", r"runIntegralAudit\s*\(\s*['\"]quick['\"]")),
    ("integral_audit_deep", ("/configuracion", r"runIntegralAudit\s*\(\s*['\"]deep['\"]")),
]


def login_session():
    import requests

    s = requests.Session()
    r = s.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD},
        allow_redirects=True,
        timeout=30,
    )
    if "login" in r.url.lower():
        raise RuntimeError("Login failed")
    return s


def count_onclick_buttons(html: str) -> int:
    return len(re.findall(r"<button\b", html, re.I))


def audit_page(session, module: str, path: str) -> dict:
    html = session.get(f"{BASE}{path}", timeout=90).text
    entry = {
        "module": module,
        "path": path,
        "button_count": count_onclick_buttons(html),
        "kernel_checks": {},
        "issues": [],
        "fixes_needed": [],
    }
    for name, pattern in KERNEL_HANDLERS:
        m = re.search(pattern, html)
        entry["kernel_checks"][name] = bool(m)
        if name == "data_novus_module" and m:
            entry["detected_module"] = m.group(1)

    if not entry["kernel_checks"].get("ai_kernel_panel_dom"):
        entry["issues"].append({
            "severity": "critical",
            "file": f"templates (page {path})",
            "function": "include ai_kernel_panel.html",
            "reason": "Panel Kernel IA no incluido — NovusAIKernel/consultKernelIA no existen en DOM",
        })
        entry["fixes_needed"].append("include partials/ai_kernel_panel.html")

    if not entry["kernel_checks"].get("global_consultKernelIA_fn"):
        entry["issues"].append({
            "severity": "critical",
            "file": "templates/partials/ai_kernel_panel.html",
            "function": "window.consultKernelIA",
            "line": "~1061",
            "reason": "Función global consultKernelIA no presente en HTML servido",
        })

    has_sidebar_btn = entry["kernel_checks"].get("sidebar_consultKernelIA")
    has_kernel_label = html.count("Consultar Kernel IA") >= 1
    if not has_sidebar_btn and not has_kernel_label:
        entry["issues"].append({
            "severity": "high",
            "file": f"templates (page {path})",
            "function": "Consultar Kernel IA button",
            "reason": "Sin botón Consultar Kernel IA visible en la página",
        })
        entry["fixes_needed"].append("include novus_nav_sidebar or inline consultKernelIA button")

    if has_sidebar_btn and not has_kernel_label:
        entry["issues"].append({
            "severity": "medium",
            "file": "templates/partials/kernel_consult_btn.html",
            "reason": "Handler consultKernelIA en HTML pero texto del botón no renderizado",
        })

    if not entry.get("detected_module"):
        entry["issues"].append({
            "severity": "medium",
            "file": f"templates (page {path})",
            "function": "detectModule()",
            "line": "ai_kernel_panel.html:896-901",
            "reason": "Falta data-novus-module en <body> — detección de módulo por URL puede fallar",
        })

    return entry, html


def test_module_consult_api():
    from main import app

    client = app.test_client()
    client.post("/login", data={"email": EMAIL, "password": PASSWORD}, follow_redirects=True)
    results = []
    for mod in MODULE_PAGES:
        r = client.post(
            "/api/ai/module-consult",
            json={"module": mod.replace("-", "_").replace("casos_estudio", "casos_estudio"), "extra": {}, "execute": True},
            content_type="application/json",
        )
        d = r.get_json() or {}
        api_mod = mod if mod != "playbooks" else "playbooks"
        if mod == "casos_estudio":
            api_mod = "casos_estudio"
        r2 = client.post(
            "/api/ai/module-consult",
            json={"module": api_mod, "extra": {}, "execute": True},
            content_type="application/json",
        )
        d2 = r2.get_json() or {}
        ok = r2.status_code == 200 and d2.get("status") == "success"
        results.append({
            "module": api_mod,
            "http": r2.status_code,
            "status": d2.get("status"),
            "has_reply": bool(d2.get("reply") or d2.get("prompt")),
            "pass": ok,
        })
    return results


def main():
    import requests

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pages": [],
        "actions": [],
        "api_module_consult": [],
        "root_causes": [],
        "summary": {},
    }

    try:
        session = login_session()
    except Exception as exc:
        print(f"[FAIL] Login: {exc}")
        return 1

    page_html = {}
    for module, path in MODULE_PAGES.items():
        entry, html = audit_page(session, module, path)
        page_html[path] = html
        report["pages"].append(entry)
        n_issues = len(entry["issues"])
        print(f"[{'OK' if n_issues == 0 else 'ISSUES'}] {path}: buttons={entry['button_count']} issues={n_issues}")

    for action_name, (path, pattern) in ACTION_PATTERNS:
        html = page_html.get(path, "")
        found = bool(re.search(pattern, html))
        report["actions"].append({
            "action": action_name,
            "path": path,
            "handler_found": found,
            "pass": found,
        })
        print(f"[{'PASS' if found else 'FAIL'}] action {action_name} @ {path}")

    report["api_module_consult"] = test_module_consult_api()
    api_fail = [x for x in report["api_module_consult"] if not x["pass"]]

    panel_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates", "partials", "ai_kernel_panel.html")
    with open(panel_path, encoding="utf-8") as f:
        panel_src = f.read()
    report["panel_open_fix"] = {
        "panelOpen_present": "panelOpen" in panel_src,
        "open_collision_removed": "open: false" not in panel_src,
        "pass": "panelOpen" in panel_src and "if (!this.panelOpen)" in panel_src,
    }
    if not report["panel_open_fix"]["pass"]:
        report.setdefault("global_issues", []).append({
            "severity": "critical",
            "file": "templates/partials/ai_kernel_panel.html",
            "function": "openPanel",
            "reason": "Colisión open/open() no corregida",
        })

    print(f"\nPanel open fix: {'PASS' if report['panel_open_fix']['pass'] else 'FAIL'}")
    print(f"\nAPI module-consult: {len(report['api_module_consult']) - len(api_fail)}/{len(report['api_module_consult'])} OK")

    # Document known root causes from code analysis
    report["root_causes"] = [
        {
            "id": "RC1",
            "title": "Botón sidebar ausente en módulos sin novus_nav_sidebar",
            "fix": "Añadido novus_nav_sidebar a endpoints, incidentes, reportes, configuracion, playbooks; botón header en network/topology",
            "status": "fixed",
        },
        {
            "id": "RC2",
            "title": "Colisión propiedad/método NovusAIKernel.open",
            "file": "templates/partials/ai_kernel_panel.html",
            "lines": "391, 873-875, 880-881",
            "evidence": "open() método reemplazaba open:false; openPanel() evaluaba !this.open como false (función truthy) → nunca añadía clase .open al panel",
            "symptom": "Primer clic en Consultar Kernel IA: fetch ejecutaba pero panel permanecía en translateY(110%) invisible",
            "fix": "Renombrado estado a panelOpen; método open() conservado",
            "status": "fixed",
        },
        {
            "id": "RC3",
            "title": "incidentes sin data-novus-module",
            "file": "templates/incidentes.html",
            "fix": "Añadido data-novus-module=incidentes y botón Kernel IA por fila",
            "status": "fixed",
        },
        {
            "id": "RC4",
            "title": "casos_estudio sin global_search/NovusAction",
            "file": "templates/casos_estudio.html",
            "fix": "Incluido partials/global_search.html",
            "status": "fixed",
        },
    ]

    total_buttons = sum(p["button_count"] for p in report["pages"])
    total_issues = sum(len(p["issues"]) for p in report["pages"])
    actions_ok = sum(1 for a in report["actions"] if a["pass"])
    pages_with_kernel_btn = sum(
        1 for p in report["pages"]
        if p["kernel_checks"].get("sidebar_consultKernelIA") or p["kernel_checks"].get("inline_consultModule")
    )

    report["summary"] = {
        "pages_audited": len(report["pages"]),
        "total_buttons_approx": total_buttons,
        "actions_audited": len(report["actions"]),
        "actions_ok": actions_ok,
        "pages_with_consult_button": pages_with_kernel_btn,
        "total_ui_issues": total_issues,
        "api_consult_pass": len(report["api_module_consult"]) - len(api_fail),
    }

    out = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ui_button_audit_report.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nReport: {out}")
    print(f"Summary: {json.dumps(report['summary'], indent=2)}")
    return 0 if total_issues == 0 and not api_fail and actions_ok == len(report["actions"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
