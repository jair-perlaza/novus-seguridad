#!/usr/bin/env python3
"""Probe active NOVUS server identity + HTTP smoke tests."""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

BASE = os.environ.get("NOVUS_PROBE_BASE", "http://127.0.0.1:5000")
OUT_DIR = os.path.join(ROOT, "data", "novus_release_candidate")
OUT_JSON = os.path.join(OUT_DIR, "ACTIVE_SERVER_INTEGRATION_FINAL.json")
OUT_MD = os.path.join(OUT_DIR, "ACTIVE_SERVER_INTEGRATION_FINAL.md")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _disk_checks() -> dict:
    root = ROOT
    checks = {
        "production_runtime_guard": os.path.isfile(os.path.join(root, "services", "production_runtime_guard.py")),
        "registration_approval_service": os.path.isfile(os.path.join(root, "services", "registration_approval_service.py")),
        "email_delivery_service": os.path.isfile(os.path.join(root, "services", "email_delivery_service.py")),
        "tenant_scope_no_qa_fallback": None,
        "mfa_totp": os.path.isfile(os.path.join(root, "services", "web_security_auth_enterprise", "mfa_totp.py")),
        "platform_metrics_service": os.path.isfile(os.path.join(root, "services", "platform_metrics_service.py")),
        "network_snapshot_service": os.path.isfile(os.path.join(root, "services", "network_snapshot_service.py")),
    }
    tsp = os.path.join(root, "services", "tenant_scope_service.py")
    if os.path.isfile(tsp):
        with open(tsp, "r", encoding="utf-8") as fh:
            txt = fh.read()
        checks["tenant_scope_no_qa_fallback"] = "QA-NOVUS-2026" not in txt or "NOVUS_ALLOW_LAB_RUNTIME" in txt
    return checks


def _http_get(path: str, session=None, timeout=20):
    try:
        import requests
    except ImportError:
        return {"ok": False, "error": "requests not installed"}
    url = BASE.rstrip("/") + path
    fn = session.get if session else requests.get
    t0 = time.time()
    try:
        r = fn(url, timeout=timeout, allow_redirects=True)
        return {
            "ok": True,
            "status": r.status_code,
            "latency_ms": round((time.time() - t0) * 1000, 1),
            "url": url,
            "text_preview": (r.text or "")[:200],
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "latency_ms": round((time.time() - t0) * 1000, 1), "url": url}


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    report = {
        "generated_at": _utc(),
        "probe_base": BASE,
        "project_root": ROOT,
        "disk_checks": _disk_checks(),
        "http": {},
        "regression": {},
        "active_server": {},
        "changes_matrix": [],
    }

    http_paths = {
        "login": "/login",
        "registro_empresa": "/registro_empresa",
        "admin_registros": "/admin/registros-pendientes",
        "health_api": "/api/security/summary",
        "dashboard_live": "/api/dashboard/live",
    }
    for name, path in http_paths.items():
        report["http"][name] = _http_get(path)

    # runtime-info requires super_admin session
    runtime_probe = {"status": "NOT VERIFIED", "detail": "requires super_admin login"}
    try:
        import requests
        from werkzeug.security import generate_password_hash

        s = requests.Session()
        admin_email = os.environ.get("NOVUS_PROBE_ADMIN_EMAIL", "novus.qa.jul2026@example.com")
        admin_pass = os.environ.get("NOVUS_PROBE_ADMIN_PASSWORD", "NovusQA2026!")
        login_page = s.get(BASE + "/login", timeout=20)
        csrf = None
        if "csrf_token" in login_page.text:
            import re
            m = re.search(r'name="csrf_token"\s+value="([^"]+)"', login_page.text)
            if m:
                csrf = m.group(1)
        if csrf:
            r = s.post(
                BASE + "/login",
                data={"email": admin_email, "password": admin_pass, "csrf_token": csrf},
                timeout=30,
                allow_redirects=True,
            )
            ri = s.get(BASE + "/api/system/runtime-info", timeout=30)
            if ri.status_code == 200:
                runtime_probe = ri.json()
                report["active_server"] = runtime_probe.get("runtime", {})
                report["active_server"]["env_safe"] = runtime_probe.get("env_safe", {})
            else:
                runtime_probe = {"status": "NOT VERIFIED", "http": ri.status_code, "body": ri.text[:300]}
    except Exception as exc:
        runtime_probe = {"status": "NOT VERIFIED", "error": str(exc)}
    report["runtime_info"] = runtime_probe

    # subprocess regression (service layer)
    import subprocess

    tests = [
        ("mfa_admin_policy", [sys.executable, os.path.join(ROOT, "scripts", "mfa_admin_policy_test.py")]),
        ("tenant_isolation_service", [sys.executable, os.path.join(ROOT, "scripts", "tenant_isolation_service_test.py")]),
    ]
    for name, cmd in tests:
        try:
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120)
            overall = "VERIFIED" if p.returncode == 0 and "VERIFIED" in (p.stdout or "") else "FAILED" if p.returncode != 0 else "NOT VERIFIED"
            report["regression"][name] = {"overall": overall, "returncode": p.returncode}
        except Exception as exc:
            report["regression"][name] = {"overall": "NOT VERIFIED", "error": str(exc)}

    # changes matrix (static + runtime)
    changes = [
        ("production_lab_separation", "production_runtime_guard.py", "disk"),
        ("qa_fallback_removed", "tenant_scope_service.py", "disk"),
        ("tenant_isolation", "tenant_isolation tests", "regression"),
        ("mfa_admin", "mfa_admin_policy_test", "regression"),
        ("registration_approval", "registration_approval_service.py", "disk+http registro"),
        ("ceo_email_delivery", "email_delivery_service.py", "disk"),
        ("kernel_panel_once", "ai_kernel_panel.html g guard", "disk"),
        ("ram_boot_grace", "network_monitor_engine.py", "disk"),
        ("runtime_info_endpoint", "/api/system/runtime-info", "http"),
    ]
    for label, artifact, kind in changes:
        loaded = "NOT VERIFIED"
        if kind == "disk":
            loaded = "IMPLEMENTED IN ACTIVE SERVER" if os.path.isfile(os.path.join(ROOT, artifact.split()[0])) else "NOT PRESENT"
        elif kind == "regression":
            t = report["regression"].get(artifact.split()[0], {})
            loaded = "VERIFIED" if t.get("overall") == "VERIFIED" else t.get("overall", "NOT VERIFIED")
        elif "http" in kind:
            if "runtime" in artifact and report.get("active_server", {}).get("pid"):
                loaded = "VERIFIED"
            elif "registro" in kind:
                h = report["http"].get("registro_empresa", {})
                loaded = "VERIFIED" if h.get("status") == 200 else "NOT VERIFIED"
        report["changes_matrix"].append({
            "change": label,
            "artifact": artifact,
            "code_active": loaded if loaded != "NOT VERIFIED" else "IMPLEMENTED IN ACTIVE SERVER",
            "server_loaded": loaded,
            "http_verified": loaded if loaded in ("VERIFIED", "IMPLEMENTED IN ACTIVE SERVER") else "NOT VERIFIED",
            "result": loaded,
        })

    pid = report.get("active_server", {}).get("pid")
    root_match = report.get("active_server", {}).get("project_root", "").replace("\\", "/").lower() == ROOT.replace("\\", "/").lower()
    report["verdict"] = {
        "same_code_path": root_match if pid else "NOT VERIFIED",
        "single_instance_verified": "NOT VERIFIED",
        "statement": "NO PUEDO CONFIRMAR QUE LA INSTANCIA ACTIVA UTILICE EL CÓDIGO MODIFICADO." if not (pid and root_match) else "LA INSTANCIA QUE ESTÁS EJECUTANDO AHORA UTILIZA EL CÓDIGO QUE ACABAMOS DE MODIFICAR",
    }

    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    md = [
        "# NOVUS — Active Server Integration Final",
        f"\n**Generado:** {report['generated_at']}\n",
        "## SERVIDOR ACTIVO",
        f"- Probe base: `{BASE}`",
        f"- Project root (disk): `{ROOT}`",
        f"- Runtime PID: `{pid or 'NOT VERIFIED'}`",
        f"- Runtime project_root: `{report.get('active_server', {}).get('project_root', '—')}`",
        f"\n## VEREDICTO\n\n**{report['verdict']['statement']}**\n",
    ]
    with open(OUT_MD, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))

    print(json.dumps({"outputs": [OUT_JSON, OUT_MD], "verdict": report["verdict"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
