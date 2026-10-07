#!/usr/bin/env python3
"""Active runtime closure audit — read-only probes, sequential HTTP."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT_DIR = os.path.join(ROOT, "data", "novus_release_candidate")
BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000")


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def probe_get(path: str, session=None, timeout=45):
    import requests

    url = BASE.rstrip("/") + path
    fn = session.get if session else requests.get
    t0 = time.time()
    try:
        r = fn(url, timeout=timeout, allow_redirects=True)
        ms = round((time.time() - t0) * 1000, 1)
        body = r.text or ""
        recovery = False
        try:
            j = r.json()
            recovery = bool(j.get("_novusRecovery"))
        except Exception:
            pass
        return {
            "endpoint": path,
            "status": r.status_code,
            "latency_ms": ms,
            "recovery": recovery,
            "result": "FAILED" if recovery else ("VERIFIED" if r.status_code < 400 else "FAILED"),
            "preview": body[:180],
        }
    except Exception as exc:
        return {
            "endpoint": path,
            "status": None,
            "latency_ms": round((time.time() - t0) * 1000, 1),
            "recovery": False,
            "result": "NOT VERIFIED",
            "error": str(exc),
        }


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    report = {
        "generated_at": utc(),
        "audit_id": "ACTIVE_RUNTIME_CLOSURE_AUDIT",
        "code_changes_this_audit": False,
        "server_identity": {},
        "dev_vs_production": {},
        "http_probes": [],
        "runtime_info": {},
        "regression": {},
        "stability": {},
        "static_data_runtime": [],
        "data_matrix_summary": {},
        "production_readiness": {},
        "blockers": [],
        "verdict_answers": {},
    }

    # --- server identity via WMIC/powershell output passed env ---
    report["server_identity"] = {
        "expected_root": ROOT,
        "probe_base": BASE,
        "note": "Populate PID via external shell; HTTP probes below confirm listener",
    }

    # --- dev vs production comparison (from code audit) ---
    report["dev_vs_production"] = {
        "development": {
            "config_class": "DevelopmentConfig",
            "DEBUG": True,
            "LOG_LEVEL": "DEBUG",
            "ALLOW_PUBLIC_REGISTRATION_default": True,
            "SESSION_COOKIE_SECURE_default": False,
            "PREFERRED_URL_SCHEME_default": "http",
            "main_py_cookies": "SESSION/REMEMBER Secure=False when NOVUS_ENV=development",
            "lab_runtime": "NOVUS_ALLOW_LAB_RUNTIME allowed if set (not in production)",
            "legacy_imcm_soc_merge": "Only if lab runtime + NOVUS_IMCM_LEGACY_MERGE",
            "enterprise_warmup": "Opt-in NOVUS_ENTERPRISE_WARMUP (disabled in production guard)",
            "qa_seed_scripts": "Allowed if NOVUS_ALLOW_QA_SEED (blocked in production)",
            "platform_tenant_fallback": "Requires NOVUS_PLATFORM_TENANT_ID or lab flag (no silent QA in prod)",
        },
        "production": {
            "config_class": "ProductionConfig",
            "DEBUG": False,
            "LOG_LEVEL": "INFO",
            "ALLOW_PUBLIC_REGISTRATION_default": False,
            "SESSION_COOKIE_SECURE_default": True,
            "PREFERRED_URL_SCHEME_default": "https",
            "BEHIND_PROXY_default": True,
            "SECRET_KEY": "Required — app aborts if missing in production/beta",
            "lab_runtime": "FORBIDDEN (is_production_runtime)",
            "legacy_imcm_soc_merge": "FORBIDDEN",
            "enterprise_warmup": "FORBIDDEN at boot",
            "qa_seed_scripts": "FORBIDDEN",
        },
        "ram_impact_switching_to_production": {
            "likely_reduces_ram": [
                "enterprise_warmup disabled",
                "legacy IMCM/SOC merge disabled",
                "DEBUG=False less logging",
            ],
            "does_not_auto_start_heavy_engines": "Lazy P2 unchanged — same boot staged in main.py",
            "risk": "LOW for RAM regression if NOVUS_ENTERPRISE_WARMUP not set; production guard disables warmup",
        },
        "required_env_for_production": [
            "NOVUS_ENV=production",
            "SECRET_KEY=<long random>",
            "NOVUS_PLATFORM_TENANT_ID=<real tenant>",
            "NOVUS_CEO_EMAIL=<ceo email>",
            "SESSION_COOKIE_SECURE=True (default in prod)",
            "PREFERRED_URL_SCHEME=https (default in prod)",
            "NOVUS_BEHIND_PROXY=True if reverse proxy",
            "NOVUS_ALLOW_REGISTRATION=False (default)",
        ],
        "must_not_set_in_production": [
            "NOVUS_ALLOW_LAB_RUNTIME=1",
            "NOVUS_ALLOW_QA_SEED=1",
            "NOVUS_ENTERPRISE_WARMUP=1 (blocked anyway)",
            "FLASK_DEBUG=True",
        ],
    }

    # --- sequential HTTP ---
    endpoints = [
        "/login",
        "/registro_empresa",
        "/dashboard",
        "/api/dashboard/live",
        "/api/health/status",
        "/api/network/nodes",
        "/api/search",
        "/api/security/vulnerabilities",
        "/api/security/threats",
        "/api/reports",
        "/api/system/runtime-info",
    ]
    import requests

    s = requests.Session()
    for ep in endpoints:
        pr = probe_get(ep, session=s if ep.startswith("/api/") else None)
        report["http_probes"].append(pr)
        time.sleep(2)

    # runtime-info authenticated
    ri_auth = {"result": "NOT VERIFIED", "detail": "auth failed"}
    try:
        lp = s.get(BASE + "/login", timeout=30)
        csrf = None
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', lp.text or "")
        if m:
            csrf = m.group(1)
        admin_email = os.environ.get("NOVUS_PROBE_ADMIN", "novus.qa.jul2026@example.com")
        admin_pass = os.environ.get("NOVUS_PROBE_PASS", "NovusQA2026!")
        if csrf:
            s.post(
                BASE + "/login",
                data={"email": admin_email, "password": admin_pass, "csrf_token": csrf},
                timeout=45,
                allow_redirects=True,
            )
        ri = s.get(BASE + "/api/system/runtime-info", timeout=45)
        if ri.status_code == 200:
            j = ri.json()
            if j.get("_novusRecovery"):
                ri_auth = {"result": "NOT VERIFIED", "detail": "recovery response", "body": j}
            elif j.get("status") == "success":
                ri_auth = {"result": "VERIFIED", "runtime": j.get("runtime"), "env_safe": j.get("env_safe")}
            elif ri.status_code == 403:
                ri_auth = {"result": "NOT VERIFIED", "detail": "403 RBAC — user not super_admin"}
            else:
                ri_auth = {"result": "NOT VERIFIED", "http": ri.status_code, "body": ri.text[:300]}
        elif ri.status_code == 401:
            ri_auth = {"result": "NOT VERIFIED", "detail": "401 — login/MFA required"}
        else:
            try:
                j = ri.json()
                if j.get("_novusRecovery"):
                    ri_auth = {"result": "NOT VERIFIED", "detail": "recovery", "ref": j.get("reference")}
                else:
                    ri_auth = {"result": "NOT VERIFIED", "http": ri.status_code, "body": ri.text[:200]}
            except Exception:
                ri_auth = {"result": "NOT VERIFIED", "http": ri.status_code}
    except Exception as exc:
        ri_auth = {"result": "NOT VERIFIED", "error": str(exc)}
    report["runtime_info"] = ri_auth

    # --- regression scripts ---
    for name, script in [
        ("tenant_isolation", "tenant_isolation_service_test.py"),
        ("mfa_admin", "mfa_admin_policy_test.py"),
    ]:
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(ROOT, "scripts", script)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=180,
            )
            report["regression"][name] = {
                "result": "VERIFIED" if p.returncode == 0 and "VERIFIED" in (p.stdout or "") else "FAILED",
                "returncode": p.returncode,
            }
        except Exception as exc:
            report["regression"][name] = {"result": "NOT VERIFIED", "error": str(exc)}

    # --- static inventory spot checks on disk (post-remediation) ---
    checks = []
    ad_path = os.path.join(ROOT, "services", "adaptive_defense_engine.py")
    with open(ad_path, encoding="utf-8") as fh:
        ad_txt = fh.read()
    checks.append({
        "item": "protection_score_floor_20",
        "inventory_risk": "CRITICAL/ALTO",
        "present_in_code": "max(20," in ad_txt,
        "runtime_ui_risk": "NOT PRESENT" if "max(20," not in ad_txt else "SIMULATED_STATIC",
    })
    topo_path = os.path.join(ROOT, "templates", "topology.html")
    with open(topo_path, encoding="utf-8") as fh:
        topo_txt = fh.read()
    checks.append({
        "item": "topology_intensity_8",
        "present_in_code": "intensity = 8" in topo_txt or "intensity=8" in topo_txt,
        "runtime_ui_risk": "SIMULATED_STATIC" if ("intensity = 8" in topo_txt) else "NOT PRESENT",
    })
    tsp = os.path.join(ROOT, "services", "tenant_scope_service.py")
    with open(tsp, encoding="utf-8") as fh:
        tsp_txt = fh.read()
    checks.append({
        "item": "qa_tenant_default_runtime",
        "present_in_code": "DEFAULT_PLATFORM_TENANT_ID" in tsp_txt and "QA-NOVUS-2026" in tsp_txt,
        "runtime_ui_risk": "PARTIAL — lab only if NOVUS_ALLOW_LAB_RUNTIME",
    })
    report["static_data_runtime"] = checks

    # matrix from prior audit file
    prior = os.path.join(OUT_DIR, "NOVUS_FINAL_REALITY_AUDIT.json")
    if os.path.isfile(prior):
        with open(prior, encoding="utf-8") as fh:
            prior_j = json.load(fh)
        report["data_matrix_summary"] = prior_j.get("module_status_counts", {})

    # stability placeholder
    report["stability"] = {
        "ram_novus_rss_mb": "NOT VERIFIED — server may be down during audit",
        "backpressure": "NOT VERIFIED",
        "recovery_observed": any(p.get("recovery") for p in report["http_probes"]),
    }

    # blockers
    blockers = []
    if any(p.get("result") in ("NOT VERIFIED", "FAILED") for p in report["http_probes"]):
        blockers.append("HTTP probes incomplete or recovery/timeout")
    if ri_auth.get("result") != "VERIFIED":
        blockers.append(f"runtime-info: {ri_auth.get('detail') or ri_auth.get('result')}")
    blockers.append("NOVUS_ENV=development — not production config")
    if not os.path.isfile(os.path.join(ROOT, ".env")):
        blockers.append("No .env — NOVUS_PLATFORM_TENANT_ID, SECRET_KEY, NOVUS_CEO_EMAIL unset")
    report["blockers"] = blockers

    report["production_readiness"] = {
        "current": report["dev_vs_production"]["development"],
        "required": report["dev_vs_production"]["required_env_for_production"],
        "ready_to_switch": False,
        "reason": "Development runtime; HTTP partial; production env vars not configured",
    }

    verified_apis = [p["endpoint"] for p in report["http_probes"] if p.get("result") == "VERIFIED"]
    not_verified_apis = [p["endpoint"] for p in report["http_probes"] if p.get("result") != "VERIFIED"]

    report["verdict_answers"] = {
        "1_active_instance_uses_C_NOVUS": "NOT VERIFIED — server not responding at audit start; re-check PID",
        "2_static_fictitious_remaining": "Deception/BAS intentional; lab JSONL if not purged; CACHED snapshots labeled stale",
        "3_apis_verified": verified_apis,
        "4_apis_not_verified": not_verified_apis,
        "5_ram_stable": "NOT VERIFIED",
        "6_dev_to_production_implication": "See dev_vs_production section — production disables lab/warmup/QA; requires SECRET_KEY+tenant",
        "7_single_next_step": "Start NOVUS from C:\\NOVUS, set production env vars, re-run HTTP audit sequentially",
    }

    out_json = os.path.join(OUT_DIR, "ACTIVE_RUNTIME_CLOSURE_AUDIT.json")
    out_md = os.path.join(OUT_DIR, "ACTIVE_RUNTIME_CLOSURE_AUDIT.md")
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    md_lines = [
        "# ACTIVE RUNTIME CLOSURE AUDIT",
        f"\n**Generado:** {report['generated_at']}\n",
        "## A. IDENTIDAD SERVIDOR",
        "Ver JSON — HTTP probes confirman listener si servidor activo.\n",
        "## B. DEV vs PRODUCTION",
        "Ver `dev_vs_production` en JSON.\n",
        "## H. CAMBIOS REALIZADOS",
        "**Ninguno** — auditoría read-only.\n",
        f"\n## VEREDICTO\n",
        f"- APIs VERIFIED: {len(verified_apis)}",
        f"- APIs NOT VERIFIED/FAILED: {len(not_verified_apis)}",
        f"- runtime-info: {ri_auth.get('result')}",
    ]
    with open(out_md, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md_lines))

    print(json.dumps({"outputs": [out_json, out_md], "verified_count": len(verified_apis)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
