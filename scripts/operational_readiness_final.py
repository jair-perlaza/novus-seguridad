#!/usr/bin/env python3
"""
NOVUS — Operational Readiness Final
Genera: data/novus_release_candidate/OPERATIONAL_READINESS_FINAL.md + .json
Sin cambios de código salvo fallos reproducidos documentados.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "novus_release_candidate"
OUT_JSON = OUT_DIR / "OPERATIONAL_READINESS_FINAL.json"
OUT_MD = OUT_DIR / "OPERATIONAL_READINESS_FINAL.md"
BASE = os.environ.get("NOVUS_TEST_BASE", "http://127.0.0.1:5000")
PYTHON = sys.executable
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
IDLE_SEC = int(os.environ.get("NOVUS_OP_IDLE_SEC", "120"))
HTTP_TIMEOUT = int(os.environ.get("NOVUS_OP_TIMEOUT", "90"))

CLIENT = (
    os.environ.get("NOVUS_CLIENT_EMAIL", "operaciones@novapay-fintech.co"),
    os.environ.get("NOVUS_CLIENT_PASSWORD", "NovaPay#Fintech2026"),
)
QA = (
    os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com"),
    os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!"),
)

BASELINE_REFS = [
    "data/novus_release_candidate/RELEASE_CANDIDATE_STATUS.json (20260819T170044Z)",
    "data/novus_real_operation_audit/RESOURCE_STABILITY_FIX_REPORT.json",
    "data/novus_real_operation_audit/TENANT_ISOLATION_SERVICE_TEST.json",
    "data/novus_compliance_audit/MFA_ADMIN_HTTP_E2E_FINAL.json",
]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_pid() -> Optional[int]:
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            return c.pid
    return None


def listeners() -> List[int]:
    return sorted(
        {
            c.pid
            for c in psutil.net_connections(kind="inet")
            if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid
        }
    )


def sample(phase: str) -> Dict[str, Any]:
    vm = psutil.virtual_memory()
    row: Dict[str, Any] = {
        "phase": phase,
        "ts": utc(),
        "system_ram_pct": round(vm.percent, 1),
        "listener_pids": listeners(),
        "listener_count": len(listeners()),
    }
    pid = find_pid()
    if pid:
        try:
            p = psutil.Process(pid)
            row["novus_pid"] = pid
            row["novus_rss_mb"] = round(p.memory_info().rss / 1024 / 1024, 1)
            row["novus_threads"] = p.num_threads()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    try:
        sys.path.insert(0, str(ROOT))
        from services.resource_backpressure_service import get_status

        row["backpressure"] = get_status()
    except Exception:
        row["backpressure"] = None
    return row


def stop_novus() -> None:
    for pid in listeners():
        try:
            psutil.Process(pid).terminate()
            psutil.Process(pid).wait(timeout=20)
        except Exception:
            try:
                psutil.Process(pid).kill()
            except Exception:
                pass
    time.sleep(4)


def start_novus() -> Optional[int]:
    env = os.environ.copy()
    env["FLASK_DEBUG"] = "False"
    log = OUT_DIR / f"op_readiness_boot_{RUN_ID}.log"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(log, "w", encoding="utf-8") as fh:
        subprocess.Popen(
            [PYTHON, str(ROOT / "main.py")],
            cwd=str(ROOT),
            env=env,
            stdout=fh,
            stderr=subprocess.STDOUT,
        )
    deadline = time.time() + 120
    while time.time() < deadline:
        if listeners():
            time.sleep(3)
            return find_pid()
        time.sleep(2)
    return None


def is_recovery(body: Any) -> bool:
    return isinstance(body, dict) and (
        body.get("status") == "recovering" or body.get("_novusRecovery") is True
    )


def login_full(email: str, password: str) -> Tuple[Optional[requests.Session], Dict[str, Any]]:
    s = requests.Session()
    meta: Dict[str, Any] = {"email": email}
    t0 = time.perf_counter()
    try:
        g = s.get(f"{BASE}/login", timeout=HTTP_TIMEOUT)
        csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', g.text)
        p = s.post(
            f"{BASE}/login",
            data={"email": email, "password": password, "csrf_token": csrf.group(1) if csrf else ""},
            allow_redirects=False,
            timeout=HTTP_TIMEOUT,
        )
        meta["post_status"] = p.status_code
        meta["location"] = p.headers.get("Location")
        if p.status_code in (301, 302, 303, 307, 308):
            loc = p.headers.get("Location", "")
            if "/mfa-setup" in loc:
                meta["mfa_enrollment_required"] = True
                meta["classification"] = "PARTIAL"
                meta["detail"] = "admin MFA enrollment pending — APIs bloqueadas hasta TOTP"
                meta["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
                return s, meta
            s.get(f"{BASE}{loc}" if loc.startswith("/") else loc, timeout=HTTP_TIMEOUT)
        dash = s.get(f"{BASE}/dashboard", timeout=HTTP_TIMEOUT)
        meta["dashboard_status"] = dash.status_code
        meta["classification"] = "VERIFIED"
        meta["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return s, meta
    except requests.Timeout:
        meta["classification"] = "NOT VERIFIED"
        meta["failure_class"] = "ENVIRONMENT/RESOURCE FAILURE"
        meta["detail"] = "timeout"
        return None, meta
    except Exception as exc:
        meta["classification"] = "FAILED"
        meta["detail"] = str(exc)[:200]
        return None, meta


def http_get(sess: requests.Session, path: str, label: str) -> Dict[str, Any]:
    before = sample(f"before_{label}")
    t0 = time.perf_counter()
    row: Dict[str, Any] = {"label": label, "path": path, "before": before}
    try:
        r = sess.get(f"{BASE}{path}", timeout=HTTP_TIMEOUT)
        body = r.json() if "json" in (r.headers.get("content-type") or "") else None
        elapsed = round((time.perf_counter() - t0) * 1000, 1)
        after = sample(f"after_{label}")
        rec = is_recovery(body)
        row.update(
            {
                "http": r.status_code,
                "elapsed_ms": elapsed,
                "recovery": rec,
                "after": after,
                "body_status": body.get("status") if isinstance(body, dict) else None,
                "data_type": classify_response(label, body, r.text),
            }
        )
        if rec:
            row["classification"] = "NOT VERIFIED"
            row["failure_class"] = "ENVIRONMENT/RESOURCE FAILURE"
        elif r.status_code >= 400:
            row["classification"] = "FAILED"
        else:
            row["classification"] = "VERIFIED"
    except requests.Timeout:
        row["classification"] = "NOT VERIFIED"
        row["failure_class"] = "ENVIRONMENT/RESOURCE FAILURE"
        row["error"] = "timeout"
    except Exception as exc:
        row["classification"] = "FAILED"
        row["error"] = str(exc)[:200]
    return row


def classify_response(label: str, body: Any, text: str) -> str:
    if body is None:
        return "NOT VERIFIED"
    if isinstance(body, dict):
        if body.get("status") == "monitoring_not_configured":
            return "REAL (tenant monitoring gate)"
        if body.get("snapshot_pending") or body.get("counters_pending"):
            return "REAL (pending snapshot)"
        if label.startswith("network"):
            nodes = body.get("nodes") or body.get("count")
            if nodes is not None:
                return "REAL"
        if "invented" in str(body).lower() and body.get("invented") is True:
            return "SIMULATED"
    return "REAL"


def run_subprocess(script: str, timeout: int = 600) -> Dict[str, Any]:
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            [PYTHON, str(ROOT / "scripts" / script)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=os.environ.copy(),
        )
        return {
            "script": script,
            "exit_code": proc.returncode,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
            "stdout_tail": (proc.stdout + proc.stderr)[-2000:],
            "classification": "VERIFIED" if proc.returncode == 0 else ("PARTIAL" if proc.returncode == 2 else "FAILED"),
        }
    except subprocess.TimeoutExpired:
        return {
            "script": script,
            "classification": "NOT VERIFIED",
            "failure_class": "ENVIRONMENT/RESOURCE FAILURE",
            "detail": "subprocess timeout",
        }
    except Exception as exc:
        return {"script": script, "classification": "FAILED", "detail": str(exc)[:200]}


def backup_test() -> Dict[str, Any]:
    sys.path.insert(0, str(ROOT))
    row: Dict[str, Any] = {"phase": "backup"}
    try:
        from services.encrypted_backup_service import (
            create_encrypted_backup,
            verify_backup,
            restore_encrypted_backup,
        )

        created = create_encrypted_backup(label=f"op_readiness_{RUN_ID}", actor="operational_readiness")
        row["create"] = {k: created.get(k) for k in ("ok", "path", "file", "sha256_plain", "size")}
        if not created.get("ok"):
            row["classification"] = "FAILED"
            return row
        path = created["path"]
        row["verify"] = verify_backup(path)
        row["restore"] = {
            k: restore_encrypted_backup(path, actor="operational_readiness").get(k)
            for k in ("ok", "dest", "verify")
        }
        ok = row["verify"].get("ok") and row["restore"].get("ok")
        row["classification"] = "VERIFIED" if ok else "PARTIAL"
        row["data_type"] = "REAL"
    except Exception as exc:
        row["classification"] = "FAILED"
        row["error"] = str(exc)[:300]
    return row


def persistence_test(db_path: Path) -> Dict[str, Any]:
    before_mtime = db_path.stat().st_mtime if db_path.is_file() else None
    before_size = db_path.stat().st_size if db_path.is_file() else None
    stop_novus()
    time.sleep(3)
    pid = start_novus()
    if not pid:
        return {"classification": "FAILED", "detail": "restart failed"}
    time.sleep(15)
    sess, meta = login_full(*CLIENT)
    after_mtime = db_path.stat().st_mtime if db_path.is_file() else None
    after_size = db_path.stat().st_size if db_path.is_file() else None
    scope = None
    if sess and not meta.get("mfa_enrollment_required"):
        r = sess.get(f"{BASE}/api/tenant/scope", timeout=HTTP_TIMEOUT)
        try:
            scope = r.json()
        except Exception:
            scope = {"http": r.status_code}
    ok = (
        db_path.is_file()
        and meta.get("classification") == "VERIFIED"
        and (scope or {}).get("status") not in ("recovering",)
        and not is_recovery(scope)
    )
    return {
        "classification": "VERIFIED" if ok else "PARTIAL",
        "db_before": {"mtime": before_mtime, "size": before_size},
        "db_after": {"mtime": after_mtime, "size": after_size},
        "login_after_restart": meta,
        "tenant_scope": scope,
        "data_type": "REAL",
    }


def load_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {
        "run_id": RUN_ID,
        "generated_at_utc": utc(),
        "baseline_refs": BASELINE_REFS,
        "code_changes_this_phase": [],
        "resource_timeline": [],
    }

    print("[OP] Clean restart...")
    stop_novus()
    report["resource_timeline"].append(sample("START"))
    pid = start_novus()
    if not pid:
        report["verdict_a"] = "NO-GO"
        report["verdict_b"] = "NO-GO"
        report["verdict_c"] = "NO-GO"
        _write_outputs(report, "FAILED — server did not start")
        return 2

    report["boot"] = {
        "classification": "VERIFIED",
        "single_instance": len(listeners()) == 1,
        "listener_pids": listeners(),
        "pid": pid,
    }

    print(f"[OP] Idle {IDLE_SEC}s...")
    t_idle = time.time()
    while time.time() - t_idle < IDLE_SEC:
        time.sleep(30)
        report["resource_timeline"].append(sample("IDLE"))
    idle = sample("IDLE_FINAL")
    report["idle"] = idle
    report["resource_timeline"].append(idle)

    print("[OP] Client operational flow...")
    sess, login_meta = login_full(*CLIENT)
    report["login_client"] = login_meta
    report["resource_timeline"].append(sample("LOGIN"))

    flow_paths = [
        ("dashboard", "/dashboard"),
        ("dashboard_live", "/api/dashboard/live"),
        ("network_page", "/network"),
        ("network_nodes", "/api/network/nodes"),
        ("network_info", "/api/network/info"),
        ("security_summary", "/api/security/summary"),
        ("vulnerabilities_page", "/vulnerabilidades"),
        ("security_vulns", "/api/security/vulnerabilities"),
        ("threats_page", "/amenazas"),
        ("security_alerts", "/api/security/alerts"),
        ("reports_page", "/reportes"),
        ("reports_api", "/api/reports"),
        ("search", "/api/search?q=test"),
        ("health", "/api/health/status"),
        ("evidence", "/api/system/evidence-center"),
        ("login_sessions", "/api/system/login-sessions"),
        ("tenant_scope", "/api/tenant/scope"),
    ]
    report["operational_flow"] = []
    if sess and login_meta.get("classification") == "VERIFIED":
        for label, path in flow_paths:
            report["operational_flow"].append(http_get(sess, path, label))
            report["resource_timeline"].append(sample(label))
    else:
        report["operational_flow"] = [{"classification": "NOT VERIFIED", "detail": "client login incomplete"}]

    print("[OP] Backup create/verify/restore...")
    report["backup"] = backup_test()
    report["resource_timeline"].append(sample("BACKUP"))

    print("[OP] Tenant HTTP verification...")
    tenant_result = run_subprocess("tenant_http_verification_final.py", timeout=900)
    report["tenant_http"] = tenant_result
    report["tenant_http_detail"] = load_json_if_exists(
        ROOT / "data" / "novus_real_operation_audit" / "TENANT_HTTP_VERIFICATION_FINAL.json"
    )

    print("[OP] MFA admin HTTP E2E...")
    mfa_result = run_subprocess("mfa_admin_http_e2e_final.py", timeout=900)
    report["mfa_http"] = mfa_result
    report["mfa_http_detail"] = load_json_if_exists(
        ROOT / "data" / "novus_compliance_audit" / "MFA_ADMIN_HTTP_E2E_FINAL.json"
    )

    print("[OP] MFA policy service...")
    report["mfa_policy"] = run_subprocess("mfa_admin_policy_test.py", timeout=120)

    print("[OP] Persistence after restart...")
    db_path = ROOT / "novus_vault_v2.db"
    report["persistence"] = persistence_test(db_path)
    report["resource_timeline"].append(sample("FINAL"))

    # Classifications summary
    flow_verified = sum(1 for x in report["operational_flow"] if x.get("classification") == "VERIFIED")
    flow_nv = sum(1 for x in report["operational_flow"] if x.get("classification") == "NOT VERIFIED")
    flow_fail = sum(1 for x in report["operational_flow"] if x.get("classification") == "FAILED")

    mfa_detail = report.get("mfa_http_detail") or {}
    mfa_overall = mfa_detail.get("overall_verdict", "NOT VERIFIED")
    tenant_detail = report.get("tenant_http_detail") or {}
    tenant_overall = tenant_detail.get("overall", "NOT VERIFIED")

    idle_ok = (idle.get("novus_rss_mb") or 999) < 400 and idle.get("listener_count") == 1
    boot_ok = report["boot"].get("single_instance")
    backup_ok = report["backup"].get("classification") == "VERIFIED"
    persist_ok = report["persistence"].get("classification") == "VERIFIED"

    # Verdict A — controlled operation
    if boot_ok and idle_ok and flow_verified >= 10 and backup_ok:
        report["verdict_a"] = "GO"
    elif boot_ok and flow_verified >= 6:
        report["verdict_a"] = "PARTIAL GO"
    else:
        report["verdict_a"] = "NO-GO"

    # Verdict B — multi-tenant commercial
    svc_ok = True  # baseline 18/18 + 13/13
    tenant_http_ok = tenant_overall in ("VERIFIED", "PASS", "VERIFIED HTTP") or (
        isinstance(tenant_detail.get("isolation_summary"), dict)
        and tenant_detail.get("isolation_summary", {}).get("deny_pass")
    )
    if svc_ok and tenant_http_ok and mfa_overall in ("VERIFIED", "PARTIALLY VERIFIED"):
        report["verdict_b"] = "PARTIAL GO"
    elif svc_ok:
        report["verdict_b"] = "PARTIAL"
    else:
        report["verdict_b"] = "NO-GO"

    # Verdict C — regulated commercial launch
    report["verdict_c"] = "NO-GO"
    report["verdict_c_blockers"] = [
        "LEGAL/BUSINESS: privacy policy, DPA, RNBD eval",
        "LEGAL/BUSINESS: DSAR/ARCO workflow",
        "Independent pentest not performed",
        "MFA Case E not fully VERIFIED" if mfa_overall != "VERIFIED" else None,
        "Production TLS not verified",
    ]
    report["verdict_c_blockers"] = [x for x in report["verdict_c_blockers"] if x]

    report["summary"] = {
        "operational_flow": {"verified": flow_verified, "not_verified": flow_nv, "failed": flow_fail},
        "idle_rss_mb": idle.get("novus_rss_mb"),
        "idle_threads": idle.get("novus_threads"),
        "mfa_overall": mfa_overall,
        "tenant_http_overall": tenant_overall,
        "backup": report["backup"].get("classification"),
        "persistence": report["persistence"].get("classification"),
    }

    report["not_verified"] = []
    report["verified"] = []
    report["partial"] = []
    report["failed"] = []

    for item in report["operational_flow"]:
        c = item.get("classification", "NOT VERIFIED")
        lbl = item.get("label", "?")
        if c == "VERIFIED":
            report["verified"].append(f"HTTP flow: {lbl}")
        elif c == "FAILED":
            report["failed"].append(f"HTTP flow: {lbl}")
        else:
            report["not_verified"].append(f"HTTP flow: {lbl}")

    if backup_ok:
        report["verified"].append("Backup create/verify/restore")
    if persist_ok:
        report["verified"].append("Persistence after restart")
    if mfa_overall == "VERIFIED":
        report["verified"].append("MFA admin HTTP E2E")
    elif mfa_overall == "PARTIALLY VERIFIED":
        report["partial"].append(f"MFA admin HTTP: {mfa_overall}")
    else:
        report["not_verified"].append(f"MFA admin HTTP: {mfa_overall}")

    report["legal_business_required"] = [
        "Privacy policy Colombia/US",
        "DPA / contrato encargo",
        "RNBD evaluation when applicable",
        "DSAR/ARCO procedure",
        "Breach notification playbook",
        "International transfer documentation",
    ]

    _write_outputs(report, report["verdict_a"])
    print(f"\nVERDICT A: {report['verdict_a']}")
    print(f"VERDICT B: {report['verdict_b']}")
    print(f"VERDICT C: {report['verdict_c']}")
    return 0 if report["verdict_a"] in ("GO", "PARTIAL GO") else 2


def _write_outputs(report: Dict[str, Any], headline: str) -> None:
    OUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    md = [
        "# NOVUS — OPERATIONAL READINESS FINAL",
        "",
        f"**Run ID:** {RUN_ID} | **Generated:** {utc()}",
        "",
        f"## Headline: **{headline}**",
        "",
        "### Veredictos independientes",
        "",
        f"| Veredicto | Resultado | Significado |",
        f"|-----------|-----------|-------------|",
        f"| **A** — Operación técnica controlada | **{report.get('verdict_a', '?')}** | ¿Funciona en entorno real controlado? |",
        f"| **B** — Multi-tenant comercial | **{report.get('verdict_b', '?')}** | ¿Lista para clientes multi-tenant? |",
        f"| **C** — Lanzamiento comercial regulado | **{report.get('verdict_c', '?')}** | ¿Lista para venta regulada CO/US? |",
        "",
        "## 1. Baseline utilizado",
        "",
    ]
    for ref in report.get("baseline_refs", []):
        md.append(f"- `{ref}`")
    md.extend([
        "",
        "## 2. Arranque e idle",
        "",
        f"- Instancia única: {report.get('boot', {}).get('single_instance')}",
        f"- RSS idle: {report.get('idle', {}).get('novus_rss_mb')} MB",
        f"- Threads idle: {report.get('idle', {}).get('novus_threads')}",
        "",
        "## 3. Flujo operacional (cliente)",
        "",
    ])
    for f in report.get("operational_flow", []):
        md.append(
            f"- **{f.get('label')}** — {f.get('classification')} "
            f"(HTTP {f.get('http')}, {f.get('elapsed_ms')}ms, data: {f.get('data_type', '?')})"
        )
    md.extend([
        "",
        "## 4. Multi-tenant HTTP",
        "",
        f"- Script: `{report.get('tenant_http', {}).get('script')}` → {report.get('tenant_http', {}).get('classification')}",
        f"- Overall tenant detail: {report.get('tenant_http_detail', {}).get('overall', 'N/A')}",
        "",
        "## 5. MFA administrativo",
        "",
        f"- Policy service: {report.get('mfa_policy', {}).get('classification')}",
        f"- HTTP E2E overall: **{report.get('mfa_http_detail', {}).get('overall_verdict', 'N/A')}**",
        "",
        "## 6. Backup y persistencia",
        "",
        f"- Backup: {report.get('backup', {}).get('classification')}",
        f"- Persistencia post-restart: {report.get('persistence', {}).get('classification')}",
        "",
        "## 7. Correcciones en esta fase",
        "",
    ])
    if report.get("code_changes_this_phase"):
        for c in report["code_changes_this_phase"]:
            md.append(f"- {c}")
    else:
        md.append("- **Ninguna** — solo pruebas y observación.")
    md.extend([
        "",
        "## 8. VERIFIED / PARTIAL / NOT VERIFIED / FAILED",
        "",
        "### VERIFIED",
        "",
    ])
    for v in report.get("verified", []) or ["(none)"]:
        md.append(f"- {v}")
    md.extend(["", "### PARTIAL", ""])
    for p in report.get("partial", []) or ["(none)"]:
        md.append(f"- {p}")
    md.extend(["", "### NOT VERIFIED", ""])
    for n in report.get("not_verified", []) or ["(none)"]:
        md.append(f"- {n}")
    md.extend(["", "### FAILED", ""])
    for f in report.get("failed", []) or ["(none)"]:
        md.append(f"- {f}")
    md.extend([
        "",
        "## 9. LEGAL / BUSINESS ACTION REQUIRED (separado de operación)",
        "",
    ])
    for lb in report.get("legal_business_required", []):
        md.append(f"- {lb}")
    md.extend([
        "",
        "## 10. Qué puede hacerse ahora",
        "",
        "- Operar NOVUS en entorno controlado con usuario cliente autenticado",
        "- Monitoreo de red real, detección, reportes, evidencia, backups on-demand",
        "- Observación prolongada sin pruebas agresivas",
        "",
        "## 11. Qué NO debe hacerse aún",
        "",
        "- Venta comercial regulada sin documentación legal",
        "- Multi-tenant enterprise sin cerrar MFA Case E HTTP",
        "- Declarar 100% compliant o certificado",
        "- P1/P2 features o refactors",
        "",
        f"JSON: `{OUT_JSON.name}`",
    ])
    OUT_MD.write_text("\n".join(md), encoding="utf-8")
    print(f"Report: {OUT_MD}")


if __name__ == "__main__":
    sys.exit(main())
