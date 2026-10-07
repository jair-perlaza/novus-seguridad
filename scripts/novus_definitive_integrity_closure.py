#!/usr/bin/env python3
"""
Cierre definitivo de integridad NOVUS — auditoría runtime + tabla de fuentes.
No documental: ejecuta APIs, tenant limpio, regresión y clasifica datos visibles.
"""
from __future__ import annotations

import json
import re
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT_DIR = ROOT / "data" / "novus_release_candidate"
JSON_OUT = OUT_DIR / "NOVUS_DEFINITIVE_INTEGRITY_CLOSURE.json"
MD_OUT = OUT_DIR / "NOVUS_DEFINITIVE_INTEGRITY_CLOSURE.md"

CLIENT_EMAIL = "operaciones@novapay-fintech.co"
QA_EMAIL = "novus.qa.jul2026@example.com"

API_MODULES: List[Tuple[str, str, str]] = [
    ("/api/tenant/scope", "tenant_scope", "Dashboard"),
    ("/api/dashboard/live", "dashboard", "Dashboard"),
    ("/api/security/summary", "security_summary", "Dashboard"),
    ("/api/network/nodes?trigger_discovery=false", "network", "Network"),
    ("/api/network/ndr?trigger_discovery=false", "ndr", "Network"),
    ("/api/network/topology?trigger_discovery=false", "topology", "Topology"),
    ("/api/monitoring/network-config", "network_config", "Configuración"),
    ("/api/monitoring/status?poll=1", "monitoring", "Monitoreo"),
    ("/api/security/threats", "threats", "Amenazas"),
    ("/api/security/vulnerabilities", "vulnerabilities", "Vulnerabilidades"),
    ("/api/security/endpoints", "endpoints", "Endpoints"),
    ("/api/reports", "reports", "Reportes"),
    ("/api/system/evidence-center", "evidence", "Evidencias"),
    ("/api/system/login-sessions", "sessions", "Sesiones"),
    ("/api/notifications?kind=security", "notifications_security", "Notificaciones"),
    ("/api/notifications?kind=system", "notifications_system", "Notificaciones"),
    ("/api/ai/status", "ai_kernel", "IA Kernel"),
    ("/api/health/status", "health", "Health"),
    ("/api/web-shield/status", "web_shield", "Web Shield"),
    ("/api/mail-shield/status", "mail_shield", "Mail Shield"),
    ("/api/search?q=network", "search", "Search"),
    ("/api/network/assets/inventory", "inventory", "Inventario"),
    ("/api/behavior/summary", "behavior", "Comportamiento"),
    ("/api/system/protection-score", "protection_score", "Dashboard"),
]

HTML_ROUTES = [
    ("/dashboard", "Dashboard"),
    ("/network", "Network"),
    ("/topology", "Topology"),
    ("/vulnerabilidades", "Vulnerabilidades"),
    ("/amenazas", "Amenazas"),
    ("/endpoints", "Endpoints"),
    ("/reportes", "Reportes"),
    ("/configuracion", "Configuración"),
    ("/web-shield", "Web Shield"),
    ("/mail-shield", "Mail Shield"),
    ("/xdr", "XDR"),
]

FAKE_MARKERS = (
    "simulated", "fixture", "demo threat", "fake_", "lorem ipsum",
    "mock data", "synthetic alert", "seed data", "lab data", "placeholder value",
)
ARTIFICIAL_KEYS = {"traffic_intensity", "demo_count", "sample_threats"}
QA_MARKERS = ("QA-NOVUS-2026", "novus.qa.jul2026@example.com", "TEST-PORT-9999")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _login(app, email: str):
    from database import SessionLocal, Usuario

    db = SessionLocal()
    try:
        row = db.query(Usuario).filter(Usuario.email == email.strip().lower()).first()
        if not row:
            raise RuntimeError(f"user_not_found:{email}")
        uid = str(row.id)
    finally:
        db.close()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = uid
        sess["_fresh"] = True
        sess["_novus_login_session_id"] = f"CLOSURE-{uid}"
        sess["_csrf_token"] = secrets.token_urlsafe(32)
    return client, uid


def _classify_field(key: str, val: Any, path: str) -> Optional[str]:
    """Retorna STATIC|SIMULATED|SYNTHETIC|UNVERIFIABLE si aplica."""
    if key in ARTIFICIAL_KEYS and val is not None:
        if key == "traffic_intensity":
            return "SYNTHETIC"
    if isinstance(val, str):
        low = val.lower()
        for m in FAKE_MARKERS:
            if m in low:
                return "SIMULATED"
    if isinstance(val, (int, float)) and key.endswith("_score") and path.count(".") < 2:
        pass
    return None


def _audit_body(body: Any, screen: str, endpoint: str, *, prefix: str = "") -> List[Dict]:
    rows: List[Dict] = []
    if isinstance(body, dict):
        for k, v in body.items():
            p = f"{prefix}.{k}" if prefix else k
            issue = _classify_field(k, v, p)
            if k in (
                "nodos_red", "count", "observed_device_count", "device_count",
                "total_threats", "threats_total", "vulnerabilities_total",
                "endpoints_total", "traffic_intensity", "motores_activos",
                "operational_status", "protection_score", "core_protection_percent",
            ):
                prov = body.get("provenance") or body.get("nodos_red_meta") or {}
                origin = prov.get("data_origin") or body.get("data_freshness") or ""
                rows.append({
                    "elemento": p,
                    "pantalla": screen,
                    "valor": v,
                    "endpoint": endpoint,
                    "fuente": prov.get("source") or body.get("source") or body.get("source_type") or "",
                    "data_origin": origin,
                    "verificable": v not in (None, "Sin datos disponibles", "NOT_VERIFIABLE"),
                    "clasificacion": issue or "OK",
                })
            if issue:
                rows.append({
                    "elemento": p,
                    "pantalla": screen,
                    "valor": v,
                    "endpoint": endpoint,
                    "clasificacion": issue,
                    "verificable": False,
                })
            rows.extend(_audit_body(v, screen, endpoint, prefix=p))
    elif isinstance(body, list):
        for i, item in enumerate(body[:20]):
            rows.extend(_audit_body(item, screen, endpoint, prefix=f"{prefix}[{i}]"))
    return rows


def _audit_topology_connections(body: dict) -> List[str]:
    issues = []
    for i, c in enumerate(body.get("connections") or []):
        ti = c.get("traffic_intensity")
        if ti is not None and not c.get("traffic_measured"):
            issues.append(f"topology.connections[{i}].traffic_intensity={ti}")
    return issues


def _audit_network_stale(body: dict) -> List[str]:
    issues = []
    fresh = (body.get("data_freshness") or "").lower()
    if fresh == "stale" and isinstance(body.get("count"), int) and body["count"] > 0:
        issues.append("network: count>0 while stale")
    return issues


def _scan_html(html: str, route: str, screen: str) -> List[Dict]:
    hits = []
    for m in FAKE_MARKERS:
        if m in html.lower():
            hits.append({"pantalla": screen, "elemento": f"html:{route}", "clasificacion": "SIMULATED", "match": m})
    hardcoded = re.findall(
        r'id="(?:nodes-val|threats-val|vulns-val|endpoints-val|traffic-val)"[^>]*>([^<]{1,40})<',
        html,
        re.I,
    )
    for val in hardcoded:
        val = val.strip()
        if val and val not in ("—", "Esperando datos...", "Esperando datos reales...", "Sin datos disponibles", "N/A"):
            if re.match(r"^\d+$", val):
                hits.append({
                    "pantalla": screen,
                    "elemento": "kpi_hardcoded_ssr",
                    "valor": val,
                    "clasificacion": "STATIC",
                    "endpoint": route,
                })
    return hits


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    from migrate_database import migrate_database

    migrate_database()
    from core.app import create_app

    app = create_app("development")
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, SESSION_COOKIE_SECURE=False, SESSION_PROTECTION="basic")
    app.login_manager.session_protection = "basic"

    report: Dict[str, Any] = {
        "generated_at": _utc(),
        "backup": "data/backups/definitive_closure_20260822_193418",
        "inventory": [],
        "issues": [],
        "regression": {},
        "clean_tenant": {},
        "regulatory": {},
        "counters": {
            "STATIC_VISIBLE": 0,
            "SIMULATED_VISIBLE": 0,
            "SYNTHETIC_VISIBLE": 0,
            "UNVERIFIABLE_VISIBLE": 0,
        },
    }

    from services.tenant_scope_service import ensure_tenant_monitoring_seeded

    ensure_tenant_monitoring_seeded()

    client, _ = _login(app, CLIENT_EMAIL)
    qa_client, _ = _login(app, QA_EMAIL)

    for path, key, screen in API_MODULES:
        resp = client.get(path)
        body = resp.get_json(silent=True) or {}
        mod_issues: List[str] = []
        if resp.status_code != 200:
            mod_issues.append(f"{key}:http_{resp.status_code}")
        if key == "topology":
            mod_issues.extend(_audit_topology_connections(body))
        if key == "network":
            mod_issues.extend(_audit_network_stale(body))
        if key == "notifications_security":
            for n in body.get("notifications") or body.get("items") or []:
                if (n.get("notification_kind") or "").lower() == "security":
                    pl = n.get("payload") or {}
                    if not (n.get("source_motor") and n.get("source_ref")):
                        mod_issues.append(f"notification:{n.get('notification_id')}:no_evidence")
        rows = _audit_body(body, screen, path)
        report["inventory"].extend(rows)
        report["issues"].extend(mod_issues)

    for path, screen in HTML_ROUTES:
        resp = client.get(path)
        if resp.status_code == 200 and resp.data:
            html = resp.data.decode("utf-8", errors="replace")
            report["inventory"].extend(_scan_html(html, path, screen))

    scope_cl = client.get("/api/tenant/scope").get_json(silent=True) or {}
    scope_qa = qa_client.get("/api/tenant/scope").get_json(silent=True) or {}
    if scope_cl.get("tenant_id") == scope_qa.get("tenant_id"):
        report["issues"].append("tenant_isolation: client==qa tenant_id")
    if not scope_cl.get("monitoring_enabled"):
        report["issues"].append("monitoring: client monitoring_enabled=false")

    for row in report["inventory"]:
        c = row.get("clasificacion")
        if c == "STATIC":
            report["counters"]["STATIC_VISIBLE"] += 1
        elif c == "SIMULATED":
            report["counters"]["SIMULATED_VISIBLE"] += 1
        elif c == "SYNTHETIC":
            report["counters"]["SYNTHETIC_VISIBLE"] += 1
        elif c == "UNVERIFIABLE" or row.get("valor") == "NOT_VERIFIABLE":
            report["counters"]["UNVERIFIABLE_VISIBLE"] += 1

    proc_verify = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "novus_inprocess_operational_verify.py")],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300,
    )
    vpath = OUT_DIR / "NOVUS_INPROCESS_OPERATIONAL_VERIFY.json"
    if vpath.is_file():
        report["regression"]["inprocess"] = json.loads(vpath.read_text(encoding="utf-8"))

    proc_clean = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "novus_v1_clean_tenant_e2e.py")],
        cwd=str(ROOT), capture_output=True, text=True, timeout=120,
    )
    cpath = OUT_DIR / "NOVUS_V1_CLEAN_TENANT_E2E.json"
    if cpath.is_file():
        report["clean_tenant"] = json.loads(cpath.read_text(encoding="utf-8"))

    reg_path = OUT_DIR / "REGULATORY_CONTROLS_MATRIX.json"
    if reg_path.is_file():
        report["regulatory"] = json.loads(reg_path.read_text(encoding="utf-8"))

    counters = report["counters"]
    tests = report.get("regression", {}).get("inprocess", {}).get("tests") or []
    reg_ok = report.get("regression", {}).get("inprocess", {}).get("pass") is True
    clean_ok = report.get("clean_tenant", {}).get("overall") == "VERIFIED"
    zero_fake = all(counters[k] == 0 for k in counters)
    no_issues = len(report["issues"]) == 0

    if zero_fake and no_issues and reg_ok and clean_ok:
        report["verdict"] = "OPERATIONAL_INTEGRITY_PASS"
    else:
        report["verdict"] = "OPERATIONAL_INTEGRITY_FAIL"

    report["motors"] = {}
    mon = client.get("/api/monitoring/status?poll=1").get_json(silent=True) or {}
    report["motors"]["defense_motors"] = mon.get("defense_motors")
    report["motors"]["ai_kernel"] = client.get("/api/ai/status").get_json(silent=True) or {}
    report["network_monitoring"] = client.get("/api/monitoring/network-config").get_json(silent=True) or {}

    with open(JSON_OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)

    md = [
        "# NOVUS — Cierre definitivo de integridad",
        "",
        f"Generado: {report['generated_at']}",
        "",
        f"## Veredicto: `{report['verdict']}`",
        "",
        "### Contadores de aceptación",
        f"- STATIC_VISIBLE: **{counters['STATIC_VISIBLE']}**",
        f"- SIMULATED_VISIBLE: **{counters['SIMULATED_VISIBLE']}**",
        f"- SYNTHETIC_VISIBLE: **{counters['SYNTHETIC_VISIBLE']}**",
        f"- UNVERIFIABLE_VISIBLE: **{counters['UNVERIFIABLE_VISIBLE']}**",
        "",
        f"- Regresión in-process: **{'OK' if reg_ok else 'FAIL'}**",
        f"- Tenant limpio E2E: **{'OK' if clean_ok else 'FAIL'}**",
        f"- Issues runtime: **{len(report['issues'])}**",
        "",
        "## Tabla de fuentes (muestra KPIs)",
        "",
        "| Elemento | Pantalla | Valor | Fuente | LIVE/CACHED/STALE | Verificable |",
        "| -------- | -------- | ----- | ------ | ----------------- | ----------- |",
    ]
    seen = set()
    for row in report["inventory"]:
        if row.get("elemento") in seen:
            continue
        if not any(x in str(row.get("elemento", "")) for x in ("nodos", "threat", "vuln", "endpoint", "traffic", "count", "operational")):
            continue
        seen.add(row.get("elemento"))
        md.append(
            f"| {row.get('elemento','')} | {row.get('pantalla','')} | {row.get('valor','')} | "
            f"{row.get('fuente','')} | {row.get('data_origin','')} | {row.get('verificable','')} |"
        )
    if report["issues"]:
        md.extend(["", "## Issues", ""])
        md.extend(f"- `{i}`" for i in report["issues"])
    md.extend(["", "## Límites", "- UI visual manual en navegador no ejecutada en este script", "- Login HTTP+MFA browser pendiente si RAM host alta"])
    MD_OUT.write_text("\n".join(md), encoding="utf-8")

    print(json.dumps({
        "verdict": report["verdict"],
        "counters": counters,
        "issues": len(report["issues"]),
        "reg_ok": reg_ok,
        "clean_ok": clean_ok,
    }))
    return 0 if report["verdict"] == "OPERATIONAL_INTEGRITY_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
