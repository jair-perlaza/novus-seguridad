#!/usr/bin/env python3
"""Informe final de integridad de datos NOVUS — post-remediación."""
from __future__ import annotations

import json
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT_DIR = ROOT / "data" / "novus_release_candidate"
MD_PATH = OUT_DIR / "NOVUS_DATA_INTEGRITY_FINAL.md"
JSON_PATH = OUT_DIR / "NOVUS_DATA_INTEGRITY_FINAL.json"
SNAP_PATH = OUT_DIR / "_integrity_final_snapshot.json"

CLIENT_EMAIL = "operaciones@novapay-fintech.co"
FAKE_MARKERS = (
    "simulated", "fixture", "demo threat", "fake_", "lorem ipsum",
    "mock data", "synthetic alert", "seed data", "lab data",
)
ARTIFICIAL_PATTERNS = (
    re.compile(r"min\s*\(\s*100\s*,", re.I),
    re.compile(r"traffic_intensity\s*[:=]\s*(?!null)\d+", re.I),
    re.compile(r"count\s*\*\s*\d+", re.I),
)

MODULES: List[Tuple[str, str]] = [
    ("/api/tenant/scope", "tenant_scope"),
    ("/api/dashboard/live", "dashboard"),
    ("/api/network/nodes?trigger_discovery=false", "network"),
    ("/api/security/summary", "security_summary"),
    ("/api/security/threats", "threats"),
    ("/api/security/vulnerabilities", "vulnerabilities"),
    ("/api/security/endpoints", "endpoints"),
    ("/api/reports", "reports"),
    ("/api/system/evidence-center", "evidence"),
    ("/api/system/login-sessions", "sessions"),
    ("/api/notifications?kind=security", "notifications_security"),
    ("/api/notifications?kind=system", "notifications_system"),
    ("/api/ai/status", "ai_kernel"),
    ("/api/health/status", "health"),
    ("/api/network/topology?trigger_discovery=false", "topology"),
    ("/api/monitoring/status?poll=1", "defense_motors"),
]


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _login_client(app, email: str):
    from database import SessionLocal, Usuario

    db = SessionLocal()
    try:
        row = db.query(Usuario).filter(Usuario.email == email.strip().lower()).first()
        if not row:
            raise RuntimeError(f"user_not_found:{email}")
        user_id = str(row.id)
    finally:
        db.close()
    client = app.test_client()
    csrf = secrets.token_urlsafe(32)
    with client.session_transaction() as sess:
        sess["_user_id"] = user_id
        sess["_fresh"] = True
        sess["_novus_login_session_id"] = f"TEST-INTEGRITY-{user_id}"
        sess["_csrf_token"] = csrf
    return client


def _walk_issues(obj: Any, path: str = "") -> List[str]:
    hits: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else k
            if k == "traffic_intensity" and v is not None and isinstance(v, (int, float)):
                hits.append(f"{p}: artificial_traffic_intensity={v}")
            if k == "count" and path.endswith("network") and isinstance(v, int) and v > 0:
                pass
            hits.extend(_walk_issues(v, p))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.extend(_walk_issues(v, f"{path}[{i}]"))
    elif isinstance(obj, str):
        low = obj.lower()
        for m in FAKE_MARKERS:
            if m in low:
                hits.append(f"{path}:{m}")
        for pat in ARTIFICIAL_PATTERNS:
            if pat.search(obj):
                hits.append(f"{path}:pattern_{pat.pattern[:30]}")
    return hits


def _audit_network_stale(body: dict) -> List[str]:
    issues = []
    fresh = (body.get("data_freshness") or body.get("snapshot_meta", {}).get("data_freshness") or "").lower()
    obs = body.get("observed_device_count")
    cnt = body.get("count")
    hist = body.get("historical_device_count")
    if fresh == "stale" and isinstance(cnt, int) and cnt > 0:
        issues.append("network: count>0 while stale (must be observed=0)")
    if fresh == "stale" and isinstance(obs, int) and obs > 0:
        issues.append("network: observed_device_count>0 while stale")
    if hist is None and fresh in ("stale", "cached"):
        issues.append("network: missing historical_device_count for stale/cached")
    return issues


def _audit_topology(body: dict) -> List[str]:
    issues = []
    for i, c in enumerate(body.get("connections") or []):
        if c.get("traffic_intensity") is not None and not c.get("traffic_measured"):
            issues.append(f"topology.connections[{i}]: traffic_intensity without traffic_measured")
        if c.get("traffic_intensity") is not None and not c.get("traffic_measured"):
            issues.append(f"topology.connections[{i}]: unmeasured intensity presented")
    return issues


def _audit_notifications(body: dict) -> List[str]:
    issues = []
    for n in body.get("notifications") or body.get("items") or []:
        kind = (n.get("notification_kind") or n.get("kind") or "").lower()
        if kind != "security":
            continue
        pl = n.get("payload") or {}
        if isinstance(pl, str):
            try:
                pl = json.loads(pl)
            except Exception:
                pl = {}
        has_ev = bool(
            pl.get("evidence_id")
            or pl.get("evidence")
            or pl.get("anomaly_id")
            or pl.get("detection_id")
            or pl.get("finding_id")
            or n.get("source_motor")
        )
        if not (n.get("source_motor") and n.get("source_ref") and has_ev):
            issues.append(f"notification:{n.get('notification_id')}: security without verifiable evidence")
    return issues


def _audit_ai_kernel(body: dict) -> List[str]:
    issues = []
    op = body.get("operational_status")
    if op == "ACTIVE" and not body.get("last_execution_at"):
        issues.append("ai_kernel: ACTIVE without last_execution_at")
    return issues


def _audit_defense_motors(body: dict) -> List[str]:
    issues = []
    motors = body.get("defense_motors") or body
    for key in ("kernel_ia", "escaneo_continuo", "web_shield", "endpoint_protection"):
        m = motors.get(key) or {}
        if m.get("status") == "Activo" and not (m.get("telemetry") or {}).get("telemetry_verifiable"):
            issues.append(f"defense_motor.{key}: Activo without telemetry")
    return issues


def _inventory_element(
    screen: str,
    element: str,
    value: Any,
    *,
    source: str = "",
    endpoint: str = "",
    data_origin: str = "",
    verifiable: bool = False,
    action: str = "OK",
) -> dict:
    return {
        "pantalla": screen,
        "elemento": element,
        "tipo": type(value).__name__,
        "valor_actual": value,
        "fuente": source,
        "endpoint": endpoint,
        "data_origin": data_origin,
        "es_verificable": verifiable,
        "accion_requerida": action,
    }


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    from migrate_database import migrate_database

    migrate_database()
    from core.app import create_app

    app = create_app("development")
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_PROTECTION"] = "basic"
    app.login_manager.session_protection = "basic"
    client = _login_client(app, CLIENT_EMAIL)

    snapshot: Dict[str, Any] = {"generated_at": _utc(), "modules": {}, "issues": [], "inventory": []}
    all_issues: List[str] = []

    for path, key in MODULES:
        resp = client.get(path)
        try:
            body = resp.get_json(silent=True) or {}
        except Exception:
            body = {}
        fake_hits = _walk_issues(body, key)
        mod_issues = fake_hits
        if resp.status_code == 401:
            mod_issues.append(f"{key}: http_401_unauthenticated")
        if key == "network":
            mod_issues += _audit_network_stale(body)
        elif key == "topology":
            mod_issues += _audit_topology(body)
        elif key == "notifications_security":
            mod_issues += _audit_notifications(body)
        elif key == "ai_kernel":
            mod_issues += _audit_ai_kernel(body)
        elif key == "defense_motors":
            mod_issues += _audit_defense_motors(body)

        snapshot["modules"][key] = {
            "http": resp.status_code,
            "issues": mod_issues,
            "body": body,
        }
        all_issues.extend(mod_issues)

        if key == "dashboard":
            meta = body.get("nodos_red_meta") or {}
            nodos = body.get("nodos_red")
            verifiable = nodos is not None and nodos != "Sin datos disponibles"
            snapshot["inventory"].append(
                _inventory_element(
                    "Dashboard",
                    "nodos_red",
                    nodos,
                    source=body.get("source_type", ""),
                    endpoint=path,
                    data_origin=meta.get("data_freshness", ""),
                    verifiable=verifiable,
                    action="OK" if verifiable or nodos == "Sin datos disponibles" else "NO_DATA",
                )
            )
        if key == "topology":
            conns = body.get("connections") or []
            intensities = [c.get("traffic_intensity") for c in conns if c.get("traffic_intensity") is not None]
            snapshot["inventory"].append(
                _inventory_element(
                    "Topology",
                    "traffic_intensity_edges",
                    intensities or "Tráfico no medido",
                    source="topology_service.build_real_connections",
                    endpoint=path,
                    verifiable=len(intensities) == 0 or all(
                        (conns[i].get("traffic_measured") for i, c in enumerate(conns) if c.get("traffic_intensity") is not None)
                    ),
                    action="OK" if not intensities else "REVIEW",
                )
            )

    # Run in-process verify subprocess
    verify_rc = 0
    verify_summary: Dict[str, Any] = {}
    try:
        import subprocess

        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "novus_inprocess_operational_verify.py")],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=300,
        )
        verify_rc = proc.returncode
        vpath = ROOT / "data" / "novus_release_candidate" / "NOVUS_INPROCESS_OPERATIONAL_VERIFY.json"
        if vpath.is_file():
            verify_summary = json.loads(vpath.read_text(encoding="utf-8"))
    except Exception as exc:
        verify_summary = {"error": str(exc)}

    tests = verify_summary.get("tests") or verify_summary.get("results") or []
    passed = sum(1 for r in tests if r.get("pass"))
    total = len(tests)
    verify_ok = (
        verify_rc == 0
        and (verify_summary.get("pass") is True or (total > 0 and passed == total))
    )

    verdict = "DATA_INTEGRITY_NOT_VERIFIED"
    if not all_issues and verify_ok:
        verdict = "DATA_INTEGRITY_VERIFIED_WITH_LIMITS"

    report = {
        "generated_at": _utc(),
        "verdict": verdict,
        "backup_used": "data/backups/data_integrity_20260822_044958",
        "changes_summary": [
            "topology: sanitize_topology_connections + traffic_intensity=None sin medición",
            "network: count=observed_device_count; historical_device_count separado",
            "notifications: validate_security_notification en emit_notification",
            "ai_kernel: ACTIVE exige last_execution_at reciente",
            "defense_motors: motores_activos sin inflación x2; NOT_VERIFIABLE sin telemetría",
            "dashboard UI: nodos stale vs histórico",
        ],
        "modified_files": [
            "services/topology_service.py",
            "services/network_snapshot_service.py",
            "services/continuous_monitoring_orchestrator.py",
            "services/ai_kernel.py",
            "static/js/novus-metrics.js",
            "templates/index.html",
            "static/js/novus-dashboard-cache.js",
        ],
        "issues_found": all_issues,
        "issues_count": len(all_issues),
        "inventory": snapshot["inventory"],
        "modules_audited": list(snapshot["modules"].keys()),
        "regression": {
            "inprocess_verify": verify_summary,
            "passed": passed,
            "total": total,
            "ok": verify_ok,
        },
        "pending_not_verifiable": [
            x for x in all_issues
        ],
        "static_simulated_synthetic": [i for i in all_issues if any(m in i for m in ("fake", "synthetic", "simulated", "artificial"))],
        "metrics_artificial": [i for i in all_issues if "traffic_intensity" in i or "artificial" in i],
        "notifications_without_evidence": [i for i in all_issues if i.startswith("notification:")],
        "known_limits": [
            "Verificación UI visual manual no ejecutada en este script",
            "Login HTTP+MFA en navegador no confirmado (RAM host alta)",
            "Snapshots legacy en disco se sanitizan al leer; regeneración completa tras próximo descubrimiento",
            "Motores sin telemetría JSONL muestran NOT_VERIFIABLE aunque el servicio exista",
            "Inventario completo de 76 elementos UI requiere auditoría forense previa + revisión manual",
        ],

    with open(JSON_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
    with open(SNAP_PATH, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2, ensure_ascii=False, default=str)

    md = [
        "# NOVUS — Informe final de integridad de datos",
        "",
        f"Generado: {report['generated_at']}",
        "",
        f"## Veredicto: `{verdict}`",
        "",
        f"- Issues detectados en APIs: **{len(all_issues)}**",
        f"- Regresión in-process: **{passed}/{total}** ({'OK' if verify_ok else 'FAIL'})",
        "",
        "## Cambios realizados",
        *[f"- {c}" for c in report["changes_summary"]],
        "",
        "## Backup",
        f"- `{report['backup_used']}`",
        "",
        "## Issues pendientes",
    ]
    if all_issues:
        md.extend([f"- `{i}`" for i in all_issues])
    else:
        md.append("- Ninguno en snapshot API actual.")
    md.extend(["", "## Inventario (muestra)", ""])
    for item in snapshot["inventory"]:
        md.append(
            f"- **{item['pantalla']} / {item['elemento']}**: `{item['valor_actual']}` "
            f"— verificable={item['es_verificable']} — {item['accion_requerida']}"
        )
    if verdict == "DATA_INTEGRITY_NOT_VERIFIED":
        md.extend(
            [
                "",
                "> No se declara FINAL/GO/100% real: queda al menos un elemento sin procedencia verificable "
                "o regresión incompleta.",
            ]
        )
    md.extend(["", "## Límites conocidos (no declarar 100% real)", ""])
    for lim in report.get("known_limits") or []:
        md.append(f"- {lim}")
    with open(MD_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))

    print(f"Verdict: {verdict}")
    print(f"Issues: {len(all_issues)}")
    print(f"Wrote {MD_PATH}")
    return 0 if verdict != "DATA_INTEGRITY_NOT_VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
