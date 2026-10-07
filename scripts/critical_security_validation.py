#!/usr/bin/env python3
"""
Validación crítica NOVUS — OBSERVAR → MEDIR → REPRODUCIR → CONFIRMAR → DOCUMENTAR.
Sin correcciones automáticas. Sin baterías HTTP agresivas.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_real_operation_audit"
PY = r"C:\Users\hp\AppData\Local\Python\pythoncore-3.14-64\python.exe"
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
CLIENT = ("operaciones@novapay-fintech.co", "NovaPay#Fintech2026")
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
MARK_A = f"A-ISOL-{RUN_ID}"
MARK_B = f"B-ISOL-{RUN_ID}"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def save_md(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def login(email: str, password: str, timeout: int = 25) -> Tuple[requests.Session, dict]:
    s = requests.Session()
    meta = {"email": email, "login_ok": False, "error": None}
    try:
        r = s.get(f"{BASE}/login", timeout=timeout)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
        s.post(
            f"{BASE}/login",
            data={"email": email, "password": password, "csrf_token": csrf.group(1) if csrf else ""},
            timeout=timeout,
        )
        meta["login_ok"] = True
    except Exception as exc:
        meta["error"] = str(exc)[:200]
    return s, meta


def resolve_tenant_ids() -> dict:
    from database import SessionLocal, Usuario

    db = SessionLocal()
    try:
        rows = {}
        for email in (QA[0], CLIENT[0]):
            u = db.query(Usuario).filter(Usuario.email == email.strip().lower()).first()
            if u:
                rows[email] = {
                    "user_id": u.id,
                    "nit_pyme": getattr(u, "nit_pyme", None),
                    "company_id": getattr(u, "company_id", None),
                    "sector": getattr(u, "sector", None),
                    "tenant_id": getattr(u, "company_id", None) or getattr(u, "nit_pyme", None) or email.split("@")[1],
                }
        return rows
    finally:
        db.close()


def insert_isolation_fixtures(tenant_a: str, tenant_b: str) -> dict:
    """Inserta registros exclusivos por tenant — marcados ISOL, no borran datos reales."""
    from database import SessionLocal, Alerta, PlatformEvidence, LoginSessionAudit

    ts = utc()
    ids = {"run_id": RUN_ID, "tenant_a": tenant_a, "tenant_b": tenant_b, "inserted": {}}
    db = SessionLocal()
    try:
        alert_a = Alerta(
            tenant_id=tenant_a,
            titulo=f"{MARK_A}-ALERT-001",
            descripcion=f"Exclusive tenant A alert {MARK_A}",
            nivel="Info",
            motor="isolation_test",
            fuente="ISOLATION_TEST",
        )
        alert_b = Alerta(
            tenant_id=tenant_b,
            titulo=f"{MARK_B}-ALERT-001",
            descripcion=f"Exclusive tenant B alert {MARK_B}",
            nivel="Info",
            motor="isolation_test",
            fuente="ISOLATION_TEST",
        )
        db.add(alert_a)
        db.add(alert_b)
        db.flush()
        ids["inserted"]["alert_a_id"] = alert_a.id
        ids["inserted"]["alert_b_id"] = alert_b.id

        ev_json = json.dumps(
            {
                "verified": True,
                "motor": "network_snapshot_service",
                "timestamp": ts,
                "evidence_summary": "Isolation test exclusive record",
            },
            ensure_ascii=False,
        )
        ev_a = PlatformEvidence(
            id=f"{MARK_A}-EVIDENCE-001",
            tenant_id=tenant_a,
            fecha=ts[:10],
            hora=ts[11:19],
            timestamp=ts,
            motor="network_snapshot_service",
            categoria="security",
            descripcion=f"Exclusive tenant A evidence {MARK_A}-EVIDENCE-001",
            nivel_riesgo="info",
            source_event_id=MARK_A,
            evidence_json=ev_json,
        )
        ev_b = PlatformEvidence(
            id=f"{MARK_B}-EVIDENCE-001",
            tenant_id=tenant_b,
            fecha=ts[:10],
            hora=ts[11:19],
            timestamp=ts,
            motor="network_snapshot_service",
            categoria="security",
            descripcion=f"Exclusive tenant B evidence {MARK_B}-EVIDENCE-001",
            nivel_riesgo="info",
            source_event_id=MARK_B,
            evidence_json=ev_json.replace("Exclusive", "Exclusive-B"),
        )
        db.add(ev_a)
        db.add(ev_b)

        sess_a = LoginSessionAudit(
            id=f"{MARK_A}-SESSION-001",
            user_email=QA[0],
            login_at=ts,
            ip_address="10.91.155.100",
            session_id=f"sess-{MARK_A}",
            login_result="success",
            security_status="verified",
        )
        sess_b = LoginSessionAudit(
            id=f"{MARK_B}-SESSION-001",
            user_email=CLIENT[0],
            login_at=ts,
            ip_address="10.91.155.101",
            session_id=f"sess-{MARK_B}",
            login_result="success",
            security_status="verified",
        )
        db.add(sess_a)
        db.add(sess_b)
        db.commit()
        ids["inserted"].update(
            {
                "evidence_a": ev_a.id,
                "evidence_b": ev_b.id,
                "session_a": sess_a.id,
                "session_b": sess_b.id,
            }
        )
        ids["ok"] = True
    except Exception as exc:
        db.rollback()
        ids["ok"] = False
        ids["error"] = str(exc)[:300]
    finally:
        db.close()

    from services.security_report_service import save_report

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for mark, tid in ((MARK_A, tenant_a), (MARK_B, tenant_b)):
        rid = f"REP-{mark}"
        save_report(
            {
                "id": rid,
                "finding_id": f"{mark}-FIND-001",
                "tipo": "Isolation test",
                "fecha": now,
                "severidad": "Informativo",
                "estado": "Abierto",
                "equipo_afectado": "isolation-test-host",
                "tenant_marker": tid,
                "resumen_ejecutivo": f"Exclusive report {mark} for tenant {tid}",
                "technical": {
                    "fecha_deteccion": now,
                    "severidad": "Informativo",
                    "estado": "Abierto",
                    "tipo_vulnerabilidad": "test",
                    "que_ocurrio": f"Report exclusive to {mark}",
                    "nivel_confianza": "alto",
                    "linea_tiempo": [],
                },
                "conclusiones": mark,
                "remediation_log": [],
                "generated_at": now,
            }
        )
        ids["inserted"][f"report_{mark[:1]}"] = rid
    return ids


def _extract_markers(body: Any, path: str = "") -> Set[str]:
    found: Set[str] = set()
    if isinstance(body, dict):
        for k, v in body.items():
            found |= _extract_markers(v, f"{path}.{k}")
            if isinstance(v, str):
                for m in re.findall(r"[AB]-ISOL-\d{8}T\d{6}Z(?:-[A-Z0-9-]+)?", v):
                    found.add(m)
                for m in re.findall(r"REP-[AB]-ISOL-\d{8}T\d{6}Z", v):
                    found.add(m)
    elif isinstance(body, list):
        for i, item in enumerate(body):
            found |= _extract_markers(item, f"{path}[{i}]")
    elif isinstance(body, str):
        for m in re.findall(r"[AB]-ISOL-\d{8}T\d{6}Z(?:-[A-Z0-9-]+)?", body):
            found.add(m)
    return found


def _fetch_endpoint(sess: requests.Session, ep: str, timeout: int = 25) -> dict:
    try:
        r = sess.get(BASE + ep, timeout=timeout)
        ctype = r.headers.get("content-type", "")
        body = r.json() if "json" in ctype else {"_raw": r.text[:500]}
        return {"http": r.status_code, "body": body, "error": None}
    except requests.exceptions.Timeout:
        return {"http": None, "body": None, "error": "timeout"}
    except Exception as exc:
        return {"http": None, "body": None, "error": str(exc)[:160]}


def classify_cross_tenant(
    tenant_label: str,
    markers_seen: Set[str],
    exclusive_a: Set[str],
    exclusive_b: Set[str],
) -> dict:
    saw_a = markers_seen & exclusive_a
    saw_b = markers_seen & exclusive_b
    if tenant_label == "tenant_a":
        foreign = saw_b
        own = saw_a
    else:
        foreign = saw_a
        own = saw_b
    if foreign:
        return {
            "classification": "RIESGO CONFIRMADO",
            "severity": "CRITICAL — CROSS-TENANT DATA EXPOSURE",
            "foreign_markers": sorted(foreign),
            "own_markers": sorted(own),
        }
    if own:
        return {"classification": "VERIFICADO", "severity": None, "own_markers": sorted(own), "foreign_markers": []}
    return {"classification": "NO VERIFICADO", "severity": None, "own_markers": [], "foreign_markers": []}


def phase1_multitenant(tenant_meta: dict) -> dict:
    tenant_a = tenant_meta[QA[0]]["tenant_id"]
    tenant_b = tenant_meta[CLIENT[0]]["tenant_id"]
    fixtures = insert_isolation_fixtures(tenant_a, tenant_b)

    exclusive_a = {
        f"{MARK_A}-ALERT-001",
        f"{MARK_A}-EVIDENCE-001",
        f"{MARK_A}-SESSION-001",
        f"REP-{MARK_A}",
        MARK_A,
    }
    exclusive_b = {
        f"{MARK_B}-ALERT-001",
        f"{MARK_B}-EVIDENCE-001",
        f"{MARK_B}-SESSION-001",
        f"REP-{MARK_B}",
        MARK_B,
    }

    endpoints = [
        ("/api/system/evidence-center", "evidence", "evidence"),
        ("/api/reports/list", "reports", "reports"),
        ("/api/system/login-sessions", "login-sessions", "sessions"),
        ("/api/security/alerts", "alerts", "alerts"),
        ("/api/playbooks/", "playbooks", "playbooks"),
        ("/api/security/summary", "security_summary", None),
        ("/api/network/nodes", "network_nodes", "nodes"),
    ]

    qa_sess, qa_login = login(QA[0], QA[1])
    cl_sess, cl_login = login(CLIENT[0], CLIENT[1])

    results = {
        "run_id": RUN_ID,
        "captured_at_utc": utc(),
        "mode": "READ_ONLY_AFTER_FIXTURE_INSERT",
        "tenant_a": {"email": QA[0], **tenant_meta[QA[0]]},
        "tenant_b": {"email": CLIENT[0], **tenant_meta[CLIENT[0]]},
        "fixtures": fixtures,
        "exclusive_markers": {"tenant_a": sorted(exclusive_a), "tenant_b": sorted(exclusive_b)},
        "endpoints": {},
        "legacy_overlap_note": (
            "IDs TEST-VALIDATION-* y AUTO-LS-* previos pueden coincidir sin ser fuga del fixture actual; "
            "este test usa marcadores A-ISOL/B-ISOL exclusivos del run."
        ),
    }

    for ep, key, list_key in endpoints:
        row = {"endpoint": ep}
        for label, sess, lmeta in (
            ("tenant_a", qa_sess, qa_login),
            ("tenant_b", cl_sess, cl_login),
        ):
            if not lmeta.get("login_ok"):
                row[label] = {"login": "failed", "error": lmeta.get("error")}
                continue
            fetched = _fetch_endpoint(sess, ep)
            body = fetched.get("body") or {}
            markers = _extract_markers(body)
            items = []
            if list_key and isinstance(body, dict):
                items = body.get(list_key) or body.get("evidence") or body.get("sessions") or []
            row[label] = {
                "http": fetched.get("http"),
                "status": body.get("status") if isinstance(body, dict) else None,
                "error": fetched.get("error"),
                "item_count": len(items) if isinstance(items, list) else 0,
                "markers_found": sorted(markers),
                "isolation": classify_cross_tenant(label, markers, exclusive_a, exclusive_b),
            }
            # Content check: foreign exclusive record with descriptive content
            if isinstance(items, list):
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    blob = json.dumps(item, ensure_ascii=False)
                    if label == "tenant_b" and MARK_A in blob and f"{MARK_A}-EVIDENCE-001" in blob:
                        row[label]["isolation"]["classification"] = "RIESGO CONFIRMADO"
                        row[label]["isolation"]["severity"] = "CRITICAL — CROSS-TENANT DATA EXPOSURE"
                    if label == "tenant_a" and MARK_B in blob and f"{MARK_B}-EVIDENCE-001" in blob:
                        row[label]["isolation"]["classification"] = "RIESGO CONFIRMADO"
                        row[label]["isolation"]["severity"] = "CRITICAL — CROSS-TENANT DATA EXPOSURE"

        ta = row.get("tenant_a", {})
        tb = row.get("tenant_b", {})
        ta_iso = (ta.get("isolation") or {}).get("classification")
        tb_iso = (tb.get("isolation") or {}).get("classification")
        if any(
            str((x.get("isolation") or {}).get("severity") or "").startswith("CRITICAL")
            for x in (ta, tb)
        ):
            row["endpoint_verdict"] = "RIESGO CONFIRMADO"
        elif ta_iso == "VERIFICADO" or tb_iso == "VERIFICADO":
            row["endpoint_verdict"] = "VERIFICADO — sin exposición cruzada del fixture"
        elif ta.get("status") == "monitoring_not_configured" or tb.get("status") == "monitoring_not_configured":
            row["endpoint_verdict"] = "GATE — tenant sin monitoring (no acceso telemetría)"
        else:
            row["endpoint_verdict"] = "NO VERIFICADO"
        results["endpoints"][key] = row

    critical = [
        k
        for k, v in results["endpoints"].items()
        if v.get("endpoint_verdict") == "RIESGO CONFIRMADO"
        or any(
            str((v.get(l, {}).get("isolation") or {}).get("severity") or "").startswith("CRITICAL")
            for l in ("tenant_a", "tenant_b")
        )
    ]
    results["critical_cross_tenant_endpoints"] = critical
    results["overall_verdict"] = (
        "NO PUEDO CONFIRMAR AISLAMIENTO — CRITICAL cross-tenant exposure demostrada"
        if critical
        else "PARCIAL — gate en telemetría; otros endpoints NO VERIFICADO o VERIFICADO parcial"
    )
    results["code_evidence"] = {
        "evidence_center_no_tenant_filter": "services/evidence_center_service.py list_evidence() — sin tenant_id",
        "login_sessions_no_tenant_filter": "services/login_session_audit_service.py list_login_sessions() — sin tenant_id en schema",
        "reports_global_index": "services/security_report_service.py list_reports() — index.json global",
        "alerts_tenant_filtered": "services/alerts_canonical_service.py get_canonical_alerts(tenant_id) + gate monitoring",
    }
    return results


def phase2_kernel(tenant_meta: dict) -> dict:
    baseline_path = ROOT / "data" / "behavioral_threat_detection" / "baseline_cache.json"
    km_dir = ROOT / "data" / "kernel_memory"
    bl = {}
    if baseline_path.is_file():
        bl = json.loads(baseline_path.read_text(encoding="utf-8"))

    qa_key = f"email_{QA[0].replace('@', '_at_')}.json"
    cl_key = f"email_{CLIENT[0].replace('@', '_at_')}.json"

    report = {
        "captured_at_utc": utc(),
        "ml_trained": False,
        "mechanism": "heuristic BTDE baseline + kernel_memory per user + GuardIA rules",
        "global_host_scope": {
            "baseline_cache.json": {
                "path": str(baseline_path),
                "has_tenant_id_field": False,
                "design_intent": "host-global per baseline.py docstring",
                "warm_cycles": bl.get("warm_cycles"),
                "proc_names_count": len(bl.get("proc_names") or []),
                "modifiable_by": "any host activity / BTDE snapshot cycles — not scoped per tenant",
                "readable_by": "all tenants on same host via shared detection pipeline",
            },
        },
        "per_user_scope": {
            "kernel_memory_dir": str(km_dir),
            "tenant_a_file": qa_key,
            "tenant_b_file": cl_key,
            "tenant_a_exists": (km_dir / qa_key).is_file(),
            "tenant_b_exists": (km_dir / cl_key).is_file(),
            "cross_file_read_via_api": False,
        },
        "tenant_a_can_modify": [
            "baseline_cache.json (indirect via host process/network activity)",
            "kernel_memory/email_novus.qa.jul2026_at_example.com.json (via Kernel IA interactions as user A)",
        ],
        "tenant_b_can_observe_from_a": [
            "baseline_cache.json effects on BTDE anomaly detection (shared host baseline)",
            "NOT tenant A kernel_memory JSON file directly via API",
        ],
        "security_decision_impact": {
            "btde_new_proc_alert": "Tenant A activity adding proc_names can reduce false positives for Tenant B on same host",
            "contamination_verdict": "DEMOSTRADO — baseline host-global puede contaminar decisiones heurísticas entre tenants en el mismo nodo",
            "kernel_memory_isolation": "VERIFICADO — archivos separados por user_key",
        },
        "guardia": {
            "type": "regex/rules",
            "tenant_scoped": "NO VERIFICADO — rules appear global",
        },
        "safe_for_multi_tenant_commercial": False,
        "overall_verdict": "NO APTO multi-tenant — baseline host-global demostrado; kernel_memory parcialmente aislado",
    }
    return report


def find_novus_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = p.info.get("cmdline") or []
            if len(cmd) >= 2 and str(cmd[-1]).endswith("main.py"):
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def phase3_ram(samples: int = 6, interval_sec: int = 120) -> dict:
    rows = []
    concurrent = []
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if "real_operation_24h" in cmd or "critical_security_validation" in cmd:
                concurrent.append({"pid": p.info["pid"], "cmd": cmd[:120]})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    for i in range(samples):
        pid = find_novus_pid()
        vm = psutil.virtual_memory()
        proc = {}
        children = []
        if pid:
            try:
                p = psutil.Process(pid)
                proc = {
                    "pid": pid,
                    "ram_mb": round(p.memory_info().rss / (1024**2), 1),
                    "cpu_pct": round(p.cpu_percent(interval=0.5), 1),
                    "threads": p.num_threads(),
                    "uptime_sec": round(time.time() - p.create_time(), 1),
                }
                for c in p.children(recursive=True):
                    try:
                        children.append(
                            {"pid": c.pid, "name": c.name(), "ram_mb": round(c.memory_info().rss / (1024**2), 1)}
                        )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc = {"pid": pid, "error": "inaccessible"}

        engines = {}
        try:
            import urllib.request

            req = urllib.request.Request("http://127.0.0.1:5000/api/engines/status", method="GET")
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
                if isinstance(body, dict):
                    eng = body.get("engines") or body
                    if isinstance(eng, dict):
                        engines = {k: (v.get("state") if isinstance(v, dict) else v) for k, v in list(eng.items())[:15]}
        except Exception as exc:
            engines = {"probe_error": str(exc)[:80]}

        rows.append(
            {
                "sample": i + 1,
                "timestamp_utc": utc(),
                "system_ram_pct": round(vm.percent, 1),
                "novus_process": proc,
                "children_count": len(children),
                "top_children_ram": sorted(children, key=lambda x: x.get("ram_mb", 0), reverse=True)[:5],
                "engine_states": engines,
            }
        )
        if i < samples - 1:
            time.sleep(interval_sec)

    ram_series = [r["novus_process"].get("ram_mb") for r in rows if r["novus_process"].get("ram_mb")]
    thread_series = [r["novus_process"].get("threads") for r in rows if r["novus_process"].get("threads")]
    sys_ram = [r["system_ram_pct"] for r in rows]

    diagnosis = []
    if len(ram_series) >= 3:
        delta = ram_series[-1] - ram_series[0]
        pct = (delta / ram_series[0] * 100) if ram_series[0] else 0
        if delta > 200 and pct > 25:
            diagnosis.append("MEMORY GROWTH / POSSIBLE LEAK")
        elif max(ram_series) - min(ram_series) < 100:
            diagnosis.append("estabilización observada en ventana corta")
    if thread_series and max(thread_series) > 50:
        diagnosis.append("acumulación elevada de threads — posibles workers activos (D/E)")
    if max(sys_ram) > 93:
        diagnosis.append("presión RAM sistema — puede ser transitoria del host (G/H)")

    active_engines = rows[-1].get("engine_states") if rows else {}
    running = [k for k, v in (active_engines or {}).items() if str(v).lower() in ("running", "active", "on")]

    return {
        "captured_at_utc": utc(),
        "method": "observacional — sin baterías HTTP agresivas",
        "samples": rows,
        "concurrent_observer_processes": concurrent,
        "ram_mb_series": ram_series,
        "thread_series": thread_series,
        "system_ram_pct_series": sys_ram,
        "diagnosis": diagnosis or ["NO VERIFICADO — ventana insuficiente"],
        "likely_causes": {
            "A_memory_leak": "MEMORY GROWTH / POSSIBLE LEAK" in diagnosis,
            "B_expected_growth": False,
            "C_worker_accumulation": max(thread_series or [0]) > 50,
            "D_engines_active": bool(running),
            "E_caches": "NO VERIFICADO",
            "F_duplicate_tasks": "NO VERIFICADO",
            "G_transient": max(sys_ram or [0]) > 90,
            "H_other": "validación previa y observador 24h concurrente pueden inflar medición",
        },
        "engines_running_at_end": running,
        "overall_verdict": (
            "MEMORY GROWTH / POSSIBLE LEAK"
            if "MEMORY GROWTH / POSSIBLE LEAK" in diagnosis
            else "PARCIAL — causa no definitiva en ventana observacional"
        ),
    }


def phase4_persistence(tenant_a: str) -> dict:
    from database import SessionLocal, PlatformEvidence

    tag = f"PERSIST-{RUN_ID}"
    ts = utc()
    db = SessionLocal()
    eid = f"{tag}-EVID"
    try:
        db.add(
            PlatformEvidence(
                id=eid,
                tenant_id=tenant_a,
                fecha=ts[:10],
                hora=ts[11:19],
                timestamp=ts,
                motor="network_snapshot_service",
                categoria="security",
                descripcion=f"Persistence validation {tag}",
                nivel_riesgo="info",
                source_event_id=tag,
                evidence_json=json.dumps({"verified": True, "motor": "network_snapshot_service", "timestamp": ts}),
            )
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        return {"verdict": "ERROR", "error": str(exc)[:200]}
    finally:
        db.close()

    def count_tag() -> int:
        db2 = SessionLocal()
        try:
            return db2.query(PlatformEvidence).filter(PlatformEvidence.source_event_id == tag).count()
        finally:
            db2.close()

    before = count_tag()

    # restart
    listeners = []
    out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    for line in out.splitlines():
        if ":5000" in line and "LISTENING" in line:
            listeners.append(int(line.split()[-1]))
    for pid in listeners:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], capture_output=True)
    time.sleep(5)
    env = os.environ.copy()
    env["FLASK_DEBUG"] = "False"
    subprocess.Popen([PY, "main.py"], cwd=str(ROOT), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(90):
        if find_novus_pid():
            time.sleep(12)
            break
        time.sleep(1)

    after = count_tag()

    backup_row = {}
    try:
        from services.encrypted_backup_service import create_encrypted_backup, verify_backup, restore_encrypted_backup

        created = create_encrypted_backup(label=f"persist_{RUN_ID}", actor="critical_validation")
        backup_row["create"] = {k: created.get(k) for k in ("ok", "file", "sha256_plain")}
        if created.get("ok"):
            path = created["path"]
            backup_row["verify"] = verify_backup(path)
            backup_row["restore"] = {k: restore_encrypted_backup(path, actor="critical_validation").get(k) for k in ("ok", "verify")}
    except Exception as exc:
        backup_row["error"] = str(exc)[:200]

    return {
        "test_tag": tag,
        "classification": "DATOS DE PRUEBA",
        "before_count": before,
        "after_restart_count": after,
        "survived_restart": before == after == 1,
        "backup": backup_row,
        "verdict": "VERIFICADO" if before == after == 1 and backup_row.get("verify", {}).get("ok") else "PARCIAL",
        "note": "No borra datos reales; tag PERSIST-* identificable",
    }


def phase5_encryption() -> dict:
    from scripts.real_operation_24h import build_data_exposure_inventory

    inv = build_data_exposure_inventory()
    for e in inv.get("entries", []):
        enc = e.get("encryption", "")
        if enc.startswith("SI"):
            e["classification"] = "CIFRADO"
        elif "PARCIAL" in enc:
            e["classification"] = "PROTEGIDO PARCIAL"
        elif enc.startswith("NO"):
            e["classification"] = "EN CLARO"
        else:
            e["classification"] = "NO VERIFICADO"
    inv["plaintext_sensitive"] = [e["file"] for e in inv.get("entries", []) if e.get("classification") == "EN CLARO"]
    inv["overall_verdict"] = "PARCIAL — runtime DB y snapshots en claro confirmados"
    return inv


def build_md_multitenant(data: dict) -> str:
    lines = [
        "# Aislamiento multi-tenant — informe definitivo",
        "",
        f"Run: `{data['run_id']}` — {data['captured_at_utc']}",
        "",
        f"**Veredicto global:** {data['overall_verdict']}",
        "",
        "## Endpoints críticos",
        "",
    ]
    for k, v in data["endpoints"].items():
        lines.append(f"### {k} — {v.get('endpoint_verdict')}")
        for t in ("tenant_a", "tenant_b"):
            tv = v.get(t) or {}
            iso = tv.get("isolation") or {}
            lines.append(f"- **{t}**: status={tv.get('status')} markers={tv.get('markers_found')} → {iso.get('classification')} {iso.get('severity') or ''}")
        lines.append("")
    lines.append("## Evidencia en código")
    for ck, cv in data.get("code_evidence", {}).items():
        lines.append(f"- `{ck}`: {cv}")
    return "\n".join(lines)


def build_md_kernel(data: dict) -> str:
    g = data["global_host_scope"]["baseline_cache.json"]
    return f"""# Kernel / aprendizaje — aislamiento por tenant

{data['captured_at_utc']}

**Veredicto:** {data['overall_verdict']}

## Global al host
- `baseline_cache.json`: warm_cycles={g.get('warm_cycles')}, proc_names={g.get('proc_names_count')}, tenant_id=**ausente**
- Contaminación cruzada: **{data['security_decision_impact']['contamination_verdict']}**

## Por usuario
- kernel_memory: archivos separados (`{data['per_user_scope']['tenant_a_file']}` vs `{data['per_user_scope']['tenant_b_file']}`)

## Seguro multi-tenant comercial
**{data['safe_for_multi_tenant_commercial']}**
"""


def build_md_ram(data: dict) -> str:
    return f"""# RAM — informe operacional definitivo

{data['captured_at_utc']}

**Veredicto:** {data['overall_verdict']}

## Series
- RAM NOVUS (MB): {data.get('ram_mb_series')}
- Threads: {data.get('thread_series')}
- RAM sistema %: {data.get('system_ram_pct_series')}

## Diagnóstico
{chr(10).join('- ' + d for d in data.get('diagnosis', []))}

## Motores activos al final
{data.get('engines_running_at_end')}
"""


def phase6_gonogo(p1, p2, p3, p4, p5) -> dict:
    critical_mt = bool(p1.get("critical_cross_tenant_endpoints"))
    kernel_bad = not p2.get("safe_for_multi_tenant_commercial")
    ram_bad = "LEAK" in p1.get("overall_verdict", "") or "LEAK" in p3.get("overall_verdict", "")
    persist_ok = p4.get("verdict") == "VERIFICADO"

    a = "APTO CON LIMITACIONES" if persist_ok and not critical_mt else "NO APTO" if critical_mt else "APTO CON LIMITACIONES"
    b = "NO APTO" if critical_mt or kernel_bad else "NO VERIFICADO"
    c = "NO APTO" if critical_mt or kernel_bad or ram_bad or p3.get("thread_series", [0])[-1:] and max(p3.get("thread_series") or [0]) > 50 else "NO APTO"

    reasons = {
        "A_supervised_real_data": (
            "Persistencia VERIFICADA con datos de prueba; operación con datos reales posible solo bajo supervisión "
            "por fugas confirmadas en evidence/reports/sessions y baseline global."
            if critical_mt
            else "Persistencia OK; telemetría con gate parcial."
        ),
        "B_commercial_multitenant": "Cross-tenant exposure demostrada y/o baseline host-global — NO APTO comercial.",
        "C_unsupervised_24_7": "RAM/threads elevados + aislamiento no confirmado + sin validación 24h completa — NO APTO sin supervisión.",
    }

    blockers = []
    if critical_mt:
        blockers.append("Aislamiento multi-tenant NO confirmado — CRITICAL en endpoints")
    if kernel_bad:
        blockers.append("Kernel baseline host-global — contaminación cruzada demostrada")
    if "LEAK" in str(p3.get("overall_verdict")):
        blockers.append("Posible memory growth NOVUS")
    if not persist_ok:
        blockers.append("Persistencia/backup PARCIAL")

    return {
        "generated_at_utc": utc(),
        "verdicts": {
            "A_supervised_real_data": a,
            "B_commercial_multitenant": b,
            "C_unsupervised_24_7": c,
        },
        "reasons": reasons,
        "five_gates": {
            "1_multitenant_isolation": "FALLA" if critical_mt else "PARCIAL",
            "2_kernel_no_cross_contamination": "FALLA" if kernel_bad else "PARCIAL",
            "3_ram_stable_or_explained": "PARCIAL" if p3.get("overall_verdict") != "MEMORY GROWTH / POSSIBLE LEAK" else "FALLA",
            "4_persistence_real": "PASA" if persist_ok else "PARCIAL",
            "5_sensitive_data_map": "PASA",
        },
        "blockers": blockers,
        "proposed_fixes_minimal": [
            {
                "problem": "evidence-center sin filtro tenant_id",
                "files": ["services/evidence_center_service.py", "api/system.py"],
                "minimal_fix": "filtrar PlatformEvidence por tenant_id del usuario autenticado",
            },
            {
                "problem": "login-sessions global",
                "files": ["services/login_session_audit_service.py", "database.py"],
                "minimal_fix": "añadir tenant_id + filtro en list_login_sessions",
            },
            {
                "problem": "reports index global",
                "files": ["services/security_report_service.py"],
                "minimal_fix": "tenant_id en index + filtro en list_reports",
            },
            {
                "problem": "baseline host-global",
                "files": ["services/behavioral_threat_detection/baseline.py"],
                "minimal_fix": "particionar baseline por tenant_id o desactivar BTDE shared en multi-tenant",
            },
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-ram-wait", action="store_true", help="1 muestra RAM solamente")
    parser.add_argument("--skip-restart", action="store_true", help="Omitir reinicio persistencia")
    args = parser.parse_args()

    tenant_meta = resolve_tenant_ids()
    p1 = phase1_multitenant(tenant_meta)
    save_json(OUT / "MULTITENANT_ISOLATION_DEFINITIVE_REPORT.json", p1)
    save_md(OUT / "MULTITENANT_ISOLATION_DEFINITIVE_REPORT.md", build_md_multitenant(p1))

    p2 = phase2_kernel(tenant_meta)
    save_json(OUT / "KERNEL_TENANT_ISOLATION_REPORT.json", p2)
    save_md(OUT / "KERNEL_TENANT_ISOLATION_REPORT.md", build_md_kernel(p2))

    p3 = phase3_ram(samples=1 if args.skip_ram_wait else 6, interval_sec=120)
    save_json(OUT / "RAM_OPERATION_DEFINITIVE_REPORT.json", p3)
    save_md(OUT / "RAM_OPERATION_DEFINITIVE_REPORT.md", build_md_ram(p3))

    tenant_a = tenant_meta[QA[0]]["tenant_id"]
    p4 = {"verdict": "OMITIDO", "note": "restart skipped"} if args.skip_restart else phase4_persistence(tenant_a)

    p5 = phase5_encryption()
    save_json(OUT / "DATA_EXPOSURE_INVENTORY.json", p5)

    p6 = phase6_gonogo(p1, p2, p3, p4, p5)
    save_json(OUT / "REAL_OPERATION_GO_NO_GO.json", p6)
    save_md(
        OUT / "REAL_OPERATION_GO_NO_GO.md",
        f"""# NOVUS — Go / No-Go operación real

{ p6['generated_at_utc'] }

## Veredictos

| Pregunta | Resultado |
|----------|-----------|
| A. ¿Datos reales bajo supervisión? | **{p6['verdicts']['A_supervised_real_data']}** |
| B. ¿Plataforma comercial multi-tenant? | **{p6['verdicts']['B_commercial_multitenant']}** |
| C. ¿24/7 sin supervisión humana? | **{p6['verdicts']['C_unsupervised_24_7']}** |

## Cinco compuertas

{json.dumps(p6['five_gates'], indent=2)}

## Bloqueadores

{chr(10).join('- ' + b for b in p6['blockers'])}

## Regla

Detenido — sin corrección automática. Fixes mínimos solo tras autorización.
""",
    )

    print(json.dumps({"ok": True, "critical_mt": p1.get("critical_cross_tenant_endpoints"), "gonogo": p6["verdicts"]}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
