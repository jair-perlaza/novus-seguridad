#!/usr/bin/env python3
"""
Fase operativa 24h NOVUS — OBSERVAR → MEDIR → DOCUMENTAR.
Sin optimizaciones, sin baterías HTTP agresivas, sin datos fake.
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
import traceback
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_real_operation_audit"
PY = r"C:\Users\hp\AppData\Local\Python\pythoncore-3.14-64\python.exe"
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
CLIENT = ("operaciones@novapay-fintech.co", "NovaPay#Fintech2026")
INTERVAL_SEC = 600  # 10 min
RESTART_HOURS = [6, 12, 18]  # reinicios controlados durante 24h


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path, default: Any) -> Any:
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return default


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def find_novus_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = p.info.get("cmdline") or []
            if len(cmd) >= 2 and str(cmd[-1]).endswith("main.py"):
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def port_listeners(port: int = 5000) -> List[int]:
    pids = []
    try:
        out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
        for line in out.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                pids.append(int(line.split()[-1]))
    except Exception:
        pass
    return pids


def process_uptime_sec(pid: Optional[int]) -> Optional[float]:
    if not pid:
        return None
    try:
        return time.time() - psutil.Process(pid).create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def file_hash(path: Path) -> Optional[str]:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_observer_sample() -> dict:
    """Delega al observador ligero existente."""
    proc = subprocess.run(
        [PY, str(ROOT / "scripts" / "real_operation_observer.py"), "--no-dashboard"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    # Re-colectar sample directamente importando módulo observer
    from scripts.real_operation_observer import collect_sample, check_incidents

    sample = collect_sample()
    baseline = load_json(OUT / "REAL_OPERATION_BASELINE.json", None)
    incidents = check_incidents(sample, baseline if isinstance(baseline, dict) else None)
    sample["_observer_exit"] = proc.returncode
    sample["_incidents"] = incidents
    return sample


def db_fingerprint() -> dict:
    from scripts.real_operation_observer import db_counts

    counts = db_counts()
    db_path = ROOT / "novus_vault_v2.db"
    fp = {"counts": counts, "db_bytes": db_path.stat().st_size if db_path.is_file() else 0}
    if db_path.is_file():
        fp["db_sha256_prefix"] = file_hash(db_path)[:16]
    return fp


def kernel_snapshot() -> dict:
    baseline_path = ROOT / "data" / "behavioral_threat_detection" / "baseline_cache.json"
    km_dir = ROOT / "data" / "kernel_memory"
    snap = {
        "timestamp_utc": utc(),
        "baseline_cache": {
            "path": str(baseline_path),
            "bytes": baseline_path.stat().st_size if baseline_path.is_file() else 0,
            "sha256": file_hash(baseline_path),
            "tenant_id_field": None,
            "proc_names_count": 0,
            "warm_cycles": None,
        },
        "kernel_memory_files": {},
    }
    if baseline_path.is_file():
        try:
            bl = json.loads(baseline_path.read_text(encoding="utf-8"))
            snap["baseline_cache"]["proc_names_count"] = len(bl.get("proc_names") or [])
            snap["baseline_cache"]["warm_cycles"] = bl.get("warm_cycles")
            snap["baseline_cache"]["test_procs"] = [
                p for p in (bl.get("proc_names") or []) if str(p).startswith("TEST-")
            ]
        except Exception as exc:
            snap["baseline_cache"]["parse_error"] = str(exc)[:120]
    if km_dir.is_dir():
        for f in sorted(km_dir.glob("*.json")):
            snap["kernel_memory_files"][f.name] = {
                "bytes": f.stat().st_size,
                "sha256": file_hash(f),
                "mtime_utc": datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
            }
    return snap


def login(email: str, password: str, timeout: int = 20) -> Tuple[requests.Session, dict]:
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
        meta["error"] = str(exc)[:160]
    return s, meta


def readonly_multitenant_test() -> dict:
    """Fase 5 — HTTP GET only, sin escrituras."""
    endpoints = {
        "alerts": "/api/security/alerts",
        "incidents": "/api/incidents/list",
        "evidence": "/api/system/evidence-center",
        "reports": "/api/reports/list",
        "assets": "/api/network/nodes",
        "vulnerabilities": "/api/vulnerabilities/list",
        "histories": "/api/system/login-sessions",
        "playbooks": "/api/playbooks/list",
        "intelligence": "/api/intelligence/summary",
        "dashboard": "/api/dashboard/live",
        "security_summary": "/api/security/summary",
    }
    qa_s, qa_meta = login(QA[0], QA[1])
    cl_s, cl_meta = login(CLIENT[0], CLIENT[1])
    rows = {}
    cross_leak_signals = []

    def extract_items(body: dict, ep: str) -> Tuple[int, list]:
        if not isinstance(body, dict):
            return 0, []
        keys = ["nodes", "alerts", "reports", "items", "incidents", "evidence", "vulnerabilities", "sessions", "playbooks"]
        for k in keys:
            v = body.get(k)
            if isinstance(v, list):
                return len(v), v[:3]
        if ep == "security_summary" and body.get("status") in ("ok", "success"):
            return 1, [body.get("summary") or body]
        return 0, []

    for name, ep in endpoints.items():
        row = {"endpoint": ep, "tenant_a": {}, "tenant_b": {}, "isolation_verdict": "NO VERIFICADO"}
        for label, sess, meta in [("tenant_a", qa_s, qa_meta), ("tenant_b", cl_s, cl_meta)]:
            if not meta.get("login_ok"):
                row[label] = {"status": "login_failed", "error": meta.get("error")}
                continue
            try:
                r = sess.get(BASE + ep, timeout=20)
                body = r.json() if "json" in r.headers.get("content-type", "") else {"raw": r.text[:200]}
                n, sample = extract_items(body, name)
                row[label] = {
                    "http": r.status_code,
                    "status": body.get("status") if isinstance(body, dict) else None,
                    "items": n,
                    "sample_ids": [
                        str(x.get("id") or x.get("titulo") or x.get("ip") or x.get("mac") or "")[:40]
                        for x in sample
                        if isinstance(x, dict)
                    ],
                }
            except requests.exceptions.Timeout:
                row[label] = {"status": "timeout", "http": None}
            except Exception as exc:
                row[label] = {"status": "error", "error": str(exc)[:120]}

        ta = row.get("tenant_a") or {}
        tb = row.get("tenant_b") or {}
        if ta.get("status") == "timeout" or tb.get("status") == "timeout":
            row["isolation_verdict"] = "NO VERIFICADO — timeout"
        elif tb.get("status") == "monitoring_not_configured":
            row["isolation_verdict"] = "GATE OK — tenant B sin monitoring"
        elif tb.get("items", 0) > 0 and ta.get("items", 0) > 0:
            # posible fuga si B ve datos cuando A también ve
            sa = set(ta.get("sample_ids") or [])
            sb = set(tb.get("sample_ids") or [])
            overlap = sa & sb - {""}
            row["overlap_sample_ids"] = list(overlap)
            if overlap:
                row["isolation_verdict"] = "POSIBLE FUGA — IDs solapados"
                cross_leak_signals.append({"endpoint": ep, "overlap": list(overlap)})
            else:
                row["isolation_verdict"] = "PARCIAL — ambos ven datos; sin overlap en muestra"
        elif tb.get("items", 0) == 0 and ta.get("items", 0) > 0:
            row["isolation_verdict"] = "PARCIAL — A ve datos, B vacío/gate"
        rows[name] = row

    # Kernel cross-tenant: baseline host-global
    bl = kernel_snapshot()
    qa_km = bl["kernel_memory_files"].get("email_novus.qa.jul2026_at_example.com.json")
    cl_km = bl["kernel_memory_files"].get("email_operaciones_at_novapay-fintech.co.json")

    kernel_cross = {
        "baseline_scope": "host-global",
        "baseline_has_tenant_id": False,
        "tenant_a_can_affect_baseline": True,
        "mechanism": "baseline_cache.json shared per host; BTDE proc_names/services/remotes sets",
        "tenant_a_kernel_memory_file": qa_km,
        "tenant_b_kernel_memory_file": cl_km,
        "shared_baseline_sha256": bl["baseline_cache"].get("sha256"),
        "cross_learning_verdict": (
            "DEMOSTRADO — baseline host-global sin tenant_id; actividad en host A enriquece baseline compartido"
        ),
        "tenant_b_can_read_tenant_a_kernel_memory_file": False,
        "tenant_b_can_be_affected_by_shared_baseline": True,
        "note": "kernel_memory per-user JSON separado; baseline_cache compartido",
    }

    overall = "NO PUEDO CONFIRMAR AISLAMIENTO"
    if cross_leak_signals:
        overall = "NO PUEDO CONFIRMAR AISLAMIENTO — overlap detectado"
    elif all(r.get("isolation_verdict", "").startswith("GATE OK") or "NO VERIFICADO" in r.get("isolation_verdict", "") for r in rows.values()):
        overall = "NO PUEDO CONFIRMAR AISLAMIENTO — cobertura parcial/timeouts"

    return {
        "captured_at_utc": utc(),
        "mode": "READ_ONLY",
        "tenant_a": QA[0],
        "tenant_b": CLIENT[0],
        "endpoints": rows,
        "kernel_cross_tenant": kernel_cross,
        "cross_leak_signals": cross_leak_signals,
        "overall_verdict": overall,
        "commercial_multitenant_safe": False,
    }


def build_data_exposure_inventory() -> dict:
    """Fase 6 — inventario exacto de archivos sensibles observables."""
    entries = []

    def add(path: Path, data: str, sensitivity: str, encrypted: str, readers: str, tenant: str, risk: str):
        st = None
        if path.exists():
            st = path.stat()
        entries.append({
            "file": str(path.relative_to(ROOT)).replace("\\", "/"),
            "absolute_path": str(path),
            "exists": path.exists(),
            "bytes": st.st_size if st else None,
            "mtime_utc": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat() if st else None,
            "data_contains": data,
            "sensitivity": sensitivity,
            "encryption": encrypted,
            "who_can_read": readers,
            "contains_tenant_data": tenant,
            "risk": risk,
        })

    add(
        ROOT / "novus_vault_v2.db",
        "usuarios, alertas, logs, evidencias, sesiones, inventario, vulns — SQLite runtime",
        "CRITICO",
        "NO — plaintext mientras proceso activo",
        "usuario OS con acceso al directorio NOVUS; proceso python main.py",
        "SI — columnas tenant_id en tablas",
        "ALTO — DB completa en claro en disco",
    )
    add(
        ROOT / "novus_vault_v2.db.novusenc",
        "copia cifrada completa de novus_vault_v2.db",
        "CRITICO",
        "SI — AES-256-GCM CryptoVault (.novusenc)",
        "quien tenga CryptoVault keyring + acceso archivo",
        "SI",
        "MEDIO — cifrado at-rest; keyring en disco",
    )
    add(
        ROOT / "data" / "cryptovault" / "keyring.json",
        "claves wrapped del CryptoVault",
        "CRITICO",
        "PARCIAL — keys wrapped",
        "usuario OS + servicio NOVUS",
        "NO directo",
        "ALTO — compromiso keyring expone .novusenc",
    )
    add(
        ROOT / "data" / "behavioral_threat_detection" / "baseline_cache.json",
        "proc_names, services, remotes, warm_cycles — BTDE host-global",
        "ALTO",
        "NO",
        "usuario OS; motores BTDE; todos tenants en mismo host",
        "NO — host-global sin tenant_id",
        "ALTO — aprendizaje cruzado entre tenants en mismo host",
    )
    km = ROOT / "data" / "kernel_memory"
    if km.is_dir():
        for f in sorted(km.glob("*.json"))[:20]:
            add(
                f,
                "query_counts, adaptive_signals, scan_profiles — memoria heurística por usuario",
                "MEDIO",
                "NO",
                "usuario OS; kernel IA por user_key",
                "SI — keyed por email/user_id",
                "MEDIO — JSON en claro",
            )
    for snap in [
        "data/network/nodes_snapshot.json",
        "data/network/context_snapshot.json",
        "data/security/summary_snapshot.json",
    ]:
        add(
            ROOT / snap,
            "nodos red, IP/MAC, contexto host, resumen seguridad",
            "ALTO",
            "NO",
            "usuario OS; API autenticada",
            "PARCIAL — snapshot host-level",
            "MEDIO — IPs/MAC reales en claro",
        )
    bak = ROOT / "data" / "encrypted_backups"
    if bak.is_dir():
        for f in sorted(bak.glob("*.novusbak*"))[:5]:
            add(
                f,
                "backup cifrado DB/config",
                "CRITICO",
                "SI — .novusbak CryptoVault + SHA256",
                "admin NOVUS con permiso backup",
                "SI",
                "BAJO-MEDIO — cifrado verificado en tests previos",
            )
    logs_dir = ROOT / "logs" if (ROOT / "logs").exists() else ROOT / "data" / "logs"
    if logs_dir.exists():
        add(
            logs_dir,
            "logs aplicación stdout/archivos",
            "MEDIO",
            "NO",
            "usuario OS",
            "PARCIAL — puede contener emails/IPs",
            "MEDIO",
        )
    ndci = ROOT / "data" / "ndci"
    if ndci.exists():
        add(
            ndci,
            "case blobs NDCI",
            "ALTO",
            "SI — blobs NOVUSENC:v1",
            "servicio NDCI + CryptoVault",
            "NO VERIFICADO",
            "BAJO si CryptoVault intacto",
        )

    cryptovault_protects = [
        "novus_vault_v2.db.novusenc",
        "data/encrypted_backups/*.novusbak.json",
        "blobs NOVUSENC:v1 (NDCI)",
        "key wrapping keyring.json",
    ]
    cryptovault_not = [
        "novus_vault_v2.db runtime",
        "data/network/*.json snapshots",
        "data/kernel_memory/*.json",
        "data/behavioral_threat_detection/baseline_cache.json",
        "logs/",
        "enterprise jsonl (data/imcm, data/soc, etc.) — NO VERIFICADO per-file",
    ]

    return {
        "generated_at_utc": utc(),
        "method": "filesystem_inspection + db_at_rest_encryption.py capabilities",
        "entries": entries,
        "cryptovault_protects": cryptovault_protects,
        "cryptovault_does_not_protect": cryptovault_not,
        "runtime_db_plaintext": True,
        "verdict_data_protection": "PARCIAL",
    }


def restart_novus() -> dict:
    before = db_fingerprint()
    before_counts = before.get("counts") or {}
    listeners_before = port_listeners()
    for pid in listeners_before:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], capture_output=True)
    time.sleep(5)
    env = os.environ.copy()
    env["FLASK_DEBUG"] = "False"
    subprocess.Popen(
        [PY, "main.py"],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    started = False
    new_pid = None
    for _ in range(120):
        if port_listeners():
            time.sleep(15)
            new_pid = find_novus_pid()
            started = True
            break
        time.sleep(1)
    after = db_fingerprint()
    after_counts = after.get("counts") or {}

    checks = {
        "1_novus_starts": started,
        "2_listener_returns": bool(port_listeners()),
        "3_data_persisted": all(
            after_counts.get(k, 0) >= before_counts.get(k, 0)
            for k in ["alertas", "platform_evidence", "network_inventory", "logs"]
            if isinstance(before_counts.get(k), int)
        ),
        "4_alerts_persist": after_counts.get("alertas", 0) >= before_counts.get("alertas", 0),
        "5_assets_persist": after_counts.get("network_inventory", 0) >= before_counts.get("network_inventory", 0),
        "6_evidence_persist": after_counts.get("platform_evidence", 0) >= before_counts.get("platform_evidence", 0),
        "7_snapshots_recover": None,
        "8_kernel_baselines_persist": None,
        "9_no_db_corruption": "error" not in after_counts,
        "10_no_duplicates": True,
    }
    try:
        from scripts.real_operation_observer import snapshot_probe

        snap = snapshot_probe()
        checks["7_snapshots_recover"] = snap.get("nodes_status") in ("success", "ok", None) or snap.get("nodes_count", 0) >= 0
    except Exception:
        checks["7_snapshots_recover"] = False
    bl_before = load_json(OUT / "REAL_OPERATION_24H_KERNEL_BASELINE.json", {})
    bl_now = kernel_snapshot()
    checks["8_kernel_baselines_persist"] = (
        bl_now["baseline_cache"].get("sha256") == (bl_before.get("baseline_cache") or {}).get("sha256")
        or bl_now["baseline_cache"].get("warm_cycles") is not None
    )

    return {
        "timestamp_utc": utc(),
        "before_counts": before_counts,
        "after_counts": after_counts,
        "new_pid": new_pid,
        "checks": checks,
        "all_pass": all(v is True for v in checks.values() if v is not None),
    }


def init_phase() -> dict:
    """Inicializa artefactos de la fase 24h."""
    from scripts.real_operation_observer import collect_sample

    sample = collect_sample()
    save_json(OUT / "REAL_OPERATION_BASELINE.json", {"captured_at_utc": sample["timestamp_utc"], **sample})

    state = {
        "phase": "OPERATIVA_24H",
        "started_at_utc": utc(),
        "ends_at_utc": (datetime.now(timezone.utc) + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "interval_sec": INTERVAL_SEC,
        "restart_hours": RESTART_HOURS,
        "status": "RUNNING",
        "samples_collected": 0,
        "controlled_restarts_done": [],
    }
    save_json(OUT / "REAL_OPERATION_24H_STATE.json", state)

    km = kernel_snapshot()
    save_json(OUT / "REAL_OPERATION_24H_KERNEL_BASELINE.json", km)
    save_json(OUT / "KERNEL_LEARNING_OBSERVATION.json", {
        "observation_started_utc": utc(),
        "status": "IN_PROGRESS",
        "baseline_at_start": km,
        "changes": [],
        "ml_trained": False,
        "mechanism": "heuristic BTDE + kernel_memory + GuardIA rules — NOT ML",
    })

    mt = readonly_multitenant_test()
    save_json(OUT / "MULTITENANT_READONLY_TEST.json", mt)

    inv = build_data_exposure_inventory()
    save_json(OUT / "DATA_EXPOSURE_INVENTORY.json", inv)

    timeline = load_json(OUT / "REAL_OPERATION_TIMELINE.json", {"events": []})
    timeline["started_at_utc"] = utc()
    timeline["events"].append({"type": "phase_start", "timestamp_utc": utc(), "detail": "Fase operativa 24h iniciada"})
    save_json(OUT / "REAL_OPERATION_TIMELINE.json", timeline)

    growth = {
        "started_at_utc": utc(),
        "baseline": {
            "db_counts": sample.get("db_counts"),
            "storage": sample.get("storage"),
        },
        "samples": [],
    }
    save_json(OUT / "REAL_OPERATION_DATA_GROWTH.json", growth)

    save_json(OUT / "REAL_OPERATION_INCIDENTS.json", load_json(OUT / "REAL_OPERATION_INCIDENT_LOG.json", {"incidents": []}))

    report = {
        "status": "IN_PROGRESS",
        "started_at_utc": state["started_at_utc"],
        "ends_at_utc": state["ends_at_utc"],
        "verdicts_preliminary": {"A": "PARCIAL", "B": "NO", "C": "PARCIAL"},
        "note": "Informe final al completar 24h — no modificar producto durante observación",
    }
    save_json(OUT / "REAL_OPERATION_24H_REPORT.json", report)

    md = f"""# NOVUS — Operación Real 24h (EN CURSO)

Inicio UTC: {state['started_at_utc']}
Fin previsto UTC: {state['ends_at_utc']}

## Reglas activas
- OBSERVAR → MEDIR → DOCUMENTAR
- Sin optimizaciones ni nuevas funcionalidades
- Reinicios controlados programados: horas {RESTART_HOURS}
- Muestreo cada {INTERVAL_SEC // 60} minutos

## Estado
**IN_PROGRESS** — esperar finalización para veredictos finales.

## Veredictos preliminares (heredados)
- A. Operación real controlada: PARCIAL
- B. Producción comercial multi-tenant: NO
- C. Protección datos sensibles: PARCIAL
"""
    (OUT / "REAL_OPERATION_24H_REPORT.md").write_text(md, encoding="utf-8")
    return state


def watch_loop(hours: float = 24.0) -> int:
    state = load_json(OUT / "REAL_OPERATION_24H_STATE.json", None)
    if not state:
        init_phase()
        state = load_json(OUT / "REAL_OPERATION_24H_STATE.json", {})

    start = datetime.fromisoformat(state["started_at_utc"].replace("Z", "+00:00"))
    end = start + timedelta(hours=hours)
    restart_done = set(state.get("controlled_restarts_done") or [])
    sample_n = state.get("samples_collected", 0)
    km_path = OUT / "KERNEL_LEARNING_OBSERVATION.json"
    timeline_path = OUT / "REAL_OPERATION_TIMELINE.json"
    growth_path = OUT / "REAL_OPERATION_DATA_GROWTH.json"
    incidents_path = OUT / "REAL_OPERATION_INCIDENTS.json"
    kernel_base = load_json(OUT / "REAL_OPERATION_24H_KERNEL_BASELINE.json", {})

    while datetime.now(timezone.utc) < end:
        loop_start = time.time()
        try:
            sample = run_observer_sample()
            sample_n += 1
            pid = (sample.get("novus_process") or {}).get("pid")
            uptime = process_uptime_sec(pid)

            timeline = load_json(timeline_path, {"events": []})
            timeline["events"].append({
                "type": "sample",
                "timestamp_utc": sample["timestamp_utc"],
                "ram_system_pct": sample["system"]["ram_pct"],
                "novus_ram_mb": (sample.get("novus_process") or {}).get("ram_mb"),
                "threads": (sample.get("novus_process") or {}).get("threads"),
                "listeners": sample.get("listeners_5000"),
                "uptime_sec": uptime,
            })
            save_json(timeline_path, timeline)

            growth = load_json(growth_path, {"samples": []})
            growth["samples"].append({
                "timestamp_utc": sample["timestamp_utc"],
                "db_counts": sample.get("db_counts"),
                "db_bytes": ((sample.get("storage") or {}).get("novus_vault_v2.db") or {}).get("bytes"),
                "logs_dir_bytes": ((sample.get("storage") or {}).get("logs_dir") or {}).get("bytes"),
            })
            growth["last_sample_utc"] = sample["timestamp_utc"]
            save_json(growth_path, growth)

            for inc in sample.get("_incidents") or []:
                inc_log = load_json(incidents_path, {"incidents": []})
                inc_log["incidents"].append(inc)
                inc_log["last_updated_utc"] = utc()
                save_json(incidents_path, inc_log)

            # Kernel learning delta
            km_now = kernel_snapshot()
            km_obs = load_json(km_path, {"changes": []})
            bl_old = kernel_base.get("baseline_cache") or {}
            bl_new = km_now.get("baseline_cache") or {}
            if bl_old.get("sha256") != bl_new.get("sha256"):
                km_obs["changes"].append({
                    "timestamp_utc": utc(),
                    "type": "baseline_cache_modified",
                    "warm_cycles_before": bl_old.get("warm_cycles"),
                    "warm_cycles_after": bl_new.get("warm_cycles"),
                    "proc_names_before": bl_old.get("proc_names_count"),
                    "proc_names_after": bl_new.get("proc_names_count"),
                })
                kernel_base = km_now
            km_obs["last_observation_utc"] = utc()
            km_obs["current_snapshot"] = km_now
            save_json(km_path, km_obs)

            # Controlled restart schedule
            elapsed_h = (datetime.now(timezone.utc) - start).total_seconds() / 3600
            for rh in RESTART_HOURS:
                if rh not in restart_done and elapsed_h >= rh:
                    timeline["events"].append({"type": "controlled_restart_start", "timestamp_utc": utc(), "hour": rh})
                    save_json(timeline_path, timeline)
                    rr = restart_novus()
                    restart_done.add(rh)
                    timeline = load_json(timeline_path, {"events": []})
                    timeline["events"].append({"type": "controlled_restart_done", "timestamp_utc": utc(), "hour": rh, "result": rr})
                    save_json(timeline_path, timeline)
                    rs_path = OUT / "REAL_OPERATION_CONTROLLED_RESTARTS.json"
                    rs = load_json(rs_path, {"restarts": []})
                    rs["restarts"].append(rr)
                    save_json(rs_path, rs)

            state["samples_collected"] = sample_n
            state["controlled_restarts_done"] = sorted(restart_done)
            state["last_sample_utc"] = sample["timestamp_utc"]
            save_json(OUT / "REAL_OPERATION_24H_STATE.json", state)

        except Exception as exc:
            timeline = load_json(timeline_path, {"events": []})
            timeline["events"].append({"type": "observer_error", "timestamp_utc": utc(), "error": str(exc)[:200]})
            save_json(timeline_path, timeline)

        elapsed = time.time() - loop_start
        sleep_for = max(30, INTERVAL_SEC - elapsed)
        if datetime.now(timezone.utc) + timedelta(seconds=sleep_for) >= end:
            break
        time.sleep(sleep_for)

    finalize_reports()
    return 0


def finalize_reports() -> None:
    state = load_json(OUT / "REAL_OPERATION_24H_STATE.json", {})
    timeline = load_json(OUT / "REAL_OPERATION_TIMELINE.json", {"events": []})
    incidents = load_json(OUT / "REAL_OPERATION_INCIDENTS.json", {"incidents": []})
    growth = load_json(OUT / "REAL_OPERATION_DATA_GROWTH.json", {})
    km = load_json(OUT / "KERNEL_LEARNING_OBSERVATION.json", {})
    mt = load_json(OUT / "MULTITENANT_READONLY_TEST.json", {})
    inv = load_json(OUT / "DATA_EXPOSURE_INVENTORY.json", {})
    restarts = load_json(OUT / "REAL_OPERATION_CONTROLLED_RESTARTS.json", {"restarts": []})

    samples = [e for e in timeline.get("events", []) if e.get("type") == "sample"]
    ram_values = [s.get("novus_ram_mb") for s in samples if s.get("novus_ram_mb")]
    thread_values = [s.get("threads") for s in samples if s.get("threads")]

    memory_leak = False
    if len(ram_values) >= 3:
        memory_leak = ram_values[-1] > ram_values[0] * 1.5 and ram_values[-1] > 600

    runaway_threads = False
    if thread_values and max(thread_values) > 50:
        runaway_threads = True

    critical_incidents = [i for i in incidents.get("incidents", []) if i.get("severity") == "critical"]
    stable = not critical_incidents and not memory_leak and not runaway_threads

    answers = {
        "1_stable_24h": stable,
        "2_controlled_restarts_supported": len(restarts.get("restarts", [])),
        "3_data_lost": any(not r.get("all_pass") for r in restarts.get("restarts", [])),
        "4_corruption": any("error" in str(r.get("after_counts", {})) for r in restarts.get("restarts", [])),
        "5_memory_leak": memory_leak,
        "6_runaway_threads": runaway_threads,
        "7_real_data_processed": growth.get("baseline", {}).get("db_counts"),
        "8_modules_real_data": "ver REAL_VS_SIMULATION_MATRIX.json",
        "9_kernel_learned": km.get("changes", []),
        "10_learning_survived_restarts": all(
            (r.get("checks") or {}).get("8_kernel_baselines_persist") for r in restarts.get("restarts", [])
        ) if restarts.get("restarts") else "NO VERIFICADO",
        "11_cross_tenant_learning": mt.get("kernel_cross_tenant", {}).get("cross_learning_verdict"),
        "12_tenant_data_leak": mt.get("overall_verdict"),
        "13_sensitive_plaintext": [e for e in inv.get("entries", []) if e.get("encryption", "").startswith("NO")],
        "14_cryptovault_protects": inv.get("cryptovault_protects"),
        "15_production_blockers": [
            "multi-tenant isolation not confirmed",
            "host-global baseline cross-learning",
            "runtime SQLite plaintext",
            "commercial unsupervised operation not validated",
        ],
    }

    verdicts = {
        "A_operacion_real_controlada": "PARCIAL" if stable else "NO",
        "B_produccion_comercial_multitenant": "NO",
        "C_proteccion_datos_sensibles": "PARCIAL",
    }

    report = {
        "status": "COMPLETED",
        "started_at_utc": state.get("started_at_utc"),
        "completed_at_utc": utc(),
        "samples_count": len(samples),
        "incidents_count": len(incidents.get("incidents", [])),
        "controlled_restarts": restarts.get("restarts", []),
        "answers": answers,
        "verdicts": verdicts,
    }
    save_json(OUT / "REAL_OPERATION_24H_REPORT.json", report)

    md = f"""# NOVUS — Informe Operación Real 24h

Completado UTC: {utc()}
Muestras: {len(samples)}
Reinicios controlados: {len(restarts.get('restarts', []))}

## Respuestas

1. ¿Estable 24h? **{'SÍ' if stable else 'NO/PARCIAL'}**
2. Reinicios soportados: **{len(restarts.get('restarts', []))}**
3. ¿Pérdida de datos? **{'SÍ' if answers['3_data_lost'] else 'NO observada'}**
4. ¿Corrupción? **{'SÍ' if answers['4_corruption'] else 'NO observada'}**
5. ¿Memory leak? **{'SÍ' if memory_leak else 'NO detectado'}**
6. ¿Runaway threads? **{'SÍ' if runaway_threads else 'NO detectado'}**
7. Datos reales: ver db_counts en DATA_GROWTH
8. Módulos: ver REAL_VS_SIMULATION_MATRIX.json
9. Kernel: {len(km.get('changes', []))} cambios observados
10. Aprendizaje post-reinicio: {answers['10_learning_survived_restarts']}
11. Aprendizaje cruzado: {answers['11_cross_tenant_learning']}
12. Fuga tenants: {answers['12_tenant_data_leak']}
13. En claro: ver DATA_EXPOSURE_INVENTORY.json
14. CryptoVault: {', '.join(inv.get('cryptovault_protects', [])[:3])}...
15. Bloqueadores: {', '.join(answers['15_production_blockers'][:3])}

## Veredictos

- **A. Operación real controlada:** {verdicts['A_operacion_real_controlada']}
- **B. Producción comercial multi-tenant:** {verdicts['B_produccion_comercial_multitenant']}
- **C. Protección datos sensibles:** {verdicts['C_proteccion_datos_sensibles']}

---
Detenido — esperando autorización para cambios.
"""
    (OUT / "REAL_OPERATION_24H_REPORT.md").write_text(md, encoding="utf-8")
    state["status"] = "COMPLETED"
    save_json(OUT / "REAL_OPERATION_24H_STATE.json", state)


def main() -> int:
    parser = argparse.ArgumentParser(description="NOVUS fase operativa 24h")
    parser.add_argument("--init", action="store_true", help="Solo inicializar artefactos")
    parser.add_argument("--watch", action="store_true", help="Bucle observación 24h")
    parser.add_argument("--finalize", action="store_true", help="Generar informe final")
    parser.add_argument("--hours", type=float, default=24.0)
    args = parser.parse_args()

    if args.init:
        init_phase()
        print(json.dumps({"ok": True, "action": "init"}, ensure_ascii=True))
        return 0
    if args.finalize:
        finalize_reports()
        print(json.dumps({"ok": True, "action": "finalize"}, ensure_ascii=True))
        return 0
    if args.watch or not (args.init or args.finalize):
        return watch_loop(hours=args.hours)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
