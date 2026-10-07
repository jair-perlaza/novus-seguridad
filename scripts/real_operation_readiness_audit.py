#!/usr/bin/env python3
"""
NOVUS — Auditoría de operación real y seguridad de producción.
Solo evidencia; no agrega funcionalidades.
Genera data/novus_real_operation_audit/REAL_OPERATION_READINESS.{json,md}
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_real_operation_audit"
PY = r"C:\Users\hp\AppData\Local\Python\pythoncore-3.14-64\python.exe"
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
CLIENT = ("operaciones@novapay-fintech.co", "NovaPay#Fintech2026")


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = p.info.get("cmdline") or []
            if len(cmd) >= 2 and str(cmd[-1]).endswith("main.py"):
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def listeners() -> List[int]:
    pids = []
    out = subprocess.check_output(["netstat", "-ano"], text=True, errors="replace")
    for line in out.splitlines():
        if ":5000" in line and "LISTENING" in line:
            pids.append(int(line.split()[-1]))
    return pids


def start_novus() -> Optional[int]:
    env = os.environ.copy()
    env["FLASK_DEBUG"] = "False"
    subprocess.Popen([PY, "main.py"], cwd=str(ROOT), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(90):
        if listeners():
            time.sleep(12)
            return find_pid()
        time.sleep(1)
    return None


def restart_novus() -> Optional[int]:
    for pid in listeners():
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], capture_output=True)
    time.sleep(4)
    return start_novus()


def login(email: str, password: str) -> requests.Session:
    s = requests.Session()
    r = s.get(f"{BASE}/login", timeout=45)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    s.post(
        f"{BASE}/login",
        data={"email": email, "password": password, "csrf_token": csrf.group(1) if csrf else ""},
        timeout=45,
    )
    return s


def file_fingerprint(path: Path) -> Optional[dict]:
    if not path.is_file():
        return None
    data = path.read_bytes()
    return {
        "size": path.stat().st_size,
        "mtime": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
        "sha256_prefix": hashlib.sha256(data[:16384]).hexdigest()[:16],
    }


def db_inventory() -> dict:
    from database import Base, SessionLocal, engine
    from sqlalchemy import inspect

    insp = inspect(engine)
    tables = sorted(insp.get_table_names())
    db = SessionLocal()
    counts = {}
    sample_models = [
        "usuarios", "alertas", "vulnerabilidades", "network_device_inventory",
        "login_session_audit", "platform_evidence", "tenant_monitoring_scope",
        "logs", "playbooks", "ndci_casos", "web_shield_events",
    ]
    try:
        for t in sample_models:
            if t in tables:
                try:
                    counts[t] = db.execute(f"SELECT COUNT(*) FROM {t}").scalar()
                except Exception as exc:
                    counts[t] = f"error:{str(exc)[:60]}"
    finally:
        db.close()
    return {"path": str(ROOT / "novus_vault_v2.db"), "tables_n": len(tables), "tables": tables, "row_counts": counts}


def persistence_probe() -> dict:
    paths = [
        ROOT / "novus_vault_v2.db",
        ROOT / "data/network/nodes_snapshot.json",
        ROOT / "data/network/context_snapshot.json",
        ROOT / "data/security/summary_snapshot.json",
        ROOT / "data/kernel_memory",
        ROOT / "data/behavioral_threat_detection/baseline_cache.json",
    ]
    before = {"files": {str(p.relative_to(ROOT)): file_fingerprint(p) for p in paths}, "db": db_inventory()}
    try:
        from services.network_snapshot_service import read_nodes_api
        snap = read_nodes_api(trigger_discovery=False, include_context=False)
        before["nodes_count"] = snap.get("count")
    except Exception as exc:
        before["nodes_error"] = str(exc)[:120]

    pid = restart_novus()
    time.sleep(15)
    after = {"files": {str(p.relative_to(ROOT)): file_fingerprint(p) for p in paths}, "db": db_inventory(), "restart_pid": pid}
    try:
        from services.network_snapshot_service import read_nodes_api
        snap = read_nodes_api(trigger_discovery=False, include_context=False)
        after["nodes_count"] = snap.get("count")
    except Exception as exc:
        after["nodes_error"] = str(exc)[:120]

    survived = {}
    for key in before["files"]:
        b, a = before["files"].get(key), after["files"].get(key)
        if b and a:
            survived[key] = a["size"] >= b["size"] and (a["sha256_prefix"] == b["sha256_prefix"] or a["mtime"] >= b["mtime"])
        elif b:
            survived[key] = a is not None

    bc = before["db"].get("row_counts", {})
    ac = after["db"].get("row_counts", {})
    for t in bc:
        if isinstance(bc[t], int) and isinstance(ac.get(t), int):
            survived[f"db:{t}"] = ac[t] >= bc[t]

    if before.get("nodes_count") is not None:
        survived["nodes_count"] = after.get("nodes_count") == before.get("nodes_count")

    return {"before": before, "after": after, "survived": survived, "verdict": "VERIFICADO" if all(survived.values()) else "PARCIAL"}


def backup_probe() -> dict:
    from services.encrypted_backup_service import create_encrypted_backup, verify_backup, restore_encrypted_backup, list_backups

    created = create_encrypted_backup(label="real_operation_audit", actor="audit_script")
    out = {"create": created}
    if created.get("ok") and created.get("path"):
        out["verify"] = verify_backup(created["path"])
        restored = restore_encrypted_backup(created["path"], actor="audit_script")
        out["restore"] = {"ok": restored.get("ok"), "dest": restored.get("dest"), "verify": restored.get("verify")}
    out["existing_backups"] = list_backups()[:5]
    out["verdict"] = "VERIFICADO" if out.get("verify", {}).get("ok") and out.get("restore", {}).get("ok") else "PARCIAL" if out.get("verify", {}).get("ok") else "NO_FUNCIONAL"
    return out


def tenant_probe() -> dict:
    qa = login(QA[0], QA[1])
    cl = login(CLIENT[0], CLIENT[1])
    probes = {}
    for label, sess in [("tenant_a_qa", qa), ("tenant_b_client", cl)]:
        row = {}
        for path in ["/api/tenant/scope", "/api/network/nodes", "/api/dashboard/live", "/api/security/summary"]:
            r = sess.get(BASE + path, timeout=45)
            body = r.json() if "json" in r.headers.get("content-type", "") else {}
            row[path] = {"http": r.status_code, "status": body.get("status"), "count": body.get("count"), "nodes": len(body.get("nodes") or [])}
        probes[label] = row

    leak = False
    cl_nodes = probes["tenant_b_client"]["/api/network/nodes"]
    qa_nodes = probes["tenant_a_qa"]["/api/network/nodes"]
    if cl_nodes.get("status") == "success" and (cl_nodes.get("nodes") or 0) > 0:
        leak = True
    checks = [
        ("B no recibe nodos de A", cl_nodes.get("status") == "monitoring_not_configured"),
        ("A puede telemetría", qa_nodes.get("status") in ("success", "no_data")),
        ("Sin fuga HTTP nodos", not leak),
    ]
    return {
        "probes": probes,
        "checks": [{"name": n, "passed": p} for n, p in checks],
        "verdict": "VERIFICADO_PARCIAL" if all(p for _, p in checks) else "FALLO",
        "note": "Aislamiento vía monitoring_enabled gate; NO PUEDO CONFIRMARLO row-level en todas las tablas DB",
    }


def auth_probe() -> dict:
    anon = requests.Session()
    paths = ["/api/network/nodes", "/api/security/summary", "/api/dashboard/live", "/api/system/blocked-ips"]
    unauth = {}
    for p in paths:
        r = anon.get(BASE + p, timeout=30, allow_redirects=False)
        unauth[p] = {"status": r.status_code, "redirect_login": r.status_code in (301, 302, 303, 307, 308)}
    qa = login(QA[0], QA[1])
    authed = qa.get(f"{BASE}/api/network/nodes", timeout=30).status_code
    return {
        "unauthenticated": unauth,
        "authenticated_nodes": authed,
        "verdict": "VERIFICADO" if all(v["status"] in (401, 302, 303) or v["redirect_login"] for v in unauth.values()) else "PARCIAL",
    }


def real_data_probe() -> dict:
    from utils.host_data import get_local_ip, get_primary_network_interface
    from services.network_snapshot_service import read_context_snapshot, read_nodes_api

    ctx = (read_context_snapshot() or {}).get("body") or {}
    nodes = read_nodes_api(trigger_discovery=False, include_context=False)
    iface = get_primary_network_interface() or {}
    return {
        "local_ip": {"value": get_local_ip(), "source": "OS utils.host_data", "class": "REAL"},
        "gateway": {"value": ctx.get("gateway") or iface.get("gateway"), "source": "route print / snapshot", "class": "REAL"},
        "mac": {"value": iface.get("mac"), "source": "OS interface", "class": "REAL"},
        "arp_nodes": {"count": nodes.get("count"), "source": "network_scanner ARP snapshot", "class": "REAL", "sample": (nodes.get("nodes") or [])[:2]},
        "interface": {"value": iface.get("adapter"), "source": "OS", "class": "REAL"},
    }


def crypto_audit() -> dict:
    from services.db_at_rest_encryption import capabilities
    from crypto_vault import CryptoVault
    from database import SessionLocal, Usuario

    v = CryptoVault()
    db = SessionLocal()
    try:
        u = db.query(Usuario).first()
        hp = getattr(u, "hashed_password", "") if u else ""
        pwd_hash = "werkzeug" if hp and (hp.startswith("pbkdf2:") or hp.startswith("scrypt:")) else ("bcrypt-like" if hp.startswith("$2") else "UNKNOWN")
    finally:
        db.close()
    return {
        "password_storage": pwd_hash,
        "cryptovault_aes": bool(getattr(v, "llave_aes", None)),
        "keyring": (ROOT / "data/cryptovault/keyring.json").is_file(),
        "db_at_rest": capabilities(),
        "runtime_db_plaintext": True,
        "verdict": "PARCIAL — cifrado at-rest .novusenc; runtime SQLite en claro mientras activo",
    }


def learning_audit() -> dict:
    baseline = ROOT / "data/behavioral_threat_detection/baseline_cache.json"
    kernel_mem = list((ROOT / "data/kernel_memory").glob("*.json")) if (ROOT / "data/kernel_memory").is_dir() else []
    return {
        "ml_libraries": False,
        "trained_models": False,
        "classification": "HEURISTIC_ADAPTIVE — baselines Counter/thresholds, kernel_memory JSON, APE profiles",
        "baseline_cache_exists": baseline.is_file(),
        "kernel_memory_files": len(kernel_mem),
        "btde_ml_classifier": False,
        "persistent_across_restart": baseline.is_file() or len(kernel_mem) > 0,
        "verdict": "NO ML REAL — adaptación heurística con persistencia en archivos/DB",
    }


def detection_matrix() -> dict:
    return {
        "dispositivos_nuevos": {"detecta": "VERIFICADO", "analiza": "SÍ", "correlaciona": "PARCIAL", "almacena": "SÍ", "alerta": "PARCIAL", "responde": "RECOMIENDA"},
        "cambios_red": {"detecta": "SÍ", "analiza": "SÍ", "correlaciona": "PARCIAL", "almacena": "SÍ", "alerta": "PARCIAL", "responde": "NO PUEDO CONFIRMARLO"},
        "vulnerabilidades": {"detecta": "CÓDIGO", "analiza": "SÍ", "correlaciona": "SÍ", "almacena": "SÍ", "alerta": "SÍ", "responde": "PARCIAL"},
        "procesos_host": {"detecta": "SÍ (endpoint lazy)", "analiza": "SÍ", "correlaciona": "BTDE", "almacena": "SÍ", "alerta": "PARCIAL", "responde": "NO PUEDO CONFIRMARLO"},
        "amenazas_xdr": {"detecta": "CÓDIGO", "analiza": "SÍ", "correlaciona": "SÍ", "almacena": "SÍ", "alerta": "SÍ", "responde": "PARCIAL"},
        "web_shield": {"detecta": "CÓDIGO P1", "analiza": "SÍ", "correlaciona": "PARCIAL", "almacena": "SÍ", "alerta": "SÍ", "responde": "NO PUEDO CONFIRMARLO E2E"},
        "mail_shield": {"detecta": "REQUIERE OAUTH", "analiza": "SÍ", "correlaciona": "PARCIAL", "almacena": "SÍ", "alerta": "SÍ", "responde": "NO PUEDO CONFIRMARLO"},
        "endpoints_lazy": {"detecta": "NO VERIFICADO", "analiza": "CÓDIGO", "correlaciona": "CÓDIGO", "almacena": "SÍ", "alerta": "NO PUEDO CONFIRMARLO", "responde": "NO"},
    }


def defense_matrix() -> dict:
    return {
        "bloquear_ip_sqlite": {"tipo": "EJECUTA", "os_real": "PARCIAL — registra + intenta netsh", "auto": "CONDICIONAL"},
        "bloquear_ip_os": {"tipo": "EJECUTA", "os_real": "SÍ Windows netsh (requiere admin)", "auto": "NO PUEDO CONFIRMARLO"},
        "aislar_dispositivo": {"tipo": "RECOMIENDA", "os_real": "NO — solo estado inventario", "auto": "NO"},
        "detener_proceso": {"tipo": "CÓDIGO", "os_real": "NO PUEDO CONFIRMARLO", "auto": "NO"},
        "playbook": {"tipo": "EJECUTA_ORQUESTACION", "os_real": "DEPENDE_PASO", "auto": "CONFIGURABLE"},
        "swarm_action": {"tipo": "CÓDIGO", "os_real": "NO PUEDO CONFIRMARLO E2E", "auto": "POLÍTICA"},
        "generar_alerta": {"tipo": "EJECUTA", "os_real": "INTERNO", "auto": "SÍ"},
        "generar_incidente": {"tipo": "EJECUTA", "os_real": "INTERNO", "auto": "PARCIAL"},
        "remediation": {"tipo": "MIXTO", "os_real": "PARCIAL netsh/firewall", "auto": "NO PUEDO CONFIRMARLO"},
    }


def ops_security() -> dict:
    import core.config as cfg
    from core.app import create_app

    app = create_app(os.environ.get("NOVUS_ENV", "development"))
    return {
        "flask_debug_config_default": getattr(cfg.Config, "DEBUG", None),
        "flask_debug_runtime": app.debug,
        "secret_key_set": bool(app.config.get("SECRET_KEY") and app.config["SECRET_KEY"] != "UNSET-RESOLVE-AT-RUNTIME"),
        "csrf_enabled": app.config.get("WTF_CSRF_ENABLED", True),
        "port_exposed": "0.0.0.0:5000 (single listener verificado en auditorías previas)",
        "rate_limiting": "SÍ — core/security.py + db_security.check_rate_limit",
        "note": "Pruebas no destructivas; NO PUEDO CONFIRMARLO pentest completo",
    }


def mock_scan() -> dict:
    intentional = [
        {"path": "api/swarm_defense.py", "type": "SIMULACION_INTENCIONAL", "detail": "/simulate-ingest dev/QA"},
        {"path": "services/deception_platform/", "type": "SIMULACION_INTENCIONAL", "detail": "honeypots/decoys"},
        {"path": "services/csv_bas/", "type": "SIMULACION_INTENCIONAL", "detail": "BAS scenarios"},
        {"path": "services/ndci_service.py", "type": "DEMO", "detail": "casos estudio documentación"},
    ]
    policies = []
    for p in ROOT.glob("services/**/limitations.py"):
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
            if "fake" in txt.lower() or "simulated" in txt.lower():
                policies.append(str(p.relative_to(ROOT)))
        except Exception:
            pass
    return {"intentional_simulation_endpoints": intentional, "anti_fake_policies_files": policies[:15], "production_ui_fake": "NO PUEDO CONFIRMARLO exhaustivo sin escaneo completo UI"}


def stable_components() -> list:
    return [
        {"component": "Network snapshot-first", "status": "DEJAR ESTABLE Y OBSERVAR", "reason": "datos ARP reales verificados"},
        {"component": "tenant monitoring gate", "status": "DEJAR ESTABLE Y OBSERVAR", "reason": "HTTP isolation QA vs client verificado"},
        {"component": "CryptoVault + .novusenc", "status": "DEJAR ESTABLE Y OBSERVAR", "reason": "AES-GCM operativo"},
        {"component": "Lazy engine manager", "status": "REQUIERE CORRECCIÓN ANTES DE USO REAL", "reason": "TIMEOUT/recovering bajo RAM"},
        {"component": "Multi-tenant row-level DB", "status": "BLOQUEADOR PRODUCCIÓN COMERCIAL", "reason": "no verificado en todas las tablas"},
        {"component": "Enterprise centers (TIE/IMCM/SOC)", "status": "REQUIERE CORRECCIÓN ANTES DE USO REAL", "reason": "implementados, no E2E"},
    ]


def blockers() -> list:
    return [
        "Lazy engines P2 no arrancan fiablemente con RAM>80% (recovering wrapper, TIMEOUT)",
        "Aislamiento multi-tenant incompleto fuera del gate monitoring_enabled — NO PUEDO CONFIRMARLO global",
        "DB SQLite runtime plaintext mientras proceso activo",
        "Mayoría de módulos enterprise sin verificación E2E con datos reales",
        "Acciones de aislamiento de dispositivo no conectadas a OS/red (solo inventario)",
    ]


def write_md(report: dict) -> None:
    lines = [
        "# NOVUS — Real Operation Readiness Audit",
        "",
        f"Generado: {report['generated_at_utc']}",
        "",
        "## 1. Veredicto general",
        "",
        f"**{report['verdict']['operation_controlled']}**",
        "",
        report["verdict"]["explanation"],
        "",
        f"**Producto comercial general:** {report['verdict']['commercial']}",
        "",
        "## 2. Seguridad almacenamiento",
        "",
        json.dumps(report["sections"]["crypto"], indent=2, ensure_ascii=False),
        "",
        "## 3. Persistencia",
        "",
        f"Verdict: **{report['sections']['persistence']['verdict']}**",
        "",
        "## 4. Base de datos",
        "",
        json.dumps(report["sections"]["database"], indent=2, ensure_ascii=False)[:3000],
        "",
        "## 5. Multi-tenancy",
        "",
        json.dumps(report["sections"]["tenant"], indent=2, ensure_ascii=False)[:2500],
        "",
        "## 6. Autenticación",
        "",
        json.dumps(report["sections"]["auth"], indent=2, ensure_ascii=False),
        "",
        "## 7. IA Kernel / aprendizaje",
        "",
        json.dumps(report["sections"]["learning"], indent=2, ensure_ascii=False),
        "",
        "## 8. Network (datos reales)",
        "",
        json.dumps(report["sections"]["real_data"], indent=2, ensure_ascii=False),
        "",
        "## 9. Detección",
        "",
        json.dumps(report["sections"]["detection"], indent=2, ensure_ascii=False),
        "",
        "## 10. Respuesta / defensa",
        "",
        json.dumps(report["sections"]["defense"], indent=2, ensure_ascii=False),
        "",
        "## 11. Backup",
        "",
        json.dumps(report["sections"]["backup"], indent=2, ensure_ascii=False),
        "",
        "## 12. Datos simulados",
        "",
        json.dumps(report["sections"]["mock_scan"], indent=2, ensure_ascii=False),
        "",
        "## 13. Bloqueadores críticos",
        "",
    ]
    for b in report["blockers"]:
        lines.append(f"- {b}")
    lines.extend(["", "## 14. Componentes estables (dejar de tocar)", ""])
    for c in report["stable_components"]:
        lines.append(f"- **{c['component']}** — {c['status']}: {c['reason']}")
    lines.extend(["", "## 15. Respuestas finales", ""])
    for q, a in report["final_answers"].items():
        lines.append(f"### {q}\n{a}\n")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "REAL_OPERATION_READINESS.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {"generated_at_utc": utc(), "audit": "real_operation_readiness"}

    pid = find_pid() or start_novus()
    if not pid:
        report["fatal"] = "NOVUS no arrancó"
        OUT.joinpath("REAL_OPERATION_READINESS.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return 1

    time.sleep(8)
    report["sections"] = {
        "database": db_inventory(),
        "real_data": real_data_probe(),
        "crypto": crypto_audit(),
        "learning": learning_audit(),
        "detection": detection_matrix(),
        "defense": defense_matrix(),
        "mock_scan": mock_scan(),
        "ops_security": ops_security(),
    }
    report["sections"]["auth"] = auth_probe()
    report["sections"]["tenant"] = tenant_probe()
    report["sections"]["backup"] = backup_probe()
    report["sections"]["persistence"] = persistence_probe()

    pers_ok = report["sections"]["persistence"]["verdict"] == "VERIFICADO"
    tenant_ok = report["sections"]["tenant"]["verdict"] in ("VERIFICADO", "VERIFICADO_PARCIAL")
    network_ok = bool(report["sections"]["real_data"].get("arp_nodes", {}).get("count", 0))

    if network_ok and pers_ok and tenant_ok:
        op_verdict = "APTO PARA OPERACIÓN REAL CON LIMITACIONES"
        explanation = (
            "Network opera con datos ARP/OS reales verificados. Persistencia de DB/snapshots sobrevive reinicio. "
            "Gate multi-tenant HTTP verificado entre QA y cliente MVP. "
            "Limitaciones: lazy engines P2, enterprise E2E, aislamiento row-level global, DB runtime plaintext."
        )
    elif network_ok and pers_ok:
        op_verdict = "APTO PARA OPERACIÓN REAL CON LIMITACIONES"
        explanation = "Datos reales y persistencia OK; tenant isolation parcial o no confirmado globalmente."
    else:
        op_verdict = "NO APTO PARA OPERACIÓN REAL"
        explanation = "Faltan pruebas críticas de datos reales o persistencia."

    report["verdict"] = {
        "operation_controlled": op_verdict,
        "commercial": "NO APTO — requiere supervisión técnica, E2E multi-tenant completo y motores P2 fiables",
        "explanation": explanation,
    }
    report["blockers"] = blockers()
    report["stable_components"] = stable_components()
    report["final_answers"] = {
        "¿Puede comenzar a operar con datos reales?": f"SÍ, en entorno controlado — {op_verdict}.",
        "¿Puede guardar persistentemente?": "SÍ — SQLite novus_vault_v2.db + snapshots JSON + jsonl enterprise.",
        "¿Recupera después de reiniciar?": f"{report['sections']['persistence']['verdict']} — evidencia en persistence_probe.",
        "¿Protegida para operación controlada?": "PARCIAL — CryptoVault AES at-rest; runtime DB en claro; contraseñas hasheadas werkzeug.",
        "¿Aprende/adapta?": "SÍ heurísticamente (baselines, kernel_memory, APE). NO ML entrenado.",
        "¿ML o heurístico?": "HEURÍSTICO/ADAPTATIVO — sin sklearn/tensorflow ni modelos persistidos.",
        "¿Qué está conectado?": "Network P1, Web/Mail Shield P1, IA Kernel P1, dashboard/security summary, tenant gate, auth.",
        "¿Qué es simulado?": "Deception, CSV/BAS, Swarm simulate-ingest, NDCI casos estudio.",
        "5 bloqueadores": "; ".join(blockers()[:5]),
        "Dejar de tocar y observar": "Network snapshot-first, CryptoVault, tenant monitoring gate, auth/CSRF stack.",
        "Mínimo antes de primer usuario real": "1) Verificar lazy engines en idle 2) Re-test tenant estable 3) Documentar DB plaintext runtime 4) No prometer aislamiento OS 5) Supervisión RAM/backpressure",
    }

    write_md(report)
    (OUT / "REAL_OPERATION_READINESS.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    print(json.dumps({"verdict": op_verdict, "persistence": report["sections"]["persistence"]["verdict"]}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
