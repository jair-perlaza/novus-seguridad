#!/usr/bin/env python3
"""
Reproducción controlada de crecimiento RAM/threads NOVUS.
Genera RESOURCE_STABILITY_FINAL.json / .md
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
OUT_DIR = ROOT / "data" / "novus_real_operation_audit"
OUT_JSON = OUT_DIR / "RESOURCE_STABILITY_FINAL.json"
OUT_MD = OUT_DIR / "RESOURCE_STABILITY_FINAL.md"
LOG_FILE = OUT_DIR / "resource_probe_novus_stdout.log"
BASE = os.environ.get("NOVUS_TEST_BASE", "http://127.0.0.1:5000")
PYTHON = sys.executable
QA = ("novus.qa.jul2026@example.com", os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!"))

# Marcadores de arranque/componentes en logs NOVUS
COMPONENT_MARKERS = [
    ("NovusDbMigrate", "db_migrate"),
    ("NovusStartupReconcile", "startup_reconcile"),
    ("NovusStagedBoot", "staged_boot_start"),
    ("Startup P0", "boot_p0"),
    ("Startup P1", "boot_p1"),
    ("Gmail background sync", "gmail_sync"),
    ("NOVUS Web Shield", "web_shield"),
    ("NOVUS Mail Shield", "mail_shield"),
    ("Background threat scanner started", "threat_scanner"),
    ("AI Kernel started", "ai_kernel"),
    ("Startup P2a", "boot_p2a_network_monitor"),
    ("Network Monitor", "network_monitor"),
    ("NovusNetDiscoveryDelay", "net_discovery_delay"),
    ("Network discovery scheduled", "network_discovery"),
    ("HttpShellCountersWarm", "http_shell_counters_warm"),
    ("SecuritySummaryWarmup", "security_summary_warmup"),
    ("SecuritySummarySnapRefresh", "security_summary_refresh"),
    ("NetworkSnapWarmup", "network_snap_warmup"),
    ("EnterpriseSnapWarmup", "enterprise_snap_warmup"),
    ("LazyStart-", "lazy_engine_start"),
    ("NovusBTDE", "btde"),
    ("NovusZDDE", "zdde"),
    ("NovusHealthEngine", "health_engine"),
    ("ThreatScanner", "threat_scanner_thread"),
    ("AIKernel", "ai_kernel_thread"),
    ("NetworkMonitorEngine", "network_monitor_engine"),
    ("Resource backpressure", "backpressure"),
    ("ALERTA IA", "ai_kernel_alert"),
    ("ARP", "arp_scan"),
    ("scan_arp", "arp_scan"),
]

RAM_SYSTEM_STOP_PCT = 85.0
RAM_NOVUS_STOP_MB = 1024.0
IDLE_MINUTES = 5
SAMPLE_INTERVAL_SEC = 30


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_novus_pid() -> Optional[int]:
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if "NOVUS" in cmd and "main.py" in cmd.replace("\\", "/"):
                return p.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def port_listener_pids() -> List[int]:
    pids = []
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            pids.append(c.pid)
    return sorted(set(pids))


def stop_novus() -> None:
    pid = find_novus_pid()
    if pid:
        try:
            psutil.Process(pid).terminate()
            psutil.Process(pid).wait(timeout=15)
        except Exception:
            try:
                psutil.Process(pid).kill()
            except Exception:
                pass
    time.sleep(3)


def start_novus() -> subprocess.Popen:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text("", encoding="utf-8")
    env = os.environ.copy()
    env["FLASK_DEBUG"] = "False"
    env["NOVUS_ENV"] = "development"
    with open(LOG_FILE, "a", encoding="utf-8") as logfh:
        proc = subprocess.Popen(
            [PYTHON, str(ROOT / "main.py")],
            cwd=str(ROOT),
            env=env,
            stdout=logfh,
            stderr=subprocess.STDOUT,
        )
    return proc


def wait_server(max_wait: int = 120) -> bool:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            r = requests.get(f"{BASE}/login", timeout=5)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def sample_novus(pid: Optional[int]) -> Dict[str, Any]:
    mem = psutil.virtual_memory()
    snap: Dict[str, Any] = {
        "ts": utc(),
        "system_ram_pct": round(mem.percent, 1),
        "system_ram_used_mb": round(mem.used / 1024 / 1024, 1),
        "system_ram_avail_mb": round(mem.available / 1024 / 1024, 1),
        "cpu_pct": round(psutil.cpu_percent(interval=0.2), 1),
        "listeners_5000": port_listener_pids(),
    }
    if pid:
        try:
            p = psutil.Process(pid)
            mi = p.memory_info()
            snap.update({
                "novus_pid": pid,
                "novus_rss_mb": round(mi.rss / 1024 / 1024, 1),
                "novus_threads": p.num_threads(),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            snap["novus_pid"] = pid
            snap["novus_error"] = "process_gone"
    return snap


def parse_log_since(offset: int) -> Tuple[List[str], int, List[str]]:
    if not LOG_FILE.exists():
        return [], offset, []
    data = LOG_FILE.read_text(encoding="utf-8", errors="replace")
    chunk = data[offset:]
    new_offset = len(data)
    events = []
    for line in chunk.splitlines():
        for marker, label in COMPONENT_MARKERS:
            if marker in line:
                events.append(label)
                break
    return chunk.splitlines()[-20:], new_offset, sorted(set(events))


def login() -> Optional[requests.Session]:
    s = requests.Session()
    try:
        r = s.get(f"{BASE}/login", timeout=30)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
        s.post(
            f"{BASE}/login",
            data={"email": QA[0], "password": QA[1], "csrf_token": csrf.group(1) if csrf else ""},
            timeout=30,
        )
        return s
    except Exception:
        return None


def http_probe(sess: requests.Session, path: str) -> Dict[str, Any]:
    t0 = time.perf_counter()
    rec = False
    status = None
    err = None
    try:
        r = sess.get(BASE + path, timeout=45)
        status = r.status_code
        if "json" in r.headers.get("content-type", ""):
            body = r.json()
            rec = body.get("status") == "recovering" or body.get("_novusRecovery") is True
    except Exception as exc:
        err = str(exc)[:120]
    return {
        "path": path,
        "http_status": status,
        "recovery": rec,
        "error": err,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
    }


def fetch_engine_status(sess: requests.Session) -> Dict[str, Any]:
    out = {}
    for path in ("/api/engines", "/api/health/status"):
        try:
            r = sess.get(BASE + path, timeout=30)
            if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                out[path] = r.json()
        except Exception as exc:
            out[path] = {"error": str(exc)[:120]}
    return out


def attribute_deltas(samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    attrs = []
    for i in range(1, len(samples)):
        prev = samples[i - 1]
        cur = samples[i]
        dr = (cur.get("novus_rss_mb") or 0) - (prev.get("novus_rss_mb") or 0)
        dt = (cur.get("novus_threads") or 0) - (prev.get("novus_threads") or 0)
        if abs(dr) >= 5 or abs(dt) >= 2:
            attrs.append({
                "from_ts": prev.get("ts"),
                "to_ts": cur.get("ts"),
                "delta_rss_mb": round(dr, 1),
                "delta_threads": dt,
                "phase": cur.get("phase"),
                "log_events": cur.get("log_events_between", []),
                "operation": cur.get("operation"),
            })
    return attrs


def run_stability_phases(sess: requests.Session, pid: int, report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """10m idle + 10m light + 10m moderate — stop early on limits."""
    phases = [
        ("idle_10m", 600, []),
        ("light_10m", 600, ["/api/tenant/scope", "/api/dashboard/live"]),
        ("moderate_10m", 600, ["/api/tenant/scope", "/api/dashboard/live", "/api/security/summary", "/api/network/nodes"]),
    ]
    all_samples: List[Dict[str, Any]] = []
    log_offset = report.get("_log_offset", 0)
    for phase_name, duration, endpoints in phases:
        phase_start = time.time()
        interval = 30
        while time.time() - phase_start < duration:
            snap = sample_novus(pid)
            _, log_offset, events = parse_log_since(log_offset)
            snap["phase"] = phase_name
            snap["log_events_between"] = events
            all_samples.append(snap)
            if snap.get("system_ram_pct", 0) > RAM_SYSTEM_STOP_PCT or snap.get("novus_rss_mb", 0) > RAM_NOVUS_STOP_MB:
                report["stopped_early"] = f"{phase_name}: limits exceeded"
                return all_samples
            if endpoints and sess and (len(all_samples) % 2 == 0):
                ep = endpoints[len(all_samples) % len(endpoints)]
                http_probe(sess, ep)
            time.sleep(interval)
    return all_samples


def main() -> int:
    report: Dict[str, Any] = {
        "run_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "captured_at_utc": utc(),
        "procedure": "controlled_reproduction",
    }

    stop_novus()
    if port_listener_pids():
        report["overall"] = "FAILED"
        report["error"] = "port_5000_still_in_use"
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        OUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return 1

    proc = start_novus()
    if not wait_server():
        report["overall"] = "FAILED"
        report["error"] = "server_did_not_start"
        proc.terminate()
        OUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return 1

    pid = find_novus_pid() or proc.pid
    report["initial"] = sample_novus(pid)
    report["initial"]["listeners"] = port_listener_pids()

    samples: List[Dict[str, Any]] = [dict(report["initial"], phase="post_boot_immediate")]
    log_offset = 0
    idle_end = time.time() + IDLE_MINUTES * 60
    stopped = False

    while time.time() < idle_end:
        time.sleep(SAMPLE_INTERVAL_SEC)
        snap = sample_novus(pid)
        _, log_offset, events = parse_log_since(log_offset)
        snap["phase"] = "idle_5m"
        snap["log_events_between"] = events
        samples.append(snap)
        if snap.get("system_ram_pct", 0) > RAM_SYSTEM_STOP_PCT:
            report["stopped_early"] = "system_ram>85%"
            stopped = True
            break
        if snap.get("novus_rss_mb", 0) > RAM_NOVUS_STOP_MB:
            report["stopped_early"] = "novus_rss>1GB"
            stopped = True
            break

    report["idle_samples"] = samples
    report["_log_offset"] = log_offset

    # Operaciones mínimas
    sess = login()
    ops: List[Dict[str, Any]] = []
    min_paths = ["/api/tenant/scope", "/api/dashboard/live"]
    if sess:
        for path in min_paths:
            before = sample_novus(pid)
            op = http_probe(sess, path)
            time.sleep(2)
            after = sample_novus(pid)
            _, log_offset, events = parse_log_since(log_offset)
            op["before_rss_mb"] = before.get("novus_rss_mb")
            op["after_rss_mb"] = after.get("novus_rss_mb")
            op["delta_rss_mb"] = round((after.get("novus_rss_mb") or 0) - (before.get("novus_rss_mb") or 0), 1)
            op["before_threads"] = before.get("novus_threads")
            op["after_threads"] = after.get("novus_threads")
            op["log_events"] = events
            ops.append(op)
            samples.append(dict(after, phase="after_op", operation=path))
        report["engine_status_after_ops"] = fetch_engine_status(sess)

    report["minimal_ops"] = ops
    report["attributions"] = attribute_deltas(samples)

    # Estabilidad 30m solo si no paró y RAM razonable
    last = samples[-1] if samples else report["initial"]
    if not stopped and (last.get("novus_rss_mb") or 0) < RAM_NOVUS_STOP_MB and sess:
        report["stability_30m"] = run_stability_phases(sess, pid, report)
        samples.extend(report["stability_30m"])
        report["attributions"] = attribute_deltas(samples)

    final = sample_novus(pid)
    report["final"] = final
    report["delta_total_rss_mb"] = round((final.get("novus_rss_mb") or 0) - (report["initial"].get("novus_rss_mb") or 0), 1)
    report["delta_total_threads"] = (final.get("novus_threads") or 0) - (report["initial"].get("novus_threads") or 0)

    # Veredicto
    rss_series = [s.get("novus_rss_mb") for s in samples if s.get("novus_rss_mb")]
    runaway = False
    if len(rss_series) >= 4:
        tail = rss_series[-4:]
        if all(tail[i] < tail[i + 1] for i in range(len(tail) - 1)) and (tail[-1] - tail[0]) > 200:
            runaway = True

    recovery_any = any(o.get("recovery") for o in ops) or report.get("stopped_early")
    stabilized = not runaway and (final.get("novus_rss_mb") or 0) < RAM_NOVUS_STOP_MB and not recovery_any

    if stabilized and report.get("stability_30m"):
        report["overall"] = "RESOURCE STABILITY VERIFIED"
    elif report.get("attributions"):
        report["overall"] = "RESOURCE STABILITY PARTIAL"
    else:
        report["overall"] = "RESOURCE STABILITY PARTIAL" if not runaway else "FAILED"

    # Causa raíz inferida solo con evidencia de logs
    root_causes = []
    for a in report.get("attributions", []):
        if a.get("delta_rss_mb", 0) >= 50 and a.get("log_events"):
            root_causes.append({
                "delta_rss_mb": a["delta_rss_mb"],
                "events": a["log_events"],
                "phase": a.get("phase"),
                "operation": a.get("operation"),
                "confidence": "CORRELATED" if a["log_events"] else "NO PUEDO CONFIRMARLO",
            })
    report["root_cause_candidates"] = root_causes

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    write_md(report)
    print(json.dumps({
        "overall": report["overall"],
        "initial_rss_mb": report["initial"].get("novus_rss_mb"),
        "final_rss_mb": final.get("novus_rss_mb"),
        "delta_mb": report["delta_total_rss_mb"],
        "threads": f"{report['initial'].get('novus_threads')}->{final.get('novus_threads')}",
        "attributions": len(report.get("attributions", [])),
    }))
    return 0 if report["overall"] == "RESOURCE STABILITY VERIFIED" else 1


def write_md(report: Dict[str, Any]) -> None:
    lines = [
        "# RESOURCE STABILITY FINAL",
        "",
        f"**Run:** {report.get('run_id')}",
        f"**Overall:** {report.get('overall')}",
        "",
        "## RAM",
        f"- Inicial: {report.get('initial', {}).get('novus_rss_mb')} MB / threads {report.get('initial', {}).get('novus_threads')}",
        f"- Final: {report.get('final', {}).get('novus_rss_mb')} MB / threads {report.get('final', {}).get('novus_threads')}",
        f"- Delta: {report.get('delta_total_rss_mb')} MB / {report.get('delta_total_threads')} threads",
        "",
        "## Atribuciones (correlación log ↔ RAM)",
        "",
    ]
    for a in report.get("attributions", []):
        lines.append(f"- **+{a.get('delta_rss_mb')} MB** ({a.get('phase')}) events={a.get('log_events')} op={a.get('operation')}")
    lines += ["", "## Causa raíz candidata", ""]
    for rc in report.get("root_cause_candidates", []):
        lines.append(f"- +{rc.get('delta_rss_mb')} MB cuando {rc.get('events')} ({rc.get('confidence')})")
    if not report.get("root_cause_candidates"):
        lines.append("- NO PUEDO CONFIRMARLO — sin correlación log suficiente")
    lines += ["", "## Ops mínimas", ""]
    for o in report.get("minimal_ops", []):
        lines.append(f"- {o.get('path')}: ΔRAM {o.get('delta_rss_mb')} MB, HTTP {o.get('http_status')}, recovery={o.get('recovery')}")
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
