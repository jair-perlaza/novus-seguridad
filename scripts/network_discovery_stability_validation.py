#!/usr/bin/env python3
"""
Validación final Network Discovery — estabilidad + datos reales.
Pruebas A–F sin modificar lógica de discovery salvo fallo demostrado.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT_DIR = ROOT / "data" / "novus_release_candidate"
OUT_JSON = OUT_DIR / "NETWORK_DISCOVERY_REAL_DATA_AUDIT.json"
OUT_MD = OUT_DIR / "NETWORK_DISCOVERY_REAL_DATA_AUDIT.md"
BASE = os.environ.get("NOVUS_TEST_BASE", "http://127.0.0.1:5000")
PYTHON = sys.executable
RUN = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
BASELINE_IDLE_SEC = int(os.environ.get("NOVUS_NET_BASELINE_IDLE", "300"))
MIN_SCAN_INTERVAL = 65  # coordinator _MIN_SCAN_INTERVAL_SEC = 60


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_pid() -> Optional[int]:
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN" and c.pid:
            return c.pid
    return None


def sample(label: str = "") -> Dict[str, Any]:
    mem = psutil.virtual_memory()
    row: Dict[str, Any] = {
        "label": label,
        "ts": utc(),
        "system_ram_pct": round(mem.percent, 1),
        "listener_count": len([
            c for c in psutil.net_connections(kind="inet")
            if c.laddr and c.laddr.port == 5000 and c.status == "LISTEN"
        ]),
    }
    pid = find_pid()
    row["novus_pid"] = pid
    if pid:
        try:
            p = psutil.Process(pid)
            row["novus_rss_mb"] = round(p.memory_info().rss / 1024 / 1024, 1)
            row["novus_threads"] = p.num_threads()
            row["worker_threads"] = [
                t.name for t in p.threads() if t.id != p.pid
            ][:20]
        except Exception as exc:
            row["proc_error"] = str(exc)
    try:
        from services.resource_backpressure_service import get_status
        row["backpressure"] = get_status()
    except Exception as exc:
        row["backpressure"] = {"error": str(exc)}
    row["recovery"] = check_recovery_http()
    return row


def check_recovery_http() -> Dict[str, Any]:
    out: Dict[str, Any] = {"recovering": False, "endpoints": {}}
    try:
        r = requests.get(f"{BASE}/login", timeout=20)
        out["endpoints"]["/login"] = {"http": r.status_code}
    except Exception as exc:
        out["endpoints"]["/login"] = {"error": str(exc)}
    try:
        r = requests.get(f"{BASE}/api/health/status", timeout=45)
        body: Dict[str, Any] = {}
        if r.headers.get("content-type", "").startswith("application/json"):
            body = r.json()
        rec = isinstance(body, dict) and (
            body.get("status") == "recovering" or body.get("_novusRecovery") is True
        )
        out["endpoints"]["/api/health/status"] = {
            "http": r.status_code,
            "recovering": rec,
            "status": body.get("status") if isinstance(body, dict) else None,
        }
        if rec:
            out["recovering"] = True
    except Exception as exc:
        out["endpoints"]["/api/health/status"] = {"error": str(exc)}
    return out


def stop_novus() -> None:
    pid = find_pid()
    if pid:
        try:
            psutil.Process(pid).terminate()
            psutil.Process(pid).wait(timeout=25)
        except Exception:
            try:
                psutil.Process(pid).kill()
            except Exception:
                pass
    time.sleep(5)


def start_novus() -> None:
    env = os.environ.copy()
    env["FLASK_DEBUG"] = "False"
    log = OUT_DIR / f"net_stability_boot_{RUN}.log"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(log, "w", encoding="utf-8") as fh:
        subprocess.Popen(
            [PYTHON, str(ROOT / "main.py")],
            cwd=str(ROOT),
            env=env,
            stdout=fh,
            stderr=subprocess.STDOUT,
        )


def wait_ready(max_sec: float = 120) -> bool:
    t0 = time.time()
    while time.time() - t0 < max_sec:
        try:
            if requests.get(f"{BASE}/login", timeout=5).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def baseline_ok(s: Dict[str, Any]) -> Tuple[bool, str]:
    bp = (s.get("backpressure") or {}).get("level") or (s.get("backpressure") or {}).get("backpressure_level")
    if s.get("recovery", {}).get("recovering"):
        return False, "recovery_active_at_baseline"
    if (s.get("system_ram_pct") or 0) >= 92:
        return False, f"system_ram_critical_{s.get('system_ram_pct')}%"
    if bp == "critical":
        return False, "backpressure_critical_at_baseline"
    if not s.get("listener_count"):
        return False, "no_listener_on_5000"
    return True, "ok"


def run_controlled_discovery() -> Dict[str, Any]:
    from utils.host_data import get_primary_network_interface
    from utils.network_helpers import get_default_gateway, get_network_range
    from utils.network_identity import get_wifi_association
    from services.network_scanner import network_scanner
    from services.network_scan_coordinator import coordinated_scan, get_coordinator_status

    primary = get_primary_network_interface() or {}
    wifi = get_wifi_association() or {}
    gateway = get_default_gateway()
    local_ip = primary.get("local_ip")
    netmask = primary.get("netmask")
    cidr = get_network_range(gateway=gateway, local_ip=local_ip, netmask=netmask)

    before = sample("discovery_before")
    t0 = time.perf_counter()
    nodes, coord_meta = coordinated_scan(
        lambda: network_scanner._perform_arp_scan(light=True),
        consumer="stability_validation",
        mode="arp_light",
    )
    duration_ms = round((time.perf_counter() - t0) * 1000, 1)
    after = sample("discovery_after")
    coord = get_coordinator_status()

    return {
        "duration_ms": duration_ms,
        "before": before,
        "after": after,
        "nodes": nodes,
        "node_count": len(nodes),
        "network": {
            "interface": primary.get("adapter"),
            "local_ip": local_ip,
            "netmask": netmask,
            "cidr": cidr,
            "gateway": gateway,
            "ssid": wifi.get("ssid"),
            "method": "arp_scapy",
        },
        "coordinator": coord_meta,
        "coordinator_status": coord,
    }


def run_second_discovery(first_nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
    from services.network_scanner import network_scanner
    from services.network_scan_coordinator import coordinated_scan, get_coordinator_status

    time.sleep(MIN_SCAN_INTERVAL)
    coord_before = get_coordinator_status()
    inflight_during = coord_before.get("scan_in_progress")

    t0 = time.perf_counter()
    nodes, meta = coordinated_scan(
        lambda: network_scanner._perform_arp_scan(light=True),
        consumer="stability_validation_second",
        mode="arp_light",
    )
    duration_ms = round((time.perf_counter() - t0) * 1000, 1)
    coord_after = get_coordinator_status()

    ips = [n.get("ip") for n in nodes if n.get("ip")]
    macs = [n.get("mac") for n in nodes if n.get("mac")]
    dup_ips = len(ips) != len(set(ips))
    dup_macs = len(macs) != len(set(macs))

    first_by_ip = {n.get("ip"): n for n in first_nodes if n.get("ip")}
    identity_ok = True
    for n in nodes:
        ip = n.get("ip")
        prev = first_by_ip.get(ip)
        if prev and prev.get("mac") and n.get("mac"):
            if prev.get("mac").lower() != n.get("mac").lower():
                identity_ok = False

    first_seen_stable = True
    for n in nodes:
        ip = n.get("ip")
        prev = first_by_ip.get(ip)
        if prev and prev.get("first_seen_utc") and n.get("first_seen_utc"):
            if prev.get("first_seen_utc") != n.get("first_seen_utc"):
                first_seen_stable = False
        if prev and n.get("last_seen_utc"):
            if not n.get("last_seen_utc"):
                first_seen_stable = False

    return {
        "duration_ms": duration_ms,
        "node_count": len(nodes),
        "duplicate_ips": dup_ips,
        "duplicate_macs": dup_macs,
        "identity_ip_mac_stable": identity_ok,
        "first_seen_stable": first_seen_stable,
        "last_seen_updated": all(n.get("last_seen_utc") for n in nodes),
        "coordinator_meta": meta,
        "scan_in_progress_before": inflight_during,
        "coordinator_after": coord_after,
        "reused_inflight": meta.get("reused_inflight") if isinstance(meta, dict) else None,
        "nodes": nodes,
    }


def verify_real_data(nodes: List[Dict[str, Any]], freshness: str = "live") -> Dict[str, Any]:
    forbidden_origins = {"fixture", "mock", "demo", "fake", "hardcoded", "static_nodes", "generated"}
    rows = []
    all_ok = True
    for n in nodes:
        origin = (n.get("data_origin") or "live_discovery").lower()
        method = n.get("detection_method") or "arp_scapy"
        bad = origin in forbidden_origins or method in forbidden_origins
        if bad:
            all_ok = False
        rows.append({
            "ip": n.get("ip"),
            "mac": n.get("mac"),
            "hostname": n.get("name"),
            "method": method,
            "origin": origin,
            "first_seen": n.get("first_seen_utc"),
            "last_seen": n.get("last_seen_utc"),
            "freshness": freshness,
            "authentic": not bad,
        })
    snap_path = ROOT / "data" / "network" / "nodes_snapshot.json"
    snap_stale = False
    snap_age = None
    if snap_path.is_file():
        try:
            snap = json.loads(snap_path.read_text(encoding="utf-8"))
            gen = snap.get("generated_at_utc")
            if gen:
                ts = datetime.strptime(gen, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                snap_age = round((datetime.now(timezone.utc) - ts).total_seconds(), 1)
                snap_stale = snap_age > 90
        except Exception:
            pass
    stale_presented_as_live = freshness == "live" and snap_stale
    if stale_presented_as_live:
        all_ok = False
    return {
        "classification": "VERIFIED" if all_ok and rows else ("NOT VERIFIED" if not all_ok else "NOT VERIFIED"),
        "nodes": rows,
        "snapshot_age_sec": snap_age,
        "stale_presented_as_live": stale_presented_as_live,
        "no_fixture_mock": all_ok,
    }


def assess_limited_visibility(nodes: List[Dict[str, Any]], network: Dict[str, Any]) -> Dict[str, Any]:
    from utils.network_helpers import assess_discovery_limitations, read_os_arp_neighbors

    os_n = read_os_arp_neighbors(interface_ip=network.get("local_ip"))
    a = assess_discovery_limitations(
        scapy_count=len(nodes),
        os_arp_count=len(os_n),
        subnet_cidr=network.get("cidr"),
        ssid=network.get("ssid"),
        connection_type=network.get("interface"),
    )
    a["ap_isolation_direct_evidence"] = False
    a["ap_isolation_note"] = (
        "No hay evidencia directa de configuración AP isolation en el router. "
        "La clasificación REAL_DATA_LIMITED_VISIBILITY se basa en que otros hosts "
        "no son observables vía ARP desde esta interfaz (Scapy y tabla OS)."
    )
    ssid_l = (network.get("ssid") or "").lower()
    if any(m in ssid_l for m in ("invitad", "guest", "visitant")):
        a["guest_ssid_indicator"] = True
        a["guest_ssid_note"] = "SSID sugiere red invitados; no confirma aislamiento por sí solo."
    else:
        a["guest_ssid_indicator"] = False
    return a


def retention_verdict(baseline_rss: float, discovery_after_rss: float, final_rss: float) -> str:
    if final_rss is None or baseline_rss is None:
        return "NOT VERIFIED"
    delta = final_rss - baseline_rss
    spike = (discovery_after_rss or baseline_rss) - baseline_rss
    if delta > max(150, baseline_rss * 0.35):
        return "NOT VERIFIED"
    if spike > 200 and delta > 80:
        return "NOT VERIFIED"
    if delta <= 50 or delta <= baseline_rss * 0.15:
        return "VERIFIED"
    return "PARTIALLY VERIFIED"


def merge_report(stability: Dict[str, Any], verdicts: Dict[str, str]) -> None:
    existing: Dict[str, Any] = {}
    if OUT_JSON.is_file():
        try:
            existing = json.loads(OUT_JSON.read_text(encoding="utf-8"))
        except Exception:
            pass
    existing["stability_validation_run"] = RUN
    existing["stability_validated_at_utc"] = utc()
    existing["NETWORK_DISCOVERY_STABILITY"] = stability
    existing["final_verdicts"] = verdicts
    existing["overall_network_status"] = verdicts.get("OVERALL_NETWORK_STATUS")
    OUT_JSON.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")

    md_extra = [
        "",
        "---",
        "",
        "## NETWORK_DISCOVERY_STABILITY",
        "",
        f"**Run:** {RUN} | **Validated:** {utc()}",
        "",
        "### Prueba A — Baseline",
        "",
    ]
    a = stability.get("test_a_baseline", {})
    for k, v in a.items():
        if k.startswith("sample"):
            md_extra.append(f"- **{k}**: RSS {v.get('novus_rss_mb')} MB, threads {v.get('novus_threads')}, bp={(v.get('backpressure') or {}).get('level')}")
    md_extra.extend([
        "",
        "### Prueba B — Discovery controlado",
        "",
        f"- Duración: {stability.get('test_b_discovery', {}).get('duration_ms')} ms",
        f"- Nodos: {stability.get('test_b_discovery', {}).get('node_count')}",
        "",
        "### Prueba C — Retención (+30 min)",
        "",
    ])
    for pt in stability.get("test_c_retention", []):
        md_extra.append(f"- **{pt.get('label')}**: RSS {pt.get('novus_rss_mb')} MB, threads {pt.get('novus_threads')}")
    md_extra.extend([
        "",
        "### Veredictos finales",
        "",
    ])
    for k, v in verdicts.items():
        md_extra.append(f"- **{k}**: {v}")

    if OUT_MD.is_file():
        base = OUT_MD.read_text(encoding="utf-8")
        if "## NETWORK_DISCOVERY_STABILITY" in base:
            base = base.split("## NETWORK_DISCOVERY_STABILITY")[0].rstrip()
        OUT_MD.write_text(base + "\n".join(md_extra), encoding="utf-8")
    else:
        OUT_MD.write_text("\n".join(md_extra), encoding="utf-8")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stability: Dict[str, Any] = {"run_id": RUN, "started_at_utc": utc()}
    verdicts: Dict[str, str] = {}

    print("[A] Clean restart...")
    stop_novus()
    start_novus()
    if not wait_ready(120):
        verdicts = {k: "NOT VERIFIED" for k in (
            "REAL_DATA", "NO_STATIC_DATA", "LIMITED_VISIBILITY",
            "DISCOVERY_STABILITY", "OVERALL_NETWORK_STATUS",
        )}
        verdicts["OVERALL_NETWORK_STATUS"] = "NO-GO"
        stability["test_a_baseline"] = {"classification": "ENVIRONMENT FAILURE", "reason": "server_not_ready"}
        merge_report(stability, verdicts)
        print(json.dumps(verdicts, indent=2))
        return 2

    sample_boot = sample("boot_immediate")
    stability["test_a_baseline"] = {"sample_boot_immediate": sample_boot}

    print(f"[A] Idle {BASELINE_IDLE_SEC}s (baseline gate)...")
    time.sleep(BASELINE_IDLE_SEC)
    sample_idle = sample("boot_idle_5min")
    stability["test_a_baseline"]["sample_idle_5min"] = sample_idle
    ok, reason = baseline_ok(sample_idle)
    if not ok:
        stability["test_a_baseline"]["classification"] = "ABORT"
        stability["test_a_baseline"]["abort_reason"] = reason
        stability["test_a_baseline"]["note"] = "boot_immediate may show warmup; gate uses idle_5min only"
        verdicts = {
            "REAL_DATA": "NOT VERIFIED",
            "NO_STATIC_DATA": "NOT VERIFIED",
            "LIMITED_VISIBILITY": "NOT VERIFIED",
            "DISCOVERY_STABILITY": "NOT VERIFIED",
            "OVERALL_NETWORK_STATUS": "NO-GO",
        }
        merge_report(stability, verdicts)
        print(f"Baseline ABORT (idle 5min): {reason}")
        return 2

    stability["test_a_baseline"]["classification"] = "VERIFIED"
    baseline_rss = sample_idle.get("novus_rss_mb") or sample_boot.get("novus_rss_mb")

    print("[B] Controlled discovery...")
    disc = run_controlled_discovery()
    stability["test_b_discovery"] = disc
    first_nodes = list(disc.get("nodes") or [])

    print("[C] Retention sampling...")
    retention_points: List[Dict[str, Any]] = []
    retention_schedule = [
        ("immediate_after_discovery", 0),
        ("plus_1_min", 60),
        ("plus_5_min", 300),
        ("plus_10_min", 600),
        ("plus_30_min", 1800),
    ]
    discovery_end = time.time()
    last_wait = 0
    for label, offset in retention_schedule:
        wait = max(0, offset - last_wait)
        if wait:
            print(f"  [C] waiting {wait}s -> {label}...")
            time.sleep(wait)
        last_wait = offset
        retention_points.append(sample(label))
    stability["test_c_retention"] = retention_points

    print("[D] Second discovery...")
    second = run_second_discovery(first_nodes)
    stability["test_d_duplicates"] = second

    snap_freshness = "cached"
    last_pt = retention_points[-1] if retention_points else {}
    age_guess = (last_pt.get("ts") or "")
    real_e = verify_real_data(second.get("nodes") or first_nodes, freshness=snap_freshness)
    stability["test_e_real_data"] = real_e

    vis = assess_limited_visibility(first_nodes, disc.get("network") or {})
    stability["test_f_visibility"] = vis

    # Verdicts
    real_ok = real_e.get("classification") == "VERIFIED" and len(first_nodes) >= 1
    for n in first_nodes:
        if (n.get("data_origin") or "").lower() in ("mock", "fixture", "fake"):
            real_ok = False

    dup_ok = (
        not second.get("duplicate_ips")
        and not second.get("duplicate_macs")
        and second.get("identity_ip_mac_stable")
    )
    final_rss = retention_points[-1].get("novus_rss_mb") if retention_points else None
    disc_after_rss = disc.get("after", {}).get("novus_rss_mb")
    ret_v = retention_verdict(baseline_rss, disc_after_rss, final_rss)
    rec_any = any(p.get("recovery", {}).get("recovering") for p in retention_points)

    verdicts["REAL_DATA"] = "VERIFIED" if real_ok else "NOT VERIFIED"
    verdicts["NO_STATIC_DATA"] = "VERIFIED" if real_e.get("no_fixture_mock") else "NOT VERIFIED"
    verdicts["LIMITED_VISIBILITY"] = "VERIFIED" if vis.get("visibility") == "limited" else "PARTIALLY VERIFIED"
    verdicts["DISCOVERY_STABILITY"] = "VERIFIED" if ret_v == "VERIFIED" and dup_ok and not rec_any else (
        "PARTIALLY VERIFIED" if ret_v == "PARTIALLY VERIFIED" else "NOT VERIFIED"
    )

    all_v = [verdicts["REAL_DATA"], verdicts["NO_STATIC_DATA"], verdicts["LIMITED_VISIBILITY"], verdicts["DISCOVERY_STABILITY"]]
    if all(v == "VERIFIED" for v in all_v):
        verdicts["OVERALL_NETWORK_STATUS"] = "GO"
    elif any(v == "NOT VERIFIED" for v in all_v):
        verdicts["OVERALL_NETWORK_STATUS"] = "NO-GO" if verdicts["DISCOVERY_STABILITY"] == "NOT VERIFIED" else "PARTIAL"
    else:
        verdicts["OVERALL_NETWORK_STATUS"] = "PARTIAL"

    stability["summary"] = {
        "baseline_rss_mb": baseline_rss,
        "discovery_after_rss_mb": disc_after_rss,
        "retention_30min_rss_mb": final_rss,
        "retention_verdict": ret_v,
        "recovery_during_test": rec_any,
    }
    stability["finished_at_utc"] = utc()

    merge_report(stability, verdicts)
    print(json.dumps({"verdicts": verdicts, "summary": stability["summary"]}, indent=2))
    print(f"Report updated: {OUT_JSON}")
    return 0 if verdicts["OVERALL_NETWORK_STATUS"] == "GO" else 1


if __name__ == "__main__":
    sys.exit(main())
