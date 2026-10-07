"""
Captura forense de tráfico — metadatos continuos + PCAP bajo demanda (incidente o manual).
Solo tráfico real observado en el host NOVUS; sin PCAP simulados.
"""
from __future__ import annotations

import json
import os
import platform
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_DIR = os.path.join(ROOT, "data", "forensic_pcap")
CAPTURES_INDEX = os.path.join(PCAP_DIR, "captures.jsonl")
METADATA_RING = os.path.join(PCAP_DIR, "metadata_ring.jsonl")
METADATA_RING_MAX_LINES = 2000

AUTO_TRIGGER_SUBSTRINGS = (
    "malware", "ransomware", "brute", "port_scan", "port scan", "mitm",
    "arp", "dns", "dhcp", "exfil", "anomal", "rogue",
)

_active: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()
_metadata_thread_started = False
_metadata_stop = threading.Event()


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ensure_dirs() -> None:
    os.makedirs(PCAP_DIR, exist_ok=True)


def capture_capability() -> Dict[str, Any]:
    """Estado real de capacidad de captura en este host."""
    system = platform.system()
    npcap = False
    scapy_ok = False
    dumpcap = None
    try:
        import scapy.all as scapy  # noqa: F401
        scapy_ok = True
        ifaces = list_capture_interfaces()
        npcap = len(ifaces) > 0
    except Exception as exc:
        return {
            "platform": system,
            "scapy_available": False,
            "npcap_or_capture_ready": False,
            "error": str(exc)[:200],
            "note": "Instale Npcap (Windows) o permisos CAP_NET_RAW (Linux) para PCAP completo.",
        }
    import shutil
    dumpcap = shutil.which("dumpcap") or shutil.which("tshark")
    return {
        "platform": system,
        "scapy_available": scapy_ok,
        "npcap_or_capture_ready": npcap,
        "dumpcap_available": bool(dumpcap),
        "interfaces_detected": len(list_capture_interfaces()),
        "requires_admin": system == "Windows",
        "protocols_note": "Captura en capa 2/3 según interfaz; no decodifica TLS interno sin claves.",
    }


def list_capture_interfaces() -> List[Dict[str, str]]:
    out: List[Dict[str, Any]] = []
    try:
        from scapy.interfaces import ifaces

        for name, iface in ifaces.items():
            out.append({"id": name, "label": str(iface.description or name)})
    except Exception:
        try:
            from scapy.all import get_if_list

            for name in get_if_list() or []:
                out.append({"id": name, "label": name})
        except Exception as exc:
            logger.debug("list interfaces: %s", exc)
    try:
        from utils.host_data import get_primary_network_interface

        primary = get_primary_network_interface()
        if primary and primary.get("adapter"):
            pid = primary["adapter"]
            if not any(x["id"] == pid for x in out):
                out.insert(0, {"id": pid, "label": f"{pid} (primaria)"})
    except Exception:
        pass
    return out


def _append_metadata_snapshot() -> None:
    """Metadatos de red sin PCAP (conexiones locales observables)."""
    _ensure_dirs()
    snap: Dict[str, Any] = {"timestamp": _now(), "type": "metadata_snapshot"}
    try:
        import psutil

        snap["connection_count"] = len(psutil.net_connections(kind="inet"))
    except Exception as exc:
        snap["connection_count_error"] = str(exc)[:120]
    try:
        from services.network_scanner import network_scanner

        snap["arp_nodes"] = len(network_scanner.get_cached_nodes() or [])
    except Exception:
        snap["arp_nodes"] = None
    try:
        with open(METADATA_RING, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(snap, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.debug("metadata ring: %s", exc)
        return
    try:
        with open(METADATA_RING, encoding="utf-8") as fh:
            lines = fh.readlines()
        if len(lines) > METADATA_RING_MAX_LINES:
            with open(METADATA_RING, "w", encoding="utf-8") as fh:
                fh.writelines(lines[-METADATA_RING_MAX_LINES:])
    except Exception:
        pass


def ensure_metadata_monitor(interval_sec: int = 45) -> None:
    global _metadata_thread_started
    if _metadata_thread_started:
        return
    _metadata_thread_started = True

    def _loop():
        while not _metadata_stop.wait(interval_sec):
            try:
                _append_metadata_snapshot()
            except Exception as exc:
                logger.debug("metadata monitor: %s", exc)

    threading.Thread(target=_loop, daemon=True, name="NovusPcapMetadata").start()


def _write_capture_index(row: Dict[str, Any]) -> None:
    _ensure_dirs()
    with open(CAPTURES_INDEX, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _finalize_pcap_file(
    *,
    capture_id: str,
    path: str,
    meta: Dict[str, Any],
) -> Dict[str, Any]:
    from services.enterprise_data_service import hash_file_sha256
    from services.forensic_evidence_integrity_service import seal_evidence

    size = os.path.getsize(path) if os.path.isfile(path) else 0
    file_hash = hash_file_sha256(path)
    meta.update({
        "capture_id": capture_id,
        "file_path": path,
        "file_size_bytes": size,
        "file_sha256": file_hash,
        "finished_at": _now(),
        "status": "completed" if size > 0 else "empty_capture",
    })
    seal = None
    if file_hash and size > 0:
        seal = seal_evidence(
            source_id=capture_id,
            source_type="forensic_pcap",
            motor="forensic_pcap_capture_service",
            evidence_type="pcap",
            payload={
                "verified": True,
                "capture": {k: meta.get(k) for k in (
                    "capture_id", "trigger", "interface", "duration_sec", "incident_id",
                    "case_id", "user_email", "tenant_id", "packet_count", "file_sha256",
                )},
                "relative_path": os.path.relpath(path, ROOT).replace("\\", "/"),
            },
            user_email=meta.get("user_email"),
            tenant_id=meta.get("tenant_id"),
            equipment=meta.get("equipment"),
        )
        meta["forensic_seal_id"] = (seal or {}).get("forensic_id")
    try:
        from services.defense_evidence_registry import record_defense_event

        record_defense_event(
            "audit",
            "forensic_pcap_saved",
            "forensic_pcap_capture_service",
            "success" if size > 0 else "skipped",
            finding_id=capture_id,
            detail=f"PCAP {size} bytes",
            evidence={"verified": True, "capture_id": capture_id, "sha256": file_hash, "path": meta.get("relative_path")},
            user_email=meta.get("user_email"),
        )
    except Exception as exc:
        logger.debug("pcap defense log: %s", exc)
    _write_capture_index(meta)
    return meta


def _capture_worker(
    capture_id: str,
    iface: Optional[str],
    duration_sec: float,
    max_bytes: int,
    bpf_filter: Optional[str],
    meta: Dict[str, Any],
) -> None:
    path = os.path.join(PCAP_DIR, f"{capture_id}.pcap")
    packet_count = 0
    err = None
    try:
        import scapy.all as scapy
        from scapy.utils import wrpcap

        kwargs: Dict[str, Any] = {"timeout": max(1, duration_sec), "store": True}
        if iface:
            kwargs["iface"] = iface
        if bpf_filter:
            kwargs["filter"] = bpf_filter
        pkts = scapy.sniff(**kwargs)
        packet_count = len(pkts)
        if packet_count == 0:
            meta["note"] = "No se capturaron paquetes en el intervalo — tráfico real ausente o permisos insuficientes."
            with open(path, "wb") as fh:
                fh.write(b"")
        else:
            wrpcap(path, pkts)
            if os.path.getsize(path) > max_bytes:
                meta["truncated"] = True
                meta["max_bytes"] = max_bytes
    except Exception as exc:
        err = str(exc)[:300]
        meta["error"] = err
        logger.error("pcap capture %s: %s", capture_id, exc)
    meta["packet_count"] = packet_count
    meta["relative_path"] = os.path.relpath(path, ROOT).replace("\\", "/")
    if err and not os.path.isfile(path):
        meta["status"] = "failed"
        _write_capture_index(meta)
    else:
        _finalize_pcap_file(capture_id=capture_id, path=path, meta=meta)
    with _lock:
        _active.pop(capture_id, None)


def start_capture(
    *,
    user_email: Optional[str] = None,
    tenant_id: Optional[str] = None,
    equipment: Optional[str] = None,
    interface: Optional[str] = None,
    duration_sec: float = 30,
    max_mb: float = 25,
    incident_id: Optional[str] = None,
    case_id: Optional[str] = None,
    trigger: str = "manual",
    threat_type: Optional[str] = None,
    bpf_filter: Optional[str] = None,
) -> Dict[str, Any]:
    cap = capture_capability()
    if not cap.get("scapy_available"):
        return {"status": "error", "message": cap.get("note") or "Scapy no disponible", "capability": cap}
    duration_sec = min(max(float(duration_sec), 1), 600)
    max_bytes = int(min(max(float(max_mb), 1), 500) * 1024 * 1024)
    capture_id = f"PCAP-{uuid.uuid4().hex[:12]}"
    _ensure_dirs()
    meta = {
        "capture_id": capture_id,
        "started_at": _now(),
        "trigger": trigger,
        "threat_type": threat_type,
        "interface": interface,
        "duration_sec": duration_sec,
        "max_mb": max_mb,
        "user_email": user_email,
        "tenant_id": tenant_id,
        "equipment": equipment,
        "incident_id": incident_id,
        "case_id": case_id,
        "status": "running",
        "metadata_ring_path": METADATA_RING,
    }
    with _lock:
        _active[capture_id] = meta
    threading.Thread(
        target=_capture_worker,
        args=(capture_id, interface, duration_sec, max_bytes, bpf_filter, meta),
        daemon=True,
        name=f"PcapCap-{capture_id[:8]}",
    ).start()
    return {"status": "started", "capture_id": capture_id, "meta": meta, "capability": cap}


def stop_capture(capture_id: str) -> Dict[str, Any]:
    """Detiene solo si implementamos stop early — sniff usa timeout; marca cancel solicitada."""
    with _lock:
        job = _active.get(capture_id)
        if not job:
            return {"status": "not_running", "capture_id": capture_id}
        job["stop_requested_at"] = _now()
    return {"status": "stop_requested", "capture_id": capture_id, "note": "La captura finaliza al completar el timeout configurado."}


def get_capture_status(capture_id: Optional[str] = None) -> Dict[str, Any]:
    with _lock:
        if capture_id:
            return {"active": _active.get(capture_id), "capture_id": capture_id}
        return {"active_captures": list(_active.values())}


def list_captures(limit: int = 50) -> List[Dict[str, Any]]:
    if not os.path.isfile(CAPTURES_INDEX):
        return []
    rows: List[Dict[str, Any]] = []
    with open(CAPTURES_INDEX, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    rows.sort(key=lambda r: r.get("started_at") or "", reverse=True)
    return rows[:limit]


def maybe_kernel_high_criticality_pcap(
    *,
    threat_count: int = 0,
    suspicious: Optional[List[Any]] = None,
    detail: str = "",
) -> None:
    """PCAP bajo decisión del Kernel IA solo con múltiples indicadores concurrentes."""
    sus = suspicious or []
    if threat_count < 2 and len(sus) < 2:
        return
    with _lock:
        if len(_active) >= 2:
            return
    start_capture(
        trigger="kernel_ia",
        threat_type="high_criticality",
        duration_sec=60,
        max_mb=20,
        bpf_filter=None,
    )


def maybe_auto_capture_from_defense(event: Dict[str, Any]) -> None:
    """PCAP automático solo ante detecciones reales catalogadas."""
    if event.get("outcome") not in ("detected", "success", "blocked"):
        return
    evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
    if evidence.get("verified") is False:
        return
    blob = " ".join([
        str(event.get("threat_type") or ""),
        str(event.get("action") or ""),
        str(event.get("detail") or ""),
    ]).lower()
    if not any(k in blob for k in AUTO_TRIGGER_SUBSTRINGS):
        return
    sev = str(evidence.get("level") or evidence.get("severity") or "").lower()
    if sev in ("info", "bajo", "low") and "critical" not in blob and "high" not in blob:
        if "ransom" not in blob and "malware" not in blob:
            return
    with _lock:
        if len(_active) >= 2:
            logger.info("pcap auto: límite de capturas concurrentes")
            return
    ip = evidence.get("ip") if isinstance(evidence, dict) else None
    bpf = f"host {ip}" if ip and _valid_ip(ip) else None
    start_capture(
        trigger="auto_incident",
        threat_type=event.get("threat_type") or event.get("action"),
        incident_id=event.get("finding_id"),
        duration_sec=45,
        max_mb=15,
        bpf_filter=bpf,
        user_email=event.get("user_email"),
    )


def _valid_ip(ip: str) -> bool:
    parts = str(ip).split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def get_pcap_manifest_for_report(report: dict) -> List[Dict[str, Any]]:
    rid = report.get("id") or report.get("report_id")
    if not rid:
        return []
    out = []
    for row in list_captures(200):
        if row.get("case_id") == rid or row.get("incident_id") == rid:
            out.append({
                "capture_id": row.get("capture_id"),
                "trigger": row.get("trigger"),
                "duration_sec": row.get("duration_sec"),
                "interface": row.get("interface"),
                "file_size_bytes": row.get("file_size_bytes"),
                "file_sha256": row.get("file_sha256"),
                "forensic_seal_id": row.get("forensic_seal_id"),
                "incident_id": row.get("incident_id"),
                "status": row.get("status"),
            })
    return out


def run_manual_pcap(params: Dict[str, Any], user_email: Optional[str], tenant_id: Optional[str]) -> Dict[str, Any]:
    action = (params.get("action") or "start").lower()
    if action == "stop":
        cid = params.get("capture_id")
        if not cid:
            return {"status": "error", "message": "capture_id requerido para detener"}
        return stop_capture(cid)
    return start_capture(
        user_email=user_email,
        tenant_id=tenant_id,
        equipment=params.get("equipment"),
        interface=params.get("interface"),
        duration_sec=float(params.get("duration_sec") or 30),
        max_mb=float(params.get("max_mb") or 25),
        case_id=params.get("case_id"),
        incident_id=params.get("incident_id"),
        trigger="manual_defense",
    )
