"""
Ejecución real de mecanismos del Centro de Defensa Manual.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.host_data import get_local_ip
from utils.logger import logger

from services.manual_defense_catalog import (
    CLOUD_PLANNED_MSG,
    MAIL_INTEGRATION_MSG,
    build_catalog,
    check_availability,
    full_protection_sequence,
    get_kernel_doc,
    get_mechanism,
)

DEEP_SCAN_WAIT_SEC = 900
DEEP_SCAN_POLL_SEC = 2.0

_active_full: Dict[str, Dict[str, Any]] = {}
_full_lock = threading.Lock()
_jobs: Dict[str, Dict[str, Any]] = {}
_jobs_lock = threading.Lock()

DEEP_SCAN_EXEC = "deep_scan"


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _result(
    *,
    status: str,
    analyzed: Any,
    findings: List[dict],
    evidence: List[Any],
    risks: List[str],
    auto_actions: List[str],
    recommendations: List[str],
    limitations: Optional[List[str]] = None,
    raw: Optional[dict] = None,
    duration_sec: float = 0,
) -> Dict[str, Any]:
    return {
        "status": status,
        "analyzed": analyzed,
        "findings": findings,
        "evidence": evidence,
        "risks": risks,
        "auto_actions": auto_actions,
        "recommendations": recommendations,
        "limitations": limitations or [],
        "raw_summary": raw,
        "duration_sec": round(duration_sec, 2),
        "timestamp": _now(),
    }


def _wait_deep_scan(scan_id: str, timeout: float = DEEP_SCAN_WAIT_SEC) -> Optional[dict]:
    from services.deep_scan_engine import deep_scan_engine

    deadline = time.time() + timeout
    while time.time() < deadline:
        st = deep_scan_engine.get_status(scan_id)
        if not st:
            return None
        if st.get("status") in ("completed", "failed", "error"):
            rep = deep_scan_engine.get_report(scan_id)
            return rep or st
        time.sleep(DEEP_SCAN_POLL_SEC)
    st = deep_scan_engine.get_status(scan_id)
    return {"status": "timeout", "scan_id": scan_id, "partial": st}


def _findings_from_report(report: dict, flt: Optional[str] = None) -> List[dict]:
    findings = list(report.get("findings") or [])
    if not flt:
        return findings
    fl = flt.lower()
    out = []
    for f in findings:
        text = json.dumps(f, ensure_ascii=False).lower()
        if fl == "ransomware" and ("ransom" in text or "entrop" in text or f.get("risk") in ("high", "critical")):
            out.append(f)
        elif fl == "dll" and ("dll" in text or "inyec" in text):
            out.append(f)
        elif fl == "hidden_process" and ("oculto" in text or "sin ejecutable" in text or "hidden" in text):
            out.append(f)
        elif fl == "privilege" and ("admin" in text or "privileg" in text or "system" in text):
            out.append(f)
        elif fl == "defender" and ("defender" in text or "antivirus" in text):
            out.append(f)
        elif fl == "disks" and ("bitlocker" in text or "cifr" in text or "encrypt" in text):
            out.append(f)
    return out if out else findings[:30]


def _start_deep_scan_only(
    profile: str,
    user_id: Optional[int],
    custom_paths: Optional[List[str]] = None,
) -> str:
    from services.deep_scan_engine import deep_scan_engine

    return deep_scan_engine.start_scan(
        session_id="manual_defense",
        user_id=user_id,
        profile=profile,
        query=f"manual_defense profile={profile}",
        modules_loaded=["Manual Defense Center", "Deep Scan Engine"],
        custom_roots=custom_paths,
    )


def _run_deep_scan(
    profile: str,
    user_id: Optional[int],
    custom_paths: Optional[List[str]] = None,
    flt: Optional[str] = None,
) -> Dict[str, Any]:
    from services.deep_scan_engine import deep_scan_engine

    t0 = time.time()
    scan_id = deep_scan_engine.start_scan(
        session_id="manual_defense",
        user_id=user_id,
        profile=profile,
        query=f"manual_defense profile={profile}",
        modules_loaded=["Manual Defense Center", "Deep Scan Engine"],
        custom_roots=custom_paths,
    )
    report = _wait_deep_scan(scan_id)
    if not report:
        return _result(
            status="error",
            analyzed=0,
            findings=[],
            evidence=[{"scan_id": scan_id}],
            risks=[],
            auto_actions=[],
            recommendations=["Escaneo no disponible"],
            duration_sec=time.time() - t0,
        )
    if report.get("status") == "timeout":
        return _result(
            status="timeout",
            analyzed=report.get("partial", {}).get("progress_pct"),
            findings=_findings_from_report(report.get("partial") or {}, flt),
            evidence=[{"scan_id": scan_id, "note": "Tiempo máximo agotado; resultados parciales"}],
            risks=["Escaneo incompleto"],
            auto_actions=[],
            recommendations=["Reintentar con perfil quick o esperar y consultar /api/ai/deep-scan/{id}/report"],
            limitations=["Timeout de ejecución manual"],
            duration_sec=time.time() - t0,
        )
    findings = _findings_from_report(report, flt)
    stats = report.get("stats") or {}
    analyzed = stats.get("files_scanned") or stats.get("processes_scanned") or len(findings)
    risks = list({f.get("risk", "info") for f in findings if f.get("risk") not in ("info", "safe")})
    return _result(
        status="completed" if report.get("status") != "failed" else "failed",
        analyzed=analyzed,
        findings=findings,
        evidence=[{"scan_id": scan_id, "host": socket.gethostname(), "profile": profile}],
        risks=risks,
        auto_actions=["Registro en endpoint_scan_records / deep_scan"],
        recommendations=(report.get("recommendations") or [])[:8],
        raw={"summary": report.get("summary"), "risk_level": report.get("risk_level")},
        duration_sec=time.time() - t0,
    )


def _run_file_path(path: str) -> Dict[str, Any]:
    t0 = time.time()
    if not path or not os.path.isfile(path):
        return _result(
            status="error",
            analyzed=0,
            findings=[],
            evidence=[],
            risks=[],
            auto_actions=[],
            recommendations=["Indique path absoluto a un archivo existente en el host NOVUS."],
            limitations=["Archivo no encontrado"],
            duration_sec=time.time() - t0,
        )
    from services.advanced_detector_service import advanced_detector

    entropy = advanced_detector.calculate_entropy(path)
    reputation = advanced_detector.scan_file_reputation(path)
    ransomware_alert = entropy > 7.2
    finding = {
        "path": path,
        "entropy": entropy,
        "reputation": reputation,
        "risk": "high" if ransomware_alert or (reputation.get("malicioso", 0) > 0) else "info",
    }
    risks = ["ALTO"] if finding["risk"] == "high" else []
    return _result(
        status="completed",
        analyzed=1,
        findings=[finding] if finding["risk"] != "info" else [],
        evidence=[finding],
        risks=risks,
        auto_actions=[],
        recommendations=["Cuarentena manual vía endpoint si el veredicto es malicioso."],
        duration_sec=time.time() - t0,
    )


def _run_processes() -> Dict[str, Any]:
    t0 = time.time()
    from services.advanced_detector_service import advanced_detector

    threats = advanced_detector.scan_running_processes()
    return _result(
        status="completed",
        analyzed=len(threats),
        findings=threats,
        evidence=threats[:50],
        risks=[t.get("severity", "medium") for t in threats],
        auto_actions=["Telemetría XDR si el motor publica eventos"],
        recommendations=["Investigar procesos con severidad alta"],
        duration_sec=time.time() - t0,
    )


def _run_miners() -> Dict[str, Any]:
    t0 = time.time()
    from services.advanced_detector_service import advanced_detector

    threats = advanced_detector.scan_running_processes()
    miners = [t for t in threats if "miner" in json.dumps(t, ensure_ascii=False).lower() or "xmrig" in json.dumps(t).lower()]
    return _result(
        status="completed",
        analyzed=len(threats),
        findings=miners,
        evidence=miners,
        risks=["high"] if miners else [],
        auto_actions=[],
        recommendations=["Terminar proceso y revisar persistencia si hay mineros confirmados"],
        duration_sec=time.time() - t0,
    )


def _run_network_scan() -> Dict[str, Any]:
    t0 = time.time()
    from services.network_scanner import network_scanner

    nodes = network_scanner.scan_network(force=True) or []
    return _result(
        status="completed" if nodes else "no_data",
        analyzed=len(nodes),
        findings=[{"ip": n.get("ip"), "mac": n.get("mac"), "vendor": n.get("vendor")} for n in nodes],
        evidence=nodes,
        risks=["Dispositivos no inventariados"] if len(nodes) > 0 else [],
        auto_actions=["Actualización caché network_scanner"],
        recommendations=["Aprobar dispositivos en inventario si son legítimos"],
        duration_sec=time.time() - t0,
    )


def _run_net_events(event_filter: str) -> Dict[str, Any]:
    t0 = time.time()
    from services.device_connection_monitor import list_events

    events = list_events(limit=100) or []
    filtered = []
    for ev in events:
        et = (ev.get("event_type") or ev.get("type") or "").lower()
        if event_filter == "connect" and "connect" in et:
            filtered.append(ev)
        elif event_filter == "disconnect" and "disconnect" in et:
            filtered.append(ev)
        elif event_filter == "reconnect" and ("reconnect" in et or "reappear" in et):
            filtered.append(ev)
    return _result(
        status="completed",
        analyzed=len(events),
        findings=filtered,
        evidence=filtered[:30],
        risks=["Eventos de red requieren revisión"] if filtered else [],
        auto_actions=["Registro device_connection_events"],
        recommendations=["Ver historial dispositivos en NOVUS"] if not filtered else ["Validar dispositivos en filtered list"],
        limitations=["Sin historial si el monitor acaba de iniciarse"] if not events else [],
        duration_sec=time.time() - t0,
    )


def _run_ndr_unknown() -> Dict[str, Any]:
    t0 = time.time()
    from services.network_ndr_service import build_ndr_payload

    payload = build_ndr_payload(force_refresh=True)
    unknown = payload.get("unknown_devices") or []
    return _result(
        status="completed",
        analyzed=len(payload.get("devices") or []),
        findings=unknown,
        evidence=unknown[:40],
        risks=["Activos desconocidos"] if unknown else [],
        auto_actions=["Alertas NDR"],
        recommendations=["Aprobar o bloquear en inventario de activos"],
        duration_sec=time.time() - t0,
    )


def _run_mitm() -> Dict[str, Any]:
    t0 = time.time()
    from services.novus_security_integration import novus_security
    from services.web_shield_host_audit import full_host_audit
    import psutil

    conns = []
    for c in psutil.net_connections(kind="inet")[:30]:
        conns.append({"laddr": str(c.laddr), "raddr": str(c.raddr) if c.raddr else None, "status": c.status})
    meta = {"active_connections_sample": conns, "host": socket.gethostname()}
    mitm = novus_security.security_engine.verify_tunnel_integrity(meta)
    audit = full_host_audit()
    return _result(
        status="completed",
        analyzed=len(conns),
        findings=[mitm] if mitm else [],
        evidence=[{"mitm": mitm, "host_audit": audit}],
        risks=[mitm.get("status")] if mitm.get("status") not in (None, "OK", "SAFE", "secure") else [],
        auto_actions=[],
        recommendations=["Revisar proxy y DNS locales si MITM no es OK"],
        limitations=["Sin captura de paquetes en tránsito"],
        duration_sec=time.time() - t0,
    )


def _run_ndr_alerts(alert_filter: str) -> Dict[str, Any]:
    t0 = time.time()
    from services.network_ndr_service import build_ndr_payload

    payload = build_ndr_payload(force_refresh=True)
    alerts = payload.get("alerts") or []
    filtered = []
    for a in alerts:
        blob = json.dumps(a, ensure_ascii=False).lower()
        if alert_filter == "arp" and ("arp" in blob or "conflict" in blob):
            filtered.append(a)
        elif alert_filter == "dhcp" and ("dhcp" in blob or "ip" in blob and "cambio" in blob):
            filtered.append(a)
    return _result(
        status="completed",
        analyzed=len(alerts),
        findings=filtered,
        evidence=filtered,
        risks=["Alerta NDR activa"] if filtered else [],
        auto_actions=[],
        recommendations=["Investigar dispositivo en topología"] if filtered else ["Sin alertas ARP/DHCP en telemetría actual"],
        limitations=["Inferencia sin sensor inline"] if alert_filter == "dhcp" else [],
        duration_sec=time.time() - t0,
    )


def _run_dns_audit() -> Dict[str, Any]:
    t0 = time.time()
    from services.web_shield_host_audit import full_host_audit

    audit = full_host_audit()
    dns = audit.get("dns") or audit.get("dns_servers") or audit
    return _result(
        status="completed",
        analyzed=1,
        findings=[],
        evidence=[audit],
        risks=[],
        auto_actions=[],
        recommendations=["Compare DNS con política corporativa esperada"],
        duration_sec=time.time() - t0,
        raw={"dns": dns},
    )


def _run_open_ports() -> Dict[str, Any]:
    t0 = time.time()
    from services.advanced_detector_service import advanced_detector

    ports = advanced_detector.scan_open_ports()
    risky = [p for p in ports if p.get("port") in (23, 445, 3389, 5900, 4444)]
    return _result(
        status="completed",
        analyzed=len(ports),
        findings=risky or ports,
        evidence=ports,
        risks=["Puertos de alto riesgo abiertos"] if risky else [],
        auto_actions=[],
        recommendations=["Cerrar servicios innecesarios"],
        duration_sec=time.time() - t0,
    )


def _run_traffic() -> Dict[str, Any]:
    t0 = time.time()
    import psutil
    from services.network_ndr_service import build_ndr_payload

    io = psutil.net_io_counters(pernic=False)
    ndr = build_ndr_payload()
    top = ndr.get("top_traffic") or []
    return _result(
        status="completed",
        analyzed=1,
        findings=top[:15],
        evidence=[{"net_io": io._asdict() if io else {}, "top_traffic": top[:15]}],
        risks=[],
        auto_actions=[],
        recommendations=[],
        duration_sec=time.time() - t0,
    )


def _run_forensic_pcap(params: Dict[str, Any], user_email: Optional[str]) -> Dict[str, Any]:
    t0 = time.time()
    from services.forensic_pcap_capture_service import (
        capture_capability,
        get_capture_status,
        list_captures,
        run_manual_pcap,
    )

    cap = capture_capability()
    action = (params.get("action") or "start").lower()
    if action == "status":
        cid = params.get("capture_id")
        st = get_capture_status(cid)
        return _result(
            status="completed",
            analyzed=1,
            findings=[],
            evidence=[st],
            risks=[],
            auto_actions=[],
            recommendations=[],
            duration_sec=time.time() - t0,
        )
    if action == "list":
        rows = list_captures(20)
        return _result(
            status="completed",
            analyzed=len(rows),
            findings=rows[:10],
            evidence=[{"captures": rows, "capability": cap}],
            risks=[],
            auto_actions=[],
            recommendations=["Use Wireshark o tshark para analizar PCAP fuera de NOVUS si se requiere DPI."],
            duration_sec=time.time() - t0,
        )
    started = run_manual_pcap(params, user_email, None)
    ok = started.get("status") in ("started", "stop_requested")
    recs = []
    if not cap.get("npcap_or_capture_ready"):
        recs.append(
            cap.get("note")
            or "Npcap/permisos de captura no detectados — ejecute NOVUS como administrador (Windows)."
        )
    if started.get("status") == "error":
        recs.append(started.get("message") or "No se pudo iniciar captura")
    return _result(
        status="completed" if ok else "error",
        analyzed=1,
        findings=[started],
        evidence=[{"capture": started, "capability": cap}],
        risks=[] if ok else ["Captura PCAP no iniciada"],
        auto_actions=[f"Captura {started.get('capture_id')} en curso"] if started.get("capture_id") else [],
        recommendations=recs,
        limitations=[
            "PCAP solo contiene tráfico real observado en la interfaz seleccionada.",
            "TLS interno no visible sin claves de sesión.",
        ],
        duration_sec=time.time() - t0,
    )


def _run_gateway() -> Dict[str, Any]:
    t0 = time.time()
    from services.network_monitor_engine import get_monitor_status

    mon = get_monitor_status()
    return _result(
        status="completed",
        analyzed=1,
        findings=[],
        evidence=[mon],
        risks=["Gateway inestable"] if not mon.get("active") else [],
        auto_actions=["Monitor de red en background"] if mon.get("active") else [],
        recommendations=["Activar monitor si inactive"],
        duration_sec=time.time() - t0,
    )


def _run_net_stability() -> Dict[str, Any]:
    return _run_gateway()


def _run_web_url(url: str) -> Dict[str, Any]:
    t0 = time.time()
    if not (url or "").strip():
        return _result(
            status="error",
            analyzed=0,
            findings=[],
            evidence=[],
            risks=[],
            auto_actions=[],
            recommendations=["Proporcione parámetro url (https://...)"],
            duration_sec=time.time() - t0,
        )
    from services.web_shield_engine import analyze_and_policy_url

    res = analyze_and_policy_url(url.strip(), source="manual_defense")
    findings = [res] if res.get("blocked") or res.get("risk") in ("high", "critical", "medium") else []
    return _result(
        status="completed",
        analyzed=1,
        findings=findings,
        evidence=[res],
        risks=[res.get("risk") or res.get("verdict")],
        auto_actions=["Política Web Shield aplicada"] if res.get("policy_action") else [],
        recommendations=[res.get("message") or "Revise veredicto Web Shield"],
        duration_sec=time.time() - t0,
    )


def _run_web_credential(url: Optional[str]) -> Dict[str, Any]:
    t0 = time.time()
    from services.web_shield_host_audit import full_host_audit

    audit = full_host_audit()
    web = _run_web_url(url) if url else None
    evidence = [{"host_audit": audit}]
    if web:
        evidence.append(web.get("evidence", [{}])[0])
    risks = list(web.get("risks", []) if web else [])
    if audit.get("proxy", {}).get("proxy_enabled"):
        risks.append("proxy_enabled")
    return _result(
        status="completed",
        analyzed=1 + (1 if url else 0),
        findings=(web.get("findings") if web else []),
        evidence=evidence,
        risks=risks,
        auto_actions=[],
        recommendations=["Desactivar proxy no autorizado", "Analizar URL sospechosa con Web Shield"],
        duration_sec=time.time() - t0,
    )


def _run_mail(user_id, mail_action: str) -> Dict[str, Any]:
    t0 = time.time()
    from services.mail_shield_service import get_integration_status, list_events

    st = get_integration_status(user_id)
    if not st.get("any_connected"):
        return _result(
            status="unavailable",
            analyzed=0,
            findings=[],
            evidence=[st],
            risks=[],
            auto_actions=[],
            recommendations=[MAIL_INTEGRATION_MSG],
            limitations=[MAIL_INTEGRATION_MSG],
            duration_sec=time.time() - t0,
        )
    if mail_action == "sync":
        from services.mail_shield_engine import sync_now

        sync = sync_now(user_id)
        return _result(
            status=sync.get("status", "completed"),
            analyzed=sync.get("messages_processed") or 0,
            findings=sync.get("findings") or [],
            evidence=[sync],
            risks=[],
            auto_actions=["Sincronización buzón OAuth"],
            recommendations=[],
            duration_sec=time.time() - t0,
        )
    events = list_events(limit=80)
    filtered = events
    if mail_action == "events_phishing":
        filtered = [e for e in events if "phish" in json.dumps(e).lower()]
    elif mail_action == "events_malware":
        filtered = [e for e in events if "malware" in json.dumps(e).lower() or "virus" in json.dumps(e).lower()]
    elif mail_action == "events_spam":
        filtered = [e for e in events if "spam" in json.dumps(e).lower()]
    elif mail_action == "events_spoof":
        filtered = [e for e in events if "spoof" in json.dumps(e).lower() or "fake" in json.dumps(e).lower()]
    elif mail_action == "bec":
        from services.novus_security_integration import novus_security

        sample = events[0] if events else {}
        bec = novus_security.security_engine.validate_transactional_integrity(
            sample.get("metadata") or {},
            sample.get("invoice") or {},
        )
        return _result(
            status="completed",
            analyzed=len(events),
            findings=[bec] if bec else [],
            evidence=[bec],
            risks=[bec.get("status")] if bec else [],
            auto_actions=[],
            recommendations=[],
            duration_sec=time.time() - t0,
        )
    elif mail_action in ("headers", "rules", "attachments", "links"):
        return _result(
            status="completed",
            analyzed=len(events),
            findings=filtered[:20],
            evidence=filtered[:20],
            risks=[],
            auto_actions=[],
            recommendations=[f"Datos reales vía eventos Mail Shield ({mail_action})"],
            limitations=["Reglas/detalle completo depende del proveedor OAuth conectado"],
            duration_sec=time.time() - t0,
        )
    return _result(
        status="completed",
        analyzed=len(filtered),
        findings=filtered,
        evidence=filtered[:30],
        risks=[],
        auto_actions=[],
        recommendations=[],
        duration_sec=time.time() - t0,
    )


def _run_system_health() -> Dict[str, Any]:
    t0 = time.time()
    from services.advanced_detector_service import advanced_detector

    data = advanced_detector.scan_system_health()
    return _result(
        status="completed",
        analyzed=1,
        findings=data.get("issues") or [],
        evidence=[data],
        risks=data.get("risk_labels") or [],
        auto_actions=[],
        recommendations=data.get("recommendations") or [],
        duration_sec=time.time() - t0,
    )


def _run_endpoint_status() -> Dict[str, Any]:
    t0 = time.time()
    from services.endpoint_scan_engine import endpoint_scan_engine

    st = endpoint_scan_engine.engine_status()
    health = _run_system_health()
    return _result(
        status="completed",
        analyzed=1,
        findings=health.get("findings") or [],
        evidence=[st, health.get("evidence", [{}])[0]],
        risks=health.get("risks") or [],
        auto_actions=["Monitor endpoint en background"],
        recommendations=health.get("recommendations") or [],
        duration_sec=time.time() - t0,
    )


def _run_cloud_uce() -> Dict[str, Any]:
    t0 = time.time()
    from services.universal_compatibility_engine import _detect_cloud

    items = _detect_cloud()
    return _result(
        status="completed",
        analyzed=len(items),
        findings=items,
        evidence=items,
        risks=["Credenciales cloud en entorno local"] if items else [],
        auto_actions=[],
        recommendations=["Rotar claves si variables cloud no deberían estar en este host"] if items else ["Sin señales cloud en variables de entorno"],
        limitations=["NOVUS Cloud Shield CSPM no operativo — solo detección local UCE"],
        duration_sec=time.time() - t0,
    )


def _run_sector(sector_key: str, email: Optional[str]) -> Dict[str, Any]:
    t0 = time.time()
    if sector_key == "cloud":
        return _result(
            status="unavailable",
            analyzed=0,
            findings=[],
            evidence=[],
            risks=[],
            auto_actions=[],
            recommendations=[CLOUD_PLANNED_MSG],
            limitations=[CLOUD_PLANNED_MSG],
            duration_sec=time.time() - t0,
        )
    from services.novus_security_integration import novus_security
    from services.sector_shield_service import scan_sector, SECTOR_ENGINE_ACTIONS

    shield = novus_security.security_engine.build_sector_protection(sector_key)
    if sector_key in SECTOR_ENGINE_ACTIONS and email:
        scan = scan_sector(email)
    else:
        vulns = novus_security.scan_vulnerabilities()
        threats = novus_security.detect_threats_realtime()
        scan = {
            "status": "success",
            "shield": shield,
            "steps": [
                {"label": "Vulnerabilidades", "detail": len(vulns)},
                {"label": "Amenazas", "detail": len(threats.get("suspicious_processes") or [])},
            ],
        }
    findings = scan.get("steps") or []
    return _result(
        status="completed",
        analyzed=len(findings),
        findings=findings,
        evidence=[{"shield": shield, "scan": scan}],
        risks=[],
        auto_actions=["ASPE puede activar módulos cruzados si hay incidente"],
        recommendations=[f"Sector {sector_key}: revisar pasos del escaneo sectorial"],
        duration_sec=time.time() - t0,
    )


def execute_mechanism(
    mechanism_id: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    user_id: Optional[int] = None,
    user_email: Optional[str] = None,
) -> Dict[str, Any]:
    params = params or {}
    mech = get_mechanism(mechanism_id)
    if not mech:
        return {"status": "error", "message": "Mecanismo desconocido"}
    avail = check_availability(mech, user_id)
    if not avail.get("available"):
        return {
            "status": "unavailable",
            "mechanism_id": mechanism_id,
            "message": avail.get("reason"),
            "result": _result(
                status="unavailable",
                analyzed=0,
                findings=[],
                evidence=[],
                risks=[],
                auto_actions=[],
                recommendations=[avail.get("reason") or "No disponible"],
                limitations=[avail.get("reason") or ""],
            ),
        }
    for p in mech.get("params") or []:
        if p not in params or not params.get(p):
            return {
                "status": "needs_params",
                "mechanism_id": mechanism_id,
                "required_params": mech.get("params"),
                "message": f"Parámetro requerido: {', '.join(mech.get('params') or [])}",
            }

    exec_type = mech.get("exec")
    t0 = time.time()
    try:
        if exec_type == "deep_scan":
            paths = None
            if params.get("paths"):
                paths = params["paths"] if isinstance(params["paths"], list) else [params["paths"]]
            if params.get("path") and mech.get("profile") == "custom":
                paths = [params["path"]]
            res = _run_deep_scan(
                mech.get("profile", "quick"),
                user_id,
                custom_paths=paths,
                flt=mech.get("filter"),
            )
        elif exec_type == "file_path":
            res = _run_file_path(params.get("path", ""))
        elif exec_type == "processes":
            res = _run_processes()
        elif exec_type == "miners":
            res = _run_miners()
        elif exec_type == "network_scan":
            res = _run_network_scan()
        elif exec_type == "net_events":
            res = _run_net_events(mech.get("event_filter", "connect"))
        elif exec_type == "ndr_unknown":
            res = _run_ndr_unknown()
        elif exec_type == "mitm":
            res = _run_mitm()
        elif exec_type == "ndr_alerts":
            res = _run_ndr_alerts(mech.get("alert_filter", "arp"))
        elif exec_type == "dns_audit":
            res = _run_dns_audit()
        elif exec_type == "open_ports":
            res = _run_open_ports()
        elif exec_type == "traffic":
            res = _run_traffic()
        elif exec_type == "forensic_pcap":
            res = _run_forensic_pcap(params, user_email)
        elif exec_type == "gateway" or exec_type == "net_stability":
            res = _run_net_stability()
        elif exec_type == "web_url":
            res = _run_web_url(params.get("url", ""))
        elif exec_type == "web_credential":
            res = _run_web_credential(params.get("url"))
        elif exec_type == "mail":
            res = _run_mail(user_id, mech.get("mail_action", "sync"))
        elif exec_type == "system_health":
            res = _run_system_health()
        elif exec_type == "endpoint_status":
            res = _run_endpoint_status()
        elif exec_type == "sector":
            res = _run_sector(mech.get("sector_key", "fintech"), user_email)
        elif exec_type == "cloud_uce":
            res = _run_cloud_uce()
        else:
            res = _result(
                status="error",
                analyzed=0,
                findings=[],
                evidence=[],
                risks=[],
                auto_actions=[],
                recommendations=["Tipo de ejecución no implementado"],
                duration_sec=time.time() - t0,
            )
    except Exception as exc:
        logger.error("manual_defense execute %s: %s", mechanism_id, exc, exc_info=True)
        res = _result(
            status="error",
            analyzed=0,
            findings=[],
            evidence=[{"error": str(exc)}],
            risks=[],
            auto_actions=[],
            recommendations=[str(exc)],
            duration_sec=time.time() - t0,
        )

    return {
        "status": "ok",
        "mechanism_id": mechanism_id,
        "title": mech.get("title"),
        "category": mech.get("category"),
        "result": res,
    }


def _attach_report(
    out: Dict[str, Any],
    *,
    user_email: Optional[str],
    history_id: Optional[str] = None,
    aggregate: Optional[dict] = None,
) -> Dict[str, Any]:
    """Genera informe persistido y expone report_id / report_available."""
    from services.manual_defense_report_service import build_manual_defense_report, report_exists

    res = out.get("result") or {}
    if res.get("status") in ("error", "unavailable", "needs_params"):
        out["report_available"] = False
        out["report_error"] = res.get("recommendations", ["Ejecución no completada"])[0] if res.get("recommendations") else "Ejecución no completada"
        return out
    try:
        report = build_manual_defense_report(
            mechanism_id=out.get("mechanism_id", ""),
            mechanism_title=out.get("title") or out.get("mechanism_id", ""),
            category=out.get("category") or "",
            result=res,
            user_email=user_email,
            history_id=history_id,
            aggregate=aggregate,
        )
        rid = report["id"]
        out["report_id"] = rid
        out["report_available"] = report_exists(rid)
        if not out["report_available"]:
            out["report_error"] = "El informe no se encontró en disco tras guardarlo."
        out["stats"] = (report.get("technical") or {}).get("estadisticas")
    except Exception as exc:
        logger.error("manual_defense report: %s", exc, exc_info=True)
        out["report_available"] = False
        out["report_error"] = f"No se pudo generar el informe: {exc}"
    return out


def start_execute_job(
    mechanism_id: str,
    params: Optional[Dict[str, Any]],
    *,
    user_id: Optional[int] = None,
    user_email: Optional[str] = None,
) -> Dict[str, Any]:
    """Inicia ejecución; deep_scan devuelve job asíncrono con progreso real."""
    params = params or {}
    mech = get_mechanism(mechanism_id)
    if not mech:
        return {"status": "error", "message": "Mecanismo desconocido"}
    avail = check_availability(mech, user_id)
    if not avail.get("available"):
        return {
            "status": "unavailable",
            "message": avail.get("reason"),
        }
    for p in mech.get("params") or []:
        if p not in params or not params.get(p):
            return {
                "status": "needs_params",
                "required_params": mech.get("params"),
                "message": f"Parámetro requerido: {', '.join(mech.get('params') or [])}",
            }

    job_id = f"MDJ-{uuid.uuid4().hex[:12]}"
    started = _now()
    if mech.get("exec") == DEEP_SCAN_EXEC:
        paths = None
        if params.get("paths"):
            paths = params["paths"] if isinstance(params["paths"], list) else [params["paths"]]
        if params.get("path") and mech.get("profile") == "custom":
            paths = [params["path"]]
        scan_id = _start_deep_scan_only(mech.get("profile", "quick"), user_id, paths)
        with _jobs_lock:
            _jobs[job_id] = {
                "job_id": job_id,
                "status": "running",
                "mechanism_id": mechanism_id,
                "title": mech.get("title"),
                "category": mech.get("category"),
                "scan_id": scan_id,
                "profile": mech.get("profile"),
                "filter": mech.get("filter"),
                "started_at": started,
                "user_email": user_email,
                "user_id": user_id,
                "_t0": time.time(),
            }
        return {
            "status": "success",
            "async": True,
            "job_id": job_id,
            "message": "Escaneo iniciado — siga el progreso en tiempo real.",
        }

    out = execute_mechanism(mechanism_id, params, user_id=user_id, user_email=user_email)
    if out.get("status") != "ok":
        return out
    out = _attach_report(out, user_email=user_email)
    with _jobs_lock:
        _jobs[job_id] = {
            "job_id": job_id,
            "status": "completed",
            "mechanism_id": mechanism_id,
            "started_at": started,
            "finished_at": _now(),
            "result": out.get("result"),
            "report_id": out.get("report_id"),
            "report_available": out.get("report_available"),
            "report_error": out.get("report_error"),
            "stats": out.get("stats"),
        }
    return {
        "status": "success",
        "async": False,
        "job_id": job_id,
        "report_id": out.get("report_id"),
        "report_available": out.get("report_available"),
        "report_error": out.get("report_error"),
        "result": out.get("result"),
        "mechanism_id": mechanism_id,
        "title": out.get("title"),
        "duration_seconds": (out.get("result") or {}).get("duration_sec"),
        "stats": out.get("stats"),
    }


def _job_finalize_deep_scan(job: Dict[str, Any]) -> Dict[str, Any]:
    from services.deep_scan_engine import deep_scan_engine

    scan_id = job.get("scan_id")
    if not scan_id:
        job["status"] = "failed"
        job["report_error"] = "scan_id ausente en el job"
        return job
    st = deep_scan_engine.get_status(scan_id)
    if not st:
        job["status"] = "failed"
        job["report_error"] = "Escaneo no encontrado en el motor"
        return job
    job["progress"] = {
        "phase": st.get("phase"),
        "phase_label": st.get("phase_label"),
        "progress_pct": st.get("progress_pct"),
        "elapsed_sec": st.get("elapsed_sec"),
        "stats": st.get("stats"),
        "current_element": st.get("current_element"),
    }
    if st.get("status") != "running":
        flt = job.get("filter")
        report = deep_scan_engine.get_report(scan_id)
        if not report and st.get("status") == "running":
            return job
        if st.get("status") in ("failed", "error"):
            job["status"] = "failed"
            job["report_error"] = st.get("error") or "Escaneo fallido"
            return job
        if not report:
            job["status"] = "timeout"
            job["report_error"] = "Escaneo terminó sin informe — reintente o consulte deep_scan status"
            return job
        findings = _findings_from_report(report, flt)
        stats = report.get("stats") or st.get("stats") or {}
        t0 = job.get("_t0") or time.time()
        res = _result(
            status="completed" if report.get("status") != "failed" else "failed",
            analyzed=stats.get("files_analyzed") or len(findings),
            findings=findings,
            evidence=[{"scan_id": scan_id, "profile": job.get("profile")}],
            risks=list({f.get("risk") for f in findings if f.get("risk")}),
            auto_actions=["Registro deep_scan_engine"],
            recommendations=(report.get("recommendations") or [])[:8],
            raw={"summary": report.get("summary"), "stats": stats, "risk_level": report.get("risk_level")},
            duration_sec=time.time() - t0,
        )
        out = {
            "status": "ok",
            "mechanism_id": job.get("mechanism_id"),
            "title": job.get("title"),
            "category": job.get("category"),
            "result": res,
        }
        out = _attach_report(out, user_email=job.get("user_email"))
        job["status"] = "completed"
        job["finished_at"] = _now()
        job["result"] = res
        job["report_id"] = out.get("report_id")
        job["report_available"] = out.get("report_available")
        job["report_error"] = out.get("report_error")
        job["stats"] = out.get("stats")
        job["duration_sec"] = res.get("duration_sec")
    return job


def get_execute_job(job_id: str) -> Optional[Dict[str, Any]]:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return None
        job = dict(job)
    if job.get("status") == "running" and job.get("scan_id"):
        job = _job_finalize_deep_scan(job)
        with _jobs_lock:
            _jobs[job_id] = job
        if job.get("status") == "completed" and not job.get("history_persisted"):
            try:
                import socket as _socket
                res = job.get("result") or {}
                hist = persist_history(
                    user_email=job.get("user_email") or "",
                    hostname=_socket.gethostname(),
                    client_ip="",
                    mechanism_ids=[job.get("mechanism_id")],
                    duration_sec=float(res.get("duration_sec") or 0),
                    aggregate={
                        "started_at": job.get("started_at"),
                        "findings_count": len(res.get("findings") or []),
                        "evidence": res.get("evidence"),
                        "mechanism_id": job.get("mechanism_id"),
                    },
                    report_id=job.get("report_id"),
                )
                job["history_id"] = hist
                job["history_persisted"] = True
                with _jobs_lock:
                    _jobs[job_id] = job
            except Exception as exc:
                logger.error("persist job history: %s", exc)
    payload = {
        "job_id": job_id,
        "status": job.get("status"),
        "mechanism_id": job.get("mechanism_id"),
        "title": job.get("title"),
        "progress": job.get("progress"),
        "report_id": job.get("report_id"),
        "report_available": job.get("report_available"),
        "report_error": job.get("report_error"),
        "result": job.get("result"),
        "stats": job.get("stats"),
        "duration_seconds": job.get("duration_sec"),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
    }
    if job.get("status") == "running" and job.get("progress"):
        prog = job["progress"]
        stats = prog.get("stats") or {}
        payload["phase_label"] = prog.get("phase_label")
        payload["progress_pct"] = prog.get("progress_pct")
        payload["elapsed_sec"] = prog.get("elapsed_sec")
        payload["elements_analyzed"] = {
            "files": stats.get("files_analyzed", 0),
            "processes": stats.get("processes_analyzed", 0),
            "services": stats.get("services_analyzed", 0),
        }
        if prog.get("elapsed_sec") and prog.get("progress_pct"):
            pct = max(prog["progress_pct"], 1)
            payload["eta_sec"] = round(prog["elapsed_sec"] * (100 - pct) / pct, 1)
    return payload


def build_kernel_consult(mechanism_id: str, user_email: Optional[str] = None) -> Dict[str, Any]:
    doc = get_kernel_doc(mechanism_id) or {}
    mech = get_mechanism(mechanism_id)
    label = mech.get("title") if mech else mechanism_id
    structured = {
        "mechanism_id": mechanism_id,
        "title": label,
        **doc,
    }
    prompt = (
        f"[Centro de Defensa Manual — {label}]\n"
        f"Explica en español, sin inventar datos:\n"
        f"1) Qué hace\n2) Qué amenazas detecta\n3) Qué técnicas utiliza\n"
        f"4) Limitaciones\n5) Información necesaria\n6) Evidencias que genera\n7) Acciones que realizará\n\n"
        f"--- ESPECIFICACIÓN VERIFICADA ---\n{json.dumps(structured, ensure_ascii=False, indent=2)}\n--- FIN ---"
    )
    from services.module_kernel_context import build_consult_prompt

    ctx = build_consult_prompt(
        "manual_defense_center",
        user_email,
        {"mechanism_id": mechanism_id, "mechanism_doc": doc},
    )
    ctx["mechanism_prompt"] = prompt
    ctx["mechanism_structured"] = structured
    return ctx


def persist_history(
    *,
    user_email: str,
    hostname: str,
    client_ip: str,
    mechanism_ids: List[str],
    duration_sec: float,
    aggregate: Dict[str, Any],
    report_id: Optional[str] = None,
) -> str:
    from database import SessionLocal, ManualDefenseRun

    run_id = f"MDR-{uuid.uuid4().hex[:12]}"
    db = SessionLocal()
    try:
        try:
            from sqlalchemy import text
            db.execute(text("SELECT report_id FROM manual_defense_runs LIMIT 1"))
        except Exception:
            try:
                db.execute(text("ALTER TABLE manual_defense_runs ADD COLUMN report_id VARCHAR"))
                db.commit()
            except Exception:
                db.rollback()
        row = ManualDefenseRun(
            id=run_id,
            user_email=user_email or "",
            hostname=hostname,
            client_ip=client_ip or "",
            started_at=aggregate.get("started_at") or _now(),
            finished_at=_now(),
            duration_sec=str(round(duration_sec, 2)),
            mechanisms_json=json.dumps(mechanism_ids, ensure_ascii=False),
            findings_json=json.dumps(aggregate.get("findings_count", 0)),
            evidence_json=json.dumps(aggregate.get("evidence", []), ensure_ascii=False)[:500000],
            actions_json=json.dumps(aggregate.get("auto_actions", []), ensure_ascii=False),
            report_json=json.dumps(aggregate, ensure_ascii=False)[:800000],
            report_id=report_id,
        )
        db.add(row)
        db.commit()
    except Exception as exc:
        logger.error("manual_defense history: %s", exc)
        db.rollback()
    finally:
        db.close()
    return run_id


def _full_protection_worker(
    run_id: str,
    user_id: Optional[int],
    user_email: Optional[str],
    mechanism_ids: List[str],
    client_ip: str,
):
    started = _now()
    t0 = time.time()
    steps = []
    total_findings = 0
    all_evidence = []
    all_actions = []
    with _full_lock:
        _active_full[run_id] = {
            "run_id": run_id,
            "status": "running",
            "started_at": started,
            "progress_pct": 0,
            "current": None,
            "steps": steps,
        }
    n = len(mechanism_ids)
    for i, mid in enumerate(mechanism_ids):
        with _full_lock:
            _active_full[run_id]["current"] = mid
            _active_full[run_id]["progress_pct"] = int((i / max(n, 1)) * 100)
        if mid == "web_credential_theft":
            ex = execute_mechanism(mid, {}, user_id=user_id, user_email=user_email)
        elif mid == "mail_scan_mailbox":
            ex = execute_mechanism(mid, {}, user_id=user_id, user_email=user_email)
        else:
            ex = execute_mechanism(mid, {}, user_id=user_id, user_email=user_email)
        res = ex.get("result") or {}
        fc = len(res.get("findings") or [])
        total_findings += fc
        step = {
            "mechanism_id": mid,
            "status": ex.get("status"),
            "findings_count": fc,
            "duration_sec": res.get("duration_sec"),
        }
        steps.append(step)
        all_evidence.extend(res.get("evidence") or [])
        all_actions.extend(res.get("auto_actions") or [])
        with _full_lock:
            _active_full[run_id]["steps"] = steps
    duration = time.time() - t0
    aggregate = {
        "started_at": started,
        "finished_at": _now(),
        "steps": steps,
        "findings_count": total_findings,
        "evidence": all_evidence[:100],
        "auto_actions": list(set(all_actions)),
    }
    report_id = None
    try:
        from services.manual_defense_report_service import build_manual_defense_report
        pseudo_result = {
            "status": "completed",
            "analyzed": total_findings,
            "findings": [],
            "evidence": aggregate["evidence"],
            "risks": [],
            "auto_actions": aggregate["auto_actions"],
            "recommendations": [f"Defensa completa: {len(steps)} mecanismos ejecutados"],
            "duration_sec": duration,
            "timestamp": aggregate["finished_at"],
        }
        rep = build_manual_defense_report(
            mechanism_id="defensa_completa",
            mechanism_title="Defensa completa",
            category="centro_defensa",
            result=pseudo_result,
            user_email=user_email,
            aggregate=aggregate,
        )
        report_id = rep["id"]
        aggregate["report_id"] = report_id
    except Exception as exc:
        logger.error("full protection report: %s", exc)
        aggregate["report_error"] = str(exc)

    hist_id = persist_history(
        user_email=user_email or "",
        hostname=socket.gethostname(),
        client_ip=client_ip,
        mechanism_ids=mechanism_ids,
        duration_sec=duration,
        aggregate=aggregate,
        report_id=report_id,
    )
    with _full_lock:
        _active_full[run_id].update({
            "status": "completed",
            "progress_pct": 100,
            "history_id": hist_id,
            "report_id": report_id,
            "report_available": bool(report_id),
            "aggregate": aggregate,
            "duration_sec": duration,
        })


def start_full_protection(
    user_id: Optional[int],
    user_email: Optional[str],
    client_ip: str,
    mechanism_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    ids = mechanism_ids or full_protection_sequence(user_id)
    run_id = f"MDF-{uuid.uuid4().hex[:10]}"
    th = threading.Thread(
        target=_full_protection_worker,
        args=(run_id, user_id, user_email, ids, client_ip),
        daemon=True,
    )
    th.start()
    return {"status": "started", "run_id": run_id, "mechanisms": ids}


def get_full_protection_status(run_id: str) -> Optional[Dict[str, Any]]:
    with _full_lock:
        return dict(_active_full.get(run_id) or {}) or None


def list_history(limit: int = 30) -> List[dict]:
    from database import SessionLocal, ManualDefenseRun

    db = SessionLocal()
    try:
        rows = (
            db.query(ManualDefenseRun)
            .order_by(ManualDefenseRun.started_at.desc())
            .limit(min(limit, 100))
            .all()
        )
        out = []
        for r in rows:
            out.append({
                "id": r.id,
                "user": r.user_email,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "hostname": r.hostname,
                "client_ip": r.client_ip,
                "duration_sec": r.duration_sec,
                "mechanisms": json.loads(r.mechanisms_json or "[]"),
                "findings_count": r.findings_json,
                "report_id": getattr(r, "report_id", None) or (
                    json.loads(r.report_json or "{}").get("report_id") if r.report_json else None
                ),
            })
        return out
    finally:
        db.close()


def get_catalog_snapshot(user_id=None) -> Dict[str, Any]:
    return {"mechanisms": len(build_catalog(user_id)), "audit": __import__("services.manual_defense_catalog", fromlist=["audit_capabilities"]).audit_capabilities(user_id)}
