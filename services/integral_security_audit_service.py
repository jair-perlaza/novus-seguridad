"""
Auditoría Integral de Seguridad NOVUS — telemetría real, modos rápido y profundo.
Evolución de «Auditoría de Datos Reales» manteniendo compatibilidad de API.
"""
from __future__ import annotations

import platform
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

NO_DATA = "Sin datos disponibles"


def _risk_from_counts(threats: int, vulns: int, anomalies: int) -> str:
    score = threats * 3 + vulns * 2 + anomalies
    if score >= 8:
        return "CRÍTICO"
    if score >= 4:
        return "ALTO"
    if score >= 1:
        return "MEDIO"
    return "BAJO"


def run_quick_audit(user_email: Optional[str] = None) -> Dict[str, Any]:
    """Auditoría rápida — componentes principales con motores existentes."""
    started = datetime.now()
    sections: Dict[str, Any] = {}
    threats: List[dict] = []
    vulnerabilities: List[dict] = []
    suspicious_apps: List[dict] = []
    suspicious_devices: List[dict] = []
    evidence: List[dict] = []
    recommendations: List[str] = []

    processes_analyzed = 0
    services_analyzed = 0
    apps_analyzed = 0
    critical_files = 0
    devices_analyzed = 0

    try:
        import psutil
        processes_analyzed = len(list(psutil.process_iter()))
        sections["processes"] = {"count": processes_analyzed, "source": "psutil.process_iter"}
    except Exception as exc:
        sections["processes"] = {"error": str(exc)}

    try:
        from services.advanced_detector_service import advanced_detector
        procs = advanced_detector.scan_running_processes() or []
        processes_analyzed = max(processes_analyzed, len(procs))
        for p in procs:
            evidence.append({"type": "suspicious_process", "detail": p})
        sections["suspicious_processes"] = procs
    except Exception as exc:
        sections["suspicious_processes_error"] = str(exc)

    try:
        from services.advanced_detector_service import advanced_detector
        ports = advanced_detector.scan_open_ports() or []
        sections["open_ports"] = ports
        for p in ports:
            if p.get("port") in (23, 445, 3389, 5900, 21):
                vulnerabilities.append({
                    "id": f"PORT-{p.get('port')}",
                    "nombre": f"Puerto expuesto {p.get('port')}",
                    "riesgo": "ALTO",
                    "evidencia": p,
                })
    except Exception as exc:
        sections["ports_error"] = str(exc)

    try:
        from services.novus_security_integration import novus_security
        cache = novus_security.detect_threats_realtime(force=False) or {}
        threats = cache.get("threats") or []
        vulnerabilities.extend(cache.get("vulnerabilities") or [])
        sections["threat_cache"] = {
            "total": cache.get("total_threats"),
            "last_scan": cache.get("last_scan"),
        }
    except Exception as exc:
        sections["threat_error"] = str(exc)

    try:
        if platform.system() == "Windows":
            import subprocess
            r = subprocess.run(
                ["sc", "query", "type=", "service", "state=", "all"],
                capture_output=True, text=True, timeout=20, creationflags=0x08000000,
            )
            services_analyzed = r.stdout.count("SERVICE_NAME:") if r.returncode == 0 else 0
            sections["services"] = {"count": services_analyzed, "platform": "Windows"}
        else:
            sections["services"] = {"note": NO_DATA, "reason": "Inventario de servicios solo implementado en Windows"}
    except Exception as exc:
        sections["services_error"] = str(exc)

    try:
        if platform.system() == "Windows":
            import subprocess
            r = subprocess.run(
                ["schtasks", "/Query", "/FO", "LIST"],
                capture_output=True, text=True, timeout=25, creationflags=0x08000000,
            )
            tasks = r.stdout.count("TaskName:") if r.returncode == 0 else 0
            sections["scheduled_tasks"] = {"count": tasks}
        else:
            sections["scheduled_tasks"] = {"note": NO_DATA}
    except Exception as exc:
        sections["scheduled_tasks_error"] = str(exc)

    try:
        if platform.system() == "Windows":
            import subprocess
            r = subprocess.run(
                ["wmic", "product", "get", "name", "/format:list"],
                capture_output=True, text=True, timeout=30, creationflags=0x08000000,
            )
            if r.returncode == 0:
                apps_analyzed = sum(1 for line in r.stdout.splitlines() if line.strip().startswith("Name="))
            sections["installed_apps"] = {"count": apps_analyzed, "unsigned_unknown": NO_DATA}
        else:
            sections["installed_apps"] = {"note": NO_DATA}
    except Exception as exc:
        sections["installed_apps_error"] = str(exc)

    try:
        from services.network_scanner import network_scanner
        nodes = network_scanner.get_cached_nodes() or []
        devices_analyzed = len(nodes)
        for n in nodes:
            if n.get("is_unknown") or (n.get("device_type") or "").lower() == "otro":
                suspicious_devices.append(n)
        meta = network_scanner.get_network_meta()
        sections["network"] = {
            "devices": devices_analyzed,
            "gateway": meta.get("gateway"),
            "network_range": meta.get("network_range"),
            "local_ip": meta.get("local_ip"),
        }
    except Exception as exc:
        sections["network_error"] = str(exc)

    try:
        from services.network_ndr_service import build_ndr_payload
        ndr = build_ndr_payload()
        sections["ndr_alerts"] = (ndr.get("alerts") or [])[:10]
        for a in ndr.get("alerts") or []:
            evidence.append({"type": "ndr_alert", "detail": a})
    except Exception as exc:
        sections["ndr_error"] = str(exc)

    try:
        from services.adaptive_defense_engine import adaptive_defense
        sections["adaptive_defense"] = adaptive_defense.get_adaptive_defense_panel(user_email)
    except Exception:
        pass
    try:
        from services.universal_compatibility_engine import uce
        sections["uce"] = uce.get_infrastructure_panel(user_email)
    except Exception:
        pass
    try:
        from services.adaptive_sector_protection_engine import aspe
        sections["aspe"] = aspe.get_sector_protection_panel(user_email)
    except Exception:
        pass

    malware_categories = {
        "malware": [], "ransomware": [], "spyware": [], "trojan": [],
        "worm": [], "rootkit": [], "botnet": [], "cryptominer": [], "backdoor": [],
    }
    for t in threats:
        ttype = str(t.get("type") or "").lower()
        if "ransom" in ttype:
            malware_categories["ransomware"].append(t)
        elif "mitm" in ttype or "auth" in ttype:
            malware_categories["malware"].append(t)
        else:
            malware_categories["malware"].append(t)
    for p in sections.get("suspicious_processes") or []:
        cmd = (p.get("command_line") or p.get("description") or "").lower()
        if "xmrig" in cmd or "minerd" in cmd:
            malware_categories["cryptominer"].append(p)
        elif "keylog" in cmd:
            malware_categories["spyware"].append(p)

    anomalies = len(sections.get("suspicious_processes") or []) + len(suspicious_devices)
    risk = _risk_from_counts(len(threats), len(vulnerabilities), anomalies)
    security_level = "Protegido" if risk == "BAJO" else ("En observación" if risk == "MEDIO" else "Requiere atención")

    if threats:
        recommendations.append("Revisar amenazas detectadas en XDR y aplicar contención si hay evidencia crítica.")
    if vulnerabilities:
        recommendations.append("Priorizar remediación de vulnerabilidades verificadas.")
    if suspicious_devices:
        recommendations.append(f"Investigar {len(suspicious_devices)} dispositivo(s) desconocido(s) en Network/Topology.")
    if not recommendations:
        recommendations.append("Continuar monitorización. Ejecutar Auditoría Profunda para análisis exhaustivo.")

    elapsed = (datetime.now() - started).total_seconds()
    return {
        "mode": "quick",
        "title": "Auditoría Integral de Seguridad — Rápida",
        "status": "completed",
        "generated_at": datetime.now().isoformat(),
        "elapsed_sec": round(elapsed, 1),
        "general_status": security_level,
        "security_level": security_level,
        "current_risk": risk,
        "counts": {
            "processes_analyzed": processes_analyzed,
            "services_analyzed": services_analyzed,
            "applications_analyzed": apps_analyzed,
            "critical_files_analyzed": critical_files,
            "devices_analyzed": devices_analyzed,
            "threats_found": len(threats),
            "vulnerabilities_found": len(vulnerabilities),
            "suspicious_applications": len(suspicious_apps),
            "suspicious_devices": len(suspicious_devices),
        },
        "malware_categories": {k: len(v) for k, v in malware_categories.items()},
        "malware_details": malware_categories,
        "threats": threats,
        "vulnerabilities": vulnerabilities[:30],
        "suspicious_applications": suspicious_apps,
        "suspicious_devices": suspicious_devices,
        "evidence": evidence[:40],
        "recommendations": recommendations,
        "sections": sections,
        "node_id": socket.gethostname(),
        "os": platform.platform(),
    }


def start_deep_audit(
    user_email: Optional[str] = None,
    session_id: str = "",
    user_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Auditoría profunda — delega en deep_scan_engine (análisis exhaustivo)."""
    from services.deep_scan_engine import deep_scan_engine
    scan_id = deep_scan_engine.start_scan(
        session_id=session_id,
        user_id=user_id,
        profile="full",
        query="Auditoría Integral de Seguridad — modo profundo",
        modules_loaded=[
            "advanced_detector", "novus_security", "network_scanner",
            "adaptive_defense", "uce", "aspe",
        ],
    )
    return {
        "mode": "deep",
        "title": "Auditoría Integral de Seguridad — Profunda",
        "status": "running",
        "scan_id": scan_id,
        "message": "Análisis profundo iniciado. Consulte el estado hasta completar.",
        "generated_at": datetime.now().isoformat(),
    }


def get_deep_audit_status(scan_id: str) -> Optional[Dict[str, Any]]:
    from services.deep_scan_engine import deep_scan_engine
    st = deep_scan_engine.get_status(scan_id)
    if not st:
        return None
    out = dict(st)
    out["mode"] = "deep"
    out["title"] = "Auditoría Integral de Seguridad — Profunda"
    scan_state = out.pop("status", "unknown")
    out["status"] = scan_state
    return out


def build_deep_audit_report(scan_id: str) -> Optional[Dict[str, Any]]:
    from services.deep_scan_engine import deep_scan_engine
    report = deep_scan_engine.get_report(scan_id)
    st = deep_scan_engine.get_status(scan_id)
    if not report and st and st.get("status") == "running":
        return {"status": "running", "scan_id": scan_id, "progress_pct": st.get("progress_pct", 0)}
    if not report:
        return None
    stats = st.get("stats") if st else {}
    findings = st.get("findings") if st else []
    threats_n = stats.get("threats_found", 0) if stats else 0
    anomalies = stats.get("anomalies_found", 0) if stats else 0
    risk = report.get("risk_level") or _risk_from_counts(threats_n, len(findings), anomalies)
    return {
        "mode": "deep",
        "title": "Auditoría Integral de Seguridad — Profunda",
        "status": "completed",
        "scan_id": scan_id,
        "generated_at": datetime.now().isoformat(),
        "general_status": report.get("summary") or "Análisis completado",
        "security_level": report.get("risk_level") or risk,
        "current_risk": risk,
        "counts": {
            "processes_analyzed": stats.get("processes_analyzed", 0),
            "services_analyzed": stats.get("services_analyzed", 0),
            "applications_analyzed": stats.get("files_analyzed", 0),
            "critical_files_analyzed": stats.get("dll_analyzed", 0),
            "devices_analyzed": stats.get("connections_analyzed", 0),
            "threats_found": threats_n,
            "vulnerabilities_found": len([f for f in (findings or []) if "vuln" in str(f).lower()]),
            "suspicious_applications": stats.get("anomalies_found", 0),
            "suspicious_devices": 0,
        },
        "text_report": report.get("text_report"),
        "sections": report.get("sections") or {},
        "findings": findings,
        "evidence": findings[:50],
        "recommendations": report.get("recommendations") or [],
        "engines_used": st.get("engines_used") if st else [],
        "elapsed_sec": st.get("elapsed_sec") if st else None,
    }


def get_integral_audit_summary() -> Dict[str, Any]:
    """Resumen para UI — incluye trazabilidad legacy."""
    from services.data_audit_registry import get_audit_summary
    legacy = get_audit_summary()
    return {
        "audit_name": "Auditoría Integral de Seguridad",
        "legacy_title": "Auditoría de Datos Reales",
        "modes": ["quick", "deep"],
        "data_sources": legacy,
    }
