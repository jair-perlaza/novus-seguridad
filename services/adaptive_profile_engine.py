"""
Adaptive Profile Engine (APE) — aprendizaje continuo en segundo plano para Kernel IA.

- No es un módulo visible del Dashboard.
- No expone la línea base ni detalles internos al usuario.
- Persiste en SQL (mismas tablas behavior_* / uso interno).
- Anti-poisoning: no incorpora de inmediato observaciones anómalas/maliciosas.
"""
from __future__ import annotations

import json
import platform
import socket
import uuid
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

ENGINE_ID = "adaptive_profile_engine"
MIN_EVENTS_FOR_BASELINE = 5
# Un indicador nuevo (IP/MAC/proceso) solo entra a la baseline tras N observaciones
PROMOTE_AFTER_SIGHTINGS = 3
# Ventana de cuarentena (eventos) tras anomalía high/critical
QUARANTINE_ON_SEVERITY = frozenset({"high", "critical"})


def _now_parts() -> Tuple[str, str, str]:
    now = datetime.now()
    return (
        now.strftime("%Y-%m-%d %H:%M:%S"),
        now.strftime("%Y-%m-%d"),
        now.strftime("%H:%M:%S"),
    )


def _dumps(obj: Any) -> Optional[str]:
    if obj is None:
        return None
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)[:14000]
    except Exception:
        return None


def _loads(raw: Optional[str], default: Any = None) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def _tenant_for_email(email: str) -> Optional[str]:
    try:
        from services.tenant_scope_service import resolve_tenant_id

        class _U:
            pass

        u = _U()
        u.email = email
        u.nit_pyme = None
        u.company_id = None
        return resolve_tenant_id(u)
    except Exception:
        return None


def _hour_bucket(event_time: Optional[str]) -> Optional[int]:
    if not event_time or len(event_time) < 2:
        return None
    try:
        return int(event_time.split(":")[0])
    except Exception:
        return None


def _collect_environment(ip: Optional[str] = None) -> Dict[str, Any]:
    """Telemetría real del entorno — sin inventar campos."""
    ctx: Dict[str, Any] = {
        "equipment": socket.gethostname(),
        "os_name": platform.system(),
        "os_version": platform.version()[:200],
        "ip_address": ip,
    }
    try:
        from utils.host_data import get_local_ip

        ctx["ip_address"] = ip or get_local_ip()
    except Exception:
        pass
    try:
        from services.network_security_history_service import (
            get_connected_network_context,
            network_scope_id,
        )

        ident = get_connected_network_context(include_public_lookup=False) or {}
        ctx["gateway"] = ident.get("gateway")
        dns = ident.get("dns_servers")
        ctx["dns"] = dns.get("servers") if isinstance(dns, dict) else dns
        ctx["wifi_ssid"] = ident.get("ssid")
        ctx["network_scope"] = network_scope_id(ident) if ident else None
        ctx["location_approx"] = ident.get("isp") or ident.get("ssid")
        ctx["network_identification"] = {
            k: ident.get(k)
            for k in ("ssid", "gateway", "local_ip", "public_ip", "isp", "connection_type", "subnet", "dns_servers")
            if ident.get(k) is not None
        }
    except Exception as exc:
        logger.debug("APE network context: %s", exc)

    try:
        import psutil

        ctx["cpu_percent"] = float(psutil.cpu_percent(interval=0.05))
        vm = psutil.virtual_memory()
        ctx["ram_percent"] = float(vm.percent)
        disk = psutil.disk_usage("C:\\" if platform.system() == "Windows" else "/")
        ctx["disk_percent"] = float(disk.percent)
    except Exception:
        pass

    try:
        import psutil

        procs = []
        for p in psutil.process_iter(["name"]):
            name = (p.info or {}).get("name")
            if name:
                procs.append(str(name)[:80])
            if len(procs) >= 50:
                break
        ctx["processes_sample"] = procs
    except Exception:
        ctx["processes_sample"] = []

    try:
        import psutil

        svcs = []
        if hasattr(psutil, "win_service_iter"):
            for s in psutil.win_service_iter():
                try:
                    info = s.as_dict()
                    if info.get("status") == "running":
                        svcs.append(str(info.get("name") or s.name())[:80])
                except Exception:
                    continue
                if len(svcs) >= 35:
                    break
        ctx["services_sample"] = svcs
    except Exception:
        ctx["services_sample"] = []

    try:
        import psutil

        ports = sorted(
            {
                int(c.laddr.port)
                for c in psutil.net_connections(kind="inet")
                if getattr(c, "status", None) == "LISTEN" and getattr(c, "laddr", None)
            }
        )[:40]
        ctx["listening_ports"] = ports
    except Exception:
        ctx["listening_ports"] = []

    try:
        from services.network_scanner import network_scanner

        nodes = network_scanner.get_cached_nodes() or []
        ctx["devices"] = [
            {"ip": n.get("ip"), "mac": n.get("mac"), "name": n.get("name")}
            for n in nodes[:50]
            if isinstance(n, dict)
        ]
    except Exception:
        ctx["devices"] = []

    return ctx


def _is_learnable(evidence: Optional[dict], risk_level: Optional[str], event_type: str) -> bool:
    """Anti-poisoning: no aprender de inmediato actividad sospechosa o forzada."""
    ev = evidence or {}
    if ev.get("learnable") is False:
        return False
    if ev.get("quarantine") or ev.get("malicious_suspected"):
        return False
    rl = (risk_level or "").lower()
    if rl in ("critical", "crítico", "alto", "high", "critico"):
        return False
    if event_type in ("malware_alert", "ransomware_alert", "intrusion", "auth_bruteforce"):
        return False
    # Señales de amenaza en evidencia
    threat_flags = ev.get("threat_flags") or []
    if isinstance(threat_flags, list) and any(
        str(x).lower() in ("malware", "ransomware", "spyware", "rootkit", "lateral_movement")
        for x in threat_flags
    ):
        return False
    return True


def observe(
    *,
    user_email: str,
    event_type: str = "heartbeat",
    ip: Optional[str] = None,
    session_audit_id: Optional[str] = None,
    session_duration_sec: Optional[int] = None,
    risk_level: Optional[str] = None,
    mechanisms: Optional[List[str]] = None,
    browser: Optional[str] = None,
    evidence: Optional[dict] = None,
    source_motor: str = ENGINE_ID,
    evaluate: bool = True,
) -> Dict[str, Any]:
    """
    Observa el entorno, persiste actividad y (si aplica) evalúa anomalías.
    Actualiza baseline solo con observaciones learnable=True.
    """
    if not user_email:
        return {"ok": False, "reason": "missing_email"}

    from database import SessionLocal, BehaviorActivityEvent

    ts, fecha, hora = _now_parts()
    ctx = _collect_environment(ip=ip)
    learnable = _is_learnable(evidence, risk_level, event_type)
    event_id = f"APE-{uuid.uuid4().hex[:14]}"
    tenant_id = _tenant_for_email(user_email)
    merged_evidence = {
        **(evidence or {}),
        "network": ctx.get("network_identification"),
        "wifi_ssid": ctx.get("wifi_ssid"),
        "cpu_percent": ctx.get("cpu_percent"),
        "ram_percent": ctx.get("ram_percent"),
        "disk_percent": ctx.get("disk_percent"),
        "listening_ports": ctx.get("listening_ports"),
        "learnable": learnable,
        "engine": ENGINE_ID,
    }
    row = BehaviorActivityEvent(
        event_id=event_id,
        user_email=user_email.strip().lower(),
        tenant_id=tenant_id,
        event_type=event_type,
        event_date=fecha,
        event_time=hora,
        recorded_at=ts,
        equipment=ctx.get("equipment"),
        ip_address=ctx.get("ip_address"),
        network_scope=ctx.get("network_scope"),
        gateway=ctx.get("gateway"),
        dns_json=_dumps(ctx.get("dns")),
        location_approx=str(ctx.get("location_approx") or "")[:200] or None,
        os_name=ctx.get("os_name"),
        os_version=ctx.get("os_version"),
        browser=browser,
        session_audit_id=session_audit_id,
        session_duration_sec=session_duration_sec,
        risk_level=risk_level,
        mechanisms_json=_dumps(mechanisms),
        devices_json=_dumps(ctx.get("devices")),
        processes_sample_json=_dumps(ctx.get("processes_sample")),
        services_sample_json=_dumps(ctx.get("services_sample")),
        apps_sample_json=_dumps(ctx.get("listening_ports")),
        alerts_count=0,
        incidents_count=0,
        scans_count=1 if event_type == "auto_scan" else 0,
        evidence_json=_dumps(merged_evidence),
        source_motor=source_motor or ENGINE_ID,
    )
    db = SessionLocal()
    try:
        db.add(row)
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("APE observe persist: %s", exc)
        return {"ok": False, "error": str(exc)[:200]}
    finally:
        db.close()

    anomalies: List[dict] = []
    if evaluate:
        try:
            anomalies = evaluate_against_profile(user_email, event_id, ctx)
        except Exception as exc:
            logger.debug("APE evaluate: %s", exc)

    # Solo reconstruir baseline con observaciones aprendibles y sin anomalías high/critical
    severe = any(a.get("severity") in QUARANTINE_ON_SEVERITY for a in anomalies)
    if learnable and not severe:
        try:
            rebuild_defense_profile(user_email)
        except Exception as exc:
            logger.debug("APE rebuild: %s", exc)
    elif severe or not learnable:
        logger.info(
            "APE quarantine/skip-learn event=%s learnable=%s severe=%s",
            event_id,
            learnable,
            severe,
        )

    return {
        "ok": True,
        "event_id": event_id,
        "learnable": learnable,
        "anomalies_n": len(anomalies),
        "anomalies": anomalies,
    }


def rebuild_defense_profile(user_email: str) -> Dict[str, Any]:
    """Construye perfil interno para motores de defensa — no expuesto en UI."""
    from database import SessionLocal, BehaviorActivityEvent, BehaviorBaselineProfile

    email = user_email.strip().lower()
    db = SessionLocal()
    try:
        rows = (
            db.query(BehaviorActivityEvent)
            .filter(BehaviorActivityEvent.user_email == email)
            .order_by(BehaviorActivityEvent.recorded_at.desc())
            .limit(800)
            .all()
        )
        learnable_rows = []
        for r in rows:
            ev = _loads(r.evidence_json, {}) or {}
            if ev.get("learnable") is False:
                continue
            learnable_rows.append(r)

        hours = Counter()
        ips: Counter = Counter()
        gateways = Counter()
        networks = Counter()
        equipment = Counter()
        locations = Counter()
        wifi = Counter()
        processes = Counter()
        services = Counter()
        devices_mac = Counter()
        ports = Counter()
        cpu_vals: List[float] = []
        ram_vals: List[float] = []
        disk_vals: List[float] = []

        for r in learnable_rows:
            hb = _hour_bucket(r.event_time)
            if hb is not None:
                hours[hb] += 1
            if r.ip_address:
                ips[r.ip_address] += 1
            if r.gateway:
                gateways[r.gateway] += 1
            if r.network_scope:
                networks[r.network_scope] += 1
            if r.equipment:
                equipment[r.equipment] += 1
            if r.location_approx:
                locations[r.location_approx] += 1
            ev = _loads(r.evidence_json, {}) or {}
            if ev.get("wifi_ssid"):
                wifi[str(ev["wifi_ssid"])] += 1
            if isinstance(ev.get("cpu_percent"), (int, float)):
                cpu_vals.append(float(ev["cpu_percent"]))
            if isinstance(ev.get("ram_percent"), (int, float)):
                ram_vals.append(float(ev["ram_percent"]))
            if isinstance(ev.get("disk_percent"), (int, float)):
                disk_vals.append(float(ev["disk_percent"]))
            for p in _loads(r.processes_sample_json, []) or []:
                processes[str(p)] += 1
            for s in _loads(r.services_sample_json, []) or []:
                services[str(s)] += 1
            for d in _loads(r.devices_json, []) or []:
                if isinstance(d, dict) and d.get("mac"):
                    devices_mac[str(d["mac"]).lower()] += 1
            for port in ev.get("listening_ports") or _loads(r.apps_sample_json, []) or []:
                try:
                    ports[int(port)] += 1
                except Exception:
                    pass

        def _promoted(counter: Counter, min_n: int = PROMOTE_AFTER_SIGHTINGS) -> List[str]:
            return [k for k, n in counter.most_common(80) if n >= min_n]

        n = len(learnable_rows)
        enough = n >= MIN_EVENTS_FOR_BASELINE
        profile = {
            "engine": ENGINE_ID,
            "events_count": n,
            "raw_events_seen": len(rows),
            "enough_data": enough,
            "min_events_required": MIN_EVENTS_FOR_BASELINE,
            "promote_after_sightings": PROMOTE_AFTER_SIGHTINGS,
            "usual_hours": [h for h, c in hours.most_common(8) if c >= 1],
            "usual_ips": _promoted(ips),
            "usual_gateways": _promoted(gateways, 2),
            "usual_networks": _promoted(networks, 2),
            "usual_equipment": _promoted(equipment, 1),
            "usual_locations": _promoted(locations, 2),
            "usual_wifi": _promoted(wifi, 2),
            "usual_processes": _promoted(processes, PROMOTE_AFTER_SIGHTINGS),
            "usual_services": _promoted(services, PROMOTE_AFTER_SIGHTINGS),
            "usual_device_macs": _promoted(devices_mac, PROMOTE_AFTER_SIGHTINGS),
            "usual_listening_ports": [p for p, c in ports.most_common(30) if c >= 2],
            "resource_baseline": {
                "cpu_avg": round(sum(cpu_vals) / len(cpu_vals), 2) if cpu_vals else None,
                "ram_avg": round(sum(ram_vals) / len(ram_vals), 2) if ram_vals else None,
                "disk_avg": round(sum(disk_vals) / len(disk_vals), 2) if disk_vals else None,
                "cpu_max_seen": max(cpu_vals) if cpu_vals else None,
                "ram_max_seen": max(ram_vals) if ram_vals else None,
            },
            "anti_poisoning": {
                "skip_non_learnable": True,
                "promote_after_sightings": PROMOTE_AFTER_SIGHTINGS,
                "quarantine_on_severity": list(QUARANTINE_ON_SEVERITY),
            },
        }
        normality = min(100.0, round(35 + n * 6, 1)) if enough else round(min(34.0, n * 6), 1)
        from database import BehaviorAnomaly

        open_n = (
            db.query(BehaviorAnomaly)
            .filter(BehaviorAnomaly.user_email == email, BehaviorAnomaly.status == "open")
            .count()
        )
        anomaly_score = min(100.0, float(open_n) * 12.0)
        ts = _now_parts()[0]
        row = db.query(BehaviorBaselineProfile).filter(BehaviorBaselineProfile.user_email == email).first()
        if not row:
            row = BehaviorBaselineProfile(user_email=email)
            db.add(row)
        row.tenant_id = _tenant_for_email(email)
        row.events_count = n
        row.enough_data = enough
        row.normality_score = normality
        row.anomaly_score = anomaly_score
        row.profile_json = _dumps(profile)
        # Recomendaciones internas (no UI) — vacías al cliente
        row.recommendations_json = _dumps(
            [
                "Perfil adaptativo interno para Kernel IA / motores de defensa.",
                "No expuesto en interfaz de usuario.",
            ]
        )
        row.built_at = ts
        row.updated_at = ts
        db.commit()
        return {
            "ok": True,
            "user_email": email,
            "events_count": n,
            "enough_data": enough,
            "normality_score": normality,
            "anomaly_score": anomaly_score,
            "updated_at": ts,
        }
    except Exception as exc:
        db.rollback()
        logger.error("APE rebuild_defense_profile: %s", exc)
        return {"ok": False, "error": str(exc)[:200]}
    finally:
        db.close()


def get_profile_for_defense(user_email: str) -> Dict[str, Any]:
    """Perfil para motores internos. No incluir en respuestas de Dashboard al cliente."""
    from database import SessionLocal, BehaviorBaselineProfile

    email = (user_email or "").strip().lower()
    if not email:
        return {"available": False}
    db = SessionLocal()
    try:
        row = db.query(BehaviorBaselineProfile).filter(BehaviorBaselineProfile.user_email == email).first()
        if not row:
            return {"available": False, "engine": ENGINE_ID, "enough_data": False}
        return {
            "available": True,
            "engine": ENGINE_ID,
            "enough_data": bool(row.enough_data),
            "events_count": row.events_count,
            "normality_score": row.normality_score,
            "anomaly_score": row.anomaly_score,
            "updated_at": row.updated_at,
            "profile": _loads(row.profile_json, {}) or {},
        }
    finally:
        db.close()


def _user_facing_conclusion(atype: str, observed: str) -> Tuple[str, str]:
    """Conclusiones para notificaciones — sin revelar el motor interno."""
    mapping = {
        "horario_anormal": (
            "Se detectó actividad fuera del horario habitual",
            "NOVUS registró uso de la plataforma en un horario poco frecuente para este entorno.",
        ),
        "cambio_ip": (
            "Se detectó una conexión desde una dirección no habitual",
            f"Origen observado: {observed}.",
        ),
        "cambio_gateway": (
            "Se detectó un cambio importante en la puerta de enlace de red",
            f"Gateway observado: {observed}.",
        ),
        "cambio_red": (
            "Se detectó una conexión desde una red no habitual",
            "El entorno de red actual no coincide con el patrón habitual del cliente.",
        ),
        "cambio_wifi": (
            "Se detectó una red Wi‑Fi no habitual",
            f"SSID observado: {observed}.",
        ),
        "ubicacion_anormal": (
            "Se detectó un cambio de ubicación/ISP aproximado",
            f"Indicador: {observed}.",
        ),
        "nuevo_dispositivo": (
            "Se detectó un dispositivo no reconocido en la red",
            f"Identificadores nuevos: {observed}.",
        ),
        "procesos_desconocidos": (
            "Se detectó un proceso con comportamiento anómalo o poco frecuente",
            f"Detalle: {observed}.",
        ),
        "puertos_nuevos": (
            "Se detectaron puertos en escucha no habituales",
            f"Puertos: {observed}.",
        ),
        "cpu_anormal": (
            "Se detectó un incremento anormal del uso de CPU",
            f"Valor observado: {observed}.",
        ),
        "ram_anormal": (
            "Se detectó un incremento anormal del uso de memoria",
            f"Valor observado: {observed}.",
        ),
        "cambio_dns": (
            "Se detectó un cambio inesperado en la configuración DNS",
            f"DNS observado: {observed}.",
        ),
    }
    return mapping.get(
        atype,
        (
            "Se detectó un cambio importante en el comportamiento del sistema",
            f"Indicador: {observed}.",
        ),
    )


def evaluate_against_profile(
    user_email: str,
    activity_event_id: str,
    ctx: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    from database import (
        SessionLocal,
        BehaviorActivityEvent,
        BehaviorBaselineProfile,
        BehaviorAnomaly,
    )

    email = user_email.strip().lower()
    db = SessionLocal()
    found: List[Dict[str, Any]] = []
    try:
        baseline_row = (
            db.query(BehaviorBaselineProfile).filter(BehaviorBaselineProfile.user_email == email).first()
        )
        if not baseline_row or not baseline_row.enough_data:
            return []
        profile = _loads(baseline_row.profile_json, {}) or {}
        event = (
            db.query(BehaviorActivityEvent)
            .filter(BehaviorActivityEvent.event_id == activity_event_id)
            .first()
        )
        if not event:
            return []
        ev = _loads(event.evidence_json, {}) or {}
        ctx = ctx or {}

        checks: List[Tuple[str, str, str, str]] = []
        usual_hours = set(profile.get("usual_hours") or [])
        hb = _hour_bucket(event.event_time)
        if usual_hours and hb is not None and hb not in usual_hours and len(usual_hours) >= 2:
            checks.append(("horario_anormal", "high", f"{hb:02d}:00", str(sorted(usual_hours))))

        usual_ips = set(profile.get("usual_ips") or [])
        if usual_ips and event.ip_address and event.ip_address not in usual_ips:
            checks.append(("cambio_ip", "high", event.ip_address, ",".join(list(usual_ips)[:4])))

        usual_gw = set(profile.get("usual_gateways") or [])
        if usual_gw and event.gateway and event.gateway not in usual_gw:
            checks.append(("cambio_gateway", "warning", event.gateway, ",".join(list(usual_gw)[:3])))

        usual_net = set(profile.get("usual_networks") or [])
        if usual_net and event.network_scope and event.network_scope not in usual_net:
            checks.append(("cambio_red", "high", (event.network_scope or "")[:80], f"{len(usual_net)} redes"))

        usual_wifi = set(profile.get("usual_wifi") or [])
        ssid = ev.get("wifi_ssid") or ctx.get("wifi_ssid")
        if usual_wifi and ssid and str(ssid) not in usual_wifi:
            checks.append(("cambio_wifi", "warning", str(ssid), ",".join(list(usual_wifi)[:3])))

        usual_loc = set(profile.get("usual_locations") or [])
        if usual_loc and event.location_approx and event.location_approx not in usual_loc:
            checks.append(("ubicacion_anormal", "warning", event.location_approx, ",".join(list(usual_loc)[:3])))

        usual_macs = set(profile.get("usual_device_macs") or [])
        new_macs = []
        for d in _loads(event.devices_json, []) or []:
            if isinstance(d, dict) and d.get("mac"):
                mac = str(d["mac"]).lower()
                if usual_macs and mac not in usual_macs:
                    new_macs.append(mac)
        if new_macs:
            checks.append(("nuevo_dispositivo", "warning", ",".join(new_macs[:5]), f"{len(usual_macs)} MAC"))

        usual_ports = set(int(x) for x in (profile.get("usual_listening_ports") or []) if str(x).isdigit())
        cur_ports = set(int(x) for x in (ev.get("listening_ports") or ctx.get("listening_ports") or []) if str(x).isdigit())
        novel_ports = sorted(cur_ports - usual_ports) if usual_ports else []
        if len(novel_ports) >= 3:
            checks.append(("puertos_nuevos", "warning", ",".join(str(p) for p in novel_ports[:8]), f"{len(usual_ports)} habituales"))

        res = profile.get("resource_baseline") or {}
        cpu = ev.get("cpu_percent") if ev.get("cpu_percent") is not None else ctx.get("cpu_percent")
        ram = ev.get("ram_percent") if ev.get("ram_percent") is not None else ctx.get("ram_percent")
        if isinstance(cpu, (int, float)) and isinstance(res.get("cpu_avg"), (int, float)):
            if cpu > max(85.0, float(res["cpu_avg"]) * 1.8):
                checks.append(("cpu_anormal", "warning", f"{cpu}%", f"promedio {res['cpu_avg']}%"))
        if isinstance(ram, (int, float)) and isinstance(res.get("ram_avg"), (int, float)):
            if ram > max(90.0, float(res["ram_avg"]) * 1.5):
                checks.append(("ram_anormal", "warning", f"{ram}%", f"promedio {res['ram_avg']}%"))

        usual_procs = set(profile.get("usual_processes") or [])
        procs = _loads(event.processes_sample_json, []) or []
        unknown = [p for p in procs if usual_procs and p not in usual_procs]
        if len(unknown) >= 10:
            checks.append(("procesos_desconocidos", "info", f"{len(unknown)} poco frecuentes", f"{len(usual_procs)} habituales"))

        ts = _now_parts()[0]
        for atype, sev, observed, baseline_v in checks:
            title, desc = _user_facing_conclusion(atype, observed)
            aid = f"APE-{uuid.uuid4().hex[:12]}"
            row = BehaviorAnomaly(
                anomaly_id=aid,
                user_email=email,
                tenant_id=baseline_row.tenant_id,
                anomaly_type=atype,
                severity=sev,
                title=title,
                description=desc,
                observed_value=str(observed)[:500],
                baseline_value=str(baseline_v)[:500],
                evidence_json=_dumps(
                    {
                        "activity_event_id": activity_event_id,
                        "anomaly_type": atype,
                        "verifiable": True,
                        "engine": ENGINE_ID,
                    }
                ),
                activity_event_id=activity_event_id,
                status="open",
                detected_at=ts,
                source_motor=ENGINE_ID,
            )
            db.add(row)
            found.append({"anomaly_id": aid, "type": atype, "severity": sev, "title": title})
            _dispatch_to_defense_stack(
                user_email=email,
                anomaly_id=aid,
                atype=atype,
                severity=sev,
                title=title,
                description=desc,
                observed=observed,
                equipment=event.equipment,
            )
        if found:
            db.commit()
        return found
    except Exception as exc:
        db.rollback()
        logger.error("APE evaluate: %s", exc)
        return []
    finally:
        db.close()


def _dispatch_to_defense_stack(
    *,
    user_email: str,
    anomaly_id: str,
    atype: str,
    severity: str,
    title: str,
    description: str,
    observed: str,
    equipment: Optional[str],
) -> None:
    """Kernel IA / Swarm / Notificaciones — conclusiones, sin exponer baseline."""
    evidence = {
        "anomaly_id": anomaly_id,
        "anomaly_type": atype,
        "observed": observed,
        "verifiable": True,
        "source": ENGINE_ID,
        "user_facing_only": True,
    }
    try:
        from services.defense_coordinator import record_detection

        record_detection(
            motor=ENGINE_ID,
            action=f"adaptive_anomaly_{atype}",
            evidence=evidence,
            phase="detect",
            outcome="detected",
            threat_type=atype,
            finding_id=anomaly_id,
            detail=title,
            confidence="medium" if severity == "warning" else "high",
            user_email=user_email,
        )
    except Exception as exc:
        logger.debug("APE→defense_coordinator: %s", exc)

    try:
        from services.defense_coordinator import notify_kernel_incident

        notify_kernel_incident(
            ENGINE_ID,
            "adaptive_anomaly",
            title,
            incident_id=anomaly_id,
            severity=severity,
            evidence=evidence,
        )
    except Exception as exc:
        logger.debug("APE→kernel_incident: %s", exc)

    try:
        from services.notification_center_service import emit_notification

        pri = severity if severity in ("info", "warning", "high", "critical") else "warning"
        emit_notification(
            user_email=user_email,
            category="seguridad",
            notification_kind="security",
            priority=pri,
            title=title,
            description=description,
            related_user=user_email,
            related_equipment=equipment,
            detail_url="/dashboard",
            incident_url="/incidentes",
            source_motor=ENGINE_ID,
            source_ref=anomaly_id,
            payload={"anomaly_id": anomaly_id, "type": atype},
        )
    except Exception as exc:
        logger.debug("APE→notifications: %s", exc)

    try:
        from services.kernel_memory import _user_key, _load_profile, _save_profile

        key = _user_key(None, user_email)
        prefs = _load_profile(key)
        signals = list(prefs.get("adaptive_signals") or [])
        signals.append(
            {
                "source": ENGINE_ID,
                "anomaly_id": anomaly_id,
                "title": title,
                "severity": severity,
                "at": _now_parts()[0],
            }
        )
        prefs["adaptive_signals"] = signals[-25:]
        _save_profile(key, prefs)
    except Exception as exc:
        logger.debug("APE→kernel_memory: %s", exc)


def observe_async(user_email: str, **kwargs) -> None:
    from services.bounded_background import submit_background

    def _run():
        try:
            observe(user_email=user_email, **kwargs)
        except Exception as exc:
            logger.error("APE observe_async: %s", exc)

    submit_background(_run, name="AdaptiveProfileObserve")


def kernel_adaptive_context(user_email: Optional[str]) -> Dict[str, Any]:
    """
    Contexto compacto para Kernel IA (interno).
    No incluye listas completas de baseline al cliente.
    """
    if not user_email:
        return {"adaptive_profile": {"available": False}}
    data = get_profile_for_defense(user_email)
    if not data.get("available"):
        return {"adaptive_profile": {"available": False, "engine": ENGINE_ID}}
    p = data.get("profile") or {}
    return {
        "adaptive_profile": {
            "available": True,
            "engine": ENGINE_ID,
            "enough_data": data.get("enough_data"),
            "events_count": data.get("events_count"),
            "normality_score": data.get("normality_score"),
            "anomaly_score": data.get("anomaly_score"),
            "updated_at": data.get("updated_at"),
            # Solo conteos / señales, no dump completo del perfil
            "signals": {
                "usual_networks_n": len(p.get("usual_networks") or []),
                "usual_ips_n": len(p.get("usual_ips") or []),
                "usual_device_macs_n": len(p.get("usual_device_macs") or []),
                "usual_processes_n": len(p.get("usual_processes") or []),
                "resource_baseline": p.get("resource_baseline"),
            },
        }
    }


def engine_status() -> Dict[str, Any]:
    """Estado operativo verificado — para auditoría interna."""
    return {
        "engine_id": ENGINE_ID,
        "visible_to_user": False,
        "storage": "sqlite:behavior_activity_events,behavior_baseline_profiles,behavior_anomalies",
        "min_events_for_baseline": MIN_EVENTS_FOR_BASELINE,
        "promote_after_sightings": PROMOTE_AFTER_SIGHTINGS,
        "anti_poisoning": True,
        "learns": [
            "horario",
            "equipo_hostname",
            "wifi_ssid",
            "gateway",
            "dns",
            "ip",
            "dispositivos_mac",
            "procesos",
            "servicios",
            "cpu_ram_disco",
            "puertos_escucha",
            "red_scope",
            "uso_novus_via_login_scan",
        ],
        "integrations_verified": [
            "kernel_agent (kernel_adaptive_context)",
            "kernel_memory (adaptive_signals)",
            "defense_coordinator.record_detection",
            "defense_coordinator.notify_kernel_incident",
            "swarm_defense (via defense_coordinator)",
            "forensic_pcap (via defense_coordinator.maybe_auto_capture)",
            "network_security_history (via defense_coordinator)",
            "notification_center (conclusiones usuario)",
            "continuous_monitoring_orchestrator (observe post-scan)",
            "login_session_audit (observe post-login)",
            "defense_coordinator←otros motores (observe defense_signal no-learn)",
        ],
        "not_user_facing": True,
    }


def enrichment_for_engine(user_email: Optional[str], engine_name: str) -> Dict[str, Any]:
    """
    Señal compacta para NDR/XDR/Endpoint/Shields/Compliance/Reportes.
    Solo conteos y scores — sin dump de baseline.
    """
    base = kernel_adaptive_context(user_email)
    ap = base.get("adaptive_profile") or {}
    return {
        "engine": ENGINE_ID,
        "consumer": engine_name,
        "available": bool(ap.get("available")),
        "enough_data": bool(ap.get("enough_data")),
        "normality_score": ap.get("normality_score"),
        "anomaly_score": ap.get("anomaly_score"),
        "signals": ap.get("signals") or {},
    }
