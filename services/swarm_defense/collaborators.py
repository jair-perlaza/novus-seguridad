"""
Colaboradores del enjambre — cada uno consulta SOLO servicios/evidencia reales.
Si no hay dato relacionado → contribution.found=False + gap explícito.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from utils.logger import logger


def _contrib(
    module_id: str,
    label: str,
    found: bool,
    facts: Optional[List[Dict[str, Any]]] = None,
    gaps: Optional[List[str]] = None,
    sources: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "module_id": module_id,
        "label": label,
        "found": found,
        "facts": facts or [],
        "gaps": gaps or [],
        "sources": sources or [],
    }


def collaborate_web_shield(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    facts, gaps, sources = [], [], []
    try:
        from services.web_shield_service import get_stats, list_events

        stats = get_stats()
        sources.append("web_shield_service.get_stats")
        facts.append({"type": "web_shield_stats", "data": stats})
        urls = set(indicators.get("urls") or [])
        domains = set(indicators.get("domains") or [])
        related = []
        if urls or domains:
            for ev in list_events(limit=40) or []:
                blob = str(ev).lower()
                if any(u.lower() in blob for u in urls) or any(d in blob for d in domains):
                    related.append(ev)
            if related:
                facts.append({"type": "web_related_events", "count": len(related), "events": related[:10]})
                return _contrib("web_shield", "Web Shield", True, facts, gaps, sources)
            gaps.append("Web Shield: sin eventos relacionados con URLs/dominios del indicador")
        else:
            gaps.append("Web Shield: el evento no aporta URL/dominio para correlacionar")
    except Exception as exc:
        gaps.append(f"web_shield: {exc}")
    return _contrib("web_shield", "Web Shield", bool(facts and not gaps), facts, gaps, sources)


def collaborate_mail_shield(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    facts, gaps, sources = [], [], []
    try:
        from services.mail_shield_service import get_stats, list_events

        stats = get_stats()
        sources.append("mail_shield_service.get_stats")
        facts.append({"type": "mail_shield_stats", "data": stats})
        domains = set(indicators.get("domains") or [])
        urls = set(indicators.get("urls") or [])
        related = []
        if domains or urls:
            for ev in list_events(limit=40) or []:
                blob = str(ev).lower()
                if any(d in blob for d in domains) or any(u.lower() in blob for u in urls):
                    related.append(ev)
            if related:
                facts.append({"type": "mail_related_events", "count": len(related), "events": related[:10]})
                return _contrib("mail_shield", "Mail Shield", True, facts, gaps, sources)
            gaps.append("Mail Shield: sin eventos de phishing/BEC/adjuntos relacionados")
        else:
            gaps.append("Mail Shield: sin dominio/URL en indicadores")
    except Exception as exc:
        gaps.append(f"mail_shield: {exc}")
    return _contrib("mail_shield", "Mail Shield", False, facts, gaps, sources)


def collaborate_endpoint(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    facts, gaps, sources = [], [], []
    try:
        import psutil

        pids = [int(p) for p in (indicators.get("pids") or []) if str(p).isdigit()]
        names = {n.lower() for n in (indicators.get("processes") or [])}
        matched = []
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                matched.append(
                    {
                        "pid": pid,
                        "name": proc.name(),
                        "status": proc.status(),
                        "exe": proc.exe() if proc.is_running() else None,
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
                gaps.append(f"endpoint pid {pid}: {exc}")
        if names:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    n = (proc.info.get("name") or "").lower()
                    if n in names:
                        matched.append({"pid": proc.info.get("pid"), "name": proc.info.get("name")})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        if matched:
            sources.append("psutil")
            facts.append({"type": "endpoint_processes", "matches": matched[:20]})
        try:
            from services.endpoint_enterprise import get_endpoint_enterprise_status, get_engine_status

            st = get_endpoint_enterprise_status()
            ys = get_engine_status()
            sources.append("endpoint_enterprise")
            facts.append(
                {
                    "type": "endpoint_enterprise_status",
                    "active": st.get("active"),
                    "cycles": st.get("cycles"),
                    "yara_backend": ys.get("backend"),
                    "yara_ok": ys.get("ok"),
                    "last_host_risk": st.get("last_host_risk"),
                    "last_yara_hits": st.get("last_yara_hits"),
                }
            )
        except Exception as exc:
            gaps.append(f"endpoint_enterprise: {exc}")
        if matched or any(f.get("type") == "endpoint_enterprise_status" for f in facts):
            return _contrib("endpoint", "Endpoint", True, facts, gaps, sources)
        gaps.append("Endpoint: sin PID/proceso coincidente en telemetría local (solo lectura psutil; sin escaneo pesado)")
    except Exception as exc:
        gaps.append(f"endpoint: {exc}")
    return _contrib("endpoint", "Endpoint", False, facts, gaps, sources)


def collaborate_ndr(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    """Solo lectura de caché/registry — no dispara ARP scan."""
    facts, gaps, sources = [], [], []
    ips = set(indicators.get("ips") or [])
    try:
        from services.defense_evidence_registry import list_recent_events

        events = list_recent_events(limit=40) or []
        sources.append("defense_evidence_registry(ndr/network filter)")
        related = []
        for ev in events:
            motor = str(ev.get("motor") or "").lower()
            if "ndr" not in motor and "network" not in motor:
                continue
            blob = str(ev)
            if ips and any(ip in blob for ip in ips):
                related.append(
                    {
                        "event_id": ev.get("event_id") or ev.get("id"),
                        "motor": ev.get("motor"),
                        "action": ev.get("action"),
                        "ts": ev.get("ts") or ev.get("timestamp"),
                    }
                )
            elif not ips and ("ndr" in motor or "network" in motor):
                related.append(
                    {
                        "event_id": ev.get("event_id") or ev.get("id"),
                        "motor": ev.get("motor"),
                        "action": ev.get("action"),
                        "ts": ev.get("ts") or ev.get("timestamp"),
                    }
                )
        if related:
            facts.append({"type": "ndr_related_registry_events", "count": len(related), "events": related[:10]})
            return _contrib("ndr", "NDR", True, facts, gaps, sources)
        gaps.append("NDR: sin eventos de red/NDR relacionados en registry (sin forzar escaneo)")
    except Exception as exc:
        gaps.append(f"ndr: {exc}")
    return _contrib("ndr", "NDR", False, facts, gaps, sources)


def collaborate_xdr(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    """Solo lectura de registry — evita capability_registry que puede re-entrar en detección."""
    facts, gaps, sources = [], [], []
    try:
        from services.defense_evidence_registry import list_recent_events

        events = list_recent_events(limit=40) or []
        sources.append("defense_evidence_registry(xdr/threat filter)")
        hits = []
        ips = set(indicators.get("ips") or [])
        domains = set(indicators.get("domains") or [])
        hashes = set((indicators.get("sha256") or []) + (indicators.get("md5") or []))
        for ev in events:
            motor = str(ev.get("motor") or "").lower()
            threat = str(ev.get("threat_type") or "").lower()
            blob = str(ev).lower()
            is_xdrish = any(x in motor or x in threat for x in ("xdr", "threat", "malware", "security"))
            if not is_xdrish:
                continue
            matched = False
            for ip in ips:
                if ip in blob:
                    hits.append({"indicator": "ip", "value": ip, "event_id": ev.get("event_id")})
                    matched = True
            for d in domains:
                if d.lower() in blob:
                    hits.append({"indicator": "domain", "value": d, "event_id": ev.get("event_id")})
                    matched = True
            for h in hashes:
                if h.lower() in blob:
                    hits.append({"indicator": "hash", "value": h, "event_id": ev.get("event_id")})
                    matched = True
            if matched or (
                str(event.get("motor") or "").lower() in motor
                or str(event.get("finding_id") or "") in str(ev)
            ):
                facts.append(
                    {
                        "type": "xdr_registry_event",
                        "motor": ev.get("motor"),
                        "action": ev.get("action"),
                        "threat_type": ev.get("threat_type"),
                    }
                )
        if hits or facts:
            if hits:
                facts.append({"type": "xdr_indicator_hits", "hits": hits[:20]})
            return _contrib("xdr", "XDR", True, facts, gaps, sources)
        gaps.append("XDR: sin eventos de amenaza relacionados en registry (sin re-escaneo)")
    except Exception as exc:
        gaps.append(f"xdr: {exc}")
    return _contrib("xdr", "XDR", False, facts, gaps, sources)


def collaborate_threat_intel(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    facts, gaps, sources = [], [], []
    try:
        from services.threat_intelligence_service import threat_intelligence

        related = []
        if hasattr(threat_intelligence, "lookup_indicators"):
            related = threat_intelligence.lookup_indicators(indicators) or []
            sources.append("threat_intelligence.lookup_indicators")
        elif hasattr(threat_intelligence, "get_operational_summary"):
            summary = threat_intelligence.get_operational_summary()
            sources.append("threat_intelligence.get_operational_summary")
            facts.append({"type": "intel_summary", "data": summary})
        else:
            gaps.append("Threat Intelligence: sin lookup/summary de solo lectura disponible")
        if related:
            facts.append({"type": "intel_matches", "matches": related[:20]})
            return _contrib("threat_intelligence", "Threat Intelligence", True, facts, gaps, sources)
        if facts:
            return _contrib("threat_intelligence", "Threat Intelligence", True, facts, gaps, sources)
        if not gaps:
            gaps.append("Threat Intelligence: sin coincidencias verificables para los indicadores")
    except Exception as exc:
        gaps.append(f"threat_intelligence: {exc}")
    return _contrib("threat_intelligence", "Threat Intelligence", False, facts, gaps, sources)


def collaborate_forensic(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    facts, gaps, sources = [], [], []
    try:
        from services.defense_evidence_registry import list_recent_events

        events = list_recent_events(limit=30) or []
        sources.append("defense_evidence_registry.list_recent_events")
        ips = set(indicators.get("ips") or [])
        related = []
        for ev in events:
            blob = str(ev)
            if any(ip in blob for ip in ips) or (
                event.get("finding_id") and str(event.get("finding_id")) in blob
            ):
                related.append(
                    {
                        "event_id": ev.get("event_id") or ev.get("id"),
                        "motor": ev.get("motor"),
                        "action": ev.get("action"),
                        "phase": ev.get("phase"),
                        "ts": ev.get("ts") or ev.get("timestamp"),
                    }
                )
        facts.append({"type": "forensic_timeline_related", "count": len(related), "events": related[:15]})
        if related:
            return _contrib("forensic", "Forense", True, facts, gaps, sources)
        gaps.append("Forense: sin eventos previos relacionados en registry")
    except Exception as exc:
        gaps.append(f"forensic: {exc}")
    return _contrib("forensic", "Forense", False, facts, gaps, sources)


def collaborate_compliance(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    facts, gaps, sources = [], [], []
    try:
        from services.compliance_catalog import FRAMEWORK_MAP

        sources.append("compliance_catalog.FRAMEWORK_MAP")
        threat = str(event.get("threat_type") or event.get("action") or "").lower()
        # Impacto regulatorio solo como mapeo declarativo de frameworks existentes — sin inventar score
        relevant = []
        for fw in FRAMEWORK_MAP:
            label = (fw.get("label") or "").lower()
            fid = (fw.get("id") or "").lower()
            if any(k in threat for k in ("phish", "data", "breach", "ransom", "auth", "malware")) or indicators.get("cves"):
                relevant.append({"id": fw.get("id"), "label": fw.get("label"), "note": fw.get("note")})
            elif "pci" in fid or "gdpr" in fid or "iso" in fid:
                # frameworks siempre listados como contexto disponible, no como hallazgo
                pass
        facts.append(
            {
                "type": "compliance_frameworks_available",
                "count": len(FRAMEWORK_MAP),
                "potentially_relevant": relevant[:8],
                "note": "Evaluación completa requiere Compliance Center; aquí solo se declara impacto potencial con base en tipo de amenaza real del evento.",
            }
        )
        if relevant or threat:
            return _contrib("compliance", "Compliance", True, facts, gaps, sources)
        gaps.append("Compliance: sin tipo de amenaza claro para evaluar impacto")
    except Exception as exc:
        gaps.append(f"compliance: {exc}")
    return _contrib("compliance", "Compliance", False, facts, gaps, sources)


def collaborate_inventory(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    facts, gaps, sources = [], [], []
    ips = set(indicators.get("ips") or [])
    try:
        from database import SessionLocal, NetworkDeviceInventory

        if ips:
            db = SessionLocal()
            try:
                matches = []
                for ip in list(ips)[:8]:
                    row = db.query(NetworkDeviceInventory).filter(NetworkDeviceInventory.ip == ip).first()
                    if row:
                        matches.append(
                            {
                                "ip": row.ip,
                                "mac": row.mac,
                                "hostname": row.hostname,
                                "vendor": row.vendor,
                                "asset_status": row.asset_status,
                                "trust_score": row.trust_score,
                                "first_seen": row.first_seen,
                                "last_seen": row.last_seen,
                                "times_seen": row.times_seen,
                                "os_estimate": row.os_estimate,
                            }
                        )
                if matches:
                    sources.append("NetworkDeviceInventory")
                    facts.append({"type": "aie_inventory_match", "count": len(matches), "devices": matches[:10]})
                    return _contrib("inventory", "Inventario", True, facts, gaps, sources)
            finally:
                db.close()
    except Exception as exc:
        gaps.append(f"inventory_aie: {exc}")
    try:
        from services.defense_evidence_registry import list_recent_events

        events = list_recent_events(limit=30) or []
        sources.append("defense_evidence_registry(inventory hints)")
        related = []
        for ev in events:
            blob = str(ev)
            if any(ip in blob for ip in ips):
                related.append({"motor": ev.get("motor"), "action": ev.get("action"), "finding_id": ev.get("finding_id")})
        if related:
            facts.append({"type": "inventory_hints_from_registry", "count": len(related), "matches": related[:10]})
            return _contrib("inventory", "Inventario", True, facts, gaps, sources)
        if not ips:
            gaps.append("Inventario: sin IP en indicadores")
        else:
            gaps.append("Inventario: sin pistas de host en registry/AIE para la IP (sin forzar escaneo de red)")
    except Exception as exc:
        gaps.append(f"inventory: {exc}")
    return _contrib("inventory", "Inventario", False, facts, gaps, sources)


def collaborate_network_history(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    facts, gaps, sources = [], [], []
    ips = indicators.get("ips") or []
    try:
        from services import network_security_history_service as nhs

        entries = []
        if hasattr(nhs, "list_recent"):
            entries = nhs.list_recent(limit=30) or []
            sources.append("network_security_history_service.list_recent")
        elif hasattr(nhs, "get_recent_events"):
            entries = nhs.get_recent_events(30) or []
            sources.append("network_security_history_service.get_recent_events")
        related = []
        for e in entries:
            blob = str(e)
            if any(ip in blob for ip in ips):
                related.append(e)
        if related:
            facts.append({"type": "network_history_matches", "count": len(related), "entries": related[:10]})
            return _contrib("network_history", "Historial de red", True, facts, gaps, sources)
        gaps.append("Historial de red: sin entradas relacionadas o API de listado no disponible")
    except Exception as exc:
        gaps.append(f"network_history: {exc}")
    return _contrib("network_history", "Historial de red", False, facts, gaps, sources)


def collaborate_defense_center(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    """Centro de Defensa / Active Defense — contexto del propio evento canónico."""
    facts, gaps, sources = [], [], []
    motor = event.get("motor")
    if motor:
        sources.append("defense_coordinator.event")
        facts.append(
            {
                "type": "origin_event",
                "motor": motor,
                "action": event.get("action"),
                "phase": event.get("phase"),
                "threat_type": event.get("threat_type"),
                "finding_id": event.get("finding_id"),
                "outcome": event.get("outcome"),
            }
        )
        return _contrib("defense_center", "Centro de Defensa", True, facts, gaps, sources)
    gaps.append("Centro de Defensa: evento sin motor origen")
    return _contrib("defense_center", "Centro de Defensa", False, facts, gaps, sources)


def collaborate_adaptive_profile(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    facts, gaps, sources = [], [], []
    try:
        from services.adaptive_profile_engine import engine_status

        st = engine_status()
        sources.append("adaptive_profile_engine.engine_status")
        if st:
            facts.append({"type": "ape_status", "data": {k: st.get(k) for k in list(st)[:12]}})
            return _contrib("adaptive_profile", "Adaptive Profile", True, facts, gaps, sources)
        gaps.append("Adaptive Profile: sin estado disponible")
    except Exception as exc:
        try:
            from services.behavior_baseline_service import get_dashboard_behavior_summary

            email = event.get("user_email") or "system"
            summary = get_dashboard_behavior_summary(str(email))
            sources.append("behavior_baseline_service")
            facts.append({"type": "behavior_summary_opaque", "keys": list((summary or {}).keys())[:10]})
            return _contrib("adaptive_profile", "Adaptive Profile", bool(summary), facts, gaps, sources)
        except Exception as exc2:
            gaps.append(f"adaptive_profile: {exc}; fallback: {exc2}")
    return _contrib("adaptive_profile", "Adaptive Profile", False, facts, gaps, sources)


def collaborate_cryptovault(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    facts, gaps, sources = [], [], []
    try:
        from crypto_vault import CryptoVault

        health = CryptoVault().verify_health()
        sources.append("crypto_vault.verify_health")
        facts.append(
            {
                "type": "cryptovault_health",
                "aes_gcm_roundtrip": health.get("aes_gcm_roundtrip"),
                "aes_key_wrapped": health.get("aes_key_wrapped"),
                "active_kid": health.get("active_kid"),
                "key_versions": health.get("key_versions"),
            }
        )
        return _contrib("cryptovault", "CryptoVault", bool(health.get("aes_gcm_roundtrip")), facts, gaps, sources)
    except Exception as exc:
        gaps.append(f"cryptovault: {exc}")
    return _contrib("cryptovault", "CryptoVault", False, facts, gaps, sources)


def collaborate_btde(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    """Colaborador Swarm: estado BTDE + última correlación (solo lectura)."""
    facts, gaps, sources = [], [], []
    try:
        from services.behavioral_threat_detection.engine import get_btde_status

        st = get_btde_status()
        sources.append("behavioral_threat_detection.get_btde_status")
        facts.append(
            {
                "type": "btde_status",
                "zero_day_detector": False,
                "ml_classifier": False,
                "last_correlation": st.get("last_correlation"),
                "last_risk": st.get("last_risk"),
            }
        )
        motor = str(event.get("motor") or "")
        if "behavioral" in motor or "btde" in str(event.get("action") or "").lower():
            facts.append({"type": "btde_origin_event", "action": event.get("action"), "finding_id": event.get("finding_id")})
            return _contrib("btde", "BTDE", True, facts, gaps, sources)
        if st.get("last_correlation"):
            return _contrib("btde", "BTDE", True, facts, gaps, sources)
        gaps.append("BTDE: sin correlación reciente")
    except Exception as exc:
        gaps.append(f"btde: {exc}")
    return _contrib("btde", "BTDE", False, facts, gaps, sources)


def collaborate_zdde(event: Dict[str, Any], indicators: Dict[str, List[str]]) -> Dict[str, Any]:
    """Colaborador Swarm: estado ZDDE (correlación multicapa; sin firmas)."""
    facts, gaps, sources = [], [], []
    try:
        from services.zero_day_detection import get_zdde_status

        st = get_zdde_status()
        sources.append("zero_day_detection.get_zdde_status")
        last = st.get("last") or {}
        facts.append(
            {
                "type": "zdde_status",
                "signature_based": False,
                "zero_day_cve_oracle": False,
                "last_classification": last.get("classification"),
                "last_risk": last.get("risk"),
                "signal_motors": last.get("signal_motors"),
                "confidence_level": last.get("confidence_level"),
            }
        )
        motor = str(event.get("motor") or "")
        if "zero_day" in motor or "zdde" in str(event.get("action") or "").lower():
            facts.append(
                {
                    "type": "zdde_origin_event",
                    "action": event.get("action"),
                    "finding_id": event.get("finding_id"),
                }
            )
            return _contrib("zdde", "ZDDE", True, facts, gaps, sources)
        if last.get("classification"):
            return _contrib("zdde", "ZDDE", True, facts, gaps, sources)
        gaps.append("ZDDE: sin ciclo reciente")
    except Exception as exc:
        gaps.append(f"zdde: {exc}")
    return _contrib("zdde", "ZDDE", False, facts, gaps, sources)


COLLABORATORS: List[Callable[[Dict[str, Any], Dict[str, List[str]]], Dict[str, Any]]] = [
    collaborate_defense_center,
    collaborate_web_shield,
    collaborate_mail_shield,
    collaborate_endpoint,
    collaborate_btde,
    collaborate_zdde,
    collaborate_ndr,
    collaborate_xdr,
    collaborate_threat_intel,
    collaborate_forensic,
    collaborate_compliance,
    collaborate_inventory,
    collaborate_network_history,
    collaborate_adaptive_profile,
    collaborate_cryptovault,
]


def run_collaborators(
    event_payload: Dict[str, Any],
    indicators: Dict[str, List[str]],
    *,
    timeout_sec: float = 3.0,
) -> List[Dict[str, Any]]:
    """
    Consulta colaboradores en paralelo con timeout.
    Si un motor falla/timeout, los demás continúan (sin SPOF).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutTimeout

    results: List[Dict[str, Any]] = []
    failed: List[str] = []

    def _run(fn):
        return fn(event_payload, indicators)

    with ThreadPoolExecutor(max_workers=min(8, len(COLLABORATORS)), thread_name_prefix="swarm-collab") as pool:
        futs = {pool.submit(_run, fn): fn for fn in COLLABORATORS}
        try:
            for fut in as_completed(futs, timeout=timeout_sec * len(COLLABORATORS) + 1):
                fn = futs[fut]
                name = getattr(fn, "__name__", "unknown")
                try:
                    results.append(fut.result(timeout=timeout_sec))
                except Exception as exc:
                    failed.append(name)
                    logger.debug("swarm collaborator failed %s: %s", name, exc)
                    results.append(_contrib(name, name, False, gaps=[f"failed_or_timeout:{exc}"]))
        except FutTimeout:
            for fut, fn in futs.items():
                if not fut.done():
                    name = getattr(fn, "__name__", "unknown")
                    failed.append(name)
                    fut.cancel()
                    results.append(_contrib(name, name, False, gaps=["timeout_redistributed"]))

    # Marcar redistribución si hubo fallos
    if failed:
        results.append(
            _contrib(
                "swarm_fault_tolerance",
                "Fault Tolerance",
                True,
                facts=[{"type": "redistributed", "failed_collaborators": failed}],
                gaps=[],
                sources=["swarm_defense.collaborators.run_collaborators"],
            )
        )
    return results


def collaborator_catalog() -> List[Dict[str, Any]]:
    return [
        {"module_id": "defense_center", "label": "Centro de Defensa", "contributes": ["evento origen", "fase", "motor", "finding_id"]},
        {"module_id": "web_shield", "label": "Web Shield", "contributes": ["stats", "eventos URL/dominio"]},
        {"module_id": "mail_shield", "label": "Mail Shield", "contributes": ["stats", "phishing/BEC relacionados"]},
        {"module_id": "endpoint", "label": "Endpoint", "contributes": ["procesos/PID vía psutil (solo lectura)"]},
        {"module_id": "btde", "label": "BTDE", "contributes": ["correlación comportamental", "risk score explicable", "sin firmas"]},
        {"module_id": "zdde", "label": "ZDDE", "contributes": ["correlación multicapa amenaza desconocida", "risk explicable", "sin firmas/AV"]},
        {"module_id": "ndr", "label": "NDR", "contributes": ["eventos network/NDR en defense_registry (sin ARP forzado)"]},
        {"module_id": "xdr", "label": "XDR", "contributes": ["eventos threat/xdr en defense_registry (sin re-escaneo)"]},
        {"module_id": "threat_intelligence", "label": "Threat Intelligence", "contributes": ["resumen/IOC si el servicio responde"]},
        {"module_id": "forensic", "label": "Forense", "contributes": ["timeline defense_registry"]},
        {"module_id": "compliance", "label": "Compliance", "contributes": ["frameworks del catálogo real"]},
        {"module_id": "inventory", "label": "Inventario", "contributes": ["pistas de host en defense_registry"]},
        {"module_id": "network_history", "label": "Historial de red", "contributes": ["historial si API de listado existe"]},
        {"module_id": "adaptive_profile", "label": "Adaptive Profile", "contributes": ["estado APE / baseline"]},
        {"module_id": "cryptovault", "label": "CryptoVault", "contributes": ["salud criptográfica / keyring"]},
    ]
