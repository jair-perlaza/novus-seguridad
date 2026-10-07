"""
Registro de capacidades del Kernel IA — motores reales de NOVUS.
Cada capacidad invoca un servicio concreto y retorna datos verificables.
"""
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil
from datetime import datetime
from utils.logger import logger


class CapabilityRegistry:
    """Ejecuta capacidades y fusiona resultados."""

    def __init__(self):
        self._result_cache: dict = {}
        self._cache_lock = threading.Lock()

    def _cache_key(self, cap_id, user_id):
        return f"{cap_id}:{user_id or 0}"

    def _get_cached(self, cap_id, user_id, ttl_sec):
        if ttl_sec <= 0:
            return None
        key = self._cache_key(cap_id, user_id)
        with self._cache_lock:
            entry = self._result_cache.get(key)
            if entry and (time.time() - entry["ts"]) <= ttl_sec:
                return entry["data"], entry["module"]
        return None

    def _set_cached(self, cap_id, user_id, data, module):
        key = self._cache_key(cap_id, user_id)
        with self._cache_lock:
            self._result_cache[key] = {"data": data, "module": module, "ts": time.time()}
            self.trim_cache(max_entries=int(__import__("os").environ.get("NOVUS_AI_CAP_CACHE_MAX", "128")))

    def trim_cache(self, max_entries: int = 128) -> int:
        """Evict oldest capability results — prevents unbounded growth under soak."""
        with self._cache_lock:
            n = len(self._result_cache)
            if n <= max_entries:
                # also drop expired (>300s) regardless
                now = time.time()
                dead = [k for k, v in self._result_cache.items() if now - float(v.get("ts") or 0) > 300]
                for k in dead:
                    self._result_cache.pop(k, None)
                return len(dead)
            ranked = sorted(self._result_cache.items(), key=lambda kv: float(kv[1].get("ts") or 0))
            drop = ranked[: max(0, n - max_entries)]
            for k, _ in drop:
                self._result_cache.pop(k, None)
            return len(drop)

    CAPABILITY_CATALOG = {
        # Vulnerabilidades
        "security.vulnerabilities": {
            "label": "Motor de vulnerabilidades",
            "service": "novus_security_integration",
            "module": "vulnerabilities",
        },
        "security.threats": {
            "label": "Motor XDR / amenazas",
            "service": "novus_security_integration",
            "module": "security",
        },
        "security.system_health": {
            "label": "Salud del sistema",
            "service": "novus_security_integration",
            "module": "system",
        },
        "advanced_detector.ports": {
            "label": "Detector avanzado — puertos",
            "service": "advanced_detector_service",
            "module": "firewall",
        },
        "advanced_detector.processes": {
            "label": "Detector avanzado — procesos",
            "service": "advanced_detector_service",
            "module": "processes",
        },
        "advanced_detector.malware": {
            "label": "Detector antimalware",
            "service": "advanced_detector_service",
            "module": "security",
        },
        # Red
        "network.scanner": {
            "label": "Escáner de red ARP",
            "service": "network_scanner",
            "module": "network",
        },
        "network.events": {
            "label": "Log de eventos de red",
            "service": "network_event_log",
            "module": "network",
        },
        "dashboard.metrics": {
            "label": "Dashboard en vivo",
            "service": "system_monitor",
            "module": "dashboard",
        },
        "traffic.stats": {
            "label": "Estadísticas de tráfico",
            "service": "system_monitor",
            "module": "traffic",
        },
        "endpoints.live": {
            "label": "Endpoints en vivo",
            "service": "system_monitor",
            "module": "endpoints",
        },
        "connections.active": {
            "label": "Conexiones activas",
            "service": "psutil",
            "module": "connections",
        },
        "firewall.ports": {
            "label": "Puertos / firewall local",
            "service": "advanced_detector_service",
            "module": "firewall",
        },
        # Procesos / sistema
        "process.scanner": {
            "label": "Escáner de procesos",
            "service": "system_monitor",
            "module": "processes",
        },
        "system.metrics": {
            "label": "Métricas CPU/RAM/Disco",
            "service": "system_monitor",
            "module": "system",
        },
        # Correo
        "gmail.analyzer": {
            "label": "Analizador Gmail OAuth",
            "service": "gmail_analyzer_service",
            "module": "gmail",
        },
        # Reportes / incidentes
        "reports.manager": {
            "label": "Gestor de reportes",
            "service": "security_report_service",
            "module": "reports",
        },
        "incidents.manager": {
            "label": "Gestor de incidentes",
            "service": "database",
            "module": "incidents",
        },
        "threat_intelligence.center": {
            "label": "Centro de Inteligencia NOVUS",
            "service": "threat_intelligence_service",
            "module": "intelligence",
        },
        "deep_scan.engine": {
            "label": "Motor Deep Scan integral",
            "service": "deep_scan_engine",
            "module": "deep_scan",
        },
        "security.sector_shield": {
            "label": "Escudo sectorial (Security Engine)",
            "service": "security_engine",
            "module": "sector",
        },
        "security.vault": {
            "label": "CryptoVault AES/ECC",
            "service": "crypto_vault",
            "module": "vault",
        },
        "vulnerability.scanner": {
            "label": "Escáner de vulnerabilidades del sistema",
            "service": "vulnerability_scanner",
            "module": "vulnerabilities",
        },
        "remediation.engine": {
            "label": "Motor de remediación",
            "service": "remediation_engine",
            "module": "remediation",
        },
        "adaptive.defense": {
            "label": "Adaptive Defense Engine",
            "service": "adaptive_defense_engine",
            "module": "adaptive_defense",
        },
        "uce.compatibility": {
            "label": "Universal Compatibility Engine",
            "service": "universal_compatibility_engine",
            "module": "uce",
        },
        "aspe.sector_protection": {
            "label": "Adaptive Sector Protection Engine",
            "service": "adaptive_sector_protection_engine",
            "module": "aspe",
        },
        "network.radar": {
            "label": "Network Radar (ARP activo)",
            "service": "network_scanner",
            "module": "network",
        },
        "network.ndr": {
            "label": "Network NDR — inventario, telemetría y alertas",
            "service": "network_ndr_service",
            "module": "network",
        },
        "topology.view": {
            "label": "Topología de red",
            "service": "network_scanner",
            "module": "topology",
        },
        "siem.logs": {
            "label": "Logs SIEM / auditoría",
            "service": "database",
            "module": "siem",
        },
        "playbooks.manager": {
            "label": "Gestor de playbooks",
            "service": "playbook_service",
            "module": "playbooks",
        },
    }

    def execute(self, capability_ids, user_id=None, force_refresh=False, parallel_groups=None, cache_ttl_sec=0):
        """Ejecuta capacidades — secuencial o por grupos paralelos con caché opcional."""
        if parallel_groups:
            ordered = []
            seen = set()
            for group in parallel_groups:
                for cap in group:
                    if cap not in seen:
                        seen.add(cap)
                        ordered.append(cap)
            for cap in capability_ids or []:
                if cap not in seen:
                    ordered.append(cap)
            capability_ids = ordered

        if parallel_groups and len(parallel_groups) > 1:
            return self._execute_parallel_groups(parallel_groups, user_id, force_refresh, cache_ttl_sec)

        return self._execute_sequential(capability_ids or [], user_id, force_refresh, cache_ttl_sec)

    def _execute_sequential(self, capability_ids, user_id, force_refresh, cache_ttl_sec):
        result = self._empty_result()
        merged = {}
        for cap_id in capability_ids:
            self._run_one(cap_id, user_id, force_refresh, cache_ttl_sec, result, merged)
        result.update(merged.get("_legacy", {}))
        result["_capability_raw"] = {k: v for k, v in merged.items() if k != "_legacy"}
        result["cache_hits"] = result.get("cache_hits", 0)
        return result

    def _execute_parallel_groups(self, parallel_groups, user_id, force_refresh, cache_ttl_sec):
        result = self._empty_result()
        merged = {}
        max_workers = min(6, max(1, len(parallel_groups)))

        def run_group(group):
            local = self._empty_result()
            local_merged = {}
            for cap_id in group:
                self._run_one(cap_id, user_id, force_refresh, cache_ttl_sec, local, local_merged)
            return local, local_merged

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(run_group, g) for g in parallel_groups if g]
            for fut in as_completed(futures):
                try:
                    local, local_merged = fut.result()
                    result["capabilities_executed"].extend(local.get("capabilities_executed") or [])
                    result["capabilities_failed"].extend(local.get("capabilities_failed") or [])
                    result["modules_queried"].extend(local.get("modules_queried") or [])
                    result["gaps"].extend(local.get("gaps") or [])
                    result["cache_hits"] = (result.get("cache_hits") or 0) + (local.get("cache_hits") or 0)
                    for cap_id, data in local_merged.items():
                        if cap_id == "_legacy":
                            for lk, lv in data.items():
                                merged.setdefault("_legacy", {})[lk] = lv
                        else:
                            merged[cap_id] = data
                            self._merge_into_legacy(merged, cap_id, data)
                except Exception as exc:
                    logger.warning(f"Parallel group failed: {exc}")
                    result["gaps"].append(str(exc))

        result["capabilities_executed"] = list(dict.fromkeys(result["capabilities_executed"]))
        result["modules_queried"] = list(dict.fromkeys(result["modules_queried"]))
        result.update(merged.get("_legacy", {}))
        result["_capability_raw"] = {k: v for k, v in merged.items() if k != "_legacy"}
        return result

    def _empty_result(self):
        return {
            "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "capabilities_executed": [],
            "capabilities_failed": [],
            "modules_queried": [],
            "gaps": [],
            "cache_hits": 0,
        }

    def _run_one(self, cap_id, user_id, force_refresh, cache_ttl_sec, result, merged):
        try:
            if not force_refresh:
                cached = self._get_cached(cap_id, user_id, cache_ttl_sec)
                if cached:
                    data, module = cached
                    result["capabilities_executed"].append(cap_id)
                    result["cache_hits"] = (result.get("cache_hits") or 0) + 1
                    if module and module not in result["modules_queried"]:
                        result["modules_queried"].append(module)
                    merged[cap_id] = data
                    self._merge_into_legacy(merged, cap_id, data)
                    return
            data, module = self._run_capability(cap_id, user_id, force_refresh)
            self._set_cached(cap_id, user_id, data, module)
            result["capabilities_executed"].append(cap_id)
            if module and module not in result["modules_queried"]:
                result["modules_queried"].append(module)
            merged[cap_id] = data
            self._merge_into_legacy(merged, cap_id, data)
        except Exception as exc:
            logger.warning(f"Capability {cap_id} failed: {exc}")
            result["capabilities_failed"].append({"id": cap_id, "error": str(exc)})
            result["gaps"].append(f"{cap_id}: {exc}")

    def _merge_into_legacy(self, merged, cap_id, data):
        legacy = merged.setdefault("_legacy", {})
        if cap_id == "security.vulnerabilities":
            legacy["vulnerabilities"] = data if isinstance(data, list) else data.get("items", [])
        elif cap_id == "security.threats":
            legacy["security"] = data
        elif cap_id == "network.scanner":
            legacy["network"] = data
        elif cap_id == "system.metrics" or cap_id == "security.system_health":
            if "system" not in legacy:
                legacy["system"] = data if isinstance(data, dict) and "cpu" in data else data.get("metrics", data)
        elif cap_id == "traffic.stats":
            legacy["traffic"] = data
        elif cap_id == "process.scanner" or cap_id == "advanced_detector.processes":
            legacy["processes"] = data.get("processes", data) if isinstance(data, dict) else data
            if isinstance(data, dict) and data.get("suspicious"):
                sec = legacy.setdefault("security", {})
                sec["suspicious_processes"] = data["suspicious"]
        elif cap_id == "connections.active":
            legacy["connections"] = data
        elif cap_id == "firewall.ports" or cap_id == "advanced_detector.ports":
            legacy["firewall"] = {"open_ports": data if isinstance(data, list) else data.get("ports", [])}
            sec = legacy.setdefault("security", {})
            sec["open_ports"] = legacy["firewall"]["open_ports"]
        elif cap_id == "gmail.analyzer":
            legacy["gmail"] = data
        elif cap_id == "reports.manager":
            legacy["reports"] = data
        elif cap_id == "incidents.manager":
            legacy["incidents"] = data
        elif cap_id == "threat_intelligence.center":
            legacy["intelligence"] = data
        elif cap_id == "dashboard.metrics":
            legacy["dashboard"] = data
        elif cap_id == "endpoints.live":
            legacy["endpoints"] = data
        elif cap_id == "topology.view":
            legacy["topology"] = data
            legacy["network"] = {"nodes": data.get("nodes", []), "meta": data.get("meta", {})}
        elif cap_id == "siem.logs":
            legacy["siem"] = data
        elif cap_id == "playbooks.manager":
            legacy["playbooks"] = data.get("playbooks", data)

    def _run_capability(self, cap_id, user_id, force_refresh):
        if cap_id == "security.vulnerabilities":
            from services.novus_security_integration import novus_security
            items = novus_security.scan_vulnerabilities()
            return {"items": items, "count": len(items)}, "vulnerabilities"

        if cap_id == "security.threats":
            from services.novus_security_integration import novus_security
            cache = novus_security._threat_cache or {}
            if not cache.get("last_scan") or force_refresh:
                novus_security.detect_threats_realtime(force=force_refresh)
                cache = novus_security._threat_cache or {}
            return {
                "threat_count": novus_security.get_cached_threat_count(),
                "suspicious_processes": cache.get("suspicious_processes") or [],
                "open_ports": cache.get("open_ports") or [],
                "summary": novus_security.get_cached_security_summary(),
            }, "security"

        if cap_id == "security.system_health":
            from services.novus_security_integration import novus_security
            health = novus_security.scan_system_health()
            from services.system_monitor import system_monitor
            metrics = system_monitor.get_system_status(force_refresh=force_refresh)
            return {"health": health, "metrics": metrics, **metrics}, "system"

        if cap_id == "advanced_detector.ports":
            from services.advanced_detector_service import advanced_detector
            from utils.host_data import get_local_ip
            ports = advanced_detector.scan_open_ports(get_local_ip())
            return {"ports": ports or []}, "firewall"

        if cap_id == "advanced_detector.processes":
            from services.advanced_detector_service import advanced_detector
            sus = advanced_detector.scan_running_processes()
            from services.system_monitor import system_monitor
            procs = system_monitor.get_process_list(limit=15)
            return {"processes": procs, "suspicious": sus or []}, "processes"

        if cap_id == "advanced_detector.malware":
            from services.advanced_detector_service import advanced_detector
            sus = advanced_detector.scan_running_processes()
            return {"suspicious_processes": sus or [], "note": "Análisis heurístico local"}, "security"

        if cap_id == "network.scanner":
            from services.network_scanner import network_scanner
            from services.network_scan_coordinator import schedule_network_discovery

            if force_refresh:
                schedule_network_discovery(consumer="ai_capability_scanner", force=True)
            return {
                "nodes": network_scanner.get_cached_nodes() or [],
                "meta": network_scanner.get_network_meta(),
                "cache": network_scanner.get_cache_info(),
            }, "network"

        if cap_id == "network.radar":
            from services.network_scanner import network_scanner
            from services.network_scan_coordinator import schedule_network_discovery

            schedule_network_discovery(consumer="ai_capability_radar", force=force_refresh)
            nodes = network_scanner.get_cached_nodes() or []
            return {
                "nodes": nodes,
                "meta": network_scanner.get_network_meta(),
                "source": "network_snapshot/cache (Radar)",
                "device_count": len(nodes),
            }, "network"

        if cap_id == "network.ndr":
            from services.network_ndr_service import build_ndr_payload_from_cache, build_ndr_payload

            payload = (
                build_ndr_payload(force_refresh=True)
                if force_refresh
                else build_ndr_payload_from_cache()
            )
            return payload, "network"

        if cap_id == "topology.view":
            from services.network_scanner import network_scanner
            from services.network_scan_coordinator import schedule_network_discovery

            if force_refresh:
                schedule_network_discovery(consumer="ai_capability_topology", force=True)
            nodes = network_scanner.get_cached_nodes() or []
            meta = network_scanner.get_network_meta() or {}
            return {
                "nodes": nodes,
                "meta": meta,
                "gateway": meta.get("gateway"),
                "local_ip": meta.get("local_ip"),
                "note": "Topología derivada de escáner ARP — UI completa en /topology",
            }, "topology"

        if cap_id == "siem.logs":
            from database import SessionLocal, Log
            from services.network_event_log import NetworkEventLog
            today = datetime.now().strftime("%Y-%m-%d")
            db = SessionLocal()
            try:
                logs = [
                    {"evento": l.evento, "detalle": l.detalle, "fecha": l.fecha}
                    for l in db.query(Log).filter(Log.fecha >= today).order_by(Log.id.desc()).limit(30).all()
                ]
            finally:
                db.close()
            net_events = NetworkEventLog.get_recent(limit=15)
            return {
                "audit_logs": logs,
                "network_events": net_events,
                "date": today,
                "total": len(logs) + len(net_events),
            }, "siem"

        if cap_id == "playbooks.manager":
            from services.playbook_service import list_playbooks
            items = list_playbooks(active_only=False)
            return {"playbooks": items, "count": len(items)}, "playbooks"

        if cap_id == "deep_scan.engine":
            return {
                "available": True,
                "note": "Deep Scan se ejecuta vía workflow async — use perfil full/network/malware",
            }, "deep_scan"

        if cap_id == "network.events":
            from services.network_event_log import NetworkEventLog
            return {"events": NetworkEventLog.get_recent(limit=20)}, "network"

        if cap_id == "dashboard.metrics":
            from services.system_monitor import system_monitor
            from services.network_scanner import network_scanner
            from services.novus_security_integration import novus_security
            sys_d = system_monitor.get_system_status(force_refresh=force_refresh)
            net = network_scanner.get_cached_nodes() or []
            stats = system_monitor.get_network_stats()
            return {
                "cpu": sys_d.get("cpu"),
                "ram": sys_d.get("ram"),
                "disk": sys_d.get("disk"),
                "nodes": len(net),
                "threats": novus_security.get_cached_threat_count(),
                "traffic_recv_mb": round(stats.get("bytes_recv", 0) / (1024 ** 2), 2),
                "traffic_sent_mb": round(stats.get("bytes_sent", 0) / (1024 ** 2), 2),
            }, "dashboard"

        if cap_id == "traffic.stats":
            from services.system_monitor import system_monitor
            stats = system_monitor.get_network_stats()
            return {
                "bytes_recv_mb": round(stats.get("bytes_recv", 0) / (1024 ** 2), 2),
                "bytes_sent_mb": round(stats.get("bytes_sent", 0) / (1024 ** 2), 2),
                "packets_recv": stats.get("packets_recv", 0),
                "packets_sent": stats.get("packets_sent", 0),
                "active_connections": stats.get("connections", 0),
            }, "traffic"

        if cap_id == "endpoints.live":
            from services.system_monitor import system_monitor
            procs = system_monitor.get_process_list(limit=10)
            sys_d = system_monitor.get_system_status()
            return {
                "process_count": sys_d.get("procesos_activos"),
                "users": sys_d.get("usuarios_conectados"),
                "top_processes": procs[:5],
            }, "endpoints"

        if cap_id == "connections.active":
            conns = psutil.net_connections(kind="inet")
            established = [c for c in conns if c.status == "ESTABLISHED"]
            sample = []
            for c in established[:8]:
                if c.laddr and c.raddr:
                    sample.append({
                        "local": f"{c.laddr.ip}:{c.laddr.port}",
                        "remote": f"{c.raddr.ip}:{c.raddr.port}",
                    })
            return {"total": len(conns), "established": len(established), "sample": sample}, "connections"

        if cap_id == "firewall.ports":
            return self._run_capability("advanced_detector.ports", user_id, force_refresh)

        if cap_id == "process.scanner":
            from services.system_monitor import system_monitor
            procs = system_monitor.get_process_list(limit=15)
            return procs, "processes"

        if cap_id == "system.metrics":
            from services.system_monitor import system_monitor
            return system_monitor.get_system_status(force_refresh=force_refresh), "system"

        if cap_id == "gmail.analyzer":
            if not user_id:
                return {"error": "Requiere usuario autenticado"}, "gmail"
            from services.gmail_analyzer_service import get_stats, get_history
            from services.gmail_oauth_service import get_connection_status
            return {
                "connection": get_connection_status(user_id),
                "stats": get_stats(user_id),
                "recent": get_history(user_id, limit=5),
            }, "gmail"

        if cap_id == "reports.manager":
            from services.security_report_service import list_reports
            return list_reports(limit=10), "reports"

        if cap_id == "incidents.manager":
            from database import SessionLocal, Alerta
            db = SessionLocal()
            try:
                items = [
                    {"id": f"INC-{a.id:04d}", "tipo": a.titulo, "ip": a.ip_afectada, "descripcion": a.descripcion}
                    for a in db.query(Alerta).order_by(Alerta.id.desc()).limit(10).all()
                ]
            finally:
                db.close()
            return items, "incidents"

        if cap_id == "threat_intelligence.center":
            from services.threat_intelligence_service import threat_intelligence
            return {
                "stats": threat_intelligence.stats(),
                "cases": threat_intelligence.list_cases(limit=15),
            }, "intelligence"

        if cap_id == "security.sector_shield":
            from flask_login import current_user
            from services.sector_shield_service import get_active_shield_status
            email = getattr(current_user, "email", None) if current_user.is_authenticated else None
            profile = get_active_shield_status(email)
            return profile, "sector"

        if cap_id == "security.vault":
            from services.novus_security_integration import novus_security
            vault = novus_security.vault
            return {
                "active": vault is not None and getattr(vault, "llave_aes", None) is not None,
                "tls_label": vault.get_tls_status() if vault else "Sin datos disponibles",
            }, "vault"

        if cap_id == "vulnerability.scanner":
            from vulnerability_scanner import vulnerability_scanner
            items = vulnerability_scanner.check_system_vulnerabilities() or []
            return {"items": items, "count": len(items)}, "vulnerabilities"

        if cap_id == "remediation.engine":
            from services.security_report_service import list_reports
            reports = list_reports(limit=5)
            return {
                "available": True,
                "recent_reports": len(reports),
                "note": "Use remediación desde panel de vulnerabilidades/incidentes",
            }, "remediation"

        if cap_id == "adaptive.defense":
            from services.adaptive_defense_engine import adaptive_defense
            panel = adaptive_defense.get_adaptive_defense_panel()
            return {
                "available": True,
                "estado": panel.get("estado_actual"),
                "contenciones": panel.get("contenciones_activas"),
                "acciones": panel.get("riesgo_reducido_acciones"),
            }, "adaptive_defense"

        if cap_id == "uce.compatibility":
            from services.universal_compatibility_engine import uce
            panel = uce.get_infrastructure_panel()
            return {
                "technologies": panel.get("technologies") or [],
                "count": panel.get("technologies_count", 0),
                "compatible_modules": panel.get("compatible_modules") or [],
                "detected_at": panel.get("detected_at"),
            }, "uce"

        if cap_id == "aspe.sector_protection":
            from services.adaptive_sector_protection_engine import aspe
            panel = aspe.get_sector_protection_panel()
            return {
                "sector": panel.get("sector_key"),
                "activas": len(panel.get("protecciones_activas") or []),
                "standby": len(panel.get("protecciones_standby") or []),
                "dinamicas": len(panel.get("protecciones_dinamicas") or []),
                "confidence": panel.get("confidence_level"),
            }, "aspe"

        raise ValueError(f"Capacidad desconocida: {cap_id}")


capability_registry = CapabilityRegistry()
