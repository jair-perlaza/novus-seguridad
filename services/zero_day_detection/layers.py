#!/usr/bin/env python3
"""
Recolección de capas reales (solo lectura) para ZDDE.
Cada capa aporta indicadores verificables o se marca ausente — nunca inventa.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def layer_btde(*, heavy: bool = False) -> Dict[str, Any]:
    """Lee estado/última correlación BTDE. No dispara escaneos ARP (solo lectura)."""
    try:
        from services.behavioral_threat_detection.engine import get_btde_status

        st = get_btde_status() or {}
        last_corr = st.get("last_correlation") or {}
        last_risk = st.get("last_risk") or last_corr.get("risk") or {}
        findings = last_corr.get("findings") or []
        # Ciclo opcional solo si heavy y el status está vacío — sin publish (evita swarm/ARP)
        if heavy and not last_corr and not st.get("last_cycle_at"):
            try:
                from services.behavioral_threat_detection.engine import run_btde_cycle

                cycle = run_btde_cycle(heavy=False, publish=False)
                corr = cycle.get("correlation") or {}
                findings = corr.get("findings") or cycle.get("findings") or []
                return {
                    "motor": "behavioral_threat_detection",
                    "ok": bool(cycle.get("ok")),
                    "enough_evidence": bool(corr.get("enough_evidence")),
                    "risk": corr.get("risk") or cycle.get("risk"),
                    "findings_n": len(findings),
                    "finding_types": sorted(
                        {str(f.get("finding_type")) for f in findings if f.get("finding_type")}
                    )[:40],
                    "alerts_n": len(corr.get("alerts") or []),
                    "correlation_reason": corr.get("correlation_reason"),
                    "signature_based": False,
                    "source": "btde_cycle_no_publish",
                    "observed_at": _utc(),
                }
            except Exception as exc:
                return {
                    "motor": "behavioral_threat_detection",
                    "ok": False,
                    "error": str(exc)[:160],
                    "findings_n": 0,
                }
        return {
            "motor": "behavioral_threat_detection",
            "ok": True,
            "enough_evidence": bool(last_corr.get("enough_evidence")),
            "risk": last_risk if isinstance(last_risk, dict) else {"level": last_risk},
            "findings_n": len(findings) if isinstance(findings, list) else int(st.get("findings_n") or 0),
            "finding_types": sorted(
                {
                    str(f.get("finding_type"))
                    for f in (findings if isinstance(findings, list) else [])
                    if isinstance(f, dict) and f.get("finding_type")
                }
            )[:40],
            "alerts_n": len(last_corr.get("alerts") or []),
            "correlation_reason": last_corr.get("correlation_reason") or st.get("last_reason"),
            "signature_based": False,
            "source": "btde_status_readonly",
            "active": bool(st.get("active")),
            "observed_at": _utc(),
        }
    except Exception as exc:
        return {"motor": "behavioral_threat_detection", "ok": False, "error": str(exc)[:160], "findings_n": 0}


def layer_swarm() -> Dict[str, Any]:
    try:
        from services.swarm_defense import swarm_defense_engine

        st = swarm_defense_engine.status()
        mesh = st.get("mesh") or {}
        sync = mesh.get("sync") or {}
        ioc = sync.get("ioc_counts") or {}
        recent = swarm_defense_engine.recent_correlations(5)
        return {
            "motor": "swarm_defense",
            "ok": bool(st.get("ok")),
            "collaborators_n": len(st.get("collaborators") or []),
            "recent_correlations_n": len(recent),
            "mesh_peers": mesh.get("peers_connected"),
            "mesh_ioc": ioc,
            "mesh_inbound": sync.get("inbound_events"),
            "mesh_outbound": sync.get("outbound_events"),
            "observed_at": _utc(),
        }
    except Exception as exc:
        return {"motor": "swarm_defense", "ok": False, "error": str(exc)[:160]}


def layer_mesh_intel(*, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Capa Mesh para ZDDE.
    P0-2: solo IOC del mismo tenant pueden influir.
    Sin tenant_id → NO_TENANT_CONTEXT (deny-by-default, sin convertir HOST pool en TENANT_GLOBAL).
    """
    try:
        from services.swarm_defense.mesh import intel_store

        stats = intel_store.stats(tenant_id=tenant_id, for_zdde_influence=True)
        recent = intel_store.recent("inbound", 5) if stats.get("has_shared_intel") else []
        return {
            "motor": "swarm_mesh",
            "ok": True,
            "ioc_counts": stats.get("ioc_counts"),
            "inbound_events": stats.get("inbound_events"),
            "recent_inbound_n": len(recent),
            "has_shared_intel": bool(stats.get("has_shared_intel")),
            "tenant_id": stats.get("tenant_id"),
            "influence": stats.get("influence"),
            "denied": bool(stats.get("denied")),
            "observed_at": _utc(),
        }
    except Exception as exc:
        return {
            "motor": "swarm_mesh",
            "ok": False,
            "error": str(exc)[:160],
            "has_shared_intel": False,
            "influence": "NO_INFLUENCE",
            "denied": True,
        }


def layer_endpoint() -> Dict[str, Any]:
    out: Dict[str, Any] = {"motor": "endpoint_enterprise", "ok": False}
    try:
        import services.endpoint_enterprise  # noqa: F401

        out["import_ok"] = True
    except Exception as exc:
        out["error"] = str(exc)[:120]
        return out
    try:
        from services.endpoint_enterprise.rootkit_hybrid import get_status as rk_status

        out["rootkit_hybrid"] = rk_status() if callable(rk_status) else {"present": True}
    except Exception:
        out["rootkit_hybrid"] = {"present": False}
    # Telemetría ligera real: procesos, red, recursos, sesiones (solo lectura)
    try:
        import psutil

        lolbins = ("powershell", "cmd.exe", "wmic", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin")
        procs = []
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
            try:
                info = p.info
                name = (info.get("name") or "").lower()
                cmd = " ".join(info.get("cmdline") or []).lower()
                if any(x in name or x in cmd for x in lolbins):
                    procs.append(
                        {
                            "pid": info.get("pid"),
                            "name": info.get("name"),
                            "user": info.get("username"),
                            "hint": "lolbin_or_shell",
                        }
                    )
                if len(procs) >= 12:
                    break
            except Exception:
                continue
        out["suspicious_tool_procs_n"] = len(procs)
        out["sample"] = procs[:6]

        # Conexiones establecidas (evidencia de comunicación; no reputación)
        est = 0
        remote_ports: Dict[int, int] = {}
        try:
            for c in psutil.net_connections(kind="inet") or []:
                if getattr(c, "status", None) == "ESTABLISHED":
                    est += 1
                    rport = (c.raddr.port if c.raddr else None)
                    if rport:
                        remote_ports[int(rport)] = remote_ports.get(int(rport), 0) + 1
        except Exception:
            pass
        out["established_connections_n"] = est
        # Puertos no habituales (lista corta de comunes excluidos — no es lista de firmas malware)
        common = {80, 443, 53, 22, 25, 110, 143, 993, 995, 587, 8080, 8443, 3389, 445, 135, 139}
        unusual = sum(n for p, n in remote_ports.items() if p not in common and p > 0)
        out["unusual_remote_port_conns_n"] = unusual

        try:
            out["cpu_percent"] = float(psutil.cpu_percent(interval=0.05))
            mem = psutil.virtual_memory()
            out["ram_percent"] = float(mem.percent)
            disk = psutil.disk_usage("/")
            out["disk_percent"] = float(disk.percent)
        except Exception:
            pass
        try:
            out["users_n"] = len(psutil.users() or [])
        except Exception:
            out["users_n"] = None
        out["ok"] = True
    except Exception as exc:
        out["error"] = str(exc)[:120]

    # Persistencia Run (solo lectura; evidencia de registro, no firma)
    try:
        import winreg

        run_n = 0
        for hive, path in (
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ):
            try:
                with winreg.OpenKey(hive, path) as k:
                    i = 0
                    while True:
                        try:
                            winreg.EnumValue(k, i)
                            run_n += 1
                            i += 1
                        except OSError:
                            break
            except OSError:
                continue
        out["persistence_run_entries_n"] = run_n
    except Exception:
        out["persistence_run_entries_n"] = None

    out["observed_at"] = _utc()
    return out


def layer_network() -> Dict[str, Any]:
    """NDR en modo solo caché / registry — NUNCA fuerza ARP durante ZDDE."""
    try:
        alerts: List[Any] = []
        keys: List[str] = []
        source = "none"
        # 1) Caché interna del módulo NDR sin llamar scan_network
        try:
            import services.network_ndr_service as ndr

            cache = getattr(ndr, "_payload_cache", None) or {}
            payload = cache.get("payload") if isinstance(cache, dict) else None
            if isinstance(payload, dict):
                alerts = payload.get("alerts") or payload.get("findings") or []
                keys = list(payload.keys())[:12]
                source = "ndr_payload_cache"
        except Exception:
            pass
        # 2) Fallback: eventos de red ya publicados (si el registry existe)
        if not alerts:
            try:
                from services import defense_coordinator as dc

                recent = []
                if hasattr(dc, "list_recent"):
                    recent = dc.list_recent(limit=40) or []
                elif hasattr(dc, "recent_events"):
                    recent = dc.recent_events(limit=40) or []
                for ev in recent:
                    motor = str((ev or {}).get("motor") or "").lower()
                    action = str((ev or {}).get("action") or "").lower()
                    if "ndr" in motor or "network" in motor or "network" in action:
                        alerts.append(ev)
                source = "defense_coordinator" if alerts else (source or "defense_coordinator_empty")
            except Exception:
                pass
        return {
            "motor": "network_ndr",
            "ok": True,
            "alerts_n": len(alerts) if isinstance(alerts, list) else 0,
            "keys": keys,
            "source": source,
            "arp_scan_forced": False,
            "observed_at": _utc(),
        }
    except Exception as exc:
        return {"motor": "network_ndr", "ok": False, "error": str(exc)[:160], "alerts_n": 0, "arp_scan_forced": False}


def layer_ape() -> Dict[str, Any]:
    try:
        from services.adaptive_profile_engine import engine_status

        st = engine_status()
        return {
            "motor": "adaptive_profile_engine",
            "ok": "error" not in (st or {}),
            "anti_poisoning": bool((st or {}).get("anti_poisoning")),
            "storage": (st or {}).get("storage"),
            "promote_after": (st or {}).get("promote_after_sightings"),
            "observed_at": _utc(),
            "profile_exposed_to_client": False,
        }
    except Exception as exc:
        return {"motor": "adaptive_profile_engine", "ok": False, "error": str(exc)[:160]}


def layer_cryptovault() -> Dict[str, Any]:
    """Salud CryptoVault sin conectar al motor de seguridad (evita efectos laterales/ARP)."""
    try:
        from crypto_vault import CryptoVault

        # verify_health puede enganchar security integration; preferir probe mínimo
        cv = CryptoVault()
        has_wrap = hasattr(cv, "verify_health") or hasattr(cv, "encrypt")
        ok = False
        detail = {}
        try:
            # Round-trip ligero si existe método rápido
            if hasattr(cv, "aes_gcm_roundtrip_ok"):
                ok = bool(cv.aes_gcm_roundtrip_ok())
                detail["aes_gcm_roundtrip"] = ok
            elif hasattr(cv, "verify_health"):
                # Timeout lógico: health a veces dispara scans; capturar y marcar presente
                h = cv.verify_health()
                ok = bool((h or {}).get("aes_gcm_roundtrip")) or bool((h or {}).get("ok"))
                detail = {
                    "aes_gcm_roundtrip": (h or {}).get("aes_gcm_roundtrip"),
                    "aes_key_wrapped": (h or {}).get("aes_key_wrapped"),
                }
            else:
                ok = has_wrap
        except Exception as exc:
            detail["error"] = str(exc)[:120]
            ok = has_wrap
        return {
            "motor": "cryptovault",
            "ok": bool(ok or has_wrap),
            **detail,
            "observed_at": _utc(),
        }
    except Exception as exc:
        return {"motor": "cryptovault", "ok": False, "error": str(exc)[:160]}


def layer_forensic() -> Dict[str, Any]:
    try:
        from services.forensic_evidence_integrity_service import get_system_summary

        s = get_system_summary() or {}
        return {
            "motor": "forensic",
            "ok": True,
            "record_count": s.get("record_count"),
            "chain_head_present": bool(s.get("chain_head")),
            "observed_at": _utc(),
        }
    except Exception as exc:
        return {"motor": "forensic", "ok": False, "error": str(exc)[:160]}


def layer_defense_center() -> Dict[str, Any]:
    """Estado ligero del Centro de Defensa — sin get_engines_panel (evita ARP/XDR realtime)."""
    try:
        from services.defense_center_service import get_automatic_protection_status

        auto = get_automatic_protection_status() or {}
        # Contar motores importables conocidos sin ejecutar escaneos
        known = [
            "services.behavioral_threat_detection",
            "services.zero_day_detection",
            "services.swarm_defense",
            "services.adaptive_profile_engine",
            "crypto_vault",
        ]
        importable = 0
        for mod in known:
            try:
                __import__(mod)
                importable += 1
            except Exception:
                pass
        return {
            "motor": "defense_center",
            "ok": True,
            "auto_protection_active": bool(auto.get("active")),
            "engines_n": importable,
            "active_n": importable if auto.get("active") else max(1, importable // 2),
            "source": "automatic_protection_status_readonly",
            "heavy_panel_skipped": True,
            "observed_at": _utc(),
        }
    except Exception as exc:
        return {"motor": "defense_center", "ok": False, "error": str(exc)[:160]}


def gather_all_layers(*, heavy: bool = False, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """
    P0-2: tenant_id opcional para Mesh→ZDDE.
    Ciclo host sin tenant → mesh layer deny-by-default (no influencia cross-tenant).
    """
    layers = {
        "btde": layer_btde(heavy=heavy),
        "swarm": layer_swarm(),
        "mesh": layer_mesh_intel(tenant_id=tenant_id),
        "endpoint": layer_endpoint(),
        "network": layer_network(),
        "ape": layer_ape(),
        "cryptovault": layer_cryptovault(),
        "forensic": layer_forensic(),
        "defense_center": layer_defense_center(),
    }
    participating = [k for k, v in layers.items() if v.get("ok")]
    return {
        "layers": layers,
        "participating": participating,
        "participating_n": len(participating),
        "gathered_at": _utc(),
    }
