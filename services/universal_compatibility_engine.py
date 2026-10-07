"""
Universal Compatibility Engine (UCE) — detección automática de infraestructura.

Reutiliza motores existentes de NOVUS (platform_metrics, network_scanner,
novus_security, psutil, config). No modifica la infraestructura del cliente.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

from services.telemetry_resolver import explain, network_nodes

NO_DATA = "Sin datos disponibles"
UCE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "uce")
STATE_FILE = os.path.join(UCE_DIR, "detection.json")
HISTORY_FILE = os.path.join(UCE_DIR, "history.jsonl")

INFRA_CATEGORIES = (
    "sistema_operativo",
    "contenedores",
    "orquestacion",
    "bases_datos",
    "productividad",
    "nube",
    "virtualizacion",
    "firewall",
    "almacenamiento",
    "apis",
    "aplicaciones_empresariales",
    "red",
)


def _ensure_dirs() -> None:
    os.makedirs(UCE_DIR, exist_ok=True)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _load_state() -> Dict[str, Any]:
    _ensure_dirs()
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_state(payload: Dict[str, Any]) -> None:
    _ensure_dirs()
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


def _append_history(record: Dict[str, Any]) -> None:
    _ensure_dirs()
    record.setdefault("timestamp", _now())
    with open(HISTORY_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def _running_process_names() -> List[str]:
    names: List[str] = []
    try:
        import psutil
        for proc in psutil.process_iter(["name"]):
            try:
                n = (proc.info.get("name") or "").lower()
                if n:
                    names.append(n)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as exc:
        logger.debug("UCE process scan: %s", exc)
    return names


def _open_ports() -> List[int]:
    ports: List[int] = []
    try:
        from services.novus_security_integration import novus_security
        cache = novus_security._threat_cache or {}
        for item in cache.get("open_ports") or []:
            p = item.get("port") if isinstance(item, dict) else item
            try:
                ports.append(int(p))
            except (TypeError, ValueError):
                continue
    except Exception as exc:
        logger.debug("UCE open ports cache: %s", exc)

    if not ports:
        try:
            from services.novus_security_integration import novus_security
            novus_security.detect_threats_realtime(force=True)
            cache = novus_security._threat_cache or {}
            for item in cache.get("open_ports") or []:
                p = item.get("port") if isinstance(item, dict) else item
                try:
                    ports.append(int(p))
                except (TypeError, ValueError):
                    continue
        except Exception as exc:
            logger.debug("UCE security rescan ports: %s", exc)

    if not ports:
        try:
            import psutil
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN" and conn.lport:
                    ports.append(int(conn.lport))
        except Exception as exc:
            logger.debug("UCE psutil ports: %s", exc)
    return sorted(set(ports))


def _detect_os() -> Dict[str, Any]:
    system = platform.system()
    release = platform.release()
    machine = platform.machine()
    version = platform.version()
    detected = bool(system)
    return {
        "id": system.lower() if system else "unknown",
        "label": f"{system} {release}".strip() if system else NO_DATA,
        "detected": detected,
        "evidence": {
            "system": system or NO_DATA,
            "release": release or NO_DATA,
            "machine": machine or NO_DATA,
            "version": (version or "")[:120] or NO_DATA,
        },
        "compatible_modules": _modules_for_os(system),
    }


def _modules_for_os(system: str) -> List[str]:
    s = (system or "").lower()
    if s == "windows":
        return ["ransom_sentinel", "advanced_detector", "network_scanner"]
    if s == "linux":
        return ["network_scanner", "iot_guard", "mitm_shield"]
    if s == "darwin":
        return ["ui_shield", "runtime_integrity", "network_scanner"]
    return ["network_scanner", "cryptovault"]


def _detect_containers(processes: List[str]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    docker_procs = [p for p in processes if "docker" in p]
    if docker_procs or shutil.which("docker"):
        items.append({
            "id": "docker",
            "label": "Docker",
            "detected": True,
            "evidence": {"processes": docker_procs[:5], "cli": bool(shutil.which("docker"))},
            "compatible_modules": ["network_scanner", "api_shield", "sqli_shield"],
        })
    podman = [p for p in processes if "podman" in p]
    if podman or shutil.which("podman"):
        items.append({
            "id": "podman",
            "label": "Podman",
            "detected": True,
            "evidence": {"processes": podman[:3], "cli": bool(shutil.which("podman"))},
            "compatible_modules": ["network_scanner", "api_shield"],
        })
    return items


def _detect_orchestration(processes: List[str]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    k8s_env = os.environ.get("KUBERNETES_SERVICE_HOST")
    kubeconfig = os.path.expanduser("~/.kube/config")
    kubectl = shutil.which("kubectl")
    k8s_procs = [p for p in processes if any(k in p for k in ("kube", "k8s"))]
    if k8s_env or os.path.exists(kubeconfig) or kubectl or k8s_procs:
        items.append({
            "id": "kubernetes",
            "label": "Kubernetes",
            "detected": True,
            "evidence": {
                "env_kubernetes": bool(k8s_env),
                "kubeconfig": os.path.exists(kubeconfig),
                "kubectl": bool(kubectl),
                "processes": k8s_procs[:5],
            },
            "compatible_modules": ["network_scanner", "api_shield", "mitm_shield", "iot_guard"],
        })
    return items


def _detect_databases(ports: List[int]) -> List[Dict[str, Any]]:
    mapping = {
        5432: ("postgresql", "PostgreSQL", ["sqli_shield", "api_shield"]),
        3306: ("mysql", "MySQL", ["sqli_shield", "api_shield"]),
        1433: ("sqlserver", "SQL Server", ["sqli_shield", "api_shield"]),
        27017: ("mongodb", "MongoDB", ["sqli_shield", "api_shield"]),
        6379: ("redis", "Redis", ["api_shield", "network_scanner"]),
    }
    items: List[Dict[str, Any]] = []
    for port, (tid, label, modules) in mapping.items():
        if port in ports:
            items.append({
                "id": tid,
                "label": label,
                "detected": True,
                "evidence": {"port": port, "source": "open_ports_scan"},
                "compatible_modules": modules,
            })
    return items


def _detect_productivity() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        from services.config_service import load_config
        cfg = load_config()
        gmail = cfg.get("gmail_oauth") or cfg.get("gmail") or {}
        if gmail.get("enabled") or gmail.get("client_id"):
            items.append({
                "id": "google_workspace",
                "label": "Google Workspace / Gmail",
                "detected": True,
                "evidence": {"config_key": "gmail_oauth", "enabled": bool(gmail.get("enabled"))},
                "compatible_modules": ["phishing_shield", "bec_shield", "ato_analyzer"],
            })
        m365 = cfg.get("microsoft_365") or cfg.get("outlook") or {}
        if m365.get("enabled") or m365.get("tenant_id"):
            items.append({
                "id": "microsoft_365",
                "label": "Microsoft 365",
                "detected": True,
                "evidence": {"config_key": "microsoft_365", "enabled": bool(m365.get("enabled"))},
                "compatible_modules": ["phishing_shield", "bec_shield", "ato_analyzer"],
            })
    except Exception as exc:
        logger.debug("UCE productivity config: %s", exc)
    return items


def _detect_cloud() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    env = os.environ
    if any(k.startswith("AWS_") for k in env):
        items.append({
            "id": "aws",
            "label": "AWS",
            "detected": True,
            "evidence": {"env_vars": [k for k in env if k.startswith("AWS_")][:5]},
            "compatible_modules": ["api_shield", "network_scanner", "mitm_shield"],
        })
    if any(k.startswith("AZURE") for k in env) or env.get("AZURE_SUBSCRIPTION_ID"):
        items.append({
            "id": "azure",
            "label": "Azure",
            "detected": True,
            "evidence": {"env_vars": [k for k in env if "AZURE" in k][:5]},
            "compatible_modules": ["api_shield", "network_scanner", "ato_analyzer"],
        })
    if env.get("GOOGLE_CLOUD_PROJECT") or env.get("GCLOUD_PROJECT"):
        items.append({
            "id": "gcp",
            "label": "Google Cloud",
            "detected": True,
            "evidence": {
                "GOOGLE_CLOUD_PROJECT": env.get("GOOGLE_CLOUD_PROJECT") or env.get("GCLOUD_PROJECT"),
            },
            "compatible_modules": ["api_shield", "network_scanner"],
        })
    return items


def _detect_virtualization(processes: List[str]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    vmware = [p for p in processes if any(k in p for k in ("vmware", "vmtools", "vmusrvc"))]
    if vmware:
        items.append({
            "id": "vmware",
            "label": "VMware",
            "detected": True,
            "evidence": {"processes": vmware[:5]},
            "compatible_modules": ["network_scanner", "ransom_sentinel"],
        })
    hyperv = [p for p in processes if any(k in p for k in ("vmms", "vmcompute", "hyper-v"))]
    if hyperv or (platform.system() == "Windows" and os.path.exists(r"C:\Windows\System32\vmms.exe")):
        items.append({
            "id": "hyperv",
            "label": "Hyper-V",
            "detected": True,
            "evidence": {"processes": hyperv[:5], "vmms_exe": os.path.exists(r"C:\Windows\System32\vmms.exe")},
            "compatible_modules": ["network_scanner", "ransom_sentinel"],
        })
    return items


def _detect_firewall() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode == 0 and "ON" in (result.stdout or "").upper():
                items.append({
                    "id": "windows_firewall",
                    "label": "Windows Firewall",
                    "detected": True,
                    "evidence": {"netsh_output": (result.stdout or "")[:300]},
                    "compatible_modules": ["network_scanner", "mitm_shield", "adaptive_defense"],
                })
        except Exception as exc:
            logger.debug("UCE firewall netsh: %s", exc)
    else:
        for cmd, label in (("ufw", "UFW"), ("firewalld", "firewalld"), ("iptables", "iptables")):
            if shutil.which(cmd):
                items.append({
                    "id": cmd,
                    "label": label,
                    "detected": True,
                    "evidence": {"cli": cmd},
                    "compatible_modules": ["network_scanner", "mitm_shield"],
                })
    return items


def _detect_storage_network() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        from services.network_scanner import network_scanner
        for node in network_scanner.get_cached_nodes() or []:
            name = str(node.get("name") or node.get("hostname") or "").lower()
            vendor = str(node.get("vendor") or "").lower()
            blob = f"{name} {vendor}"
            if any(k in blob for k in ("nas", "synology", "qnap", "netapp", "storage")):
                items.append({
                    "id": f"nas_{node.get('ip', 'unknown')}",
                    "label": f"NAS / Almacenamiento ({node.get('ip') or NO_DATA})",
                    "detected": True,
                    "evidence": {"node": {k: node.get(k) for k in ("ip", "mac", "name", "vendor") if node.get(k)}},
                    "compatible_modules": ["network_scanner", "iot_guard", "ransom_sentinel"],
                })
    except Exception as exc:
        logger.debug("UCE NAS scan: %s", exc)
    return items


def _detect_apis(ports: List[int]) -> List[Dict[str, Any]]:
    api_ports = [p for p in ports if p in (80, 443, 8080, 8443, 3000, 5000, 8000)]
    if not api_ports:
        return []
    return [{
        "id": "http_apis",
        "label": "APIs / Servicios HTTP",
        "detected": True,
        "evidence": {"ports": api_ports},
        "compatible_modules": ["api_shield", "sqli_shield", "ato_analyzer"],
    }]


def _detect_enterprise_apps(processes: List[str]) -> List[Dict[str, Any]]:
    patterns = {
        "sap": ("sap", "SAP ERP"),
        "oracle": ("oracle", "Oracle ERP/DB"),
        "salesforce": ("salesforce", "Salesforce CRM"),
        "dynamics": ("dynamics", "Microsoft Dynamics"),
    }
    items: List[Dict[str, Any]] = []
    for pid, (needle, label) in patterns.items():
        matches = [p for p in processes if needle in p]
        if matches:
            items.append({
                "id": pid,
                "label": label,
                "detected": True,
                "evidence": {"processes": matches[:5]},
                "compatible_modules": ["bec_shield", "api_shield", "ato_analyzer", "sqli_shield"],
            })
    return items


def _detect_network_layer() -> Dict[str, Any]:
    endpoints = 0
    nodes = 0
    try:
        from services.platform_metrics_service import build_endpoint_inventory
        inv = build_endpoint_inventory()
        endpoints = len(inv)
    except Exception:
        pass
    try:
        from services.network_scanner import network_scanner
        nodes = len(network_scanner.get_cached_nodes() or [])
    except Exception:
        pass
    return {
        "endpoints_monitoreados": endpoints if endpoints else explain("endpoints_inventory_empty"),
        "nodos_red": network_nodes(nodes) if not nodes else nodes,
        "detected": endpoints > 0 or nodes > 0,
        "compatible_modules": ["network_scanner", "topology", "network_ndr"],
    }


def detect_infrastructure(user_email: Optional[str] = None, persist: bool = True) -> Dict[str, Any]:
    """Escaneo real de infraestructura — sin modificar el entorno."""
    processes = _running_process_names()
    ports = _open_ports()

    categories: Dict[str, Any] = {
        "sistema_operativo": _detect_os(),
        "contenedores": _detect_containers(processes),
        "orquestacion": _detect_orchestration(processes),
        "bases_datos": _detect_databases(ports),
        "productividad": _detect_productivity(),
        "nube": _detect_cloud(),
        "virtualizacion": _detect_virtualization(processes),
        "firewall": _detect_firewall(),
        "almacenamiento": _detect_storage_network(),
        "apis": _detect_apis(ports),
        "aplicaciones_empresariales": _detect_enterprise_apps(processes),
        "red": _detect_network_layer(),
    }

    detected_flat: List[Dict[str, Any]] = []
    compatible_modules: List[str] = []

    os_item = categories["sistema_operativo"]
    if os_item.get("detected"):
        detected_flat.append({"category": "sistema_operativo", **os_item})

    for cat in INFRA_CATEGORIES:
        if cat in ("sistema_operativo", "red"):
            continue
        val = categories.get(cat)
        if isinstance(val, list):
            for item in val:
                if item.get("detected"):
                    detected_flat.append({"category": cat, **item})
                    compatible_modules.extend(item.get("compatible_modules") or [])
        elif isinstance(val, dict) and val.get("detected"):
            detected_flat.append({"category": cat, **val})
            compatible_modules.extend(val.get("compatible_modules") or [])

    if categories["red"].get("detected"):
        detected_flat.append({"category": "red", "id": "red_novus", "label": "Red monitoreada NOVUS", **categories["red"]})
        compatible_modules.extend(categories["red"].get("compatible_modules") or [])

    compatible_unique = list(dict.fromkeys(compatible_modules))
    technologies = [d.get("label") for d in detected_flat if d.get("label")]

    sector_key = "otros"
    active_modules: List[str] = []
    background_modules: List[str] = []
    try:
        from services.sector_profile_service import resolve_sector_for_user
        from services.adaptive_sector_protection_engine import _priority_modules_for_sector
        sector_key = resolve_sector_for_user(user_email) if user_email else "otros"
        active_modules = _priority_modules_for_sector(sector_key, user_email)
        background_modules = [m for m in compatible_unique if m not in active_modules]
    except Exception as uce_exc:
        logger.debug("UCE sector modules: %s", uce_exc)
        active_modules = compatible_unique[:6]

    payload = {
        "motor": "Universal Compatibility Engine",
        "status": "success",
        "detected_at": _now(),
        "user_email": user_email,
        "sector_key": sector_key,
        "technologies_count": len(detected_flat),
        "technologies": technologies,
        "detected_items": detected_flat,
        "categories": categories,
        "compatible_modules": compatible_unique,
        "active_modules": active_modules,
        "background_modules": background_modules,
        "open_ports_sample": ports[:20] if ports else [],
        "sources": [
            "platform", "psutil", "novus_security._threat_cache",
            "network_scanner", "config_service", "platform_metrics_service",
        ],
    }

    if persist:
        _save_state(payload)
        _append_history({
            "event": "uce_scan",
            "technologies_count": len(detected_flat),
            "technologies": technologies[:15],
            "user_email": user_email,
        })
        try:
            from services.defense_coordinator import defense_coordinator

            defense_coordinator.record_detection(
                "universal_compatibility_engine",
                "infra_detect",
                {
                    "technologies_count": len(detected_flat),
                    "active_modules": active_modules,
                    "background_modules": background_modules[:10],
                    "sector_key": sector_key,
                },
                phase="audit",
                outcome="success",
                detail=f"UCE detectó {len(detected_flat)} tecnologías",
                confidence="Alta" if detected_flat else "Media",
                user_email=user_email,
            )
        except Exception as uce_reg_exc:
            logger.debug("UCE defense registry: %s", uce_reg_exc)

    return payload


def get_infrastructure_panel(user_email: Optional[str] = None) -> Dict[str, Any]:
    """Panel para dashboard/intel — usa caché reciente o escanea."""
    state = _load_state()
    if state.get("detected_at"):
        try:
            ts = datetime.strptime(state["detected_at"], "%Y-%m-%d %H:%M:%S")
            age_min = (datetime.now() - ts).total_seconds() / 60
            if age_min < 30:
                return state
        except Exception:
            pass
    return detect_infrastructure(user_email=user_email, persist=True)


def recommend_modules_for_otros_sector(user_email: Optional[str] = None) -> List[str]:
    """Prioridad de módulos para sector Otros según infraestructura detectada."""
    infra = get_infrastructure_panel(user_email)
    modules = list(infra.get("compatible_modules") or [])
    if not modules:
        return ["network_scanner", "cryptovault", "sqli_shield", "ransom_sentinel"]
    defaults = ["cryptovault", "network_scanner", "adaptive_defense"]
    return list(dict.fromkeys(modules + defaults))[:8]


def generate_compatibility_audit(user_email: Optional[str] = None) -> Dict[str, Any]:
    """Informe de compatibilidad UCE para auditoría."""
    infra = detect_infrastructure(user_email=user_email, persist=True)
    detected = infra.get("detected_items") or []
    strengths = []
    limitations = []
    if detected:
        strengths.append(f"{len(detected)} tecnología(s) identificada(s) con evidencia real")
    else:
        limitations.append("Sin tecnologías adicionales detectadas en este host — escaneo de red pendiente")
    if not infra.get("open_ports_sample"):
        limitations.append("Puertos abiertos no disponibles hasta ejecutar escaneo de seguridad NOVUS")
    os_ev = (infra.get("categories") or {}).get("sistema_operativo", {})
    if os_ev.get("detected"):
        strengths.append(f"Sistema operativo: {os_ev.get('label')}")

    return {
        "motor": "Universal Compatibility Engine",
        "generated_at": _now(),
        "tecnologias_detectadas": infra.get("technologies") or [],
        "items": detected,
        "modulos_compatibles": infra.get("compatible_modules") or [],
        "compatibilidad_lograda_pct": round(
            min(100, len(detected) * 12 + len(infra.get("compatible_modules") or []) * 5), 1
        ),
        "fortalezas": strengths,
        "limitaciones": limitations,
        "oportunidades": [
            "Ejecutar escaneo completo NOVUS para enriquecer puertos y amenazas",
            "Conectar OAuth Gmail/Microsoft para detección productividad",
            "Activar Network Radar para inventario LAN extendido",
        ],
    }


class UniversalCompatibilityEngine:
    detect_infrastructure = staticmethod(detect_infrastructure)
    get_infrastructure_panel = staticmethod(get_infrastructure_panel)
    recommend_modules_for_otros_sector = staticmethod(recommend_modules_for_otros_sector)
    generate_compatibility_audit = staticmethod(generate_compatibility_audit)


uce = UniversalCompatibilityEngine()
