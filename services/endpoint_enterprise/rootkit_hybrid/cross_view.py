"""
T1–T3 — Cross-view: procesos, servicios, módulos, sesiones, usuarios, conexiones.
"""
from __future__ import annotations

import platform
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from utils.logger import logger

# SERVICE_* Type bits (winnt.h) — solo Win32 cuentan para SCM vs registro
_SERVICE_KERNEL_DRIVER = 0x00000001
_SERVICE_FILE_SYSTEM_DRIVER = 0x00000002
_SERVICE_WIN32_OWN = 0x00000010
_SERVICE_WIN32_SHARE = 0x00000020


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_win32_service_type(stype: Any) -> bool:
    try:
        t = int(stype)
    except (TypeError, ValueError):
        return False
    if t & (_SERVICE_KERNEL_DRIVER | _SERVICE_FILE_SYSTEM_DRIVER):
        return False
    return bool(t & (_SERVICE_WIN32_OWN | _SERVICE_WIN32_SHARE))


def _finding(
    ftype: str,
    *,
    severity: str,
    confidence: str,
    evidence: dict,
    detection_method: str,
) -> Dict[str, Any]:
    return {
        "finding_type": ftype,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "detection_method": detection_method,
        "equipment": socket.gethostname(),
        "timestamp_utc": _utc(),
        "verified": True,
        "source": "rootkit_hybrid.cross_view",
        "ring0": False,
    }


def collect_process_views() -> Dict[str, Any]:
    """Tres vistas user-mode: psutil, Win32_Process (CIM), tasklist."""
    views: Dict[str, Set[int]] = {"psutil": set(), "wmi": set(), "tasklist": set()}
    detail: Dict[int, Dict[str, Any]] = {}

    try:
        for p in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                pid = int(p.info["pid"])
                views["psutil"].add(pid)
                detail[pid] = {
                    "pid": pid,
                    "name": p.info.get("name"),
                    "path": p.info.get("exe"),
                    "user": p.info.get("username"),
                    "seen_in": ["psutil"],
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
                continue
    except Exception as exc:
        logger.debug("psutil view: %s", exc)

    if platform.system() == "Windows":
        try:
            out = subprocess.check_output(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "Get-CimInstance Win32_Process | "
                        "Select-Object ProcessId,Name,ExecutablePath | ConvertTo-Json -Compress"
                    ),
                ],
                timeout=25,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            import json

            raw = (out or "").strip()
            if raw:
                data = json.loads(raw)
                rows = data if isinstance(data, list) else [data]
                for r in rows:
                    try:
                        pid = int(r.get("ProcessId"))
                    except (TypeError, ValueError):
                        continue
                    views["wmi"].add(pid)
                    d = detail.setdefault(pid, {"pid": pid, "seen_in": []})
                    d.setdefault("seen_in", []).append("wmi")
                    d["name"] = d.get("name") or r.get("Name")
                    d["path"] = d.get("path") or r.get("ExecutablePath")
        except Exception as exc:
            logger.debug("wmi view: %s", exc)

        try:
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                timeout=20,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            for line in out.splitlines():
                # "name","pid","session","session#","mem"
                parts = [p.strip().strip('"') for p in line.split(",")]
                if len(parts) >= 2 and parts[1].isdigit():
                    pid = int(parts[1])
                    views["tasklist"].add(pid)
                    d = detail.setdefault(pid, {"pid": pid, "name": parts[0], "seen_in": []})
                    if "tasklist" not in d["seen_in"]:
                        d["seen_in"].append("tasklist")
                    d["name"] = d.get("name") or parts[0]
        except Exception as exc:
            logger.debug("tasklist view: %s", exc)

    return {"views": {k: sorted(v) for k, v in views.items()}, "detail": detail, "counts": {k: len(v) for k, v in views.items()}}


def _pid_alive_in_psutil(pid: int) -> bool:
    try:
        return psutil.pid_exists(pid) and psutil.Process(pid).is_running()
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
        return False


def find_hidden_process_candidates(proc_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Proceso en ≥2 vistas OS pero ausente en psutil tras reconfirmación.
    Evita carreras temporales (NO falsos positivos por timing).
    """
    views = {k: set(v) for k, v in (proc_data.get("views") or {}).items()}
    detail = proc_data.get("detail") or {}
    findings = []
    if not views.get("wmi") and not views.get("tasklist"):
        return findings

    # Candidatos: en WMI y tasklist, no en psutil (doble fuente OS) — único path actionable
    dual = (views.get("wmi", set()) & views.get("tasklist", set())) - views.get("psutil", set())

    candidates: List[Tuple[int, str, str]] = []
    for pid in sorted(dual)[:20]:
        candidates.append((pid, "high", "cross_view_wmi_and_tasklist_minus_psutil"))

    # Reconfirmación tras breve espera — descarta carreras temporales
    if candidates:
        time.sleep(0.4)
        try:
            ps2 = {int(p.pid) for p in psutil.process_iter(["pid"])}
        except Exception:
            ps2 = set()
        confirmed = []
        for pid, conf, method in candidates:
            if pid in ps2 or _pid_alive_in_psutil(pid):
                continue
            confirmed.append((pid, conf, method))
        candidates = confirmed

    for pid, conf, method in candidates:
        info = detail.get(pid) or {"pid": pid}
        findings.append(
            _finding(
                "hidden_process_candidate",
                severity="high",
                confidence=conf,
                detection_method=method,
                evidence={
                    "pid": pid,
                    "process": info.get("name"),
                    "path": info.get("path"),
                    "user": info.get("user"),
                    "seen_in": info.get("seen_in"),
                    "missing_from": ["psutil"],
                    "reconfirmed": True,
                    "note": "Visible en WMI+tasklist, ausente en psutil tras re-muestreo",
                },
            )
        )

    # Large discrepancy psutil-only (timing noise filtered)
    only_ps = views.get("psutil", set()) - views.get("wmi", set()) - views.get("tasklist", set())
    if views.get("wmi") and len(only_ps) > 12:
        findings.append(
            _finding(
                "process_view_skew",
                severity="low",
                confidence="low",
                detection_method="cross_view_psutil_only_count",
                evidence={
                    "psutil_only_count": len(only_ps),
                    "sample_pids": sorted(only_ps)[:15],
                    "note": "Puede ser timing/privilegios; no prueba rootkit solo",
                },
            )
        )
    return findings


def _normalize_service_name(name: str) -> str:
    """Per-user services: AarSvc_1a2b3c4d → aarsvc."""
    n = (name or "").lower().strip()
    if "_" in n:
        base, suf = n.rsplit("_", 1)
        if suf and all(c in "0123456789abcdef" for c in suf) and len(suf) >= 4:
            return base
    return n


def collect_service_views() -> Dict[str, Any]:
    """SCM (psutil) vs registro CurrentControlSet\\Services."""
    scm: Set[str] = set()
    scm_raw: Set[str] = set()
    scm_running: Set[str] = set()
    registry: Set[str] = set()
    reg_start: Dict[str, Any] = {}

    if hasattr(psutil, "win_service_iter"):
        try:
            for s in psutil.win_service_iter():
                try:
                    raw = s.name().lower()
                    scm_raw.add(raw)
                    name = _normalize_service_name(raw)
                    scm.add(name)
                    if s.status() == "running":
                        scm_running.add(name)
                except Exception:
                    continue
        except Exception as exc:
            logger.debug("scm services: %s", exc)

    if platform.system() == "Windows":
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services",
            )
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(key, i).lower()
                    i += 1
                    registry.add(name)
                    try:
                        sk = winreg.OpenKey(key, name)
                        start = None
                        stype = None
                        image = None
                        try:
                            start, _ = winreg.QueryValueEx(sk, "Start")
                        except OSError:
                            pass
                        try:
                            stype, _ = winreg.QueryValueEx(sk, "Type")
                        except OSError:
                            pass
                        try:
                            image, _ = winreg.QueryValueEx(sk, "ImagePath")
                        except OSError:
                            pass
                        reg_start[name] = {
                            "start": start,
                            "type": stype,
                            "image_path": image,
                            "win32": _is_win32_service_type(stype),
                        }
                        winreg.CloseKey(sk)
                    except OSError:
                        pass
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception as exc:
            logger.debug("registry services: %s", exc)

    return {
        "scm": sorted(scm),
        "scm_raw": sorted(scm_raw),
        "scm_running": sorted(scm_running),
        "registry": sorted(registry),
        "registry_meta": reg_start,
        "counts": {
            "scm": len(scm),
            "scm_raw": len(scm_raw),
            "scm_running": len(scm_running),
            "registry": len(registry),
        },
    }


def find_service_inconsistencies(svc: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    scm = set(svc.get("scm") or [])
    registry = set(svc.get("registry") or [])
    running = set(svc.get("scm_running") or [])
    meta = svc.get("registry_meta") or {}

    # Running in SCM but no registry key (very suspicious if true)
    for name in sorted(running - registry)[:20]:
        findings.append(
            _finding(
                "hidden_service_candidate",
                severity="high",
                confidence="high",
                detection_method="scm_running_missing_registry",
                evidence={"service": name, "missing_from": ["registry"], "note": "Servicio running sin clave de registro"},
            )
        )

    # Solo Win32 no normalizados en SCM (ni instancia per-user AarSvc_xxxx)
    for name in sorted(registry - scm):
        m = meta.get(name) or {}
        if not m.get("win32"):
            continue
        start = m.get("start")
        if start not in (2, 3) or not m.get("image_path"):
            continue
        # También presente como instancia sufijada en scm_raw
        raw = set(svc.get("scm_raw") or [])
        if any(r == name or r.startswith(name + "_") for r in raw):
            continue
        findings.append(
            _finding(
                "service_registry_not_in_scm",
                severity="medium",
                confidence="medium",
                detection_method="registry_win32_minus_scm",
                evidence={
                    "service": name,
                    "start": start,
                    "type": m.get("type"),
                    "image_path": m.get("image_path"),
                    "missing_from": ["scm"],
                    "note": "Servicio Win32 en registro no listado por SCM/psutil (ni instancia per-user)",
                },
            )
        )
        if len([f for f in findings if f.get("finding_type") == "service_registry_not_in_scm"]) >= 15:
            break
    return findings


def collect_sessions_users_conns() -> Dict[str, Any]:
    users = []
    try:
        for u in psutil.users():
            users.append({"name": u.name, "terminal": getattr(u, "terminal", None), "started": getattr(u, "started", None)})
    except Exception:
        pass
    conns = 0
    try:
        conns = len(psutil.net_connections(kind="inet"))
    except Exception:
        pass
    return {"users": users, "users_n": len(users), "connections_n": conns}


def run_cross_view() -> Dict[str, Any]:
    proc = collect_process_views()
    svc = collect_service_views()
    sess = collect_sessions_users_conns()
    findings = []
    findings.extend(find_hidden_process_candidates(proc))
    findings.extend(find_service_inconsistencies(svc))
    return {
        "ok": True,
        "processes": {"counts": proc.get("counts"), "views_available": list((proc.get("views") or {}).keys())},
        "services": svc.get("counts"),
        "sessions": sess,
        "findings": findings,
        "timestamp_utc": _utc(),
    }
