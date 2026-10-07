"""
Baseline BTDE — host-global (proc/servicios OS) + tenant-scoped (remotes/aprendizaje).

Clasificación:
- GLOBAL DEL HOST: proc_names, services (telemetría del nodo)
- ESPECÍFICO DEL TENANT: remotes, warm_cycles (aprendizaje por cliente monitorizado)
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Set

_lock = threading.Lock()
_prev: Optional[Dict[str, Any]] = None
_seen_proc_names: Set[str] = set()
_seen_services: Set[str] = set()
_tenant_remotes: Dict[str, Set[str]] = {}
_tenant_warm_cycles: Dict[str, int] = {}
_active_tenant_id: Optional[str] = None

_ROOT = Path(__file__).resolve().parents[2] / "data" / "behavioral_threat_detection"
_LEGACY_CACHE = _ROOT / "baseline_cache.json"
_HOST_CACHE = _ROOT / "host_baseline.json"
_TENANT_DIR = _ROOT / "tenant_baselines"


def _ensure_dir() -> None:
    _ROOT.mkdir(parents=True, exist_ok=True)
    _TENANT_DIR.mkdir(parents=True, exist_ok=True)


def _safe_tid(tenant_id: str) -> str:
    from services.tenant_isolation_service import sanitize_tenant_id_for_path
    return sanitize_tenant_id_for_path(tenant_id)


def _tenant_cache_path(tenant_id: str) -> Path:
    return _TENANT_DIR / f"{_safe_tid(tenant_id)}.json"


def _default_platform_tenant() -> str:
    from services.tenant_scope_service import get_platform_tenant_id
    return get_platform_tenant_id()


def _migrate_legacy_if_needed() -> None:
    if not _LEGACY_CACHE.is_file() or _HOST_CACHE.is_file():
        return
    try:
        data = json.loads(_LEGACY_CACHE.read_text(encoding="utf-8"))
        host_payload = {
            "scope": "HOST_GLOBAL",
            "proc_names": data.get("proc_names") or [],
            "services": data.get("services") or [],
        }
        _HOST_CACHE.write_text(json.dumps(host_payload, ensure_ascii=False), encoding="utf-8")
        tid = _default_platform_tenant()
        tenant_payload = {
            "scope": "TENANT",
            "tenant_id": tid,
            "remotes": data.get("remotes") or [],
            "warm_cycles": int(data.get("warm_cycles") or 0),
            "migration_source": "baseline_cache.json",
        }
        _tenant_cache_path(tid).write_text(json.dumps(tenant_payload, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def load_baseline(tenant_id: Optional[str] = None) -> None:
    global _seen_proc_names, _seen_services, _tenant_remotes, _tenant_warm_cycles, _active_tenant_id
    _ensure_dir()
    _migrate_legacy_if_needed()
    tid = tenant_id or _default_platform_tenant()
    with _lock:
        _active_tenant_id = tid
        _seen_proc_names = set()
        _seen_services = set()
        if _HOST_CACHE.exists():
            try:
                host = json.loads(_HOST_CACHE.read_text(encoding="utf-8"))
                _seen_proc_names = set(host.get("proc_names") or [])
                _seen_services = set(host.get("services") or [])
            except Exception:
                pass
        elif _LEGACY_CACHE.exists():
            try:
                data = json.loads(_LEGACY_CACHE.read_text(encoding="utf-8"))
                _seen_proc_names = set(data.get("proc_names") or [])
                _seen_services = set(data.get("services") or [])
            except Exception:
                pass
        tpath = _tenant_cache_path(tid)
        if tpath.exists():
            try:
                tdata = json.loads(tpath.read_text(encoding="utf-8"))
                _tenant_remotes[tid] = set(tdata.get("remotes") or [])
                _tenant_warm_cycles[tid] = int(tdata.get("warm_cycles") or 0)
            except Exception:
                _tenant_remotes.setdefault(tid, set())
                _tenant_warm_cycles.setdefault(tid, 0)
        else:
            _tenant_remotes.setdefault(tid, set())
            _tenant_warm_cycles.setdefault(tid, 0)


def _save_host_baseline() -> None:
    _ensure_dir()
    payload = {
        "scope": "HOST_GLOBAL",
        "proc_names": sorted(_seen_proc_names)[:2000],
        "services": sorted(_seen_services)[:2000],
    }
    _HOST_CACHE.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _save_tenant_baseline(tenant_id: str) -> None:
    _ensure_dir()
    remotes = _tenant_remotes.get(tenant_id) or set()
    warm = int(_tenant_warm_cycles.get(tenant_id) or 0)
    payload = {
        "scope": "TENANT",
        "tenant_id": tenant_id,
        "remotes": sorted(remotes)[:1500],
        "warm_cycles": warm,
    }
    _tenant_cache_path(tenant_id).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def save_baseline(tenant_id: Optional[str] = None) -> None:
    tid = tenant_id or _active_tenant_id or _default_platform_tenant()
    with _lock:
        try:
            _save_host_baseline()
            _save_tenant_baseline(tid)
        except Exception:
            pass


def get_baseline_view(tenant_id: str) -> Dict[str, Any]:
    """Vista de baseline para un tenant — usado en pruebas de aislamiento."""
    load_baseline(tenant_id)
    with _lock:
        return {
            "tenant_id": tenant_id,
            "host_proc_names_n": len(_seen_proc_names),
            "host_services_n": len(_seen_services),
            "tenant_remotes_n": len(_tenant_remotes.get(tenant_id) or set()),
            "tenant_warm_cycles": int(_tenant_warm_cycles.get(tenant_id) or 0),
            "tenant_remotes_sample": sorted(_tenant_remotes.get(tenant_id) or set())[:5],
        }


def get_prev_snapshot() -> Optional[Dict[str, Any]]:
    with _lock:
        return dict(_prev) if _prev else None


def update_from_snapshot(snap: Dict[str, Any], *, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """Actualiza baseline host + tenant; retorna meta de aprendizaje (interno)."""
    global _prev, _active_tenant_id, _seen_proc_names, _seen_services
    tid = tenant_id or _active_tenant_id or _default_platform_tenant()
    procs = snap.get("processes") or {}
    svcs = snap.get("services") or {}
    conns = snap.get("connections") or {}
    with _lock:
        _active_tenant_id = tid
        seen_remotes = _tenant_remotes.setdefault(tid, set())
        warm_cycles = int(_tenant_warm_cycles.get(tid) or 0)

        new_procs = set(procs.get("names") or []) - _seen_proc_names
        new_svcs = set(svcs.get("running") or []) - _seen_services
        remotes = set(conns.get("remotes") or [])
        new_remotes = remotes - seen_remotes

        _seen_proc_names |= set(procs.get("names") or [])
        _seen_services |= set(svcs.get("running") or [])
        if warm_cycles >= 1:
            seen_remotes |= remotes
        elif remotes:
            seen_remotes |= remotes
        _tenant_remotes[tid] = seen_remotes

        warm_before = warm_cycles
        warm_cycles += 1
        _tenant_warm_cycles[tid] = warm_cycles
        _prev = snap
        meta = {
            "tenant_id": tid,
            "warm_cycles": warm_cycles,
            "was_cold": warm_before == 0,
            "new_proc_names": sorted(new_procs)[:30],
            "new_services": sorted(new_svcs)[:30],
            "new_remotes_n": len(new_remotes) if warm_before >= 2 else 0,
            "new_remotes_sample": sorted(new_remotes)[:15] if warm_before >= 2 else [],
            "baseline_proc_n": len(_seen_proc_names),
            "baseline_svc_n": len(_seen_services),
            "baseline_remote_n": len(seen_remotes),
            "host_scope": ["proc_names", "services"],
            "tenant_scope": ["remotes", "warm_cycles"],
        }
    if warm_cycles % 3 == 0:
        save_baseline(tid)
    return meta


def is_warm(tenant_id: Optional[str] = None) -> bool:
    tid = tenant_id or _active_tenant_id or _default_platform_tenant()
    with _lock:
        return int(_tenant_warm_cycles.get(tid) or 0) >= 2
