"""
Motor YARA Enterprise — yara-x (libyara nativa vía crate; sin simulaciones).
Escanea archivos y buffers de memoria de proceso cuando AccessDenied lo permite.
"""
from __future__ import annotations

import hashlib
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

RULES_DIR = Path(__file__).resolve().parent / "rules"
_ENGINE = None
_ENGINE_ERROR: Optional[str] = None
_BACKEND = None


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str, limit: int = 32 * 1024 * 1024) -> Optional[str]:
    try:
        h = hashlib.sha256()
        total = 0
        with open(path, "rb") as fh:
            while total < limit:
                chunk = fh.read(65536)
                if not chunk:
                    break
                h.update(chunk)
                total += len(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _meta_dict(rule) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        md = getattr(rule, "metadata", None) or ()
        # yara-x metadata can be iterable of (key, value) or Mapping
        if hasattr(md, "items"):
            for k, v in md.items():
                out[str(k)] = v
        else:
            for item in md:
                if isinstance(item, (tuple, list)) and len(item) >= 2:
                    out[str(item[0])] = item[1]
                elif hasattr(item, "identifier"):
                    out[str(item.identifier)] = getattr(item, "value", None)
    except Exception as exc:
        logger.debug("yara meta parse: %s", exc)
    return out


def _matches_to_records(
    results,
    *,
    target_type: str,
    target: str,
    content_hash: Optional[str],
    pid: Optional[int] = None,
    process_name: Optional[str] = None,
    user: Optional[str] = None,
) -> List[Dict[str, Any]]:
    records = []
    for rule in results.matching_rules or ():
        meta = _meta_dict(rule)
        pats = []
        for p in rule.patterns or ():
            for m in p.matches or ():
                pats.append(
                    {
                        "pattern": getattr(p, "identifier", None),
                        "offset": getattr(m, "offset", None),
                        "length": getattr(m, "length", None),
                    }
                )
        records.append(
            {
                "rule": getattr(rule, "identifier", None),
                "namespace": getattr(rule, "namespace", None),
                "tags": list(getattr(rule, "tags", ()) or ()),
                "meta": meta,
                "confidence": str(meta.get("confidence") or meta.get("novus_confidence") or "medium"),
                "severity": str(meta.get("novus_severity") or "medium"),
                "category": str(meta.get("novus_category") or "yara"),
                "matches": pats[:20],
                "target_type": target_type,
                "target": target,
                "sha256": content_hash,
                "pid": pid,
                "process": process_name,
                "user": user,
                "equipment": socket.gethostname(),
                "timestamp_utc": _utc(),
                "backend": _BACKEND,
                "verified": True,
            }
        )
    return records


def get_engine_status() -> Dict[str, Any]:
    ensure_engine()
    return {
        "ok": _ENGINE is not None,
        "backend": _BACKEND,
        "error": _ENGINE_ERROR,
        "rules_dir": str(RULES_DIR),
        "rules_files": [p.name for p in RULES_DIR.glob("*.yar")] if RULES_DIR.is_dir() else [],
    }


def ensure_engine():
    """Compila reglas YARA desde rules/*.yar usando yara_x."""
    global _ENGINE, _ENGINE_ERROR, _BACKEND
    if _ENGINE is not None:
        return _ENGINE
    if _ENGINE_ERROR and _BACKEND is None:
        return None
    try:
        import yara_x

        compiler = yara_x.Compiler()
        files = sorted(RULES_DIR.glob("*.yar"))
        if not files:
            _ENGINE_ERROR = "no_yar_rules_in_rules_dir"
            return None
        for path in files:
            compiler.add_source(path.read_text(encoding="utf-8"), origin=str(path.name))
        _ENGINE = compiler.build()
        _BACKEND = "yara_x"
        _ENGINE_ERROR = None
        logger.info("Endpoint YARA engine ready (%s rules files)", len(files))
        return _ENGINE
    except Exception as exc:
        _ENGINE = None
        _BACKEND = None
        _ENGINE_ERROR = str(exc)[:400]
        logger.warning("YARA engine unavailable: %s", exc)
        return None


def scan_bytes(
    data: bytes,
    *,
    target_type: str = "buffer",
    target: str = "memory",
    pid: Optional[int] = None,
    process_name: Optional[str] = None,
    user: Optional[str] = None,
) -> List[Dict[str, Any]]:
    eng = ensure_engine()
    if not eng or not data:
        return []
    try:
        results = eng.scan(data)
        return _matches_to_records(
            results,
            target_type=target_type,
            target=target,
            content_hash=_sha256_bytes(data[: min(len(data), 1024 * 1024)]),
            pid=pid,
            process_name=process_name,
            user=user,
        )
    except Exception as exc:
        logger.debug("yara scan_bytes: %s", exc)
        return []


def scan_file(path: str, *, max_bytes: int = 8 * 1024 * 1024) -> List[Dict[str, Any]]:
    if not path or not os.path.isfile(path):
        return []
    try:
        size = os.path.getsize(path)
        if size <= 0 or size > max_bytes:
            # Still try partial read for large files (first max_bytes)
            if size > max_bytes:
                with open(path, "rb") as fh:
                    data = fh.read(max_bytes)
            else:
                return []
        else:
            with open(path, "rb") as fh:
                data = fh.read()
        return scan_bytes(
            data,
            target_type="file",
            target=os.path.normpath(path),
            user=os.environ.get("USERNAME"),
        )
    except Exception as exc:
        logger.debug("yara scan_file %s: %s", path, exc)
        return []


def reload_engine():
    """Fuerza recompilación de reglas (p. ej. tras añadir .yar)."""
    global _ENGINE, _ENGINE_ERROR, _BACKEND
    _ENGINE = None
    _ENGINE_ERROR = None
    _BACKEND = None
    return ensure_engine()


def scan_directory(
    target_path: str,
    *,
    max_files: int = 200,
    max_bytes_per_file: int = 8 * 1024 * 1024,
) -> Dict[str, Any]:
    """Escaneo recursivo vía yara-x — sin fallback regex ni yara clásico."""
    path = os.path.normpath(target_path or "")
    if not path or not os.path.exists(path):
        return {
            "status": "ERROR",
            "message": f"Ruta no existe: {target_path}",
            "files_scanned": 0,
            "matches": [],
            "verified": False,
            "invented": False,
        }

    st = get_engine_status()
    if not st.get("ok"):
        return {
            "status": "ENGINE_UNAVAILABLE",
            "message": st.get("error") or "yara-x no disponible",
            "files_scanned": 0,
            "matches": [],
            "backend": st.get("backend"),
            "verified": True,
            "invented": False,
        }

    files: List[str] = []
    if os.path.isfile(path):
        files.append(path)
    else:
        for root, _, names in os.walk(path):
            for name in names:
                files.append(os.path.join(root, name))
                if len(files) >= max_files:
                    break
            if len(files) >= max_files:
                break

    all_matches: List[Dict[str, Any]] = []
    scanned = 0
    for fp in files:
        if not os.path.isfile(fp):
            continue
        try:
            if os.path.getsize(fp) > max_bytes_per_file:
                continue
        except OSError:
            continue
        scanned += 1
        hits = scan_file(fp, max_bytes=max_bytes_per_file)
        if hits:
            all_matches.extend(hits)

    return {
        "status": "COMPLETED",
        "target_path": path,
        "files_scanned": scanned,
        "matches_count": len(all_matches),
        "matches": all_matches[:50],
        "backend": st.get("backend"),
        "rules_files": st.get("rules_files"),
        "verified": True,
        "invented": False,
        "note": "Coincidencia YARA = señal heurística; correlacionar con BTDE/Endpoint antes de contención.",
    }


def generate_yara_rule_draft(rule_name: str, strings_list: List[str]) -> str:
    """Genera borrador de regla YARA — no la instala automáticamente."""
    from datetime import datetime, timezone

    safe = re.sub(r"[^A-Za-z0-9_]", "_", rule_name or "Auto")[:40]
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    formatted = "\n        ".join(
        f'$s{i + 1} = "{s}" nocase ascii wide' for i, s in enumerate(strings_list or []) if s
    )
    if not formatted:
        formatted = '$s1 = "PLACEHOLDER" ascii'
    return f"""rule NOVUS_AutoGenerated_{safe}
{{
    meta:
        description = "Borrador autogenerado — revisión humana requerida antes de despliegue"
        author = "NOVUS AI Kernel Core"
        created_at = "{ts}"
        novus_severity = "medium"
        novus_category = "draft"
    strings:
        {formatted}
    condition:
        any of them
}}"""


def scan_process_memory(pid: int, *, max_regions: int = 40, max_bytes_total: int = 12 * 1024 * 1024) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Lee regiones legibles del proceso (Windows ReadProcessMemory) y aplica YARA.
    Limitación OS: AccessDenied en procesos protegidos → documentado, no inventado.
    """
    meta: Dict[str, Any] = {
        "pid": pid,
        "regions_scanned": 0,
        "bytes_scanned": 0,
        "access_denied": False,
        "limitation": None,
    }
    try:
        import psutil

        proc = psutil.Process(pid)
        name = proc.name()
        user = None
        try:
            user = proc.username()
        except Exception:
            user = os.environ.get("USERNAME")
    except Exception as exc:
        meta["error"] = str(exc)[:160]
        return [], meta

    matches: List[Dict[str, Any]] = []
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400
        handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            meta["access_denied"] = True
            meta["limitation"] = "OpenProcess AccessDenied — procesos protegidos/sistema no escaneables sin privilegios elevados"
            return [], meta

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        MEM_COMMIT = 0x1000
        PAGE_NOACCESS = 0x01
        PAGE_GUARD = 0x100
        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        total = 0
        regions = 0
        while regions < max_regions and total < max_bytes_total:
            result = kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not result:
                break
            base = mbi.BaseAddress or 0
            size = int(mbi.RegionSize or 0)
            protect = int(mbi.Protect or 0)
            state = int(mbi.State or 0)
            next_addr = base + size
            if next_addr <= address:
                break
            address = next_addr
            if state != MEM_COMMIT or size <= 0:
                continue
            if protect & PAGE_NOACCESS or protect & PAGE_GUARD:
                continue
            # Readable-ish pages
            readable = protect in (0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80) or (protect & 0xEE)
            if not readable:
                continue
            read_size = min(size, 512 * 1024, max_bytes_total - total)
            if read_size <= 0:
                break
            buf = (ctypes.c_char * read_size)()
            read = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(
                handle, ctypes.c_void_p(base), buf, read_size, ctypes.byref(read)
            )
            if not ok or read.value <= 0:
                continue
            chunk = bytes(buf[: read.value])
            total += len(chunk)
            regions += 1
            hits = scan_bytes(
                chunk,
                target_type="process_memory",
                target=f"pid:{pid}+0x{base:x}",
                pid=pid,
                process_name=name,
                user=user,
            )
            for h in hits:
                h["region_base"] = hex(base)
                h["region_protect"] = protect
            matches.extend(hits)
        kernel32.CloseHandle(handle)
        meta["regions_scanned"] = regions
        meta["bytes_scanned"] = total
    except Exception as exc:
        meta["error"] = str(exc)[:240]
        meta["limitation"] = "memory_scan_failed"
    return matches, meta


def scan_watch_dirs(paths: Optional[List[str]] = None, *, max_files: int = 40) -> List[Dict[str, Any]]:
    """Escanea TEMP/Downloads/Desktop por extensiones de riesgo (incremental, acotado)."""
    roots = paths or []
    if not roots:
        home = os.path.expanduser("~")
        for sub in ("Downloads", "Desktop"):
            p = os.path.join(home, sub)
            if os.path.isdir(p):
                roots.append(p)
        temp = os.environ.get("TEMP") or os.path.join(home, "AppData", "Local", "Temp")
        if temp and os.path.isdir(temp):
            roots.append(temp)
    exts = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr", ".hta"}
    hits: List[Dict[str, Any]] = []
    seen = 0
    for root in roots:
        try:
            for entry in os.scandir(root):
                if seen >= max_files:
                    return hits
                if not entry.is_file():
                    continue
                name = entry.name.lower()
                if not any(name.endswith(e) for e in exts):
                    continue
                # Prefer recently modified
                try:
                    mtime = entry.stat().st_mtime
                except Exception:
                    mtime = 0
                if mtime and (datetime.now().timestamp() - mtime) > 7 * 86400:
                    continue
                seen += 1
                hits.extend(scan_file(entry.path))
        except (PermissionError, OSError) as exc:
            logger.debug("yara watch dir %s: %s", root, exc)
    return hits
