"""
Garantiza una sola instancia lógica de NOVUS por directorio de proyecto.
Evita procesos duplicados en :5000 que elevan RAM y provocan DB locks.
"""
from __future__ import annotations

import atexit
import os
import sys
from typing import Optional

_LOCK_HANDLE = None
_LOCK_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "novus_instance.lock",
)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        import psutil

        return psutil.pid_exists(pid)
    except Exception:
        return False


def _read_lock_pid() -> Optional[int]:
    try:
        with open(_LOCK_PATH, "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
        return int(raw) if raw.isdigit() else None
    except Exception:
        return None


def _release_lock() -> None:
    global _LOCK_HANDLE
    handle = _LOCK_HANDLE
    _LOCK_HANDLE = None
    if handle is None:
        return
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        handle.close()
    except Exception:
        pass
    try:
        if os.path.isfile(_LOCK_PATH):
            os.remove(_LOCK_PATH)
    except Exception:
        pass


def acquire_singleton_or_exit(*, force: bool = False) -> bool:
    """
    Adquiere lock de instancia única. Si otra instancia vive, sale con código 1.
    force=True elimina lock stale de PID muerto.
    """
    global _LOCK_HANDLE
    os.makedirs(os.path.dirname(_LOCK_PATH), exist_ok=True)
    existing = _read_lock_pid()
    if existing and _pid_alive(existing):
        print(
            f"NOVUS ya está en ejecución (PID {existing}). "
            f"Detenga la instancia existente antes de iniciar otra.",
            file=sys.stderr,
        )
        sys.exit(1)
    if existing and force:
        try:
            os.remove(_LOCK_PATH)
        except Exception:
            pass

    try:
        handle = open(_LOCK_PATH, "w", encoding="utf-8")
        if os.name == "nt":
            import msvcrt

            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                handle.close()
                live = _read_lock_pid()
                if live and _pid_alive(live):
                    print(f"NOVUS lock activo — PID {live}", file=sys.stderr)
                    sys.exit(1)
                raise
        handle.seek(0)
        handle.write(str(os.getpid()))
        handle.flush()
        _LOCK_HANDLE = handle
        atexit.register(_release_lock)
        return True
    except Exception as exc:
        print(f"NOVUS no pudo adquirir lock de instancia: {exc}", file=sys.stderr)
        sys.exit(1)
