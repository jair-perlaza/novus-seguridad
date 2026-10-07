"""Escaneo YARA asíncrono — wrapper sobre yara-x (no yara clásico ni ProcessPool)."""
from __future__ import annotations

import asyncio
import concurrent.futures
import os
from typing import Any, Dict, Optional

from utils.logger import logger

_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None


def _get_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _executor
    if _executor is None:
        _executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="novus-yara")
    return _executor


class EnterpriseYARAScanner:
    """
    Escaneo multihilo asíncrono para producción.
    Delega a endpoint_enterprise.yara_engine (yara-x) — no compila reglas yara clásicas.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir
        from services.endpoint_enterprise.yara_engine import RULES_DIR, reload_engine

        reload_engine()
        self._rules_dir = rules_dir or str(RULES_DIR)

    def _scan_sync(self, directory: str, max_files: int = 200) -> Dict[str, Any]:
        from services.endpoint_enterprise.yara_engine import scan_directory, get_engine_status

        result = scan_directory(directory, max_files=max_files)
        result["rules_dir"] = self._rules_dir
        result["engine"] = get_engine_status()
        result["backend"] = "yara_x"
        result["note"] = "EnterpriseYARAScanner delega a yara_engine — sin fallback carbanak/yara clásico"
        return result

    async def scan_directory_async(self, directory: str, max_files: int = 200) -> Dict[str, Any]:
        path = os.path.normpath(directory or "")
        if not path or not os.path.exists(path):
            return {
                "status": "ERROR",
                "message": "Ruta no encontrada",
                "files_scanned": 0,
                "matches_count": 0,
                "matches": [],
                "verified": False,
                "invented": False,
            }
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(
                _get_executor(),
                lambda: self._scan_sync(path, max_files=max_files),
            )
        except Exception as exc:
            logger.debug("scan_directory_async: %s", exc)
            return {
                "status": "ERROR",
                "message": str(exc)[:200],
                "verified": False,
                "invented": False,
            }


async def scan_directory_async(directory: str, max_files: int = 200) -> Dict[str, Any]:
    scanner = EnterpriseYARAScanner()
    return await scanner.scan_directory_async(directory, max_files=max_files)
