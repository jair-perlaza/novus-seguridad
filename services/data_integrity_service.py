"""
Integridad de artefactos críticos (keyring, wraps, configs sensibles).
Detecta modificación no autorizada vía SHA-256 almacenado; registra fallos.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE_DIR = os.path.join(ROOT, "data", "integrity")
STORE_PATH = os.path.join(STORE_DIR, "artifact_hashes.json")


def _ensure() -> None:
    os.makedirs(STORE_DIR, exist_ok=True)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_store() -> Dict[str, Any]:
    _ensure()
    if not os.path.isfile(STORE_PATH):
        return {"artifacts": {}}
    try:
        with open(STORE_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data.setdefault("artifacts", {})
            return data
    except Exception:
        pass
    return {"artifacts": {}}


def _save_store(data: Dict[str, Any]) -> None:
    _ensure()
    tmp = STORE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, STORE_PATH)


def mark_artifact_hash(artifact_id: str, path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {"ok": False, "reason": "missing_file"}
    digest = _sha256_file(path)
    store = _load_store()
    store["artifacts"][artifact_id] = {
        "path": os.path.abspath(path),
        "sha256": digest,
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    _save_store(store)
    return {"ok": True, "artifact_id": artifact_id, "sha256": digest}


def verify_artifact(artifact_id: str, path: Optional[str] = None) -> Dict[str, Any]:
    store = _load_store()
    meta = (store.get("artifacts") or {}).get(artifact_id)
    if not meta:
        return {"ok": False, "status": "unknown", "artifact_id": artifact_id}
    target = path or meta.get("path")
    if not target or not os.path.isfile(target):
        result = {"ok": False, "status": "missing", "artifact_id": artifact_id}
        _record_failure(artifact_id, result)
        return result
    current = _sha256_file(target)
    expected = meta.get("sha256")
    if current == expected:
        return {"ok": True, "status": "verified", "artifact_id": artifact_id, "sha256": current}
    result = {
        "ok": False,
        "status": "tampered",
        "artifact_id": artifact_id,
        "expected": expected,
        "actual": current,
    }
    _record_failure(artifact_id, result)
    return result


def _record_failure(artifact_id: str, detail: dict) -> None:
    logger.error("data_integrity failure %s: %s", artifact_id, detail.get("status"))
    try:
        from services.sensitive_operations_audit import log_sensitive_operation

        log_sensitive_operation(
            "data_integrity_failure",
            actor="system",
            outcome="failed",
            detail=detail,
        )
    except Exception:
        pass
    try:
        from services.forensic_evidence_integrity_service import seal_evidence

        seal_evidence(
            source_id=f"INT-{artifact_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            source_type="data_integrity",
            motor="data_integrity_service",
            evidence_type="integrity_failure",
            payload=detail,
        )
    except Exception:
        pass


def verify_critical_artifacts() -> Dict[str, Any]:
    """Verifica keyring y manifiestos conocidos."""
    checks: List[dict] = []
    keyring = os.path.join(ROOT, "data", "cryptovault", "keyring.json")
    if os.path.isfile(keyring):
        # Si no hay marca previa, establecer baseline (no es fallo)
        store = _load_store()
        if "cryptovault_keyring" not in (store.get("artifacts") or {}):
            mark_artifact_hash("cryptovault_keyring", keyring)
        checks.append(verify_artifact("cryptovault_keyring", keyring))
    flask_wrap = os.path.join(ROOT, "data", "secrets", "flask_secret.wrap")
    if os.path.isfile(flask_wrap):
        store = _load_store()
        if "flask_secret_wrap" not in (store.get("artifacts") or {}):
            mark_artifact_hash("flask_secret_wrap", flask_wrap)
        checks.append(verify_artifact("flask_secret_wrap", flask_wrap))
    ok_n = sum(1 for c in checks if c.get("ok"))
    return {
        "ok": all(c.get("ok") for c in checks) if checks else True,
        "checked": len(checks),
        "verified": ok_n,
        "results": checks,
    }
