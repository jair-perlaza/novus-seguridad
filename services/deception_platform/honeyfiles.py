#!/usr/bin/env python3
"""Honeyfiles DPE — archivos senuelo con integridad; sin contenido real."""
from __future__ import annotations
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from services.deception_platform.limitations import HONEYFILE_TYPES, NA, NAMESPACE, USERNAME_PREFIX
from services.deception_platform.store import (
    append_jsonl, read_jsonl, FILES_PATH, HONEYFILES_DIR, ensure_dir,
)


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _sign(digest: str) -> tuple:
    try:
        from services.forensic_evidence_keys import load_signing_keypair
        pk, kid = load_signing_keypair()
        return pk.sign(digest.encode()).hex(), kid or "novus-ed25519-default"
    except Exception:
        return NA, NA


def _decoy_bytes(ftype: str, uid: str) -> bytes:
    # Synthetic placeholder only — never copy real documents
    banner = (
        f"NOVUS DPE HONEYFILE\n"
        f"uuid={uid}\n"
        f"type={ftype}\n"
        f"namespace={NAMESPACE}\n"
        f"WARNING: This is a decoy artifact. Not a real corporate document.\n"
    )
    return banner.encode("utf-8")


def create_honeyfile(
    ftype: str,
    classification: str = "CONFIDENCIAL_DECOY",
    owner_ficticio: Optional[str] = None,
) -> Dict[str, Any]:
    ftype = (ftype or "").lower().strip()
    if ftype not in HONEYFILE_TYPES:
        return {"ok": False, "error": f"tipo no soportado: {ftype}", "supported": HONEYFILE_TYPES}
    uid = str(uuid.uuid4())
    owner = owner_ficticio or f"{USERNAME_PREFIX}docs.{uid[:8]}"
    ensure_dir()
    content = _decoy_bytes(ftype, uid)
    sha = hashlib.sha256(content).hexdigest()
    path = os.path.join(HONEYFILES_DIR, f"{uid}.{ftype if ftype not in ('backup', 'database') else 'bin'}")
    with open(path, "wb") as fh:
        fh.write(content)
    core = {
        "uuid": uid,
        "ftype": ftype,
        "sha256": sha,
        "namespace": NAMESPACE,
        "decoy": True,
        "real_document": False,
    }
    digest = hashlib.sha256(_canonical(core).encode()).hexdigest()
    sig, kid = _sign(digest)
    meta = {
        "uuid": uid,
        "sha256": sha,
        "ed25519": sig,
        "key_id": kid,
        "fecha": _utc(),
        "propietario_ficticio": owner,
        "clasificacion": classification,
        "tipo": ftype,
        "path_local": path,
        "estado": "emitido",
        "namespace": NAMESPACE,
        "decoy": True,
        "real_document": False,
        "opens": 0,
        "invented": False,
    }
    append_jsonl(FILES_PATH, meta)
    return {"ok": True, "honeyfile": meta}


def _is_honeyfile_meta(row: Dict[str, Any]) -> bool:
    return bool(
        row
        and row.get("decoy") is True
        and row.get("sha256")
        and row.get("tipo")
        and row.get("event") != "open_counter"
    )


def list_honeyfiles(limit: int = 200) -> Dict[str, Any]:
    rows = [f for f in read_jsonl(FILES_PATH, 5000) if _is_honeyfile_meta(f)]
    rows = list(reversed(rows))[:limit]
    return {"count": len(rows), "files": rows, "types": HONEYFILE_TYPES, "invented": False}


def get_honeyfile(uid: str) -> Optional[Dict[str, Any]]:
    found = None
    for f in read_jsonl(FILES_PATH, 5000):
        if f.get("uuid") == uid and _is_honeyfile_meta(f):
            found = f
    return found


def mark_opened(uid: str, source_ip: Optional[str] = None, actor: Optional[str] = None) -> Dict[str, Any]:
    """Registra apertura REAL del honeyfile (canary). No inventa atacantes."""
    from services.deception_platform.integration import handle_decoy_interaction

    meta = get_honeyfile(uid)
    if not meta:
        return {"ok": False, "error": "honeyfile_not_found"}
    return handle_decoy_interaction(
        resource_type="honeyfile",
        resource_id=uid,
        action="open",
        evidence={
            "sha256": meta.get("sha256"),
            "tipo": meta.get("tipo"),
            "source_ip": source_ip or NA,
            "actor": actor or NA,
            "classification": meta.get("clasificacion"),
        },
    )
