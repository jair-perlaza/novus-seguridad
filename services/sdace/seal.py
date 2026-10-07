#!/usr/bin/env python3
"""Sello forense de correlaciones importantes — escribe solo en data/sdace."""
from __future__ import annotations
import hashlib
import json
from typing import Any, Dict
from services.sdace.limitations import NA
from services.sdace.store import save_seal


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def seal_correlation(kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    core = {"kind": kind, "payload": payload, "invented": False}
    digest = hashlib.sha256(_canonical(core).encode("utf-8")).hexdigest()
    sig, kid = NA, NA
    try:
        from services.forensic_evidence_keys import load_signing_keypair
        private_key, kid = load_signing_keypair()
        sig = private_key.sign(digest.encode("utf-8")).hex()
    except Exception:
        pass
    entry = {
        "kind": kind,
        "sha256": digest,
        "ed25519_sig": sig,
        "key_id": kid,
        "chain_of_custody": {
            "phase": "sdace_correlation_seal",
            "immutable_ref": digest,
        },
        "payload_summary": {
            "keys": list(payload.keys())[:20],
            "invented": False,
        },
        "invented": False,
    }
    save_seal(entry)
    return entry
