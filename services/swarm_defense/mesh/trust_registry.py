#!/usr/bin/env python3
"""
Registro de confianza / revocación de peers del Swarm Mesh.
Solo peers explícitamente confiados pueden inyectar intel.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
MESH_DIR = os.path.join(ROOT, "data", "swarm_mesh")
TRUST_PATH = os.path.join(MESH_DIR, "trust_registry.json")
_lock = threading.RLock()


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure() -> None:
    os.makedirs(MESH_DIR, exist_ok=True)
    if not os.path.isfile(TRUST_PATH):
        with open(TRUST_PATH, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "peers": {}, "revoked": {}}, fh, indent=2)


def _load() -> Dict[str, Any]:
    _ensure()
    with open(TRUST_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _save(data: Dict[str, Any]) -> None:
    _ensure()
    tmp = TRUST_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, TRUST_PATH)


def list_peers(*, include_revoked: bool = False) -> List[Dict[str, Any]]:
    with _lock:
        data = _load()
        out = []
        for pid, row in (data.get("peers") or {}).items():
            if row.get("revoked") and not include_revoked:
                continue
            out.append({"peer_id": pid, **row})
        return out


def get_peer(peer_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        data = _load()
        row = (data.get("peers") or {}).get(peer_id)
        if not row or row.get("revoked"):
            return None
        return {"peer_id": peer_id, **row}


def is_trusted(peer_id: str, fingerprint: Optional[str] = None) -> bool:
    peer = get_peer(peer_id)
    if not peer:
        return False
    if fingerprint and peer.get("fingerprint") and peer["fingerprint"] != fingerprint:
        return False
    return True


def is_revoked(peer_id: str) -> bool:
    with _lock:
        data = _load()
        if peer_id in (data.get("revoked") or {}):
            return True
        row = (data.get("peers") or {}).get(peer_id) or {}
        return bool(row.get("revoked"))


def trust_peer(
    *,
    peer_id: str,
    public_pem: str,
    base_url: str,
    fingerprint: Optional[str] = None,
    label: str = "",
    actor: str = "system",
) -> Dict[str, Any]:
    """Añade peer a lista de confianza. Requiere PEM Ed25519 real."""
    from services.swarm_defense.mesh.node_identity import load_public_key_pem
    import hashlib

    pem = public_pem.strip()
    load_public_key_pem(pem)  # validate
    fp = fingerprint or hashlib.sha256(pem.encode("ascii")).hexdigest()[:32]
    base_url = (base_url or "").rstrip("/")
    if not peer_id or not base_url:
        return {"ok": False, "error": "peer_id_and_base_url_required"}
    with _lock:
        data = _load()
        # Re-confianza explícita: quitar de revoked si el operador re-agrega el peer
        if peer_id in (data.get("revoked") or {}):
            del data["revoked"][peer_id]
        peers = data.setdefault("peers", {})
        peers[peer_id] = {
            "public_pem": pem,
            "fingerprint": fp,
            "base_url": base_url,
            "label": label or peer_id,
            "trusted_at": _utc(),
            "trusted_by": actor,
            "revoked": False,
            "reputation": 50,
            "messages_accepted": int((peers.get(peer_id) or {}).get("messages_accepted") or 0),
            "messages_rejected": int((peers.get(peer_id) or {}).get("messages_rejected") or 0),
        }
        _save(data)
    return {"ok": True, "peer_id": peer_id, "fingerprint": fp, "base_url": base_url}


def revoke_peer(*, peer_id: str, reason: str = "", actor: str = "system") -> Dict[str, Any]:
    with _lock:
        data = _load()
        peers = data.setdefault("peers", {})
        row = peers.get(peer_id)
        if row:
            row["revoked"] = True
            row["revoked_at"] = _utc()
            row["revoked_by"] = actor
            row["revoke_reason"] = reason[:200]
        data.setdefault("revoked", {})[peer_id] = {
            "at": _utc(),
            "by": actor,
            "reason": reason[:200],
        }
        _save(data)
    return {"ok": True, "peer_id": peer_id, "revoked": True}


def bump_peer_stats(peer_id: str, *, accepted: bool) -> None:
    with _lock:
        data = _load()
        row = (data.get("peers") or {}).get(peer_id)
        if not row:
            return
        if accepted:
            row["messages_accepted"] = int(row.get("messages_accepted") or 0) + 1
            row["reputation"] = min(100, int(row.get("reputation") or 50) + 1)
        else:
            row["messages_rejected"] = int(row.get("messages_rejected") or 0) + 1
            row["reputation"] = max(0, int(row.get("reputation") or 50) - 5)
        _save(data)


def trust_status() -> Dict[str, Any]:
    peers = list_peers(include_revoked=True)
    active = [p for p in peers if not p.get("revoked")]
    revoked = [p for p in peers if p.get("revoked")]
    return {
        "ok": True,
        "trusted_peers": len(active),
        "revoked_peers": len(revoked),
        "peers": active,
        "path": TRUST_PATH,
    }
