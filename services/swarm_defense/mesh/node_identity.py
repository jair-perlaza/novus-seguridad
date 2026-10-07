#!/usr/bin/env python3
"""
Swarm Mesh Enterprise — identidad criptográfica por nodo (Ed25519).
Cada instancia NOVUS = un nodo. Sin identidades ficticias.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
MESH_DIR = os.path.join(ROOT, "data", "swarm_mesh")
NODES_DIR = os.path.join(MESH_DIR, "nodes")


def _ensure() -> None:
    os.makedirs(NODES_DIR, exist_ok=True)


def resolve_node_id() -> str:
    """Identidad estable: NODE_ID env o hostname+path hash (no aleatorio por arranque)."""
    env = (os.environ.get("NOVUS_MESH_NODE_ID") or os.environ.get("NODE_ID") or "").strip()
    if env:
        return env[:64]
    host = socket.gethostname() or "novus-host"
    digest = hashlib.sha256(f"{host}|{ROOT}".encode("utf-8")).hexdigest()[:12]
    return f"novus-{host[:24]}-{digest}"


def _node_dir(node_id: Optional[str] = None) -> str:
    nid = node_id or resolve_node_id()
    path = os.path.join(NODES_DIR, nid)
    os.makedirs(path, exist_ok=True)
    return path


def ensure_node_identity(node_id: Optional[str] = None) -> Dict[str, Any]:
    """Crea o carga clave Ed25519 del nodo. Privada envuelta DPAPI/keyring."""
    _ensure()
    nid = node_id or resolve_node_id()
    base = _node_dir(nid)
    meta_path = os.path.join(base, "identity.json")
    pub_path = os.path.join(base, "ed25519_public.pem")
    wrap_path = os.path.join(base, "ed25519_private.pem.wrap")

    from services.key_protection_service import write_wrapped_file, read_wrapped_file

    if os.path.isfile(wrap_path) and os.path.isfile(pub_path) and os.path.isfile(meta_path):
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
        return {
            "ok": True,
            "node_id": nid,
            "public_pem_path": pub_path,
            "algorithm": "Ed25519",
            "created_at": meta.get("created_at"),
            "fingerprint": meta.get("fingerprint"),
        }

    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    priv_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    write_wrapped_file(wrap_path, priv_pem)
    with open(pub_path, "wb") as fh:
        fh.write(pub_pem)
    fp = hashlib.sha256(pub_pem).hexdigest()[:32]
    from datetime import datetime, timezone

    meta = {
        "node_id": nid,
        "algorithm": "Ed25519",
        "fingerprint": fp,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "public_pem": pub_pem.decode("ascii"),
    }
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    return {
        "ok": True,
        "node_id": nid,
        "public_pem_path": pub_path,
        "algorithm": "Ed25519",
        "created_at": meta["created_at"],
        "fingerprint": fp,
    }


def load_signing_keypair(node_id: Optional[str] = None) -> Tuple[Ed25519PrivateKey, str, bytes]:
    """Returns (private_key, node_id, public_pem_bytes)."""
    nid = node_id or resolve_node_id()
    ensure_node_identity(nid)
    base = _node_dir(nid)
    from services.key_protection_service import read_wrapped_file

    priv_pem = read_wrapped_file(os.path.join(base, "ed25519_private.pem.wrap"))
    with open(os.path.join(base, "ed25519_public.pem"), "rb") as fh:
        pub_pem = fh.read()
    private = serialization.load_pem_private_key(priv_pem, password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("mesh_identity_not_ed25519")
    return private, nid, pub_pem


def load_public_key_pem(pem: bytes | str) -> Ed25519PublicKey:
    raw = pem.encode("utf-8") if isinstance(pem, str) else pem
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not_ed25519_public")
    return key


def public_pem_for(node_id: Optional[str] = None) -> str:
    ensure_node_identity(node_id)
    path = os.path.join(_node_dir(node_id), "ed25519_public.pem")
    with open(path, encoding="ascii") as fh:
        return fh.read()


def identity_status(node_id: Optional[str] = None) -> Dict[str, Any]:
    try:
        info = ensure_node_identity(node_id)
        return {**info, "implemented": True}
    except Exception as exc:
        return {"ok": False, "implemented": True, "error": str(exc)[:200]}
