#!/usr/bin/env python3
"""
Canal AES-256-GCM por peer (clave envuelta localmente).
Sin clave de canal no hay cifrado compartido — se establece al confiar el peer.
"""
from __future__ import annotations

import os
from typing import Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
CHANNEL_DIR = os.path.join(ROOT, "data", "swarm_mesh", "channels")


def _path(peer_id: str) -> str:
    os.makedirs(CHANNEL_DIR, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in peer_id)[:80]
    return os.path.join(CHANNEL_DIR, f"{safe}.wrap")


def has_channel(peer_id: str) -> bool:
    return os.path.isfile(_path(peer_id))


def get_or_create_channel_key(peer_id: str, *, existing: Optional[bytes] = None) -> bytes:
    """Devuelve clave de 32 bytes; crea y envuelve si no existe."""
    from services.key_protection_service import read_wrapped_file, write_wrapped_file

    path = _path(peer_id)
    if existing is not None:
        if len(existing) != 32:
            raise ValueError("channel_key_must_be_32_bytes")
        write_wrapped_file(path, existing)
        return existing
    if os.path.isfile(path):
        return read_wrapped_file(path)
    key = os.urandom(32)
    write_wrapped_file(path, key)
    return key


def load_channel_key(peer_id: str) -> bytes:
    from services.key_protection_service import read_wrapped_file

    path = _path(peer_id)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"no_channel_for_{peer_id}")
    key = read_wrapped_file(path)
    if len(key) != 32:
        raise ValueError("invalid_channel_key_length")
    return key


def export_channel_key_b64(peer_id: str) -> str:
    """Solo para enrollment administrativo entre nodos de confianza (out-of-band)."""
    import base64

    return base64.b64encode(load_channel_key(peer_id)).decode("ascii")


def import_channel_key_b64(peer_id: str, key_b64: str) -> None:
    import base64

    raw = base64.b64decode(key_b64)
    get_or_create_channel_key(peer_id, existing=raw)
