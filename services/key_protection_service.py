"""
Protección de material criptográfico en reposo (NOVUS).

Windows: DPAPI (CryptProtectData / CryptUnprotectData) — atado al usuario/máquina.
Fallback: AES-GCM con KEK derivada de NOVUS_KEY_WRAP_SECRET (obligatoria fuera de Windows).

Formato de blob: b"NOVUSWRAP1" + raw_protected_bytes
"""
from __future__ import annotations

import os
import sys
from typing import Optional, Tuple

from utils.logger import logger

MAGIC = b"NOVUSWRAP1"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WRAP_DIR = os.path.join(ROOT, "data", "cryptovault")
SALT_PATH = os.path.join(WRAP_DIR, "wrap_salt.bin")


def _ensure_dir() -> None:
    os.makedirs(WRAP_DIR, exist_ok=True)


def _dpapi_protect(raw: bytes) -> Optional[bytes]:
    if sys.platform != "win32":
        return None
    try:
        import win32crypt

        # CRYPTPROTECT_UI_FORBIDDEN = 0x1
        blob = win32crypt.CryptProtectData(raw, "NOVUS-KeyWrap", None, None, None, 0x1)
        return blob
    except Exception as exc:
        logger.warning("DPAPI protect failed: %s", exc)
        return None


def _dpapi_unprotect(blob: bytes) -> Optional[bytes]:
    if sys.platform != "win32":
        return None
    try:
        import win32crypt

        _desc, raw = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
        return raw
    except Exception as exc:
        logger.warning("DPAPI unprotect failed: %s", exc)
        return None


def _pbkdf2_kek() -> Optional[bytes]:
    secret = (os.environ.get("NOVUS_KEY_WRAP_SECRET") or "").strip()
    if not secret:
        return None
    _ensure_dir()
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    if os.path.isfile(SALT_PATH):
        salt = open(SALT_PATH, "rb").read()
    else:
        salt = os.urandom(16)
        with open(SALT_PATH, "wb") as fh:
            fh.write(salt)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    return kdf.derive(secret.encode("utf-8"))


def _aes_wrap(raw: bytes, kek: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    ct = AESGCM(kek).encrypt(nonce, raw, b"NOVUS-KEY-WRAP")
    return nonce + ct


def _aes_unwrap(blob: bytes, kek: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce, ct = blob[:12], blob[12:]
    return AESGCM(kek).decrypt(nonce, ct, b"NOVUS-KEY-WRAP")


def wrap_secret(raw: bytes) -> bytes:
    """Envuelve bytes sensibles. Prefiere DPAPI en Windows."""
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        raise ValueError("wrap_secret requiere bytes no vacíos")
    protected = _dpapi_protect(bytes(raw))
    method = b"D"  # DPAPI
    if protected is None:
        kek = _pbkdf2_kek()
        if kek is None:
            raise RuntimeError(
                "No se pudo envolver la clave: DPAPI no disponible y falta NOVUS_KEY_WRAP_SECRET"
            )
        protected = _aes_wrap(bytes(raw), kek)
        method = b"A"  # AES-KEK
    return MAGIC + method + protected


def unwrap_secret(blob: bytes) -> bytes:
    """Desenvuelve blob NOVUSWRAP1."""
    if not blob.startswith(MAGIC):
        raise ValueError("blob no es NOVUSWRAP1")
    method = blob[len(MAGIC) : len(MAGIC) + 1]
    payload = blob[len(MAGIC) + 1 :]
    if method == b"D":
        raw = _dpapi_unprotect(payload)
        if raw is None:
            raise RuntimeError("DPAPI unprotect falló")
        return raw
    if method == b"A":
        kek = _pbkdf2_kek()
        if kek is None:
            raise RuntimeError("Falta NOVUS_KEY_WRAP_SECRET para desenvolver")
        return _aes_unwrap(payload, kek)
    raise ValueError(f"método de wrap desconocido: {method!r}")


def is_wrapped_blob(data: bytes) -> bool:
    return bool(data) and data.startswith(MAGIC)


def wrap_file(src_path: str, dest_path: str) -> str:
    """Lee archivo plaintext y escribe versión envuelta."""
    with open(src_path, "rb") as fh:
        raw = fh.read()
    wrapped = wrap_secret(raw)
    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    with open(dest_path, "wb") as fh:
        fh.write(wrapped)
    return dest_path


def read_wrapped_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        blob = fh.read()
    if is_wrapped_blob(blob):
        return unwrap_secret(blob)
    # Compatibilidad: archivo aún en claro
    return blob


def write_wrapped_file(path: str, raw: bytes) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(wrap_secret(raw))


def protection_status() -> dict:
    """Estado verificable del mecanismo (sin exponer secretos)."""
    dpapi = False
    if sys.platform == "win32":
        try:
            probe = _dpapi_protect(b"novus-probe")
            dpapi = bool(probe) and _dpapi_unprotect(probe) == b"novus-probe"
        except Exception:
            dpapi = False
    return {
        "platform": sys.platform,
        "dpapi_available": dpapi,
        "pbkdf2_fallback_configured": bool((os.environ.get("NOVUS_KEY_WRAP_SECRET") or "").strip()),
        "magic": MAGIC.decode("ascii"),
    }
