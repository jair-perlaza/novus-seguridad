"""
Claves Ed25519 forenses — privada envuelta + cifrado PEM por passphrase,
almacén de confianza multi-clave para verificación de evidencias históricas.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY_DIR = os.path.join(ROOT, "data", "forensic_keys")
PRIV_PATH = os.path.join(KEY_DIR, "ed25519_private.pem")
PRIV_WRAP_PATH = os.path.join(KEY_DIR, "ed25519_private.pem.wrap")
PUB_PATH = os.path.join(KEY_DIR, "ed25519_public.pem")
META_PATH = os.path.join(KEY_DIR, "key_meta.json")
LEGACY_DIR = os.path.join(KEY_DIR, "legacy")
TRUST_DIR = os.path.join(KEY_DIR, "trust_store")
PASSPHRASE_WRAP = os.path.join(KEY_DIR, "ed25519_passphrase.wrap")


def _passphrase_bytes() -> bytes:
    """Passphrase real: env o secreto envuelto (DPAPI); nunca hardcodeada en claro."""
    env = os.environ.get("NOVUS_FORENSIC_KEY_PASSPHRASE", "").strip()
    if env:
        return env.encode("utf-8")
    from services.key_protection_service import read_wrapped_file, write_wrapped_file

    if os.path.isfile(PASSPHRASE_WRAP):
        return read_wrapped_file(PASSPHRASE_WRAP)
    # Generar passphrase de 32 bytes y envolverla
    raw = os.urandom(32)
    write_wrapped_file(PASSPHRASE_WRAP, raw)
    return raw


def _migrate_plaintext_if_needed() -> None:
    if os.path.isfile(PRIV_WRAP_PATH):
        return
    if not os.path.isfile(PRIV_PATH):
        return
    from services.key_protection_service import write_wrapped_file

    with open(PRIV_PATH, "rb") as fh:
        raw = fh.read()
    # Re-empaquetar con passphrase si es PEM sin cifrar
    try:
        key = serialization.load_pem_private_key(raw, password=None)
        raw = _private_pem_encrypted(key)
    except Exception:
        pass
    write_wrapped_file(PRIV_WRAP_PATH, raw)
    os.makedirs(LEGACY_DIR, exist_ok=True)
    dest = os.path.join(LEGACY_DIR, "ed25519_private.pem.migrated")
    try:
        os.replace(PRIV_PATH, dest)
    except Exception:
        pass


def _private_pem_encrypted(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(_passphrase_bytes()),
    )


def _load_private_key_from_pem(pem: bytes) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except TypeError:
        key = serialization.load_pem_private_key(pem, password=_passphrase_bytes())
    except Exception:
        key = serialization.load_pem_private_key(pem, password=_passphrase_bytes())
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("not Ed25519 private key")
    return key


def _read_private_pem() -> bytes:
    from services.key_protection_service import read_wrapped_file

    _migrate_plaintext_if_needed()
    if os.path.isfile(PRIV_WRAP_PATH):
        return read_wrapped_file(PRIV_WRAP_PATH)
    if os.path.isfile(PRIV_PATH):
        with open(PRIV_PATH, "rb") as fh:
            return fh.read()
    raise FileNotFoundError("Ed25519 private key missing")


def _write_public_from_private(private_key: Ed25519PrivateKey) -> None:
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(PUB_PATH, "wb") as fh:
        fh.write(pub_pem)


def _trust_add_public(pem: bytes, *, key_id: str, label: str) -> None:
    os.makedirs(TRUST_DIR, exist_ok=True)
    digest = hashlib.sha256(pem).hexdigest()[:16]
    path = os.path.join(TRUST_DIR, f"{key_id or digest}.pem")
    if not os.path.isfile(path):
        with open(path, "wb") as fh:
            fh.write(pem)
    meta_path = os.path.join(TRUST_DIR, f"{key_id or digest}.json")
    if not os.path.isfile(meta_path):
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump({"key_id": key_id, "label": label, "sha256_16": digest}, fh, indent=2)


def sync_public_key_from_wrap(*, retire_plaintext: bool = True) -> dict:
    """
    Repara desync público/privado: la verificación fallaba porque public.pem
    no correspondía a la privada envuelta. No altera evidencias del ledger.
    """
    os.makedirs(KEY_DIR, exist_ok=True)
    _migrate_plaintext_if_needed()
    pem = _read_private_pem()
    private_key = _load_private_key_from_pem(pem)
    # Asegurar PEM cifrado por passphrase dentro del wrap
    enc_pem = _private_pem_encrypted(private_key)
    from services.key_protection_service import write_wrapped_file

    write_wrapped_file(PRIV_WRAP_PATH, enc_pem)
    _write_public_from_private(private_key)

    kid = "novus-ed25519-default"
    if os.path.isfile(META_PATH):
        with open(META_PATH, encoding="utf-8") as fh:
            meta = json.load(fh)
        kid = meta.get("key_id") or kid
        meta["private_storage"] = "wrapped+passphrase"
        meta["pem_encryption"] = "BestAvailableEncryption"
        meta["public_synced_from_wrap"] = True
        with open(META_PATH, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
    else:
        kid = f"NOVUS-ED25519-{uuid.uuid4().hex[:12]}"
        with open(META_PATH, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "key_id": kid,
                    "algorithm": "Ed25519",
                    "private_storage": "wrapped+passphrase",
                    "pem_encryption": "BestAvailableEncryption",
                    "created_at": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                },
                fh,
                indent=2,
            )

    pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _trust_add_public(pub, key_id=kid, label="active")

    # Confiar también en legacy migrado (misma o anterior material)
    legacy = os.path.join(LEGACY_DIR, "ed25519_private.pem.migrated")
    legacy_ok = False
    if os.path.isfile(legacy):
        try:
            leg_key = _load_private_key_from_pem(open(legacy, "rb").read())
            leg_pub = leg_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            _trust_add_public(leg_pub, key_id=f"{kid}-legacy", label="legacy_migrated")
            legacy_ok = True
        except Exception:
            pass

    retired = False
    if retire_plaintext and os.path.isfile(PRIV_PATH):
        os.makedirs(LEGACY_DIR, exist_ok=True)
        dest = os.path.join(LEGACY_DIR, "ed25519_private.pem.out_of_sync_retired")
        try:
            os.replace(PRIV_PATH, dest)
            retired = True
        except Exception:
            try:
                os.remove(PRIV_PATH)
                retired = True
            except OSError:
                pass

    return {
        "ok": True,
        "key_id": kid,
        "public_synced": True,
        "passphrase_protected_pem": True,
        "legacy_trusted": legacy_ok,
        "plaintext_retired": retired,
    }


def ensure_forensic_signing_key() -> str:
    """Devuelve key_id; genera o sincroniza par Ed25519."""
    os.makedirs(KEY_DIR, exist_ok=True)
    if os.path.isfile(PRIV_WRAP_PATH) or os.path.isfile(PRIV_PATH):
        # Siempre re-sincronizar público si wrap existe (idempotente / barato)
        try:
            sync_public_key_from_wrap(retire_plaintext=True)
        except Exception:
            _migrate_plaintext_if_needed()
        if os.path.isfile(META_PATH):
            with open(META_PATH, encoding="utf-8") as fh:
                meta = json.load(fh)
            return meta.get("key_id") or "novus-ed25519-default"

    from services.key_protection_service import write_wrapped_file

    private_key = Ed25519PrivateKey.generate()
    key_id = f"NOVUS-ED25519-{uuid.uuid4().hex[:12]}"
    enc_pem = _private_pem_encrypted(private_key)
    write_wrapped_file(PRIV_WRAP_PATH, enc_pem)
    _write_public_from_private(private_key)
    pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _trust_add_public(pub, key_id=key_id, label="active")
    with open(META_PATH, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "key_id": key_id,
                "algorithm": "Ed25519",
                "private_storage": "wrapped+passphrase",
                "pem_encryption": "BestAvailableEncryption",
                "created_at": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            fh,
            indent=2,
        )
    return key_id


def load_signing_keypair() -> Tuple[Ed25519PrivateKey, str]:
    kid = ensure_forensic_signing_key()
    pem = _read_private_pem()
    private_key = _load_private_key_from_pem(pem)
    return private_key, kid


def load_verify_public_key() -> bytes:
    ensure_forensic_signing_key()
    with open(PUB_PATH, "rb") as fh:
        return fh.read()


def load_trusted_public_keys() -> List[Tuple[str, Ed25519PublicKey]]:
    """Todas las claves públicas de confianza (activa + trust_store)."""
    ensure_forensic_signing_key()
    out: List[Tuple[str, Ed25519PublicKey]] = []
    seen = set()
    paths = [PUB_PATH]
    if os.path.isdir(TRUST_DIR):
        for name in os.listdir(TRUST_DIR):
            if name.endswith(".pem"):
                paths.append(os.path.join(TRUST_DIR, name))
    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            pem = open(path, "rb").read()
            digest = hashlib.sha256(pem).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            pub = serialization.load_pem_public_key(pem)
            if isinstance(pub, Ed25519PublicKey):
                out.append((os.path.basename(path), pub))
        except Exception:
            continue
    return out


def forensic_key_status() -> dict:
    passphrase_wrap = os.path.isfile(PASSPHRASE_WRAP) or bool(
        os.environ.get("NOVUS_FORENSIC_KEY_PASSPHRASE", "").strip()
    )
    pem_encrypted = False
    try:
        if os.path.isfile(PRIV_WRAP_PATH):
            from services.key_protection_service import read_wrapped_file

            raw = read_wrapped_file(PRIV_WRAP_PATH)
            # Si carga sin password falla o requiere password → cifrado
            try:
                serialization.load_pem_private_key(raw, password=None)
                pem_encrypted = False
            except TypeError:
                pem_encrypted = True
            except Exception:
                try:
                    serialization.load_pem_private_key(raw, password=_passphrase_bytes())
                    pem_encrypted = True
                except Exception:
                    pem_encrypted = False
    except Exception:
        pass
    return {
        "private_wrapped": os.path.isfile(PRIV_WRAP_PATH),
        "private_plaintext_present": os.path.isfile(PRIV_PATH),
        "public_present": os.path.isfile(PUB_PATH),
        "meta_present": os.path.isfile(META_PATH),
        "passphrase_configured": passphrase_wrap,
        "pem_passphrase_encrypted": pem_encrypted,
        "trust_store_keys": len(
            [n for n in os.listdir(TRUST_DIR) if n.endswith(".pem")]
        )
        if os.path.isdir(TRUST_DIR)
        else 0,
    }
