"""
CryptoVault — AES-256-GCM + identidad ECC X25519.

Fase 1 Protección de Datos:
- Claves AES envueltas (DPAPI / NOVUS_KEY_WRAP_SECRET), no plaintext en disco.
- Versionado NOVUSENC:v2:{kid}:{b64} con compatibilidad de ciphertext legado.
- ECC privada envuelta; pública en claro.
"""
from __future__ import annotations

import base64
import json
import os
import uuid
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

ROOT = os.path.dirname(os.path.abspath(__file__))
KEYRING_DIR = os.path.join(ROOT, "data", "cryptovault")
KEYS_DIR = os.path.join(KEYRING_DIR, "keys")
LEGACY_DIR = os.path.join(KEYRING_DIR, "legacy")
KEYRING_PATH = os.path.join(KEYRING_DIR, "keyring.json")
LEGACY_AES_PATH = "master_aes.key"
LEGACY_ECC_PRIV = "ecc_private.key"
LEGACY_ECC_PUB = "ecc_public.key"
ENC_PREFIX = "NOVUSENC:v2:"


def _ensure_dirs() -> None:
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(LEGACY_DIR, exist_ok=True)


def _new_kid() -> str:
    return f"aes-{uuid.uuid4().hex[:12]}"


class CryptoVault:
    def __init__(self):
        self.archivo_ecc_priv = LEGACY_ECC_PRIV
        self.archivo_ecc_pub = LEGACY_ECC_PUB
        self.key_path = LEGACY_AES_PATH  # compat API / health checks
        self.llave_aes: Optional[bytes] = None
        self.active_kid: Optional[str] = None
        self._key_cache: Dict[str, bytes] = {}
        self.aesgcm: Optional[AESGCM] = None
        _ensure_dirs()
        self._inicializar_identidad_ecc()
        self._cargar_o_migrar_aes()

    # —— Keyring ——
    def _load_keyring(self) -> Dict[str, Any]:
        if not os.path.isfile(KEYRING_PATH):
            return {"version": 1, "active_kid": None, "keys": []}
        try:
            with open(KEYRING_PATH, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                data.setdefault("version", 1)
                data.setdefault("keys", [])
                return data
        except Exception:
            pass
        return {"version": 1, "active_kid": None, "keys": []}

    def _save_keyring(self, ring: Dict[str, Any]) -> None:
        _ensure_dirs()
        tmp = KEYRING_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(ring, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, KEYRING_PATH)
        try:
            from services.data_integrity_service import mark_artifact_hash

            mark_artifact_hash("cryptovault_keyring", KEYRING_PATH)
        except Exception:
            pass

    def _wrapped_path(self, kid: str) -> str:
        return os.path.join(KEYS_DIR, f"{kid}.aes.wrap")

    def _store_key_version(self, kid: str, raw_key: bytes, *, make_active: bool = True) -> None:
        from services.key_protection_service import write_wrapped_file

        write_wrapped_file(self._wrapped_path(kid), raw_key)
        ring = self._load_keyring()
        keys = [k for k in ring.get("keys") or [] if k.get("kid") != kid]
        from datetime import datetime

        keys.append(
            {
                "kid": kid,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "wrapped_file": self._wrapped_path(kid),
            }
        )
        ring["keys"] = keys
        if make_active:
            ring["active_kid"] = kid
        self._save_keyring(ring)
        self._key_cache[kid] = raw_key

    def _load_key_by_kid(self, kid: str) -> Optional[bytes]:
        if kid in self._key_cache:
            return self._key_cache[kid]
        path = self._wrapped_path(kid)
        if not os.path.isfile(path):
            ring = self._load_keyring()
            for entry in ring.get("keys") or []:
                if entry.get("kid") == kid and entry.get("wrapped_file"):
                    path = entry["wrapped_file"]
                    break
        if not os.path.isfile(path):
            return None
        from services.key_protection_service import read_wrapped_file

        raw = read_wrapped_file(path)
        if len(raw) != 32:
            return None
        self._key_cache[kid] = raw
        return raw

    def _migrate_legacy_aes_if_needed(self) -> None:
        ring = self._load_keyring()
        if ring.get("active_kid") and os.path.isfile(self._wrapped_path(ring["active_kid"])):
            return
        if not os.path.isfile(LEGACY_AES_PATH):
            return
        with open(LEGACY_AES_PATH, "rb") as fh:
            raw = fh.read()
        if not raw or len(raw) not in (16, 24, 32):
            return
        kid = _new_kid()
        self._store_key_version(kid, raw, make_active=True)
        # Retirar plaintext del cwd operativo
        dest = os.path.join(LEGACY_DIR, f"master_aes.key.migrated.{kid}")
        try:
            os.replace(LEGACY_AES_PATH, dest)
        except Exception:
            try:
                import shutil

                shutil.copy2(LEGACY_AES_PATH, dest)
                os.remove(LEGACY_AES_PATH)
            except Exception:
                pass

    def _cargar_o_migrar_aes(self) -> None:
        self._migrate_legacy_aes_if_needed()
        ring = self._load_keyring()
        kid = ring.get("active_kid")
        raw: Optional[bytes] = None
        if kid:
            raw = self._load_key_by_kid(kid)
        if raw is None and os.path.isfile(LEGACY_AES_PATH):
            with open(LEGACY_AES_PATH, "rb") as fh:
                raw = fh.read()
            if raw:
                kid = kid or _new_kid()
                self._store_key_version(kid, raw, make_active=True)
        if raw is None:
            raw = AESGCM.generate_key(bit_length=256)
            kid = _new_kid()
            self._store_key_version(kid, raw, make_active=True)
        self.llave_aes = raw
        self.active_kid = kid
        self.aesgcm = AESGCM(raw)
        # Marcador de compatibilidad para health checks antiguos
        self.key_path = self._wrapped_path(kid) if kid else LEGACY_AES_PATH

    def list_key_ids(self) -> List[str]:
        ring = self._load_keyring()
        return [k.get("kid") for k in ring.get("keys") or [] if k.get("kid")]

    def rotate_aes_key(self, *, actor: str = "system") -> Dict[str, Any]:
        """Nueva versión activa; versiones previas permanecen para descifrado."""
        new_raw = AESGCM.generate_key(bit_length=256)
        kid = _new_kid()
        prev = self.active_kid
        self._store_key_version(kid, new_raw, make_active=True)
        self.llave_aes = new_raw
        self.active_kid = kid
        self.aesgcm = AESGCM(new_raw)
        self.key_path = self._wrapped_path(kid)
        result = {
            "status": "success",
            "new_kid": kid,
            "previous_kid": prev,
            "keys_retained": self.list_key_ids(),
            "actor": actor,
        }
        try:
            from services.sensitive_operations_audit import log_sensitive_operation

            log_sensitive_operation(
                "cryptovault_aes_rotate_versioned",
                actor=actor,
                outcome="success",
                detail={"new_kid": kid, "previous_kid": prev},
            )
        except Exception:
            pass
        try:
            from services.forensic_evidence_integrity_service import seal_evidence

            seal_evidence(
                source_id=f"AES-ROTATE-{kid}",
                source_type="cryptovault_rotation",
                motor="cryptovault",
                evidence_type="key_rotation",
                payload={
                    "new_kid": kid,
                    "previous_kid": prev,
                    "keys_retained_n": len(self.list_key_ids()),
                    "verifiable": True,
                },
                equipment=os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME"),
            )
        except Exception:
            pass
        return result

    # —— ECC ——
    def _inicializar_identidad_ecc(self):
        """Curve25519 — privada envuelta; pública en claro."""
        from services.key_protection_service import (
            is_wrapped_blob,
            read_wrapped_file,
            write_wrapped_file,
        )

        wrapped_priv = LEGACY_ECC_PRIV + ".wrap"
        pub_path = LEGACY_ECC_PUB

        if os.path.isfile(wrapped_priv):
            return
        if os.path.isfile(LEGACY_ECC_PRIV):
            # Migrar plaintext → wrap
            with open(LEGACY_ECC_PRIV, "rb") as fh:
                raw = fh.read()
            write_wrapped_file(wrapped_priv, raw)
            dest = os.path.join(LEGACY_DIR, "ecc_private.key.migrated")
            try:
                os.replace(LEGACY_ECC_PRIV, dest)
            except Exception:
                pass
            return

        priv_key = x25519.X25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        write_wrapped_file(wrapped_priv, priv_pem)
        with open(pub_path, "wb") as f:
            f.write(pub_pem)

    def load_ecc_private_pem(self) -> bytes:
        from services.key_protection_service import read_wrapped_file

        wrapped_priv = LEGACY_ECC_PRIV + ".wrap"
        if os.path.isfile(wrapped_priv):
            return read_wrapped_file(wrapped_priv)
        if os.path.isfile(LEGACY_ECC_PRIV):
            with open(LEGACY_ECC_PRIV, "rb") as fh:
                return fh.read()
        raise FileNotFoundError("ECC private key no disponible")

    # —— Encrypt / decrypt ——
    def proteger(self, texto: str) -> str:
        """Cifrado AES-256-GCM versionado (compatible con lectores v2)."""
        try:
            if not self.aesgcm or not self.active_kid:
                return "[ERROR EN CIFRADO]"
            nonce = os.urandom(12)
            token_cifrado = self.aesgcm.encrypt(nonce, texto.encode(), None)
            b64 = base64.b64encode(nonce + token_cifrado).decode("utf-8")
            return f"{ENC_PREFIX}{self.active_kid}:{b64}"
        except Exception:
            return "[ERROR EN CIFRADO]"

    def _decrypt_with_key(self, raw_key: bytes, blob: bytes) -> str:
        nonce, payload = blob[:12], blob[12:]
        return AESGCM(raw_key).decrypt(nonce, payload, None).decode("utf-8")

    def desproteger(self, token_b64: str) -> str:
        """Descifrado con kid activo, keyring histórico o ciphertext legado."""
        try:
            if not token_b64 or token_b64.startswith("[ERROR"):
                return "[ERROR: DATO CORRUPTO O LLAVE INVÁLIDA]"

            if token_b64.startswith(ENC_PREFIX):
                rest = token_b64[len(ENC_PREFIX) :]
                kid, _, b64 = rest.partition(":")
                raw = self._load_key_by_kid(kid)
                if raw is None:
                    return "[ERROR: DATO CORRUPTO O LLAVE INVÁLIDA]"
                return self._decrypt_with_key(raw, base64.b64decode(b64))

            # Legado: base64(nonce+ct) sin kid — probar todas las claves
            datos = base64.b64decode(token_b64)
            candidates: List[Tuple[str, bytes]] = []
            if self.llave_aes and self.active_kid:
                candidates.append((self.active_kid, self.llave_aes))
            for kid in self.list_key_ids():
                if self.active_kid and kid == self.active_kid:
                    continue
                k = self._load_key_by_kid(kid)
                if k:
                    candidates.append((kid, k))
            last_err = None
            for _kid, key in candidates:
                try:
                    return self._decrypt_with_key(key, datos)
                except Exception as exc:
                    last_err = exc
                    continue
            if last_err:
                return "[ERROR: DATO CORRUPTO O LLAVE INVÁLIDA]"
            return "[ERROR: DATO CORRUPTO O LLAVE INVÁLIDA]"
        except Exception:
            return "[ERROR: DATO CORRUPTO O LLAVE INVÁLIDA]"

    def get_tls_status(self):
        """
        Estado TLS solo si hay evidencia objetiva (handshake o HTTPS público verificado).
        No afirma TLS 1.3 Active sin prueba.
        """
        try:
            from services.tls_channel_service import get_tls_status_label

            return get_tls_status_label()
        except Exception:
            secure = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
            behind = os.environ.get("NOVUS_BEHIND_PROXY", "False").lower() == "true"
            return (
                f"TLS_NOT_TERMINATED_BY_APP "
                f"(session_cookie_secure={secure}, behind_proxy={behind})"
            )

    def proteger_json(self, payload: dict) -> str:
        return self.proteger(json.dumps(payload, ensure_ascii=True))

    def desproteger_json(self, token_b64: str):
        raw = self.desproteger(token_b64)
        if raw.startswith("[ERROR"):
            return {"error": raw}
        try:
            return json.loads(raw)
        except Exception:
            return {"raw": raw}

    def verify_health(self) -> dict:
        sample = "NOVUS-CryptoVault-Health"
        token = self.proteger(sample)
        ok = self.desproteger(token) == sample
        # Compat legado: cifrar estilo antiguo y recuperar
        legacy_ok = False
        try:
            nonce = os.urandom(12)
            legacy_b64 = base64.b64encode(
                nonce + self.aesgcm.encrypt(nonce, sample.encode(), None)
            ).decode("utf-8")
            legacy_ok = self.desproteger(legacy_b64) == sample
        except Exception:
            legacy_ok = False
        from services.key_protection_service import protection_status

        wrap = protection_status()
        wrapped_active = bool(
            self.active_kid and os.path.isfile(self._wrapped_path(self.active_kid))
        )
        plaintext_aes_present = os.path.isfile(LEGACY_AES_PATH)
        return {
            "aes_gcm_roundtrip": ok,
            "legacy_ciphertext_roundtrip": legacy_ok,
            "ecc_private": os.path.isfile(LEGACY_ECC_PRIV + ".wrap")
            or os.path.isfile(LEGACY_ECC_PRIV),
            "ecc_private_wrapped": os.path.isfile(LEGACY_ECC_PRIV + ".wrap"),
            "ecc_public": os.path.isfile(LEGACY_ECC_PUB),
            "aes_key": wrapped_active or plaintext_aes_present,
            "aes_key_wrapped": wrapped_active,
            "aes_plaintext_retired": not plaintext_aes_present,
            "active_kid": self.active_kid,
            "key_versions": len(self.list_key_ids()),
            "key_wrap": wrap,
            "tls_status": self.get_tls_status(),
            "status": "success" if ok else "failed",
        }
