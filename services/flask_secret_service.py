"""
SECRET_KEY de Flask — sin fallback hardcodeado.
Prioridad: env SECRET_KEY → archivo envuelto → generar y envolver nuevo.
"""
from __future__ import annotations

import os
import secrets
from typing import Tuple

from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET_DIR = os.path.join(ROOT, "data", "secrets")
SECRET_WRAP = os.path.join(SECRET_DIR, "flask_secret.wrap")


def resolve_flask_secret_key() -> Tuple[str, str]:
    """
    Returns (secret_key, source) where source in {env, wrapped_file, generated, generated_ephemeral}.
    Nunca usa el literal hardcodeado histórico.
    CLOUD-P0: beta/production y NOVUS_REQUIRE_SHARED_SECRET=1 exigen secreto compartido
    (env o archivo envuelto) — no ephemeral por proceso (rompe multi-instancia).
    """
    env = (os.environ.get("SECRET_KEY") or "").strip()
    if env and env != "clave_secreta_definitiva_para_novus_2026":
        return env, "env"

    require_shared = os.environ.get("NOVUS_REQUIRE_SHARED_SECRET", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    novus_env = (os.environ.get("NOVUS_ENV") or "development").strip().lower()
    cloudish = require_shared or novus_env in ("beta", "production", "cloud")

    os.makedirs(SECRET_DIR, exist_ok=True)
    if os.path.isfile(SECRET_WRAP):
        try:
            from services.key_protection_service import read_wrapped_file

            raw = read_wrapped_file(SECRET_WRAP)
            text = raw.decode("utf-8").strip()
            if text:
                if cloudish and not env:
                    logger.warning(
                        "SECRET_KEY via wrapped_file — set SECRET_KEY env (Secret Manager) "
                        "for multi-instance Cloud Run"
                    )
                return text, "wrapped_file"
        except Exception as exc:
            logger.error("flask secret unwrap failed: %s", exc)

    if cloudish:
        raise RuntimeError(
            "CLOUD-P0: SECRET_KEY must be provided via environment (or existing wrapped file) "
            "for shared multi-instance session signing. Refusing per-process ephemeral key."
        )

    # Generar nuevo secreto fuerte y envolverlo (solo development)
    new_key = secrets.token_urlsafe(48)
    try:
        from services.key_protection_service import write_wrapped_file

        write_wrapped_file(SECRET_WRAP, new_key.encode("utf-8"))
        from services.sensitive_operations_audit import log_sensitive_operation

        log_sensitive_operation(
            "flask_secret_generated",
            actor="system",
            outcome="success",
            detail={"storage": SECRET_WRAP},
        )
    except Exception as exc:
        logger.error("flask secret persist failed: %s", exc)
        return new_key, "generated_ephemeral"

    return new_key, "generated"


def flask_secret_status() -> dict:
    return {
        "env_set": bool((os.environ.get("SECRET_KEY") or "").strip()),
        "wrapped_file_present": os.path.isfile(SECRET_WRAP),
        "hardcoded_fallback_removed": True,
        "require_shared_secret": os.environ.get("NOVUS_REQUIRE_SHARED_SECRET", "").strip().lower()
        in ("1", "true", "yes", "on"),
        "cloud_p0_ephemeral_blocked_in_beta_production": True,
    }
