"""Tokens OAuth Mail Shield — cifrado con CryptoVault (sin texto plano en disco)."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from utils.logger import logger

BASE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "mail_shield", "tokens")


def _path(provider: str, user_id) -> str:
    folder = os.path.join(BASE, provider, str(user_id))
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, "credentials.vault")


def _vault():
    from crypto_vault import CryptoVault
    return CryptoVault()


def save_credentials(provider: str, user_id, data: Dict[str, Any]) -> bool:
    try:
        vault = _vault()
        payload = json.dumps(data, ensure_ascii=False)
        sealed = vault.proteger(payload)
        with open(_path(provider, user_id), "w", encoding="utf-8") as fh:
            json.dump({"sealed": sealed, "provider": provider}, fh)
        return True
    except Exception as exc:
        logger.error("mail_shield_token_vault save: %s", exc)
        return False


def load_credentials(provider: str, user_id) -> Optional[Dict[str, Any]]:
    path = _path(provider, user_id)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            wrap = json.load(fh)
        vault = _vault()
        plain = vault.desproteger(wrap["sealed"])
        return json.loads(plain)
    except Exception as exc:
        logger.error("mail_shield_token_vault load: %s", exc)
        return None


def delete_credentials(provider: str, user_id) -> None:
    path = _path(provider, user_id)
    if os.path.isfile(path):
        os.remove(path)
