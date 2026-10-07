"""
Gmail OAuth 2.0 service — official Google API only.
Never stores passwords; tokens persisted per user under data/gmail/.
"""
import json
import os
from datetime import datetime

from flask import session, request
from utils.logger import logger

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GMAIL_DATA_DIR = os.path.join(BASE_DIR, "data", "gmail")

GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]

OAUTH_PENDING_KEY = "gmail_oauth_state"


def _user_token_path(user_id):
    path = os.path.join(GMAIL_DATA_DIR, str(user_id))
    os.makedirs(path, exist_ok=True)
    return os.path.join(path, "token.json")


def is_oauth_configured():
    """True when Google Cloud OAuth client credentials are set."""
    from core.config import Config
    return bool(Config.GOOGLE_CLIENT_ID and Config.GOOGLE_CLIENT_SECRET)


def get_setup_instructions():
    from core.config import Config
    from core.public_url import get_oauth_callback_url
    redirect = Config.GOOGLE_REDIRECT_URI or get_oauth_callback_url()
    if not redirect:
        redirect = "(configure NOVUS_PUBLIC_URL o acceda vía túnel para generar callback automático)"
    return {
        "configured": is_oauth_configured(),
        "steps": [
            "Crear un proyecto en Google Cloud Console (https://console.cloud.google.com).",
            "Habilitar la Gmail API en APIs y servicios > Biblioteca.",
            "Crear credenciales OAuth 2.0 (tipo Aplicación web).",
            f"Añadir URI de redirección autorizada: {redirect}",
            "Definir variables de entorno GOOGLE_CLIENT_ID y GOOGLE_CLIENT_SECRET en el servidor NOVUS.",
            "Opcional: GOOGLE_REDIRECT_URI si difiere del callback automático.",
            "Reiniciar NOVUS y usar «Conectar Gmail» en Kernel IA > Seguridad del correo.",
        ],
        "env_vars": ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI (opcional)"],
        "security_note": "NOVUS nunca solicita contraseña de Gmail. Solo OAuth 2.0 oficial.",
    }


def _build_flow(redirect_uri):
    from google_auth_oauthlib.flow import Flow
    from core.config import Config

    client_config = {
        "web": {
            "client_id": Config.GOOGLE_CLIENT_ID,
            "client_secret": Config.GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri],
        }
    }
    return Flow.from_client_config(client_config, scopes=GMAIL_SCOPES, redirect_uri=redirect_uri)


def get_redirect_uri():
    from core.config import Config
    from core.public_url import get_oauth_callback_url
    if Config.GOOGLE_REDIRECT_URI:
        return Config.GOOGLE_REDIRECT_URI
    uri = get_oauth_callback_url()
    if uri:
        return uri
    return request.host_url.rstrip("/") + "/api/gmail/oauth/callback"


def start_oauth(user_id):
    if not is_oauth_configured():
        return None, "OAuth no configurado. Revise GOOGLE_CLIENT_ID y GOOGLE_CLIENT_SECRET."

    redirect_uri = get_redirect_uri()
    flow = _build_flow(redirect_uri)
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    session[OAUTH_PENDING_KEY] = {"state": state, "user_id": user_id}
    return auth_url, None


def complete_oauth(user_id, authorization_response):
    pending = session.pop(OAUTH_PENDING_KEY, None)
    if not pending or pending.get("user_id") != user_id:
        return False, "Estado OAuth inválido o sesión expirada."

    redirect_uri = get_redirect_uri()
    flow = _build_flow(redirect_uri)
    flow.fetch_token(authorization_response=authorization_response)
    creds = flow.credentials

    token_data = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": list(creds.scopes or GMAIL_SCOPES),
        "expiry": creds.expiry.isoformat() if creds.expiry else None,
        "connected_at": datetime.now().isoformat(),
        "email": None,
    }

    path = _user_token_path(user_id)
    # Fase 1: no persistir token.json en claro — solo vault cifrado
    try:
        from services.mail_shield_token_vault import save_credentials
        if not save_credentials("google_workspace", user_id, token_data):
            # Fallback temporal solo si vault falla (compatibilidad operativa)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(token_data, f, indent=2)
            logger.warning("Gmail token vault failed; wrote legacy token.json for user %s", user_id)
        else:
            # Eliminar plaintext legado si existía
            if os.path.isfile(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
            try:
                from services.data_access_audit_service import log_data_access

                log_data_access(
                    resource=f"gmail_oauth/{user_id}",
                    operation="store_token_vault",
                    result="success",
                    user_email=None,
                )
            except Exception:
                pass
    except Exception as exc:
        logger.error("mail_shield vault google: %s", exc)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(token_data, f, indent=2)

    logger.info(f"Gmail OAuth connected for user {user_id}")
    return True, "Gmail conectado correctamente vía OAuth 2.0."


def disconnect(user_id):
    path = _user_token_path(user_id)
    if os.path.isfile(path):
        os.remove(path)
    try:
        from services.mail_shield_token_vault import delete_credentials

        delete_credentials("google_workspace", user_id)
    except Exception:
        pass
    meta = os.path.join(GMAIL_DATA_DIR, str(user_id), "meta.json")
    if os.path.isfile(meta):
        os.remove(meta)
    return True


def _load_token_dict(user_id):
    """Carga dict de credenciales: vault primero, migra token.json si existe."""
    data = None
    try:
        from services.mail_shield_token_vault import load_credentials, save_credentials

        data = load_credentials("google_workspace", user_id)
    except Exception:
        data = None

    path = _user_token_path(user_id)
    if data is None and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Migrar a vault y retirar plaintext
            try:
                from services.mail_shield_token_vault import save_credentials

                if save_credentials("google_workspace", user_id, data):
                    os.remove(path)
            except Exception:
                pass
        except Exception:
            return None
    return data


def load_credentials(user_id):
    if not is_oauth_configured():
        return None

    data = _load_token_dict(user_id)
    if not data:
        return None

    try:
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request

        creds = Credentials(
            token=data.get("token"),
            refresh_token=data.get("refresh_token"),
            token_uri=data.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=data.get("client_id"),
            client_secret=data.get("client_secret"),
            scopes=data.get("scopes", GMAIL_SCOPES),
        )

        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            data["token"] = creds.token
            data["expiry"] = creds.expiry.isoformat() if creds.expiry else None
            try:
                from services.mail_shield_token_vault import save_credentials

                save_credentials("google_workspace", user_id, data)
            except Exception:
                path = _user_token_path(user_id)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)

        return creds
    except Exception as exc:
        logger.error(f"Gmail credentials error user {user_id}: {exc}")
        return None


def is_connected(user_id):
    return load_credentials(user_id) is not None


def get_connection_status(user_id):
    connected = is_connected(user_id)
    meta_path = os.path.join(GMAIL_DATA_DIR, str(user_id), "meta.json")
    email = None
    last_sync = None
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            email = meta.get("email")
            last_sync = meta.get("last_sync")
        except Exception:
            pass

    return {
        "oauth_configured": is_oauth_configured(),
        "connected": connected,
        "email": email,
        "last_sync": last_sync,
        "protection_active": connected and is_oauth_configured(),
    }


def save_meta(user_id, **fields):
    path = os.path.join(GMAIL_DATA_DIR, str(user_id), "meta.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    meta = {}
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {}
    meta.update(fields)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
