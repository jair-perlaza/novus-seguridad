"""Microsoft 365 — OAuth 2.0 / Microsoft Graph (preparado, requiere credenciales Azure)."""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from utils.logger import logger

GRAPH_SCOPES = (
    "https://graph.microsoft.com/Mail.Read",
    "https://graph.microsoft.com/Mail.ReadWrite",
    "offline_access",
    "openid",
    "profile",
)


def is_oauth_configured() -> bool:
    return bool(
        os.environ.get("AZURE_CLIENT_ID", "").strip()
        and os.environ.get("AZURE_CLIENT_SECRET", "").strip()
        and os.environ.get("AZURE_TENANT_ID", "").strip()
    )


def get_setup_instructions() -> Dict[str, Any]:
    redirect = os.environ.get("AZURE_REDIRECT_URI", "").strip() or "(configure AZURE_REDIRECT_URI o NOVUS_PUBLIC_URL + /api/mail-shield/m365/oauth/callback)"
    return {
        "configured": is_oauth_configured(),
        "provider": "microsoft365",
        "steps": [
            "Registrar aplicación en Azure Portal > Entra ID > Registros de aplicaciones.",
            "Permisos delegados Microsoft Graph: Mail.Read, Mail.ReadWrite (admin consent).",
            f"URI de redirección: {redirect}",
            "Variables: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, AZURE_REDIRECT_URI (opcional).",
            "Autorización explícita del administrador del tenant Microsoft 365.",
        ],
        "env_vars": ["AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID", "AZURE_REDIRECT_URI"],
        "security_note": "Tokens almacenados cifrados vía CryptoVault — mail_shield_token_vault.",
    }


def get_connection_status(user_id) -> Dict[str, Any]:
    from services.mail_shield_token_vault import load_credentials

    if not is_oauth_configured():
        return {
            "provider": "microsoft365",
            "oauth_configured": False,
            "connected": False,
            "message": "Integración no configurada",
        }
    creds = load_credentials("microsoft365", user_id)
    if not creds:
        return {
            "provider": "microsoft365",
            "oauth_configured": True,
            "connected": False,
            "message": "Esperando autorización del cliente (OAuth)",
        }
    return {
        "provider": "microsoft365",
        "oauth_configured": True,
        "connected": True,
        "email": creds.get("email"),
        "connected_at": creds.get("connected_at"),
        "last_sync": creds.get("last_sync"),
    }


def start_oauth(user_id) -> Tuple[Optional[str], Optional[str]]:
    if not is_oauth_configured():
        return None, "Integración Microsoft 365 no configurada en el servidor."
    tenant = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ["AZURE_CLIENT_ID"]
    redirect = os.environ.get("AZURE_REDIRECT_URI") or ""
    if not redirect:
        from core.public_url import get_oauth_callback_url
        base = get_oauth_callback_url() or ""
        redirect = f"{base}/api/mail-shield/m365/oauth/callback" if base else ""
    if not redirect:
        return None, "Defina AZURE_REDIRECT_URI o NOVUS_PUBLIC_URL."
    scope = " ".join(GRAPH_SCOPES)
    url = (
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
        f"?client_id={client_id}&response_type=code&redirect_uri={redirect}"
        f"&response_mode=query&scope={scope}&state={user_id}"
    )
    return url, None


def complete_oauth(user_id, authorization_code: str) -> Tuple[bool, str]:
    """Intercambia code por tokens vía endpoint oficial Microsoft."""
    if not is_oauth_configured():
        return False, "Integración no configurada"
    import urllib.parse
    import urllib.request

    tenant = os.environ["AZURE_TENANT_ID"]
    redirect = os.environ.get("AZURE_REDIRECT_URI", "")
    if not redirect:
        from core.public_url import get_oauth_callback_url
        redirect = f"{get_oauth_callback_url()}/api/mail-shield/m365/oauth/callback"

    data = urllib.parse.urlencode({
        "client_id": os.environ["AZURE_CLIENT_ID"],
        "client_secret": os.environ["AZURE_CLIENT_SECRET"],
        "code": authorization_code,
        "redirect_uri": redirect,
        "grant_type": "authorization_code",
    }).encode()
    token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    try:
        req = urllib.request.Request(token_url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
        import json
        tokens = json.loads(body)
        if "error" in tokens:
            return False, tokens.get("error_description") or tokens["error"]
        from services.mail_shield_token_vault import save_credentials
        save_credentials("microsoft365", user_id, {
            **tokens,
            "connected_at": datetime.now().isoformat(),
        })
        return True, "Microsoft 365 conectado vía OAuth 2.0."
    except Exception as exc:
        logger.error("m365 oauth: %s", exc)
        return False, str(exc)


def sync_messages(user_id) -> Dict[str, Any]:
    """Graph API — requiere token válido; analiza mensajes reales."""
    from services.mail_shield_token_vault import load_credentials

    creds = load_credentials("microsoft365", user_id)
    if not creds or not creds.get("access_token"):
        return {"status": "error", "message": "Microsoft 365 no conectado", "analyzed": 0}

    import json
    import urllib.request

    headers = {"Authorization": f"Bearer {creds['access_token']}", "Accept": "application/json"}
    url = "https://graph.microsoft.com/v1.0/me/messages?$top=10&$filter=isRead eq false"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        return {"status": "error", "message": str(exc), "analyzed": 0}

    from services.mail_shield_analyzer import analyze_graph_message
    from services.mail_shield_service import ingest_analysis_record

    analyzed = []
    for msg in data.get("value") or []:
        record = analyze_graph_message(msg)
        ingest_analysis_record(user_id, "microsoft365", record)
        analyzed.append(record)
    return {"status": "success", "analyzed": len(analyzed), "records": analyzed}
