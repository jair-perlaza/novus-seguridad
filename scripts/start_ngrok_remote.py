#!/usr/bin/env python3
"""
Expone NOVUS (puerto 5000) mediante túnel NGROK para acceso remoto autenticado.
Requiere: servidor NOVUS activo, ngrok/pyngrok instalado, NOVUS_BEHIND_PROXY=True.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REMOTE_INFO = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "remote_access.json")


def _check_novus(port: int) -> bool:
    try:
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/login", timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def main():
    port = int(os.environ.get("PORT", os.environ.get("NOVUS_PORT", 5000)))

    print("=" * 60)
    print("NOVUS — Túnel NGROK (acceso remoto con autenticación)")
    print("=" * 60)

    if not _check_novus(port):
        print(f"ERROR: NOVUS no responde en http://127.0.0.1:{port}/login")
        print("Inicie el servidor primero: py -3 main.py")
        return 1

    print(f"NOVUS activo en puerto {port}")

    public_url = None
    try:
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=3) as resp:
            data = json.loads(resp.read().decode())
            for t in data.get("tunnels") or []:
                addr = (t.get("config") or {}).get("addr", "")
                if str(port) in addr and t.get("public_url"):
                    public_url = t["public_url"]
                    print(f"Túnel existente detectado: {public_url}")
                    break
    except Exception:
        pass

    if not public_url:
        try:
            from pyngrok import ngrok
        except ImportError:
            print("ERROR: instale pyngrok — pip install pyngrok")
            return 1

        try:
            tunnel = ngrok.connect(port, "http")
            public_url = tunnel.public_url
        except Exception as exc:
            err = str(exc)
            if "already online" in err or "ERR_NGROK_334" in err:
                try:
                    import urllib.request
                    with urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=3) as resp:
                        data = json.loads(resp.read().decode())
                        for t in data.get("tunnels") or []:
                            if t.get("public_url"):
                                public_url = t["public_url"]
                                print(f"Túnel existente reutilizado: {public_url}")
                                break
                except Exception:
                    pass
            if not public_url:
                print(f"ERROR al crear túnel ngrok: {exc}")
                return 1

    info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "public_url": public_url,
        "local_url": f"http://127.0.0.1:{port}",
        "login_url": f"{public_url}/login",
        "sector_login_url": f"{public_url}/sector-login",
        "proxy_required_env": {
            "NOVUS_BEHIND_PROXY": "True",
            "NOVUS_TRUSTED_PROXY_COUNT": "1",
            "NOVUS_PUBLIC_URL": public_url,
            "SESSION_COOKIE_SECURE": "True",
            "PREFERRED_URL_SCHEME": "https",
        },
        "auth_note": "Autenticación obligatoria — sin acceso anónimo a la plataforma",
    }

    os.makedirs(os.path.dirname(REMOTE_INFO), exist_ok=True)
    with open(REMOTE_INFO, "w", encoding="utf-8") as fh:
        json.dump(info, fh, ensure_ascii=False, indent=2)

    print("\n" + "=" * 60)
    print("URL PÚBLICA NGROK:")
    print(public_url)
    print("=" * 60)
    print(f"Login:         {info['login_url']}")
    print(f"Sector login:  {info['sector_login_url']}")
    print(f"\nConfigure en .env: NOVUS_PUBLIC_URL={public_url}")
    print("NOVUS_BEHIND_PROXY=True (requerido para IP real del cliente)")
    print("\nMantenga esta ventana abierta. Ctrl+C para cerrar el túnel.")

    try:
        while True:
            time.sleep(30)
    except KeyboardInterrupt:
        print("\nCerrando túnel...")
        ngrok.disconnect(public_url)
        print("Túnel cerrado.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
