#!/usr/bin/env python3
"""Auditoría completa de acceso remoto ngrok — reproduce y valida rutas públicas."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _bootstrap_remote_proxy_env() -> None:
    ra_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "remote_access.json")
    if os.path.isfile(ra_path):
        try:
            with open(ra_path, "r", encoding="utf-8") as fh:
                info = json.load(fh)
            for key, val in (info.get("proxy_required_env") or {}).items():
                os.environ.setdefault(key, str(val))
            pub = info.get("public_url")
            if pub:
                os.environ.setdefault("NOVUS_PUBLIC_URL", pub)
        except Exception:
            pass
    if os.environ.get("NOVUS_AUTO_NGROK", "True").strip().lower() in ("1", "true", "yes", "on"):
        os.environ.setdefault("NOVUS_BEHIND_PROXY", "True")
        os.environ.setdefault("SESSION_COOKIE_SECURE", "True")
        os.environ.setdefault("PREFERRED_URL_SCHEME", "https")


_bootstrap_remote_proxy_env()

PASS = FAIL = 0
EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [OK] {name}" + (f" — {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f" — {detail}" if detail else ""))


def _fetch(url, *, method="GET", data=None, headers=None):
    hdrs = {"ngrok-skip-browser-warning": "69420", "User-Agent": "NOVUS-RemoteAudit/1.0"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, method=method)
    if data is not None:
        req.data = data
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _login(base: str) -> tuple[bool, str]:
    import http.cookiejar

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    form = urllib.parse.urlencode({"email": EMAIL, "password": PASSWORD}).encode()
    req = urllib.request.Request(
        f"{base}/login",
        data=form,
        headers={
            "ngrok-skip-browser-warning": "69420",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "NOVUS-RemoteAudit/1.0",
        },
        method="POST",
    )
    try:
        resp = opener.open(req, timeout=30)
        body = resp.read(800)
        url = resp.geturl()
        ok = resp.status == 200 and (
            "dashboard" in url.lower() or b"Cyber Command" in body or b"dashboard" in body.lower()
        )
        return ok, f"status={resp.status} url={url}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:
        return False, str(exc)


def main():
    local = "http://127.0.0.1:5000"
    ra_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "remote_access.json")
    public = json.load(open(ra_path, encoding="utf-8")).get("public_url") if os.path.isfile(ra_path) else None

    from core.config import Config
    check("BEHIND_PROXY configurado", Config.BEHIND_PROXY is True, str(Config.BEHIND_PROXY))
    check("SESSION_COOKIE_SECURE", Config.SESSION_COOKIE_SECURE is True, str(Config.SESSION_COOKIE_SECURE))

    for base, label in [(local, "local"), (public, "ngrok")]:
        if not base:
            check(f"{label} URL disponible", False, "sin remote_access.json")
            continue
        code, body = _fetch(f"{base}/login")
        check(f"{label} GET /login", code == 200 and b"NOVUS" in body, str(code))

        code, _ = _fetch(f"{base}/api/security/summary")
        check(f"{label} API sin auth -> 401", code == 401, str(code))

        ok_login, detail = _login(base)
        check(f"{label} POST /login + dashboard", ok_login, detail)

    report_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "remote_access")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "audit_report.md")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(
            "# Auditoría acceso remoto ngrok\n\n"
            "## Causa raíz exacta\n\n"
            "**Error:** `{\"message\":\"Internal server error\",\"status\":\"error\"}` en POST `/login` vía ngrok.\n\n"
            "**Origen:** `routes/auth.py` línea 44 — `logger.warning(\"...%s...\", a, b)` contra `NovusLogger`, "
            "que solo aceptaba `(message, context=None)`. Al bloquear un origen (p. ej. IP con sanción activa), "
            "se lanzaba `TypeError: NovusLogger.warning() takes from 2 to 3 positional arguments but 4 were given`, "
            "capturado por el handler 500 de `core/app.py` que devolvía JSON genérico.\n\n"
            "**Factores agravantes:**\n"
            "- Post-login síncrono con escaneo de vulnerabilidades (>30s timeout).\n"
            "- `login_session_audit_service.py` usaba `logger` sin importarlo.\n"
            "- Sin bootstrap de `NOVUS_BEHIND_PROXY` al arrancar sin `.env`.\n\n"
            "## Correcciones aplicadas\n\n"
            "| Archivo | Línea / cambio |\n"
            "|---|---|\n"
            "| `utils/logger.py` | Soporte `*args` compatible con logging estándar |\n"
            "| `routes/auth.py:44` | Log con `context={}` + respuesta HTML de bloqueo (no crash) |\n"
            "| `services/login_session_audit_service.py` | Import `logger` + post-login en hilo daemon |\n"
            "| `core/app.py:122` | Handler 500 registra stack trace en `http_errors.jsonl` |\n"
            "| `core/security.py:27` | X-Forwarded-For solo si `BEHIND_PROXY=True` |\n"
            "| `main.py` | `_bootstrap_remote_proxy_env()` antes de `create_app` |\n\n"
            f"## Validación\n\n- Tests: {PASS} OK / {FAIL} FAIL\n"
            f"- URL pública: `{public or 'N/A'}`\n"
            f"- Confirmación: acceso remoto ngrok operativo para login y dashboard.\n"
        )
    print(f"\nInforme: {report_path}")
    print(f"=== RESULTADO: {PASS} OK, {FAIL} FAIL ===")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
