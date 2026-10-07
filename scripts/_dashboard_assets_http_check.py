#!/usr/bin/env python3
"""Verifica URLs de assets referenciadas en index.html (sin autenticación)."""
from __future__ import annotations

import json
import os
import re
import sys

import requests

ROOT = os.path.dirname(os.path.dirname(__file__))
INDEX = os.path.join(ROOT, "templates", "index.html")
BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000").rstrip("/")


def main() -> int:
    html = open(INDEX, encoding="utf-8").read()
    externals = re.findall(r'(?:src|href)=["\'](https?://[^"\']+)["\']', html, re.I)
    # Tailwind original (cdn.tailwindcss.com) puede estar caído; el mirror jsDelivr es la fuente activa.
    if "@tailwindcss/browser" in html:
        externals.append("https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4")
    statics = re.findall(
        r'url_for\(\s*[\'"]static[\'"]\s*,\s*filename=[\'"]([^\'"]+)[\'"]\s*\)',
        html,
    )
    results = {"external": [], "static": [], "dead_tailwind_cdn": None}
    try:
        r = requests.get("https://cdn.tailwindcss.com", timeout=15)
        results["dead_tailwind_cdn"] = {"http": r.status_code, "reachable": r.status_code == 200}
    except Exception as exc:
        results["dead_tailwind_cdn"] = {"http": 0, "reachable": False, "error": str(exc)[:120]}

    for url in sorted(set(externals)):
        try:
            r = requests.get(url, timeout=30)
            results["external"].append(
                {"url": url, "http": r.status_code, "ok": r.status_code == 200, "bytes": len(r.content)}
            )
        except Exception as exc:
            results["external"].append({"url": url, "http": 0, "ok": False, "error": str(exc)[:120]})

    for path in sorted(set(statics)):
        url = f"{BASE}/static/{path.replace(chr(92), '/')}"
        try:
            r = requests.get(url, timeout=15)
            ct = r.headers.get("content-type", "")
            results["static"].append(
                {
                    "path": path,
                    "url": url,
                    "http": r.status_code,
                    "ok": r.status_code == 200,
                    "content_type": ct,
                    "bytes": len(r.content),
                }
            )
        except Exception as exc:
            results["static"].append({"path": path, "http": 0, "ok": False, "error": str(exc)[:120]})

    results["pass"] = (
        any(e.get("ok") and "@tailwindcss/browser" in e.get("url", "") for e in results["external"])
        and all(s.get("ok") for s in results["static"])
        and all(e.get("ok") for e in results["external"])
    )
    out = os.path.join(ROOT, "data", "ui_repair", "dashboard_assets_http_check.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0 if results["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
