#!/usr/bin/env python3
"""Recorre páginas HTML visibles — carga, recovery, marcadores raw/QA."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_release_candidate" / "NOVUS_UI_PAGES_PROBE.json"
BASE = "http://127.0.0.1:5000"

PAGES = [
    "/dashboard",
    "/network",
    "/topology",
    "/inventario-activos",
    "/vulnerabilidades",
    "/xdr",
    "/web-shield",
    "/amenazas",
    "/incidentes",
    "/endpoints",
    "/reportes",
    "/centro-evidencias",
    "/accesos",
    "/historial-seguridad-red",
    "/configuracion",
    "/health-center",
    "/login",
    "/registro-empresa",
]

BAD = (
    "traceback",
    "raw_excerpt",
    "exception:",
    "jinja2",
    "configuración para la interfaz",
    "lorem ipsum",
    "demo threat",
    "simulated",
    "fixture",
)


def probe(session, path: str) -> dict:
    import requests

    r = session.get(BASE + path, timeout=120, allow_redirects=True)
    text = (r.text or "")[:50000].lower()
    hits = [m for m in BAD if m in text]
    recovery = bool(r.headers.get("X-Novus-Recovery")) or "_novusrecovery" in text
    return {
        "path": path,
        "final_url": r.url,
        "http": r.status_code,
        "recovery": recovery,
        "hits": hits,
        "pass": r.status_code == 200 and not hits and not recovery,
    }


def main() -> int:
    import requests
    from scripts.reports_regression_probe import login

    s = requests.Session()
    login(s)
    rows = [probe(s, p) for p in PAGES if p not in ("/login", "/registro-empresa")]
    import requests as req

    sr = s.get(BASE + "/api/search?q=test", timeout=120)
    rows.append({
        "path": "/api/search (global search API)",
        "final_url": sr.url,
        "http": sr.status_code,
        "recovery": bool(sr.headers.get("X-Novus-Recovery")),
        "hits": [],
        "pass": sr.status_code == 200,
    })
    rows.append(probe(requests.Session(), "/login"))
    rows.append(probe(requests.Session(), "/registro-empresa"))
    report = {"pages": rows, "pass": all(r["pass"] for r in rows)}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"pass": report["pass"], "pages": len(rows), "failed": [r["path"] for r in rows if not r["pass"]]}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
