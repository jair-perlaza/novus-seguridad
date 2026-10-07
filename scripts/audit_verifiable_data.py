#!/usr/bin/env python3
"""
Auditoría global: datos no verificables en NOVUS (RFC 5737, mock, JSON crudo, amenazas sin evidencia).
Genera data/ui_truth/evidence_audit_report.json y .md
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000")
EMAIL = os.environ.get("NOVUS_QA_EMAIL", "novus.qa.jul2026@example.com")
PASSWORD = os.environ.get("NOVUS_QA_PASSWORD", "NovusQA2026!")

DOC_IP_RE = re.compile(r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b")
PYTHON_DICT_RE = re.compile(r"\{['\"]verified['\"]\s*:")
MOCK_RE = re.compile(r"\b(mock|fake|dummy|placeholder|simulated|demo threat)\b", re.I)

ENDPOINTS = [
    ("Dashboard priority", "/api/dashboard/priority"),
    ("Security summary", "/api/security/summary"),
    ("Security alerts", "/api/security/alerts"),
    ("Security threats", "/api/security/threats"),
    ("Threat registry", "/api/security/threat-registry"),
    ("Defense registry", "/api/system/defense-registry"),
    ("Evidence center", "/api/system/evidence-center"),
    ("Network NDR", "/api/network/ndr"),
]

PAGES = ["/dashboard", "/amenazas", "/xdr", "/network", "/topology"]


def login_session():
    import requests
    s = requests.Session()
    r = s.post(f"{BASE}/login", data={"email": EMAIL, "password": PASSWORD}, allow_redirects=True, timeout=120)
    if "login" in r.url.lower():
        raise RuntimeError("Login failed")
    return s


def _strip_ui_noise(html: str) -> str:
    """Quita atributos HTML inocuos que disparan falsos positivos (placeholder=)."""
    html = re.sub(r'\bplaceholder="[^"]*"', "", html, flags=re.I)
    html = re.sub(r"\bplaceholder='[^']*'", "", html, flags=re.I)
    return html


def scan_blob(label: str, blob: str, issues: list) -> None:
    if label.startswith("/") and not label.startswith("/api"):
        blob = _strip_ui_noise(blob)
    if DOC_IP_RE.search(blob):
        issues.append({"source": label, "type": "documentation_ip", "detail": "IP RFC 5737 detectada"})
    if PYTHON_DICT_RE.search(blob):
        issues.append({"source": label, "type": "python_dict_leak", "detail": "Dict Python visible"})
    if MOCK_RE.search(blob):
        issues.append({"source": label, "type": "mock_marker", "detail": "Marcador mock/fake/demo"})


def main() -> int:
    import requests

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "issues": [],
        "endpoints_ok": 0,
        "endpoints_total": len(ENDPOINTS),
        "pages_ok": 0,
        "pages_total": len(PAGES),
    }
    issues = report["issues"]

    try:
        session = login_session()
    except Exception as exc:
        print(f"FAIL login: {exc}")
        return 1

    for name, path in ENDPOINTS:
        try:
            r = session.get(f"{BASE}{path}", timeout=120)
            body = r.text
            if r.status_code != 200:
                issues.append({"source": path, "type": "http_error", "detail": str(r.status_code)})
                continue
            scan_blob(path, body, issues)
            report["endpoints_ok"] += 1
            print(f"OK API {path}")
        except Exception as exc:
            issues.append({"source": path, "type": "exception", "detail": str(exc)})

    for path in PAGES:
        try:
            r = session.get(f"{BASE}{path}", timeout=120)
            scan_blob(path, r.text, issues)
            report["pages_ok"] += 1
            print(f"OK PAGE {path}")
        except Exception as exc:
            issues.append({"source": path, "type": "exception", "detail": str(exc)})

    # Canonical alerts must all pass evidence gate
    from services.alerts_canonical_service import get_canonical_alerts
    from utils.verifiable_evidence import passes_evidence_gate

    alerts = get_canonical_alerts(limit=200)
    for alert in alerts:
        ok, reason = passes_evidence_gate(alert)
        if not ok:
            issues.append({
                "source": "get_canonical_alerts",
                "type": "unverifiable_alert",
                "detail": f"{alert.get('id')}: {reason}",
            })

    report["canonical_alerts"] = len(alerts)
    report["issues_count"] = len(issues)
    report["pass"] = len(issues) == 0

    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ui_truth")
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "evidence_audit_report.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    md_path = os.path.join(out_dir, "evidence_audit_report.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("# Auditoría evidencia verificable NOVUS\n\n")
        fh.write(f"Generado: {report['generated_at']}\n\n")
        fh.write(f"- Alertas canónicas: {report['canonical_alerts']}\n")
        fh.write(f"- APIs OK: {report['endpoints_ok']}/{report['endpoints_total']}\n")
        fh.write(f"- Páginas OK: {report['pages_ok']}/{report['pages_total']}\n")
        fh.write(f"- Issues: {report['issues_count']}\n")
        fh.write(f"- **Resultado:** {'PASS' if report['pass'] else 'FAIL'}\n\n")
        if issues:
            fh.write("## Problemas\n\n")
            for i in issues:
                fh.write(f"- [{i['type']}] {i['source']}: {i['detail']}\n")

    print(f"\nReport: {json_path}")
    print(f"PASS={report['pass']} issues={report['issues_count']}")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
