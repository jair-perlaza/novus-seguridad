"""Verificacion modulo Reportes empresariales."""
import subprocess
import sys

import requests

BASE = "http://127.0.0.1:5000"
EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"


def main():
    s = requests.Session()
    print(f"[{'OK' if s.get(BASE, timeout=10).status_code == 200 else 'FAIL'}] HTTP 200")
    r = s.post(f"{BASE}/login", data={"email": EMAIL, "password": PASSWORD}, allow_redirects=True, timeout=60)
    if "login" in r.url.lower():
        print("[FAIL] Login"); return 1
    print("[OK] Login")

    page = s.get(f"{BASE}/reportes", timeout=30)
    ok_ui = "GENERAR REPORTE" in page.text and "gen-modal" in page.text
    print(f"[{'OK' if page.status_code == 200 and ok_ui else 'FAIL'}] /reportes UI")

    gen = s.post(f"{BASE}/api/reports/generate", json={"sections": ["general", "vulnerabilidades"]}, timeout=180)
    if gen.status_code != 200:
        print(f"[FAIL] generate -> {gen.status_code}: {gen.text[:200]}"); return 1
    data = gen.json()
    rid = data.get("report_id")
    report = data.get("report") or {}
    print(f"[OK] Informe generado: {rid}")
    print(f"    Tipo: {report.get('report_type')} | Riesgo: {report.get('severidad')}")
    print(f"    Portada: {bool(report.get('cover'))} | Firma: {bool(report.get('signature'))}")
    print(f"    Hallazgos: {report.get('findings_count', 0)} | Graficos: {bool(report.get('charts'))}")

    for fmt in ("pdf", "html", "json", "csv"):
        ex = s.get(f"{BASE}/api/reports/{rid}/export?format={fmt}", timeout=60)
        print(f"[{'OK' if ex.status_code == 200 else 'FAIL'}] Export {fmt.upper()} -> {ex.status_code} ({len(ex.content)} bytes)")

    sha = (report.get("signature") or {}).get("integridad_sha256", "")
    print(f"[{'OK' if len(sha) == 64 else 'FAIL'}] Integridad SHA-256")

    c = sum(1 for l in subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout.splitlines()
            if ":5000" in l and "LISTENING" in l)
    print(f"[{'OK' if c == 1 else 'FAIL'}] Instancia unica :5000 ({c})")
    print("\n=== REPORTS AUDIT COMPLETE ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
