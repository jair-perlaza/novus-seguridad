"""Verifica flujo: detección → cascada auto → guía manual → verify-manual."""
import json
import sys

import requests

BASE = "http://127.0.0.1:5000"
EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"


def login(session):
    r = session.post(
        f"{BASE}/login",
        data={"email": EMAIL, "password": PASSWORD},
        allow_redirects=True,
        timeout=30,
    )
    return r.status_code == 200 and "login" not in r.url.lower()


def main():
    s = requests.Session()
    s.headers.update({"User-Agent": "NOVUS-RemediationVerify/1.0"})

    # HTTP 200 root
    root = s.get(BASE, timeout=15)
    print(f"[{'OK' if root.status_code == 200 else 'FAIL'}] HTTP {root.status_code} en {BASE}")

    if not login(s):
        print("[FAIL] Login")
        return 1
    print("[OK] Login")

    vulns = s.get(f"{BASE}/api/security/vulnerabilities", timeout=60)
    if vulns.status_code != 200:
        print(f"[FAIL] Vulnerabilities API -> {vulns.status_code}")
        return 1
    data = vulns.json()
    activas = data.get("vulnerabilities") or data.get("activas") or []
    print(f"[OK] Vulnerabilidades activas: {len(activas)}")
    if not activas:
        print("[WARN] Sin vulnerabilidades activas para probar remediación")
        return 0

    target = activas[0]
    fid = target.get("id")
    print(f"[*] Probando remediación cascada en {fid}")

    rem = s.post(
        f"{BASE}/api/reports/remediate",
        json={"target_id": fid, "target_type": "vulnerability"},
        timeout=120,
    )
    if rem.status_code != 200:
        print(f"[FAIL] Remediate -> {rem.status_code}: {rem.text[:300]}")
        return 1
    rem_data = rem.json()
    strategies = rem_data.get("strategies_attempted") or []
    steps = rem_data.get("steps") or []
    print(f"[{'OK' if len(strategies) >= 1 else 'FAIL'}] Estrategias intentadas: {len(strategies)}")
    print(f"    IDs: {[s.get('id') for s in strategies]}")
    print(f"    Pasos log: {len(steps)}")
    print(f"    Resolved: {rem_data.get('resolved')}")
    print(f"    Requires manual: {rem_data.get('requires_manual')}")

    if rem_data.get("requires_manual"):
        guide = rem_data.get("manual_guide") or {}
        print(f"[{'OK' if guide.get('titulo') else 'FAIL'}] Guía manual presente")
        print(f"    Título: {guide.get('titulo', '')[:80]}")
        print(f"    Puerto: {guide.get('puerto_abierto')}")
        print(f"    Proceso: {guide.get('nombre_proceso')}")
        print(f"    Botones ayuda: {len(guide.get('botones_ayuda') or [])}")
        print(f"    Pasos manuales: {len(guide.get('pasos_manuales') or [])}")

        mg = s.get(f"{BASE}/api/reports/remediate/manual-guide/{fid}", timeout=30)
        print(f"[{'OK' if mg.status_code == 200 else 'FAIL'}] GET manual-guide -> {mg.status_code}")

        ms = s.post(
            f"{BASE}/api/reports/remediate/manual-step",
            json={"finding_id": fid, "step_index": 0},
            timeout=30,
        )
        print(f"[{'OK' if ms.status_code == 200 else 'FAIL'}] POST manual-step -> {ms.status_code}")

        if guide.get("botones_ayuda"):
            btn = guide["botones_ayuda"][0]
            lt = s.post(
                f"{BASE}/api/system/launch-tool",
                json={"tool": btn["tool"], "path": btn.get("path")},
                timeout=15,
            )
            print(f"[{'OK' if lt.status_code == 200 else 'FAIL'}] launch-tool ({btn['tool']}) -> {lt.status_code}")

        verify = s.post(
            f"{BASE}/api/reports/remediate/verify-manual",
            json={"finding_id": fid},
            timeout=90,
        )
        print(f"[{'OK' if verify.status_code == 200 else 'FAIL'}] verify-manual -> {verify.status_code}")
        vdata = verify.json()
        print(f"    Verificación resolved: {vdata.get('resolved')}")

    elif rem_data.get("resolved"):
        print("[OK] Remediación automática resolvió el hallazgo")

    # Re-scan
    vulns2 = s.get(f"{BASE}/api/security/vulnerabilities", timeout=60)
    data2 = vulns2.json()
    activas2 = data2.get("vulnerabilities") or data2.get("activas") or []
    print(f"[OK] Re-escaneo post-remediación: {len(activas2)} activas")

    print("\n=== REMEDIATION CASCADE VERIFY COMPLETE ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
