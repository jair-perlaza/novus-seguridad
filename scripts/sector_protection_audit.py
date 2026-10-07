#!/usr/bin/env python3
"""
Auditoría técnica de protección sectorial — 4 sectores MVP + verificación clientes.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CLIENTS = [
    ("operaciones@novapay-fintech.co", "NovaPay#Fintech2026", "fintech"),
    ("operaciones@translogistica-novus.co", "TransLog#2026Novus", "logistica"),
    ("operaciones@appmovil-novus.co", "AppMovil#2026Novus", "aplicaciones_moviles"),
    ("operaciones@corp-otros-novus.co", "CorpOtros#2026Novus", "otros"),
]

BASE = os.environ.get("NOVUS_BASE_URL", "http://10.196.213.166:5000")


def run_sector_audits():
    from services.sector_profile_service import audit_sector_protection, apply_sector_profile_for_user

    reports = {}
    for key in ("fintech", "logistica", "aplicaciones_moviles", "otros"):
        email = next((c[0] for c in CLIENTS if c[2] == key), None)
        apply_sector_profile_for_user(email) if email else None
        reports[key] = audit_sector_protection(key, email)
    return reports


def verify_clients_live(base_url: str = BASE):
    import requests

    results = []
    for email, password, expected in CLIENTS:
        s = requests.Session()
        login = s.post(f"{base_url}/login", data={"email": email, "password": password}, timeout=30)
        ok_login = login.status_code == 200 and "/dashboard" in login.url
        profile = s.get(f"{base_url}/api/system/sector-profile", timeout=30)
        shield = s.get(f"{base_url}/api/system/sector-shield/status", timeout=60)
        ctx = s.get(f"{base_url}/api/ai/context", timeout=30)
        chat = s.post(
            f"{base_url}/api/ai/chat",
            json={"message": "Resume mi sector y escudo activo en una línea."},
            timeout=90,
        )
        pd = profile.json() if profile.ok else {}
        sd = shield.json() if shield.ok else {}
        cd = ctx.json() if ctx.ok else {}
        sector_key = pd.get("sector_key") or sd.get("sector_key")
        results.append({
            "email": email,
            "login": ok_login,
            "dashboard": s.get(f"{base_url}/dashboard", timeout=30).status_code == 200,
            "sector_key": sector_key,
            "expected": expected,
            "profile_ok": sector_key == expected,
            "shield_ok": sd.get("sector_key") == expected,
            "kernel_context_ok": (cd.get("sector") or {}).get("sector_key") == expected,
            "kernel_chat_ok": chat.status_code == 200 and expected.replace("_", " ") in (chat.json().get("reply") or "").lower() or expected in (chat.json().get("reply") or "").lower(),
            "dashboard_focus": pd.get("sector_profile", {}).get("dashboard_focus") or pd.get("profile", {}).get("dashboard_focus"),
        })
    return results


def main():
    print("=" * 72)
    print("NOVUS — Auditoría de protección sectorial (4 sectores MVP)")
    print("=" * 72)

    reports = run_sector_audits()
    out_path = os.path.join(os.path.dirname(__file__), "sector_audit_results.json")

    for key, report in reports.items():
        print(f"\n{'-' * 72}")
        print(f"SECTOR: {report['sector_label']} ({key})")
        print(f"Cobertura de protección: {report['coverage_pct']}%")
        print(f"Checks: {report['checks_passed']}/{report['checks_total']}")
        print(f"Producción lista: {'SÍ' if report['production_ready'] else 'NO (condicional)'}")
        print("\nComponentes activos:")
        ac = report["active_components"]
        print(f"  Motores: {', '.join(ac['motors'][:5])}")
        print(f"  Cifrado: {', '.join(ac['crypto_models'])}")
        print(f"  Kernel: {', '.join(ac['kernel_capabilities'][:4])}")
        print(f"  Playbooks: {ac['playbooks']}")
        if report["risks_detected"]:
            print("\nRiesgos:")
            for r in report["risks_detected"]:
                print(f"  • {r}")
        if report["missing_or_disconnected"]:
            print("\nPendientes de conectar/completar:")
            for m in report["missing_or_disconnected"]:
                print(f"  • {m['id']} ({m['module']})")

    payload = {"sector_audits": reports}
    try:
        payload["client_verification"] = verify_clients_live()
    except Exception as exc:
        payload["client_verification_error"] = str(exc)
        payload["client_verification"] = []

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"\n{'=' * 72}")
    print("Verificación clientes reales:")
    all_ok = True
    for c in payload.get("client_verification") or []:
        ok = c.get("profile_ok") and c.get("shield_ok") and c.get("login")
        all_ok = all_ok and ok
        print(f"  {c['email']}: sector={c['sector_key']} login={'OK' if c['login'] else 'FAIL'} perfil={'OK' if c['profile_ok'] else 'FAIL'}")
    print(f"\nResultados guardados: {out_path}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
