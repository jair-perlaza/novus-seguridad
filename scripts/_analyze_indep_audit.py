#!/usr/bin/env python3
import json
from pathlib import Path

e = json.loads(Path("data/audit_master_independiente/EVIDENCIA_INDEPENDIENTE.json").read_text(encoding="utf-8"))
print("GLOBAL", e["global"])
print("REPRO", json.dumps(e["reproducibility"], ensure_ascii=False, indent=2))
print("--- FAIL ---")
for a in e["areas"]:
    fails = [c for c in a["criterios"] if not c["cumplido"]]
    if fails:
        print(a["area"], a["porcentaje"], f"{a['cumplidos']}/{a['total_criterios']}")
        for c in fails:
            print("  -", c["criterio"], "|", str(c["evidencia"])[:140])

p = json.loads(Path("data/audit_master_independiente/LIVE_READONLY_PROBE_INDEPENDIENTE.json").read_text(encoding="utf-8"))
print("reencrypt_live", p.get("reencrypt_live"))
print("backups.verify", (p.get("backups") or {}).get("latest_verify"))
print("backups.restore", (p.get("backups") or {}).get("live_restore"))
print("ape_live", p.get("ape_live"))
print("auth_live", p.get("auth_live"))
print("tls", {k: (p.get("tls") or {}).get(k) for k in ["tls_1_3_verified", "status_label", "claims_fake_tls_13_active"]})
print("headers", p.get("security_headers"))
print("forensic", p.get("forensic_verifier"))
print("compliance", p.get("compliance_fintech"))
print("mfa", (p.get("modules") or {}).get("wsae"))
ws = [x for x in (p.get("engines_panel") or []) if isinstance(x, dict) and x.get("id") == "web_shield"]
print("web_shield", ws[:1])
