#!/usr/bin/env python3
"""LIVE proof + pentest DPE — solo evidencia real; sin ataques inventados."""
from __future__ import annotations
import json, os, sys, time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
DATA = os.path.join(ROOT, "data", "deception_platform")
os.makedirs(DATA, exist_ok=True)

results, pentest = [], []
NA, NI, NC = "NO DISPONIBLE", "NO IMPLEMENTADO", "NO CONFIGURADO"

def _utc(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def _ok(n, d=""): results.append({"test": n, "status": "PASS", "detail": d, "ts": _utc()})
def _fail(n, d=""): results.append({"test": n, "status": "FAIL", "detail": d, "ts": _utc()})
def _pt(n, ok, d=""): pentest.append({"test": n, "status": "PASS" if ok else "FAIL", "detail": d, "ts": _utc()})

print("=" * 70)
print("NOVUS DPE — LIVE PROOF + PENTEST")
print("=" * 70)

from services.deception_platform import (
    get_dashboard, get_status, stats, search, POLICY, LIMITATIONS,
    list_honeypots, configure_honeypot, activate_honeypot,
    mint_honeytoken, list_honeytokens,
    create_honeyfile, list_honeyfiles,
    create_honeycredential, list_honeycredentials,
    list_honeyshares, configure_honeyshare,
    list_honeydatabases, configure_honeydatabase,
    list_decoy_servers, configure_decoy_server,
    segregation_report, ask_kernel, swarm_anonymous_summary,
)

assert POLICY.get("auto_start_listeners") is False
assert POLICY.get("simulate_attacks") is False
assert POLICY.get("invent_events") is False
assert POLICY.get("reuse_real_assets") is False
assert POLICY.get("modify_engines") is False
assert POLICY.get("kernel_executes") is False
_ok("policy", "no auto listeners / no simulate / no invent")

print("\n[1] Honeypots (default NO CONFIGURADO)...")
pots = list_honeypots()
assert pots.get("invented") is False
assert pots.get("auto_start") is False
assert pots.get("counts", {}).get("activo", 0) == 0
print(f"  counts={pots.get('counts')} active={pots.get('active_protocols')}")
_ok("honeypots_default", f"activo=0 no_configurado={pots.get('counts',{}).get('no_configurado')}")

cfg = configure_honeypot("ssh", bind_host="127.0.0.1", bind_port=2222)
assert cfg.get("status") == "CONFIGURADO"
assert cfg.get("listener_started") is False
act = activate_honeypot("ssh")
assert act.get("listener_started") is False
assert act.get("status") != "ACTIVO"  # no listener verified
pots2 = list_honeypots()
assert pots2.get("counts", {}).get("activo", 0) == 0
_ok("honeypots_no_false_activo", "activate sin listener => no ACTIVO")

print("\n[2] Honeytokens...")
for t in ("api_key", "jwt", "oauth_token", "cookie", "secret", "password", "usuario"):
    r = mint_honeytoken(t)
    assert r.get("ok") is True, r
    tok = r["token"]
    assert tok.get("uuid") and tok.get("hash") and tok.get("firma")
    assert tok.get("decoy") is True and tok.get("real_credential") is False
    assert "value_local_only" not in tok
_ok("honeytokens", f"count={list_honeytokens().get('count')}")

print("\n[3] Honeyfiles...")
for ft in ("pdf", "docx", "xlsx", "txt", "csv", "backup", "database"):
    r = create_honeyfile(ft)
    assert r.get("ok") is True, r
    f = r["honeyfile"]
    assert f.get("sha256") and f.get("ed25519") and f.get("decoy") is True
    assert f.get("real_document") is False
_ok("honeyfiles", f"count={list_honeyfiles().get('count')}")

print("\n[4] Honeycredentials + segregation...")
for role in ("usuario", "administrador", "cuenta_servicio"):
    r = create_honeycredential(role)
    assert r.get("ok") is True, r
    assert r["credential"].get("real_account") is False
    assert r["credential"]["username"].startswith("dpe.honey.")
seg = segregation_report()
assert seg.get("policy", {}).get("reuse_real_assets") is False
_ok("honeycredentials_segregation", f"creds={list_honeycredentials().get('count')} real_users={seg.get('real_users_sample_count')}")

print("\n[5] Shares / DB / Decoy servers...")
sh = configure_honeyshare("smb")
assert sh.get("ok")
db = configure_honeydatabase()
assert db.get("ok") and db["database"].get("contains_real_data") is False
ds = configure_decoy_server("web")
assert ds.get("ok") and ds["server"].get("enabled") is False
decoys = list_decoy_servers()
assert decoys.get("all_disabled_by_default") is True
assert decoys.get("activo") == []
_ok("shares_db_decoys", "frameworks configurables; sin listeners")

print("\n[6] Dashboard honesty (sin ataques inventados)...")
# Snapshot events BEFORE any canary — proof must not invent attacks
from services.deception_platform.store import load_events
events_before = len(load_events(5000))
dash = get_dashboard()
assert dash.get("invented") is False
assert dash.get("simulated_attacks") is False
assert dash.get("claims", {}).get("afirma_ataques_sin_evidencia") is False
assert dash.get("claims", {}).get("honeypots_activos", 0) == 0
print(f"  events={dash.get('events_count')} activo={dash.get('claims',{}).get('honeypots_activos')}")
_ok("dashboard", f"events={dash.get('events_count')} sources={sum(1 for v in (dash.get('sources_status') or {}).values() if v.get('available'))}")

print("\n[7] Kernel...")
for q in [
    "¿Qué recurso señuelo fue tocado?",
    "¿Qué atacante interactuó con un honeytoken?",
    "¿Qué incidente provino de un honeypot?",
    "¿Qué IOC se generó?",
    "¿Qué playbook recomienda SOPE?",
]:
    a = ask_kernel(q)
    assert a.get("executes_actions") is False
    assert a.get("invented") is False
_ok("kernel", "5 questions executes_actions=false")

print("\n[8] Swarm privacy...")
sw = swarm_anonymous_summary()
assert sw.get("privacy") == "no_pii"
assert sw.get("contains_credentials") is False
blob = json.dumps(sw)
assert "dpe_ak_" not in blob and "DPE!" not in blob
_ok("swarm", "no_pii")

print("\n[9] Search/stats...")
st = stats()
sr = search("dpe", limit=10)
assert st.get("invented") is False and sr.get("invented") is False
_ok("search_stats", f"stats={st}")

# Controlled LIVE canary (operator open) — real interaction, not simulated attack fiction
print("\n[10] Canary LIVE open (interaccion real operator)...")
hf = (list_honeyfiles().get("files") or [None])[0]
canary = None
if hf and hf.get("uuid"):
    from services.deception_platform import mark_opened
    canary = mark_opened(hf["uuid"], source_ip="127.0.0.1", actor="dpe_live_proof_operator")
    assert canary.get("ok") is True
    assert canary.get("simulated") is False
    assert canary.get("invented") is False
    assert canary.get("event", {}).get("event_id")
    assert canary.get("ioc", {}).get("ioc_id")
    _ok("canary_open", f"event={canary['event']['event_id']} imcm={canary.get('pipeline',{}).get('imcm')}")
else:
    _fail("canary_open", "no honeyfile")

print("\n" + "=" * 70)
print("PENTEST DPE")
print("=" * 70)
checks = [
    ("honeypots_states", pots2.get("counts", {}).get("activo", 0) == 0),
    ("no_auto_start", POLICY["auto_start_listeners"] is False),
    ("tokens_signed", all(t.get("hash") for t in (list_honeytokens().get("tokens") or [])[:5])),
    ("files_sha256", all(f.get("sha256") for f in (list_honeyfiles().get("files") or [])[:5])),
    ("no_real_docs", all(f.get("real_document") is False for f in (list_honeyfiles().get("files") or [])[:20])),
    ("creds_prefix", all(str(c.get("username","")).startswith("dpe.honey.") for c in (list_honeycredentials().get("credentials") or [])[:20])),
    ("decoys_disabled", list_decoy_servers().get("activo") == []),
    ("dashboard", dash.get("invented") is False),
    ("kernel", ask_kernel("IOC").get("executes_actions") is False),
    ("swarm", sw.get("privacy") == "no_pii"),
    ("canary_real", bool(canary and canary.get("ok") and not canary.get("invented"))),
    ("status", get_status().get("simulated_attacks") is False),
]
for name, ok in checks:
    _pt(name, ok, "ok" if ok else "fail")
    print(f"  [PT] {name}: {'PASS' if ok else 'FAIL'}")

passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
pt_pass = sum(1 for p in pentest if p["status"] == "PASS")
pt_fail = sum(1 for p in pentest if p["status"] == "FAIL")

live = {
    "generated_at_utc": _utc(),
    "module": "DPE",
    "results": results,
    "passed": passed,
    "failed": failed,
    "dashboard_snapshot": {
        "events_count": get_dashboard().get("events_count"),
        "honeypots_activo": get_dashboard().get("claims", {}).get("honeypots_activos"),
        "tokens": list_honeytokens().get("count"),
        "files": list_honeyfiles().get("count"),
        "sources": get_dashboard().get("sources_status"),
    },
    "events_before_canary": events_before,
    "canary": {
        "event_id": (canary or {}).get("event", {}).get("event_id"),
        "ioc_id": (canary or {}).get("ioc", {}).get("ioc_id"),
        "imcm": (canary or {}).get("pipeline", {}).get("imcm"),
        "simulated": False,
    },
    "policy": POLICY,
    "limitations": LIMITATIONS,
    "invented": False,
}
pentest_doc = {
    "generated_at_utc": _utc(),
    "module": "DPE",
    "tests": pentest,
    "passed": pt_pass,
    "failed": pt_fail,
    "invented": False,
}
matriz = {
    "generated_at_utc": _utc(),
    "capabilities": {
        "honeypots_framework": True,
        "honeypots_auto_start": False,
        "honeytokens": True,
        "honeyfiles": True,
        "honeycredentials": True,
        "honeyshares_framework": True,
        "honeydatabase_framework": True,
        "decoy_servers_disabled_default": True,
        "integration_on_real_interaction": True,
        "kernel_executes_actions": False,
        "swarm_pii": False,
        "simulate_attacks": False,
    },
}
evidencia = {
    "generated_at_utc": _utc(),
    "live_proof": live,
    "pentest": pentest_doc,
    "data_dir": DATA,
    "note": "Canary open es interaccion REAL de operador LIVE, no ataque inventado.",
}

with open(os.path.join(DATA, "LIVE_PROOF_DPE.json"), "w", encoding="utf-8") as f:
    json.dump(live, f, indent=2, ensure_ascii=False, default=str)
with open(os.path.join(DATA, "PENTEST_DPE.json"), "w", encoding="utf-8") as f:
    json.dump(pentest_doc, f, indent=2, ensure_ascii=False, default=str)
with open(os.path.join(DATA, "MATRIZ_DPE.json"), "w", encoding="utf-8") as f:
    json.dump(matriz, f, indent=2, ensure_ascii=False, default=str)
with open(os.path.join(DATA, "EVIDENCIA_DPE.json"), "w", encoding="utf-8") as f:
    json.dump(evidencia, f, indent=2, ensure_ascii=False, default=str)

md = [
    "# INFORME DPE — Deception Platform Enterprise",
    f"\nGenerado: {_utc()}", "",
    "## Resultado",
    f"- LIVE: {passed}/{passed+failed} PASS",
    f"- PENTEST: {pt_pass}/{pt_pass+pt_fail} PASS", "",
    "## Principios",
    "- Espacio logico independiente (namespace dpe.decoy)",
    "- Sin auto-arranque de listeners inseguros",
    "- ACTIVO solo con listener verificado",
    "- Sin telemetria/ataques inventados",
    "- Canary LIVE = interaccion real de operador", "",
    "## Capacidades",
    "- Honeypots / Honeytokens / Honeyfiles / Honeycredentials",
    "- Honeyshares / Honeydatabase / Decoy servers (framework)",
    "- Integracion IMCM+TIE+SOPE ante interaccion real",
    "- Sellos SHA-256+Ed25519",
    "- Kernel IA analyst-only", "",
    "## Limitaciones",
]
md.extend(f"- {x}" for x in LIMITATIONS)
md += ["", "---", "Generado por NOVUS DPE LIVE proof."]
with open(os.path.join(DATA, "INFORME_DPE.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(md))

total_pass = passed + pt_pass
total_fail = failed + pt_fail
print("=" * 70)
print(f"RESULTADO: {total_pass}/{total_pass+total_fail} PASS | {total_fail} FAIL")
print("=" * 70)
sys.exit(1 if total_fail else 0)
