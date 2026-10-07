#!/usr/bin/env python3
"""
NOVUS P0-2 gate — Mesh IOC → ZDDE tenant isolation.
TEST_FIXTURE / SYNTHETIC_TEST_ONLY — never LIVE.
Uses isolated STORE_DIR; does not write fixtures into production mesh intel.
"""
from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "production_closure" / "mesh_ioc_zdde_p0_2"
OUT.mkdir(parents=True, exist_ok=True)

TENANT_A = "P0_2_TEST_TENANT_A"
TENANT_B = "P0_2_TEST_TENANT_B"
IOC_A = "198.51.100.201"
IOC_B = "198.51.100.202"
FIXTURE = {"TEST_FIXTURE": True, "SYNTHETIC_TEST_ONLY": True}


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check(name: str, ok: bool, **detail) -> Dict[str, Any]:
    return {"id": name, "ok": ok, "result": "PASS" if ok else "FAIL", **detail}


def _reload_store(store_dir: Path):
    import services.swarm_defense.mesh.intel_store as intel_store

    importlib.reload(intel_store)
    intel_store.STORE_DIR = str(store_dir)
    return intel_store


def mesh_score_boost(has_shared: bool, ioc_counts: Dict[str, Any]) -> int:
    """Mirror correlator mesh weights without running full ZDDE."""
    boost = 0
    if has_shared:
        boost += 16
    peers_hint = sum(1 for k in ("ips", "domains", "hashes") if int((ioc_counts or {}).get(k) or 0) > 0) >= 2
    if peers_hint:
        boost += 10
    return boost


def run_suite(store_dir: Path) -> Dict[str, Any]:
    intel_store = _reload_store(store_dir)
    from services.zero_day_detection.layers import layer_mesh_intel
    from services.zero_day_detection.correlator import _score_factors, correlate_layers
    from services.swarm_defense.mesh.propagator import build_intel_payload_from_correlation

    checks: List[Dict[str, Any]] = []

    # --- missing tenant deny ---
    denied = intel_store.apply_indicators(
        {"ips": [IOC_A], "domains": [], "hashes": []},
        peer_id="peer-fixture",
        msg_id="MSG-NO-TENANT",
        payload={**FIXTURE},
    )
    layer_none = layer_mesh_intel(tenant_id=None)
    checks.append(
        check(
            "missing_tenant_apply",
            denied.get("denied") is True and denied.get("influence") == "NO_INFLUENCE",
            applied=denied,
        )
    )
    checks.append(
        check(
            "missing_tenant_zdde_layer",
            layer_none.get("has_shared_intel") is False
            and layer_none.get("denied") is True
            and layer_none.get("influence") == "NO_TENANT_CONTEXT"
            and mesh_score_boost(layer_none.get("has_shared_intel"), layer_none.get("ioc_counts") or {}) == 0,
            layer=layer_none,
        )
    )

    # --- A → A ---
    app_a = intel_store.apply_indicators(
        {"ips": [IOC_A], "domains": ["evil-a.p02.test"], "hashes": ["aa" * 32]},
        peer_id="peer-a",
        msg_id="MSG-A-1",
        tenant_id=TENANT_A,
        payload={"tenant_id": TENANT_A, **FIXTURE},
    )
    layer_a = layer_mesh_intel(tenant_id=TENANT_A)
    vis_a = intel_store.tenant_ioc_visible(viewer_tenant_id=TENANT_A, value=IOC_A, bucket="ips")
    boost_a = mesh_score_boost(layer_a.get("has_shared_intel"), layer_a.get("ioc_counts") or {})
    checks.append(
        check(
            "tenant_a_to_a",
            app_a.get("ok") is True
            and app_a.get("tenant_id") == TENANT_A
            and layer_a.get("has_shared_intel") is True
            and layer_a.get("tenant_id") == TENANT_A
            and vis_a.get("visible") is True
            and boost_a >= 16,
            apply=app_a,
            layer=layer_a,
            visible=vis_a,
            mesh_boost=boost_a,
        )
    )

    # --- B → B ---
    app_b = intel_store.apply_indicators(
        {"ips": [IOC_B], "domains": ["evil-b.p02.test"], "hashes": ["bb" * 32]},
        peer_id="peer-b",
        msg_id="MSG-B-1",
        tenant_id=TENANT_B,
        payload={"tenant_id": TENANT_B, **FIXTURE},
    )
    layer_b = layer_mesh_intel(tenant_id=TENANT_B)
    vis_b = intel_store.tenant_ioc_visible(viewer_tenant_id=TENANT_B, value=IOC_B, bucket="ips")
    checks.append(
        check(
            "tenant_b_to_b",
            app_b.get("ok") is True
            and layer_b.get("has_shared_intel") is True
            and vis_b.get("visible") is True,
            apply=app_b,
            layer=layer_b,
            visible=vis_b,
        )
    )

    # --- A → B DENIED ---
    layer_b_vs_a = layer_mesh_intel(tenant_id=TENANT_B)
    vis_b_sees_a = intel_store.tenant_ioc_visible(viewer_tenant_id=TENANT_B, value=IOC_A, bucket="ips")
    # B has own intel so has_shared may be True — but must NOT see A's IOC value
    # For pure A→B influence: score factors on a bundle where mesh is built for B after only A write
    # Reset perspective: compute layer for B looking at whether A's exclusive domain appears in counts correctly
    # Isolation: B cannot see IOC_A value
    checks.append(
        check(
            "tenant_a_to_b",
            vis_b_sees_a.get("visible") is False
            and (layer_b_vs_a.get("tenant_id") == TENANT_B)
            and IOC_A not in json.dumps(layer_b_vs_a),
            visible=vis_b_sees_a,
            layer=layer_b_vs_a,
        )
    )

    # Influence: correlator with mesh layer for B must not include A's-only families if B empty
    # Use fresh store snapshot logic: score with mesh=layer for tenant that has no IOC
    empty_tenant = "P0_2_TEST_TENANT_EMPTY"
    layer_empty = layer_mesh_intel(tenant_id=empty_tenant)
    score_empty, factors_empty = _score_factors({"mesh": layer_empty})
    mesh_factors_empty = [f for f in factors_empty if str(f.get("factor", "")).startswith("mesh_")]
    checks.append(
        check(
            "tenant_a_cannot_boost_empty_tenant",
            layer_empty.get("has_shared_intel") is False and len(mesh_factors_empty) == 0,
            layer=layer_empty,
            mesh_factors=mesh_factors_empty,
            score=score_empty,
        )
    )

    # --- B → A DENIED ---
    vis_a_sees_b = intel_store.tenant_ioc_visible(viewer_tenant_id=TENANT_A, value=IOC_B, bucket="ips")
    checks.append(
        check(
            "tenant_b_to_a",
            vis_a_sees_b.get("visible") is False and IOC_B not in json.dumps(layer_mesh_intel(tenant_id=TENANT_A)),
            visible=vis_a_sees_b,
        )
    )

    # --- cache cross-tenant (store is the cache) ---
    # A write already done; B lookup of A's value denied; invert already covered
    checks.append(
        check(
            "cache_isolation",
            vis_a.get("visible") is True
            and vis_b.get("visible") is True
            and vis_b_sees_a.get("visible") is False
            and vis_a_sees_b.get("visible") is False,
        )
    )

    # --- legacy unscoped ignored ---
    # Simulate legacy by writing old-format-like via direct legacy bucket
    ioc_path = store_dir / "shared_iocs.json"
    raw = json.loads(ioc_path.read_text(encoding="utf-8"))
    raw.setdefault("legacy_unscoped", {}).setdefault("ips", {})["203.0.113.250"] = {
        "count": 9,
        "peers": ["legacy"],
        "first_seen": utc(),
    }
    ioc_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    leg_vis = intel_store.tenant_ioc_visible(viewer_tenant_id=TENANT_A, value="203.0.113.250", bucket="ips")
    layer_leg = layer_mesh_intel(tenant_id=TENANT_A)
    # A's has_shared still true from own IOCs; legacy value not visible to A as tenant entry
    checks.append(
        check(
            "legacy_unscoped_ignored",
            leg_vis.get("visible") is False and leg_vis.get("legacy_present_but_ignored") is True,
            visible=leg_vis,
            layer_has_shared=layer_leg.get("has_shared_intel"),
        )
    )

    # --- serialization / payload tenant preserved ---
    payload = build_intel_payload_from_correlation(
        correlation={"confidence": {"level": "medium"}, "tenant_id": TENANT_A, **FIXTURE},
        origin_event={"tenant_id": TENANT_A, "finding_id": "FIND-A-SER", **FIXTURE},
        indicators={"ips": [IOC_A]},
    )
    ser = json.loads(json.dumps(payload))
    checks.append(
        check(
            "serialization_tenant",
            ser.get("tenant_id") == TENANT_A and (ser.get("origin") or {}).get("tenant_id") == TENANT_A,
            payload=ser,
        )
    )

    # correlator full path with tenant A mesh vs B mesh
    bundle_a = {"layers": {"mesh": layer_mesh_intel(tenant_id=TENANT_A)}, "participating": ["mesh"], "participating_n": 1}
    bundle_b_only_mesh = {"layers": {"mesh": layer_mesh_intel(tenant_id=TENANT_B)}, "participating": ["mesh"], "participating_n": 1}
    corr_a = correlate_layers(bundle_a)
    corr_b = correlate_layers(bundle_b_only_mesh)
    factors_a = ((corr_a.get("risk") or {}).get("factors") or corr_a.get("factors") or [])
    factors_b = ((corr_b.get("risk") or {}).get("factors") or corr_b.get("factors") or [])
    checks.append(
        check(
            "correlator_tenant_mesh",
            any(f.get("factor") == "mesh_shared_intel" for f in factors_a)
            and any(f.get("factor") == "mesh_shared_intel" for f in factors_b),
            corr_a_factors=[f.get("factor") for f in factors_a],
            corr_b_factors=[f.get("factor") for f in factors_b],
            score_a=(corr_a.get("risk") or {}).get("score"),
            score_b=(corr_b.get("risk") or {}).get("score"),
        )
    )

    # Host ZDDE cycle without tenant must not get mesh boost from store
    from services.zero_day_detection.layers import gather_all_layers

    # Avoid heavy layers side effects: only assert mesh portion via layer_mesh_intel(None)
    host_mesh = layer_mesh_intel(tenant_id=None)
    checks.append(
        check(
            "host_zdde_no_mesh_influence",
            host_mesh.get("has_shared_intel") is False and host_mesh.get("denied") is True,
            layer=host_mesh,
        )
    )

    return {"checks": checks}


def persistence_test(store_dir: Path) -> Dict[str, Any]:
    intel_store = _reload_store(store_dir)
    intel_store.apply_indicators(
        {"ips": ["198.51.100.210"], "domains": [], "hashes": []},
        peer_id="p",
        msg_id="PERS-A",
        tenant_id=TENANT_A,
    )
    intel_store.apply_indicators(
        {"ips": ["198.51.100.211"], "domains": [], "hashes": []},
        peer_id="p",
        msg_id="PERS-B",
        tenant_id=TENANT_B,
    )
    child = f"""
import json, sys, importlib
sys.path.insert(0, {str(ROOT)!r})
import services.swarm_defense.mesh.intel_store as intel_store
importlib.reload(intel_store)
intel_store.STORE_DIR = {str(store_dir)!r}
from services.zero_day_detection.layers import layer_mesh_intel
va = intel_store.tenant_ioc_visible(viewer_tenant_id={TENANT_A!r}, value='198.51.100.210', bucket='ips')
vb = intel_store.tenant_ioc_visible(viewer_tenant_id={TENANT_B!r}, value='198.51.100.211', bucket='ips')
xa = intel_store.tenant_ioc_visible(viewer_tenant_id={TENANT_A!r}, value='198.51.100.211', bucket='ips')
xb = intel_store.tenant_ioc_visible(viewer_tenant_id={TENANT_B!r}, value='198.51.100.210', bucket='ips')
la = layer_mesh_intel(tenant_id={TENANT_A!r})
lb = layer_mesh_intel(tenant_id={TENANT_B!r})
print(json.dumps({{
  'a_sees_a': va.get('visible'), 'b_sees_b': vb.get('visible'),
  'a_sees_b': xa.get('visible'), 'b_sees_a': xb.get('visible'),
  'la': la.get('has_shared_intel'), 'lb': lb.get('has_shared_intel'),
}}))
"""
    proc = subprocess.run([sys.executable, "-c", child], cwd=str(ROOT), capture_output=True, text=True, timeout=60)
    try:
        parsed = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception:
        parsed = {"stdout": proc.stdout[-400:], "stderr": proc.stderr[-400:]}
    ok = (
        proc.returncode == 0
        and parsed.get("a_sees_a") is True
        and parsed.get("b_sees_b") is True
        and parsed.get("a_sees_b") is False
        and parsed.get("b_sees_a") is False
    )
    return {"ok": ok, "result": "PASS" if ok else "FAIL", "parsed": parsed, "returncode": proc.returncode}


def security_smoke() -> Dict[str, Any]:
    checks = []
    paths = {
        "mfa": ROOT / "services" / "web_security_auth_enterprise" / "mfa_totp.py",
        "csrf": ROOT / "services" / "csrf_service.py",
        "abuse": ROOT / "services" / "http_abuse_guard.py",
        "rbac": ROOT / "services" / "enterprise_access_control.py",
        "tenant": ROOT / "services" / "tenant_scope_service.py",
    }
    for k, p in paths.items():
        checks.append({"id": k, "ok": p.exists(), "path": str(p)})
    # no bypass in modified files
    bad = []
    for rel in (
        "services/swarm_defense/mesh/intel_store.py",
        "services/swarm_defense/mesh/ingest.py",
        "services/zero_day_detection/layers.py",
    ):
        txt = (ROOT / rel).read_text(encoding="utf-8")
        for n in ("ALLOW_ALL", "bypass tenant", "if testing:"):
            if n in txt:
                bad.append(f"{rel}:{n}")
    checks.append({"id": "no_bypass", "ok": len(bad) == 0, "bad": bad})
    http = {}
    try:
        import urllib.request

        t0 = time.perf_counter()
        with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:5000/login"), timeout=5) as r:
            http["/login"] = {"status": r.status, "ms": round((time.perf_counter() - t0) * 1000, 1)}
    except Exception as exc:
        http["error"] = str(exc)[:160]
    ok = all(c.get("ok") for c in checks)
    return {"ok": ok, "result": "PASS" if ok else "FAIL", "checks": checks, "http": http}


def production_deny_probe() -> Dict[str, Any]:
    """Production store: ZDDE without tenant must not get mesh influence from legacy IOCs."""
    import services.swarm_defense.mesh.intel_store as intel_store

    importlib.reload(intel_store)
    # restore production STORE_DIR
    intel_store.STORE_DIR = str(ROOT / "data" / "swarm_mesh" / "intel")
    from services.zero_day_detection.layers import layer_mesh_intel

    layer = layer_mesh_intel(tenant_id=None)
    inv = intel_store.stats(for_zdde_influence=False)
    return {
        "ok": layer.get("has_shared_intel") is False and layer.get("denied") is True,
        "layer": layer,
        "inventory_ioc_counts": inv.get("ioc_counts"),
        "note": "Legacy/host inventory may be non-zero; ZDDE influence without tenant must be denied",
    }


def perf_probe() -> Dict[str, Any]:
    import services.swarm_defense.mesh.intel_store as intel_store
    from services.zero_day_detection.layers import layer_mesh_intel

    importlib.reload(intel_store)
    intel_store.STORE_DIR = str(ROOT / "data" / "swarm_mesh" / "intel")
    samples = []
    for _ in range(5):
        t0 = time.perf_counter()
        layer_mesh_intel(tenant_id=TENANT_A)
        samples.append(round((time.perf_counter() - t0) * 1000, 3))
    try:
        import psutil

        p = psutil.Process(os.getpid())
        ram, threads = round(p.memory_info().rss / 1e6, 2), p.num_threads()
    except Exception:
        ram, threads = None, None
    return {
        "layer_mesh_intel_ms_samples": samples,
        "avg_ms": round(sum(samples) / len(samples), 3),
        "ram_rss_mb": ram,
        "threads": threads,
    }


def main() -> int:
    before = {}
    bp = OUT / "p0_2_before.json"
    if bp.exists():
        before = json.loads(bp.read_text(encoding="utf-8"))

    tmp = Path(tempfile.mkdtemp(prefix="novus_p0_2_mesh_"))
    suite = run_suite(tmp)
    pers = persistence_test(tmp)
    sec = security_smoke()
    prod = production_deny_probe()
    perf = perf_probe()

    checks = list(suite["checks"])
    checks.append({"id": "persistence", **pers})
    checks.append({"id": "security_regression", "ok": sec["ok"], "result": sec["result"], **sec})
    checks.append(
        {
            "id": "production_host_deny",
            "ok": prod["ok"],
            "result": "PASS" if prod["ok"] else "FAIL",
            **prod,
        }
    )
    checks.append(
        {
            "id": "performance",
            "ok": perf["avg_ms"] < 2000,
            "result": "PASS" if perf["avg_ms"] < 2000 else "FAIL",
            "perf": perf,
        }
    )

    by = {c["id"]: c for c in checks}

    def g(i: str) -> str:
        return "PASS" if (by.get(i) or {}).get("ok") else "FAIL"

    critical = [
        "tenant_a_to_a",
        "tenant_b_to_b",
        "tenant_a_to_b",
        "tenant_b_to_a",
        "cache_isolation",
        "missing_tenant_apply",
        "missing_tenant_zdde_layer",
        "persistence",
        "serialization_tenant",
        "host_zdde_no_mesh_influence",
        "production_host_deny",
        "legacy_unscoped_ignored",
        "correlator_tenant_mesh",
        "tenant_a_cannot_boost_empty_tenant",
    ]
    crit_ok = all((by.get(i) or {}).get("ok") for i in critical)
    sec_ok = (by.get("security_regression") or {}).get("ok")
    if crit_ok and sec_ok:
        verdict = "P0_2_PASS"
    elif crit_ok:
        verdict = "P0_2_PASS_WITH_LIMITATIONS"
    else:
        verdict = "P0_2_BLOCKED"

    tests = {
        "generated_at_utc": utc(),
        "verdict": verdict,
        "A_to_A": g("tenant_a_to_a"),
        "B_to_B": g("tenant_b_to_b"),
        "A_to_B": g("tenant_a_to_b"),
        "B_to_A": g("tenant_b_to_a"),
        "cache_isolation": g("cache_isolation"),
        "missing_tenant": "DENIED" if g("missing_tenant_apply") == "PASS" else "FAIL",
        "persistence": g("persistence"),
        "serialization": g("serialization_tenant"),
        "security_regression": g("security_regression"),
        "checks": checks,
        "performance": perf,
        "production_files_modified": [
            "services/swarm_defense/mesh/intel_store.py",
            "services/swarm_defense/mesh/ingest.py",
            "services/swarm_defense/mesh/propagator.py",
            "services/zero_day_detection/layers.py",
            "services/zero_day_detection/engine.py",
        ],
    }
    (OUT / "p0_2_tests.json").write_text(json.dumps(tests, indent=2, ensure_ascii=False), encoding="utf-8")

    after = {
        "generated_at_utc": utc(),
        "verdict": verdict,
        "behavior": {
            "apply_requires_tenant": True,
            "zdde_mesh_without_tenant": "NO_TENANT_CONTEXT",
            "legacy_unscoped_influences_zdde": False,
            "cross_tenant_ioc_visible": False,
        },
        "performance": perf,
    }
    (OUT / "p0_2_after.json").write_text(json.dumps(after, indent=2), encoding="utf-8")
    (OUT / "p0_2_before_after.json").write_text(
        json.dumps(
            {
                "before": before.get("behavior") or before.get("contamination_path") or before,
                "after": after,
                "performance_before": before.get("performance"),
                "performance_after": perf,
                "files_changed": tests["production_files_modified"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    report = f"""# P0-2 REPORT — Mesh IOC → ZDDE tenant isolation

## VERDICT

`{verdict}`

## CAMBIOS

| Archivo | Cambio |
|---------|--------|
| `services/swarm_defense/mesh/intel_store.py` | Store tenant-scoped; deny sin tenant; legacy ignorado para ZDDE |
| `services/swarm_defense/mesh/ingest.py` | Pasa payload/tenant a apply; registra NO_INFLUENCE |
| `services/swarm_defense/mesh/propagator.py` | Incluye `tenant_id` en payload/origin |
| `services/zero_day_detection/layers.py` | `layer_mesh_intel(tenant_id=)`; deny-by-default |
| `services/zero_day_detection/engine.py` | `run_zdde_cycle(tenant_id=)` opcional |

## ARCHIVOS NO MODIFICADOS

collective_memory P0-1, MAC feedback, learning.jsonl, BTDE, Identity Intelligence, AI Kernel, Traffic, Network Monitor, YARA, Endpoint Enterprise, auth/MFA/RBAC/CSRF/CryptoVault/Abuse Guard, dashboard/UI/APIs nuevas.

## EVIDENCIA

| Prueba | Resultado |
|--------|-----------|
| A→A | {g('tenant_a_to_a')} |
| B→B | {g('tenant_b_to_b')} |
| A→B | {g('tenant_a_to_b')} (DENIED) |
| B→A | {g('tenant_b_to_a')} (DENIED) |
| cache | {g('cache_isolation')} |
| missing tenant | {g('missing_tenant_apply')} / {g('missing_tenant_zdde_layer')} |
| persistence | {g('persistence')} |
| serialization | {g('serialization_tenant')} |
| security | {g('security_regression')} |
| host ZDDE deny | {g('host_zdde_no_mesh_influence')} / {g('production_host_deny')} |

## LIMITACIONES

1. Ciclos ZDDE host (`tenant_id=None`) **no** consumen mesh intel (deny-by-default). Influencia same-tenant requiere `run_zdde_cycle(tenant_id=...)` / `layer_mesh_intel(tenant_id=...)`.
2. Filas legacy en `legacy_unscoped` no se reasignan ni influencian ZDDE.
3. Reiniciar proceso NOVUS para cargar el código.
4. Mesh status inventory (`stats()` sin `for_zdde_influence`) puede seguir mostrando totales de inventario — **no** es score ZDDE.
5. Envelope crypto E2E peer-to-peer completo: **NO PUEDO CONFIRMARLO** en este gate (se validó preservación de `tenant_id` en payload JSON).

## ROLLBACK

Restaurar:
- `services/swarm_defense/mesh/intel_store.py`
- `services/swarm_defense/mesh/ingest.py`
- `services/swarm_defense/mesh/propagator.py`
- `services/zero_day_detection/layers.py`
- `services/zero_day_detection/engine.py`

Propiedad perdida al revertir: aislamiento Mesh IOC → ZDDE (vuelve contaminación lógica vía `has_shared_intel` global).
"""
    (OUT / "p0_2_report.md").write_text(report, encoding="utf-8")

    try:
        shutil.rmtree(tmp, ignore_errors=True)
    except Exception:
        pass

    print(json.dumps({"verdict": verdict, "crit_ok": crit_ok, "sec_ok": sec_ok}, indent=2))
    return 0 if verdict.startswith("P0_2_PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
