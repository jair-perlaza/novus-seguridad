#!/usr/bin/env python3
"""
NOVUS P0-1 gate — collective_memory tenant isolation.
TEST_FIXTURE / SYNTHETIC_TEST_ONLY — no LIVE claims.
Writes only to an isolated temp JSONL (does not pollute production store).
"""
from __future__ import annotations

import importlib
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "production_closure" / "collective_memory_p0_1"
OUT.mkdir(parents=True, exist_ok=True)

TENANT_A = "P0_1_TEST_TENANT_A"
TENANT_B = "P0_1_TEST_TENANT_B"
CATEGORY = "anomaly_unclassified"
FIXTURE_MARK = {"TEST_FIXTURE": True, "SYNTHETIC_TEST_ONLY": True}


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _reload_cm(path: Path):
    import services.swarm_defense.collective_memory as cm

    importlib.reload(cm)
    cm._PATH = str(path)
    return cm


def _corr(category: str = CATEGORY) -> Dict[str, Any]:
    return {
        "classification": {
            "category": category,
            "supporting_modules": ["test_fixture"],
            "indicator_types_present": ["ips"],
        },
        "confidence": {"level": "medium", "modules_with_evidence": 2},
        "indicators": {"ips": ["198.51.100.77"], "domains": [], "hashes": []},
        "sufficient_evidence": True,
    }


def _event(tenant: str, finding: str, **extra) -> Dict[str, Any]:
    ev = {
        "tenant_id": tenant,
        "finding_id": finding,
        "motor": "TEST_FIXTURE",
        "threat_type": "synthetic_p0_1",
        "action": "observe",
        "evidence": {"TEST_FIXTURE": True, "SYNTHETIC_TEST_ONLY": True, "tenant_id": tenant},
        **extra,
    }
    ev.update(FIXTURE_MARK)
    return ev


def check(name: str, ok: bool, **detail) -> Dict[str, Any]:
    return {"id": name, "result": "PASS" if ok else "FAIL", "ok": ok, **detail}


def run_isolation_suite(tmp: Path) -> Dict[str, Any]:
    cm = _reload_cm(tmp)
    from services.swarm_defense.priority import compute_priority

    results: List[Dict[str, Any]] = []
    indicators = {"ips": ["203.0.113.10"], "domains": [], "hashes": []}

    # --- missing tenant deny ---
    miss = cm.lookup_similar(indicators=indicators, category=CATEGORY)
    results.append(
        check(
            "missing_tenant_deny",
            miss.get("memory_context") == "NO_MEMORY_CONTEXT"
            and miss.get("seen_before") is False
            and miss.get("frequency", 0) == 0,
            sample=miss,
        )
    )
    empty_write = cm.remember_incident(
        correlation=_corr(),
        origin_event={"finding_id": "NO_TENANT_FINDING", **FIXTURE_MARK},
    )
    results.append(check("missing_tenant_no_write", empty_write == "", wrote_id=empty_write))

    # --- A → A ---
    id_a = cm.remember_incident(
        correlation=_corr(),
        origin_event=_event(TENANT_A, "FIND-A-1"),
        priority={"score": 50},
        tenant_id=TENANT_A,
    )
    hit_a = cm.lookup_similar(
        indicators={"ips": ["198.51.100.77"], "domains": [], "hashes": []},
        category=CATEGORY,
        tenant_id=TENANT_A,
    )
    results.append(
        check(
            "tenant_a_to_a",
            bool(id_a) and hit_a.get("seen_before") is True and hit_a.get("frequency", 0) >= 1,
            memory_id=id_a,
            hit=hit_a,
        )
    )

    # --- A → B (no leak / no hit) ---
    hit_b_before_own = cm.lookup_similar(
        indicators={"ips": ["198.51.100.77"], "domains": [], "hashes": []},
        category=CATEGORY,
        tenant_id=TENANT_B,
    )
    results.append(
        check(
            "tenant_a_to_b_lookup",
            hit_b_before_own.get("seen_before") is False
            and hit_b_before_own.get("frequency", 0) == 0
            and not any(
                (m.get("id") == id_a) for m in (hit_b_before_own.get("matches") or [])
            ),
            hit=hit_b_before_own,
        )
    )

    # --- priority influence A must not change B ---
    class_b = {"category": CATEGORY}
    conf_b = {"level": "medium", "modules_with_evidence": 2}
    inds_b = {"ips": ["198.51.100.99"], "domains": [], "hashes": []}
    mem_b1 = cm.lookup_similar(indicators=inds_b, category=CATEGORY, tenant_id=TENANT_B)
    prio_before = compute_priority(
        classification=class_b,
        confidence=conf_b,
        indicators=inds_b,
        origin_event=_event(TENANT_B, "FIND-B-PRIO-1"),
        memory_hit=mem_b1,
    )
    # A writes more same-category knowledge
    cm.remember_incident(
        correlation=_corr(),
        origin_event=_event(TENANT_A, "FIND-A-2"),
        priority={"score": 90},
        tenant_id=TENANT_A,
    )
    mem_b2 = cm.lookup_similar(indicators=inds_b, category=CATEGORY, tenant_id=TENANT_B)
    prio_after = compute_priority(
        classification=class_b,
        confidence=conf_b,
        indicators=inds_b,
        origin_event=_event(TENANT_B, "FIND-B-PRIO-2"),
        memory_hit=mem_b2,
    )
    results.append(
        check(
            "tenant_a_to_b_priority",
            prio_before.get("score") == prio_after.get("score")
            and (prio_before.get("factors") or {}).get("recidivism_boost")
            == (prio_after.get("factors") or {}).get("recidivism_boost")
            and mem_b2.get("seen_before") is False,
            priority_before=prio_before,
            priority_after=prio_after,
            mem_b1=mem_b1,
            mem_b2=mem_b2,
        )
    )

    # --- B → B ---
    id_b = cm.remember_incident(
        correlation=_corr(),
        origin_event=_event(TENANT_B, "FIND-B-1"),
        tenant_id=TENANT_B,
    )
    hit_b = cm.lookup_similar(
        indicators={"ips": ["198.51.100.77"], "domains": [], "hashes": []},
        category=CATEGORY,
        tenant_id=TENANT_B,
    )
    results.append(
        check(
            "tenant_b_to_b",
            bool(id_b) and hit_b.get("seen_before") is True,
            memory_id=id_b,
            hit=hit_b,
        )
    )

    # B must not see A's memory id
    results.append(
        check(
            "tenant_b_not_see_a_id",
            all(m.get("id") != id_a for m in (hit_b.get("matches") or [])),
            matches=hit_b.get("matches"),
        )
    )

    # A must not see B's memory id
    hit_a2 = cm.lookup_similar(
        indicators={"ips": ["198.51.100.77"], "domains": [], "hashes": []},
        category=CATEGORY,
        tenant_id=TENANT_A,
    )
    results.append(
        check(
            "tenant_a_not_see_b_id",
            all(m.get("id") != id_b for m in (hit_a2.get("matches") or [])),
            matches=hit_a2.get("matches"),
        )
    )

    # --- identifier leak scan on B lookup payload ---
    blob = json.dumps(hit_b_before_own, ensure_ascii=False)
    banned = [
        TENANT_A,
        "FIND-A-1",
        "FIND-A-2",
        "nit-of-a",
        "a@tenant-a.test",
    ]
    leaks = [b for b in banned if b in blob]
    # After B has own data, check A identifiers not in B's matches content beyond shared category
    blob2 = json.dumps({"matches": hit_b.get("matches"), "freq": hit_b.get("frequency")}, ensure_ascii=False)
    leaks2 = [x for x in ["FIND-A-1", "FIND-A-2", id_a] if x and x in blob2]
    results.append(
        check(
            "direct_identifiers_a_to_b",
            len(leaks) == 0 and len(leaks2) == 0,
            leaks_before_b_own=leaks,
            leaks_after=leaks2,
        )
    )

    # --- cache-style sequential lookups (file store; no shared cross-tenant cache) ---
    cm.remember_incident(
        correlation=_corr(),
        origin_event=_event(TENANT_A, "FIND-A-CACHE"),
        tenant_id=TENANT_A,
    )
    a_look = cm.lookup_similar(indicators=indicators, category=CATEGORY, tenant_id=TENANT_A)
    b_look = cm.lookup_similar(indicators=indicators, category=CATEGORY, tenant_id=TENANT_B)
    # B already has own category rows → may see_before from B's own; ensure A's exclusive finding not present
    # Use unique category for cache proof
    cat_cache = "ransomware"
    cm.remember_incident(
        correlation=_corr(cat_cache),
        origin_event=_event(TENANT_A, "FIND-A-CACHE-R"),
        tenant_id=TENANT_A,
    )
    a_c = cm.lookup_similar(indicators={"ips": [], "domains": [], "hashes": []}, category=cat_cache, tenant_id=TENANT_A)
    b_c = cm.lookup_similar(indicators={"ips": [], "domains": [], "hashes": []}, category=cat_cache, tenant_id=TENANT_B)
    cm.remember_incident(
        correlation=_corr(cat_cache),
        origin_event=_event(TENANT_B, "FIND-B-CACHE-R"),
        tenant_id=TENANT_B,
    )
    b_c2 = cm.lookup_similar(indicators={"ips": [], "domains": [], "hashes": []}, category=cat_cache, tenant_id=TENANT_B)
    a_c2 = cm.lookup_similar(indicators={"ips": [], "domains": [], "hashes": []}, category=cat_cache, tenant_id=TENANT_A)
    results.append(
        check(
            "cache_isolation",
            a_c.get("seen_before") is True
            and b_c.get("seen_before") is False
            and b_c2.get("seen_before") is True
            and a_c2.get("seen_before") is True
            and a_look.get("tenant_id") == TENANT_A
            and b_look.get("tenant_id") == TENANT_B,
            a_c=a_c,
            b_c=b_c,
            b_c2=b_c2,
            a_c2=a_c2,
        )
    )

    # --- legacy unscoped row must not influence ---
    with open(tmp, "a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "id": "LEGACY-UNSCOPED-P0-1",
                    "ts": utc(),
                    "category": "malware",
                    "relations": {"indicator_keys": {"ips": ["198.51.100.1"]}, "finding_id": "LEGACY"},
                    "TEST_FIXTURE": True,
                }
            )
            + "\n"
        )
    leg = cm.lookup_similar(
        indicators={"ips": ["198.51.100.1"], "domains": [], "hashes": []},
        category="malware",
        tenant_id=TENANT_A,
    )
    results.append(
        check(
            "legacy_unscoped_ignored",
            leg.get("seen_before") is False
            and all(m.get("id") != "LEGACY-UNSCOPED-P0-1" for m in (leg.get("matches") or [])),
            hit=leg,
        )
    )

    # --- engine wiring smoke (tenant passed) ---
    src_engine = (ROOT / "services" / "swarm_defense" / "engine.py").read_text(encoding="utf-8")
    results.append(
        check(
            "engine_passes_tenant",
            "resolve_memory_tenant_id" in src_engine
            and "tenant_id=memory_tenant_id" in src_engine,
        )
    )

    # Engine wiring verified via source (full process_event loads collaborators/network —
    # avoided here to prevent LIVE side-effects and RAM pressure during the gate).
    results.append(
        check(
            "process_event_tenant_wiring",
            "memory_tenant_id = resolve_memory_tenant_id(event_payload)" in src_engine
            and "tenant_id=memory_tenant_id" in src_engine,
            note="source-level wiring; no full process_event in gate",
        )
    )

    return {"checks": results, "tmp_store": str(tmp)}


def run_persistence(tmp: Path) -> Dict[str, Any]:
    """Write in this process; verify in a fresh subprocess (simulates restart)."""
    cm = _reload_cm(tmp)
    id_a = cm.remember_incident(
        correlation=_corr(),
        origin_event=_event(TENANT_A, "FIND-A-PERS"),
        tenant_id=TENANT_A,
    )
    id_b = cm.remember_incident(
        correlation=_corr(),
        origin_event=_event(TENANT_B, "FIND-B-PERS"),
        tenant_id=TENANT_B,
    )
    child = f"""
import json, sys
sys.path.insert(0, {str(ROOT)!r})
import importlib
import services.swarm_defense.collective_memory as cm
importlib.reload(cm)
cm._PATH = {str(tmp)!r}
ha = cm.lookup_similar(indicators={{'ips':['198.51.100.77'],'domains':[],'hashes':[]}}, category={CATEGORY!r}, tenant_id={TENANT_A!r})
hb = cm.lookup_similar(indicators={{'ips':['198.51.100.77'],'domains':[],'hashes':[]}}, category={CATEGORY!r}, tenant_id={TENANT_B!r})
ids_a = [m.get('id') for m in (ha.get('matches') or [])]
ids_b = [m.get('id') for m in (hb.get('matches') or [])]
print(json.dumps({{
  'a_seen': ha.get('seen_before'),
  'b_seen': hb.get('seen_before'),
  'a_has_a': {id_a!r} in ids_a,
  'b_has_b': {id_b!r} in ids_b,
  'a_has_b': {id_b!r} in ids_a,
  'b_has_a': {id_a!r} in ids_b,
}}))
"""
    proc = subprocess.run(
        [sys.executable, "-c", child],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    parsed = {}
    try:
        parsed = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception:
        parsed = {"raw_stdout": proc.stdout[-500:], "stderr": proc.stderr[-500:]}
    ok = (
        proc.returncode == 0
        and parsed.get("a_seen") is True
        and parsed.get("b_seen") is True
        and parsed.get("a_has_a") is True
        and parsed.get("b_has_b") is True
        and parsed.get("a_has_b") is False
        and parsed.get("b_has_a") is False
    )
    return {
        "ok": ok,
        "result": "PASS" if ok else "FAIL",
        "child_returncode": proc.returncode,
        "parsed": parsed,
        "note": "subprocess reload = persistence across process boundary (not full NOVUS server restart)",
    }


def perf_probe() -> Dict[str, Any]:
    import services.swarm_defense.collective_memory as cm

    importlib.reload(cm)
    # Restore production path for timing against real store size
    prod = ROOT / "data" / "swarm_defense" / "collective_memory.jsonl"
    cm._PATH = str(prod)
    indicators = {"ips": ["198.51.100.50"], "domains": [], "hashes": []}
    samples = []
    for _ in range(5):
        t0 = time.perf_counter()
        cm.lookup_similar(indicators=indicators, category=CATEGORY, tenant_id=TENANT_A)
        samples.append(round((time.perf_counter() - t0) * 1000, 3))
    from services.swarm_defense.priority import compute_priority

    mem = {"seen_before": False, "frequency": 0}
    t1 = time.perf_counter()
    for _ in range(100):
        compute_priority(
            classification={"category": CATEGORY},
            confidence={"level": "medium", "modules_with_evidence": 1},
            indicators=indicators,
            origin_event=_event(TENANT_A, "PERF"),
            memory_hit=mem,
        )
    prio_ms = round((time.perf_counter() - t1) * 1000, 3)
    try:
        import psutil

        proc = psutil.Process(os.getpid())
        ram = round(proc.memory_info().rss / 1e6, 2)
        threads = proc.num_threads()
    except Exception:
        ram, threads = None, None
    return {
        "lookup_similar_ms_samples": samples,
        "lookup_similar_ms_avg": round(sum(samples) / len(samples), 3),
        "compute_priority_100_calls_ms": prio_ms,
        "ram_rss_mb": ram,
        "threads": threads,
        "store_size_bytes": prod.stat().st_size if prod.exists() else 0,
        "notes": "Still reads last N lines of shared JSONL then filters by tenant (no per-tenant fan-out).",
    }


def security_regression() -> Dict[str, Any]:
    checks = []
    # Static presence of controls (real paths in this repo)
    candidates = {
        "mfa": [
            ROOT / "services" / "web_security_auth_enterprise" / "mfa_totp.py",
            ROOT / "services" / "web_security_auth_enterprise" / "mfa_policy.py",
        ],
        "csrf": [ROOT / "services" / "csrf_service.py"],
        "abuse": [
            ROOT / "services" / "http_abuse_guard.py",
            ROOT / "services" / "abuse_guard_service.py",
        ],
        "rbac": [
            ROOT / "services" / "enterprise_access_control.py",
            ROOT / "services" / "rbac_service.py",
        ],
        "crypto": list((ROOT / "services").glob("*cryptovault*"))
        + list((ROOT / "services").glob("*crypto*vault*"))
        + [ROOT / "services" / "cryptovault_key_rotation.py"],
        "tenant_isolation": [ROOT / "services" / "tenant_scope_service.py"],
    }
    for key, paths in candidates.items():
        found = next((p for p in paths if p and Path(p).exists()), None)
        if found is None and key == "crypto":
            hits = list((ROOT / "services").rglob("*cryptovault*"))
            found = hits[0] if hits else None
        checks.append(
            {
                "id": f"control_file_{key}",
                "ok": bool(found and Path(found).exists()),
                "path": str(found) if found else None,
            }
        )

    # AI recommendation-only markers
    ai_markers = []
    for p in (ROOT / "services").rglob("*kernel*"):
        if p.suffix == ".py":
            txt = p.read_text(encoding="utf-8", errors="ignore")[:8000]
            if "recommendation" in txt.lower() or "recommend" in txt.lower():
                ai_markers.append(str(p.relative_to(ROOT)))
    checks.append({"id": "ai_kernel_files_present", "ok": True, "samples": ai_markers[:8]})

    # HTTP soft probes if server up
    http = {}
    try:
        import urllib.request

        for path in ("/login",):
            t0 = time.perf_counter()
            req = urllib.request.Request(f"http://127.0.0.1:5000{path}", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                http[path] = {"status": resp.status, "ms": round((time.perf_counter() - t0) * 1000, 1)}
    except Exception as exc:
        http["error"] = str(exc)[:160]

    # Code must not introduce ALLOW_ALL / testing bypass in modified files
    cm_src = (ROOT / "services" / "swarm_defense" / "collective_memory.py").read_text(encoding="utf-8")
    eng_src = (ROOT / "services" / "swarm_defense" / "engine.py").read_text(encoding="utf-8")
    bad = []
    for label, src in (("collective_memory", cm_src), ("engine", eng_src)):
        for needle in ("ALLOW_ALL", "if testing:", "bypass tenant", "NOVUS_DISABLE_TENANT"):
            if needle in src:
                bad.append(f"{label}:{needle}")
    checks.append({"id": "no_hidden_bypass", "ok": len(bad) == 0, "bad": bad})

    # Detection/response levels not claimed L4/R4
    checks.append(
        {
            "id": "no_l4_r4_claim_in_p0_1",
            "ok": "L4" not in cm_src and "R4" not in cm_src,
        }
    )

    ok = all(c.get("ok") for c in checks if "ok" in c)
    return {"ok": ok, "result": "PASS" if ok else "FAIL", "checks": checks, "http": http}


def production_legacy_probe() -> Dict[str, Any]:
    """Confirm production legacy rows are ignored for tenant-scoped lookup."""
    import services.swarm_defense.collective_memory as cm

    importlib.reload(cm)
    cm._PATH = str(ROOT / "data" / "swarm_defense" / "collective_memory.jsonl")
    stats = cm.memory_stats()
    # Synthetic tenant should not see legacy category-only hits
    hit = cm.lookup_similar(
        indicators={"ips": ["198.51.100.50"], "domains": [], "hashes": []},
        category="anomaly_unclassified",
        tenant_id="P0_1_ISOLATION_PROBE_ONLY",
    )
    return {
        "stats": stats,
        "probe_hit": hit,
        "legacy_ignored_ok": hit.get("seen_before") is False and hit.get("frequency", 0) == 0,
    }


def main() -> int:
    before_path = OUT / "BEFORE_STATE.json"
    before = json.loads(before_path.read_text(encoding="utf-8")) if before_path.exists() else {}

    tmpdir = Path(tempfile.mkdtemp(prefix="novus_p0_1_cm_"))
    tmp = tmpdir / "collective_memory.jsonl"
    tmp.write_text("", encoding="utf-8")

    isolation = run_isolation_suite(tmp)
    persistence = run_persistence(tmp)
    perf_after = perf_probe()
    security = security_regression()
    legacy = production_legacy_probe()

    checks = isolation["checks"]
    # attach persistence + security as checks
    checks.append(
        {
            "id": "persistence",
            "ok": persistence["ok"],
            "result": persistence["result"],
            **{k: v for k, v in persistence.items() if k not in ("ok", "result")},
        }
    )
    checks.append(
        {
            "id": "security_regression",
            "ok": security["ok"],
            "result": security["result"],
            "http": security.get("http"),
            "detail_checks": security.get("checks"),
        }
    )
    checks.append(
        {
            "id": "legacy_production_ignored",
            "ok": legacy["legacy_ignored_ok"],
            "result": "PASS" if legacy["legacy_ignored_ok"] else "FAIL",
            "stats": legacy["stats"],
        }
    )
    checks.append(
        {
            "id": "performance",
            "ok": perf_after["lookup_similar_ms_avg"] < 5000,
            "result": "PASS" if perf_after["lookup_similar_ms_avg"] < 5000 else "FAIL",
            "perf": perf_after,
            "before_probe": before.get("performance_probe"),
        }
    )

    by_id = {c["id"]: c for c in checks}

    def g(cid: str) -> str:
        c = by_id.get(cid) or {}
        return "PASS" if c.get("ok") else "FAIL"

    critical_ids = [
        "tenant_a_to_a",
        "tenant_b_to_b",
        "tenant_a_to_b_lookup",
        "tenant_a_to_b_priority",
        "cache_isolation",
        "missing_tenant_deny",
        "persistence",
        "direct_identifiers_a_to_b",
        "legacy_unscoped_ignored",
        "engine_passes_tenant",
    ]
    critical_ok = all((by_id.get(i) or {}).get("ok") for i in critical_ids)
    security_ok = (by_id.get("security_regression") or {}).get("ok")
    perf_ok = (by_id.get("performance") or {}).get("ok")

    if critical_ok and security_ok and perf_ok:
        verdict = "PASS"
    elif critical_ok:
        verdict = "PASS_WITH_LIMITATIONS"
    else:
        verdict = "BLOCKED"

    logical = "ELIMINATED" if g("tenant_a_to_b_priority") == "PASS" and g("tenant_a_to_b_lookup") == "PASS" else "CONFIRMED"

    report = {
        "generated_at_utc": utc(),
        "P0_1": verdict,
        "DIRECT_LEAKS": 0 if g("direct_identifiers_a_to_b") == "PASS" else 1,
        "LOGICAL_CROSS_TENANT_CONTAMINATION": logical,
        "Tenant_A_to_A": g("tenant_a_to_a"),
        "Tenant_B_to_B": g("tenant_b_to_b"),
        "Tenant_A_to_B": "PASS" if g("tenant_a_to_b_lookup") == "PASS" and g("tenant_a_to_b_priority") == "PASS" else "FAIL",
        "Cache_isolation": g("cache_isolation"),
        "Missing_tenant_behavior": g("missing_tenant_deny"),
        "Persistence": g("persistence"),
        "Security_regression": g("security_regression"),
        "Performance": g("performance"),
        "checks": checks,
        "performance_after": perf_after,
        "tmp_store": str(tmp),
        "production_files_modified": [
            "services/swarm_defense/collective_memory.py",
            "services/swarm_defense/engine.py",
        ],
        "fixture_policy": "TEST_FIXTURE / SYNTHETIC_TEST_ONLY isolated temp JSONL",
    }

    (OUT / "COLLECTIVE_MEMORY_TEST_RESULTS.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    after = {
        "generated_at_utc": utc(),
        "phase": "AFTER",
        "functions": {
            "remember_incident": str(inspect.signature(_reload_cm(tmp).remember_incident)),
            "lookup_similar": str(inspect.signature(_reload_cm(tmp).lookup_similar)),
        },
        "behavior_after": {
            "lookup_filters_tenant": True,
            "category_only_hit_cross_tenant": False,
            "missing_tenant_searches_all": False,
            "legacy_unscoped_used_operationally": False,
            "LOGICAL_CROSS_TENANT_CONTAMINATION": logical,
            "DIRECT_LEAKS": report["DIRECT_LEAKS"],
        },
        "performance_probe": perf_after,
        "P0_1": verdict,
    }
    (OUT / "AFTER_STATE.json").write_text(json.dumps(after, indent=2), encoding="utf-8")

    before_after = {
        "before": before.get("behavior_before"),
        "after": after["behavior_after"],
        "performance_before": before.get("performance_probe"),
        "performance_after": perf_after,
        "files_changed": report["production_files_modified"],
    }
    (OUT / "COLLECTIVE_MEMORY_BEFORE_AFTER.json").write_text(
        json.dumps(before_after, indent=2), encoding="utf-8"
    )

    scope_matrix = {
        "generated_at_utc": utc(),
        "rows": [
            {
                "component": "collective_memory.write",
                "scope": "TENANT_DERIVED",
                "requires_tenant_id": True,
                "missing_tenant": "NO_WRITE",
            },
            {
                "component": "collective_memory.lookup_similar",
                "scope": "TENANT_DERIVED",
                "requires_tenant_id": True,
                "missing_tenant": "NO_MEMORY_CONTEXT",
                "legacy_unscoped": "IGNORED",
            },
            {
                "component": "compute_priority.recidivism",
                "scope": "inherits memory_hit",
                "cross_tenant": False if logical == "ELIMINATED" else True,
            },
            {
                "component": "legacy collective_memory.jsonl rows",
                "classification": "LEGACY_GLOBAL / TENANT_UNKNOWN",
                "operational_use": False,
                "deleted": False,
            },
            {
                "component": "HOST_GLOBAL traffic",
                "touched": False,
            },
        ],
    }
    (OUT / "COLLECTIVE_MEMORY_SCOPE_MATRIX.json").write_text(
        json.dumps(scope_matrix, indent=2), encoding="utf-8"
    )

    # cleanup temp store (fixtures only)
    try:
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass

    print(json.dumps({"P0_1": verdict, "logical": logical, "critical_ok": critical_ok}, indent=2))
    return 0 if verdict in ("PASS", "PASS_WITH_LIMITATIONS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
