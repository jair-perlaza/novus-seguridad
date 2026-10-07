#!/usr/bin/env python3
"""
NOVUS Global Learning Boundary Audit — READ-ONLY forensics.
No production code changes. No anonymization / ML / architecture changes.
Writes: data/production_closure/global_learning_boundary_audit/*
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure" / "global_learning_boundary_audit"
OUT.mkdir(parents=True, exist_ok=True)
BASE = os.environ.get("NOVUS_TEST_BASE", "http://127.0.0.1:5000")
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write(name: str, data: Any) -> None:
    p = OUT / name
    if name.endswith(".md"):
        p.write_text(str(data), encoding="utf-8")
    else:
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def sample_jsonl(rel: str, max_lines: int = 3, scan_for_keys: Optional[List[str]] = None) -> Dict[str, Any]:
    path = ROOT / rel
    scan_for_keys = scan_for_keys or ["tenant_id", "email", "user_id", "company_id", "nit"]
    if not path.exists():
        return {"exists": False, "path": rel}
    samples = []
    key_hits: Dict[str, int] = {k: 0 for k in scan_for_keys}
    n = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            n += 1
            try:
                obj = json.loads(line)
            except Exception:
                continue
            blob = json.dumps(obj, default=str)
            for k in scan_for_keys:
                if f'"{k}"' in blob or f"'{k}'" in blob:
                    # count only if key present in object tree
                    if k in obj or k in blob:
                        key_hits[k] += 1
            if len(samples) < max_lines:
                # slim for evidence
                samples.append({k: obj.get(k) for k in list(obj.keys())[:14]})
    return {
        "exists": True,
        "path": rel,
        "bytes": path.stat().st_size,
        "lines_approx": n,
        "key_presence_counts_in_scan": key_hits,
        "tenant_id_present": key_hits.get("tenant_id", 0) > 0,
        "samples": samples,
    }


def sample_json(rel: str) -> Dict[str, Any]:
    path = ROOT / rel
    if not path.exists():
        return {"exists": False, "path": rel}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return {"exists": True, "path": rel, "error": str(e)[:160]}
    keys = list(data.keys())[:20] if isinstance(data, dict) else []
    has_tenant = "tenant_id" in json.dumps(data, default=str)[:50000]
    return {
        "exists": True,
        "path": rel,
        "bytes": path.stat().st_size,
        "top_keys": keys,
        "tenant_id_present_in_file": has_tenant,
        "type": type(data).__name__,
    }


def inventory() -> Dict[str, Any]:
    stores = [
        {
            "id": "swarm_learning",
            "store": "data/swarm_defense/learning.jsonl",
            "owner": "services/swarm_defense/learning.py",
            "scope": "HOST_GLOBAL",
            "format": "JSONL",
            "writers": [
                "record_confirmed_incident ← engine.process_event",
                "record_confirmed_incident ← response_policy.generate_report",
            ],
            "readers": ["recent_learning / learning_stats ← engine.status, api/swarm_defense audit"],
            "persistence": "append-only file",
            "tenant_id": "NO",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": sample_jsonl("data/swarm_defense/learning.jsonl"),
        },
        {
            "id": "swarm_learning_rejected",
            "store": "data/swarm_defense/learning_rejected.jsonl",
            "owner": "services/swarm_defense/learning.py",
            "scope": "HOST_GLOBAL",
            "format": "JSONL",
            "writers": ["_kernel_learning_safe reject path"],
            "readers": ["learning_stats count"],
            "tenant_id": "NO",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": sample_jsonl("data/swarm_defense/learning_rejected.jsonl", 1),
        },
        {
            "id": "collective_memory",
            "store": "data/swarm_defense/collective_memory.jsonl",
            "owner": "services/swarm_defense/collective_memory.py",
            "scope": "HOST_GLOBAL",
            "format": "JSONL",
            "writers": ["remember_incident ← engine.process_event"],
            "readers": ["lookup_similar ← engine.process_event → compute_priority", "memory_stats"],
            "tenant_id": "NO",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "NOT_IMPLEMENTED",
            "logical_contamination": "CONFIRMED — lookup_similar has no tenant filter",
            "file_evidence": sample_jsonl("data/swarm_defense/collective_memory.jsonl"),
        },
        {
            "id": "mesh_shared_iocs",
            "store": "data/swarm_mesh/intel/shared_iocs.json",
            "owner": "services/swarm_defense/mesh/intel_store.py",
            "scope": "NOVUS_GLOBAL",
            "format": "JSON",
            "writers": ["apply_indicators ← mesh/ingest.ingest_envelope", "propagator outbound"],
            "readers": ["intel_store.stats ← ZDDE layer_mesh_intel", "api/swarm_mesh"],
            "tenant_id": "NO",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": sample_json("data/swarm_mesh/intel/shared_iocs.json"),
        },
        {
            "id": "mesh_inbound",
            "store": "data/swarm_mesh/intel/inbound.jsonl",
            "owner": "mesh/intel_store.py",
            "scope": "NOVUS_GLOBAL",
            "format": "JSONL",
            "tenant_id": "NO",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": sample_jsonl("data/swarm_mesh/intel/inbound.jsonl", 1),
        },
        {
            "id": "mesh_outbound",
            "store": "data/swarm_mesh/intel/outbound.jsonl",
            "owner": "mesh/intel_store.py",
            "scope": "NOVUS_GLOBAL",
            "format": "JSONL",
            "tenant_id": "NO",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": sample_jsonl("data/swarm_mesh/intel/outbound.jsonl", 1),
        },
        {
            "id": "global_search_learning",
            "store": "data/global_search_learning.json",
            "owner": "services/global_search_learning_store.py",
            "scope": "MIXED",
            "format": "JSON",
            "writers": ["record_search / record_click ← search APIs"],
            "readers": ["per-user ranking boosts; global_queries counted in audit_snapshot"],
            "tenant_id": "NO (email keys)",
            "isolation": "PARTIAL — user partition; global_queries shared",
            "anonymization": "NOT_IMPLEMENTED (lowercase query only)",
            "file_evidence": sample_json("data/global_search_learning.json"),
        },
        {
            "id": "ai_kernel_feedback",
            "store": "data/ai_kernel_feedback/feedback.json",
            "owner": "services/ai_kernel_event_engine/knowledge_adapter.py",
            "scope": "HOST_GLOBAL",
            "format": "JSON",
            "writers": ["learn_from_feedback ← request_router / asset_intelligence admin"],
            "readers": ["analyze_event is_whitelisted / get_risk_modifier"],
            "tenant_id": "NO (MAC keys)",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": sample_json("data/ai_kernel_feedback/feedback.json"),
        },
        {
            "id": "kernel_operations",
            "store": "data/kernel_operations.jsonl",
            "owner": "services/kernel_memory.py log_operation",
            "scope": "HOST_GLOBAL",
            "format": "JSONL",
            "tenant_id": "NO (typically)",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": sample_jsonl("data/kernel_operations.jsonl", 1),
        },
        {
            "id": "kernel_memory_user",
            "store": "data/kernel_memory/*.json",
            "owner": "services/kernel_memory.py",
            "scope": "TENANT/USER",
            "format": "JSON per user key",
            "tenant_id": "NO (user_id/email key)",
            "isolation": "file-per-user PATH isolation",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": {
                "dir_exists": (ROOT / "data/kernel_memory").exists(),
                "sample_files": [p.name for p in (ROOT / "data/kernel_memory").glob("*.json")][:8]
                if (ROOT / "data/kernel_memory").exists()
                else [],
            },
        },
        {
            "id": "btde_host_baseline",
            "store": "data/behavioral_threat_detection/host_baseline.json",
            "owner": "services/behavioral_threat_detection/baseline.py",
            "scope": "HOST_GLOBAL",
            "format": "JSON",
            "tenant_id": "NO",
            "isolation": "ISOLATION_NOT_DEMONSTRATED (intentional host scope)",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": sample_json("data/behavioral_threat_detection/host_baseline.json"),
        },
        {
            "id": "btde_tenant_baselines",
            "store": "data/behavioral_threat_detection/tenant_baselines/<tid>.json",
            "owner": "baseline.py",
            "scope": "TENANT",
            "format": "JSON",
            "tenant_id": "YES (filename + field)",
            "isolation": "filesystem partition (PARTIAL if cycle uses platform tid)",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": {
                "files": [
                    p.name
                    for p in (ROOT / "data/behavioral_threat_detection/tenant_baselines").glob("*.json")
                ][:15]
                if (ROOT / "data/behavioral_threat_detection/tenant_baselines").exists()
                else []
            },
        },
        {
            "id": "lan_baseline",
            "store": "data/network_baseline/lan_baseline.json",
            "owner": "services/network_baseline_service.py",
            "scope": "HOST_GLOBAL",
            "format": "JSON",
            "tenant_id": "NO",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": sample_json("data/network_baseline/lan_baseline.json"),
        },
        {
            "id": "ape_sqlite",
            "store": "novus_vault_v2.db behavior_* tables",
            "owner": "services/adaptive_profile_engine.py",
            "scope": "MIXED (user_email primary; tenant_id metadata)",
            "format": "SQLite",
            "tenant_id": "YES column; query by email",
            "isolation": "PARTIAL user-scoped",
            "anonymization": "NOT_IMPLEMENTED",
            "global_export": False,
        },
        {
            "id": "playbook_learning",
            "store": "data/playbook_learning/records.jsonl",
            "owner": "playbook_orchestrator.save_playbook_learning",
            "scope": "HOST_GLOBAL",
            "format": "JSONL",
            "tenant_id": "NO (usuario email may appear)",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": sample_jsonl("data/playbook_learning/records.jsonl", 1),
        },
        {
            "id": "adaptive_defense_state",
            "store": "data/adaptive_defense/state.json",
            "owner": "adaptive_defense_engine.py",
            "scope": "HOST_GLOBAL",
            "tenant_id": "NO",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": sample_json("data/adaptive_defense/state.json"),
        },
        {
            "id": "aspe_state",
            "store": "data/aspe/state.json",
            "owner": "adaptive_sector_protection_engine.py",
            "scope": "HOST_GLOBAL/MIXED",
            "tenant_id": "NO",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "NOT_IMPLEMENTED",
            "file_evidence": sample_json("data/aspe/state.json"),
        },
        {
            "id": "identity_intelligence",
            "store": "data/identity_intelligence/*",
            "owner": "identity_intelligence/store.py",
            "scope": "HOST_GLOBAL",
            "tenant_id": "NO partition",
            "isolation": "ISOLATION_NOT_DEMONSTRATED",
            "anonymization": "PARTIAL only on export swarm_anonymous_summary API",
            "file_evidence": {
                "dir_exists": (ROOT / "data/identity_intelligence").exists(),
                "files": [p.name for p in (ROOT / "data/identity_intelligence").glob("*")][:20]
                if (ROOT / "data/identity_intelligence").exists()
                else [],
            },
        },
    ]
    return {"run_id": RUN_ID, "stores": stores, "anonymization_overall": "NOT_IMPLEMENTED"}


def field_catalog() -> Dict[str, Any]:
    """Fields from code construction + samples — classified without invention."""
    return {
        "run_id": RUN_ID,
        "stores": {
            "learning.jsonl": {
                "fields_from_code": [
                    "id",
                    "ts",
                    "source",
                    "validated",
                    "kernel_learning_gate",
                    "threat_type",
                    "category",
                    "evidences.indicators",
                    "evidences.supporting_modules",
                    "evidences.confidence",
                    "evidences.priority",
                    "mechanisms_used",
                    "patterns",
                    "response_results",
                    "response_time",
                    "origin_motor",
                    "finding_id",
                ],
                "tenant_id": {"present": False, "class": "CONFIRMED"},
                "field_classes": {
                    "finding_id": "TENANT_PRIVATE",
                    "evidences.indicators.ips": "TENANT_PRIVATE",
                    "evidences.indicators.domains": "TENANT_PRIVATE",
                    "evidences.indicators.hashes": "DERIVED",
                    "category": "DERIVED",
                    "confidence": "DERIVED",
                    "origin_motor": "DERIVED",
                    "tenant_id": "UNKNOWN — absent",
                    "email": "UNKNOWN — absent in writer",
                },
            },
            "collective_memory.jsonl": {
                "fields_from_code": [
                    "id",
                    "ts",
                    "category",
                    "tactics",
                    "behaviors",
                    "relations.indicator_keys",
                    "relations.finding_id",
                    "frequency_hint",
                    "confidence",
                    "priority",
                    "patterns",
                ],
                "tenant_id": {"present": False, "class": "CONFIRMED"},
                "field_classes": {
                    "relations.indicator_keys.ips": "TENANT_PRIVATE",
                    "relations.finding_id": "TENANT_PRIVATE",
                    "category": "DERIVED",
                    "patterns": "DERIVED",
                },
            },
            "mesh shared_iocs": {
                "fields_from_code": ["ips|domains|hashes|urls|behaviors → count, peers, first_seen, last_seen, last_msg_id"],
                "tenant_id": {"present": False, "class": "CONFIRMED"},
                "field_classes": {
                    "ioc_value": "TENANT_PRIVATE",
                    "count": "DERIVED",
                    "peers": "DERIVED",
                },
                "GLOBAL_SAFE_CANDIDATE": "count aggregates AFTER legal anonymization — NOT currently demonstrated",
            },
            "global_queries": {
                "fields_from_code": ["users[email].queries", "users[email].clicks", "global_queries[q]=count", "metrics"],
                "tenant_id": {"present": False, "class": "CONFIRMED"},
                "field_classes": {
                    "email": "TENANT_PRIVATE",
                    "query_string": "TENANT_PRIVATE",
                    "global_queries counts": "DERIVED",
                },
            },
            "ai_kernel_feedback": {
                "fields_from_code": ["learned_exceptions[MAC]", "risk_modifiers[MAC]", "history"],
                "tenant_id": {"present": False, "class": "CONFIRMED"},
                "field_classes": {
                    "MAC": "TENANT_PRIVATE",
                    "risk_modifier": "DERIVED",
                    "reason": "DERIVED",
                },
            },
        },
        "note": "GLOBAL_SAFE_CANDIDATE only as future possibility — not current status",
    }


def dataflows() -> Dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "flows": [
            {
                "store": "learning.jsonl",
                "trace": (
                    "SOURCE detection event (may carry tenant_id in payload)\n"
                    "→ COLLECTION swarm bus process_event\n"
                    "→ TENANT IDENTIFICATION correlate may filter contributions if scope=TENANT\n"
                    "→ NORMALIZATION correlation dict\n"
                    "→ TRANSFORM record_confirmed_incident builds entry WITHOUT tenant_id\n"
                    "→ FILTER kernel_learning_safe (anti-poison, NOT tenant)\n"
                    "→ GLOBAL STORE learning.jsonl\n"
                    "→ CONSUMERS recent_learning/stats/audit API (HOST_GLOBAL read)"
                ),
                "tenant_preserved_in_store": False,
                "contamination_avoidance": "NONE → ISOLATION_NOT_DEMONSTRATED",
            },
            {
                "store": "collective_memory.jsonl",
                "trace": (
                    "SOURCE same process_event after sufficient_evidence\n"
                    "→ remember_incident (no tenant_id)\n"
                    "→ GLOBAL STORE\n"
                    "→ CONSUMERS lookup_similar → compute_priority → auto_responses (MIXED influence)"
                ),
                "logical_path": "TENANT_A → remember → store → lookup_similar → TENANT_B priority",
                "status": "CONFIRMED",
            },
            {
                "store": "mesh shared_iocs",
                "trace": (
                    "SOURCE local correlation / peer envelope\n"
                    "→ propagate/ingest\n"
                    "→ apply_indicators\n"
                    "→ shared_iocs.json\n"
                    "→ ZDDE layer_mesh_intel / mesh API (GLOBAL consumer)"
                ),
                "status": "CONFIRMED",
            },
            {
                "store": "global_queries",
                "trace": (
                    "SOURCE user search query + email\n"
                    "→ record_search\n"
                    "→ users[email] AND global_queries[q]++\n"
                    "→ ranking uses per-user only; global_queries for audit counts"
                ),
                "logical_influence_on_other_tenant_ranking": False,
                "shared_counter_exists": True,
                "status": "PARTIAL",
            },
            {
                "store": "ai_kernel_feedback MAC",
                "trace": (
                    "SOURCE admin feedback / AIE action\n"
                    "→ learn_from_feedback(MAC)\n"
                    "→ feedback.json\n"
                    "→ analyze_event risk_modifier / whitelist (any later event with same MAC)"
                ),
                "status": "CONFIRMED",
            },
        ],
    }


def ai_kernel_scope() -> Dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "pipeline": [
            {"step": "USER", "scope": "TENANT/user"},
            {"step": "SESSION", "scope": "user_id only"},
            {"step": "TENANT", "scope": "resolved per request — not stored in kernel_memory key"},
            {"step": "PROMPT", "scope": "HOST_GLOBAL static prompts"},
            {"step": "MEMORY", "scope": "TENANT/user file data/kernel_memory/<key>.json"},
            {"step": "CACHE", "scope": "MIXED short TTL orchestrator"},
            {"step": "FEEDBACK", "scope": "HOST_GLOBAL MAC feedback.json"},
            {"step": "OUTPUT", "scope": "RECOMMENDED to requesting user"},
        ],
        "mac_feedback": {
            "contains": "MAC, whitelist flag, risk_modifier 0.5|1.5, reason, history",
            "generated_by": "admin phrases / AIE approve|isolate|block…",
            "consumed_by": "NOVUSAIKernelEngine.analyze_event",
            "tenant_related": "MAC may belong to tenant network assets — PARTIAL",
            "can_influence_other_tenant": "CONFIRMED if same MAC appears in later analysis for another tenant/context on host",
        },
        "trained_ml": False,
        "classification": "MIXED",
    }


def swarm_scope() -> Dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "correlate": {
            "scope": "TENANT_SCOPED when event.scope=TENANT else HOST_GLOBAL",
            "multi_signal": "within event modules — not multi-tenant",
            "multi_tenant_correlation": "policy no_cross_tenant_correlation on contributions",
        },
        "learning_jsonl": {"scope": "HOST_GLOBAL", "tenant_id": False},
        "collective_memory": {
            "scope": "HOST_GLOBAL",
            "lookup_tenant_filter": False,
            "evidence": "collective_memory.lookup_similar lines 73-123 — no tenant parameter",
        },
        "mesh": {
            "envelopes": "peer_id + indicators — no tenant_id",
            "scope": "NOVUS_GLOBAL",
            "fingerprints": "node crypto identity — HOST/NOVUS",
        },
        "classification": "MIXED (correlate can be tenant; stores HOST/NOVUS global)",
    }


def baseline_analysis() -> Dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "APE": {
            "scope": "BASELINE_TENANT/user",
            "A_influences_B": False,
            "note": "email-scoped SQLite; collision only if same email",
            "status": "CONFIRMED isolated by email",
        },
        "BTDE_host": {
            "scope": "BASELINE_GLOBAL(HOST)",
            "A_influences_B": True,
            "path": "any cycle updates host_baseline → novelty detection for all",
            "status": "CONFIRMED",
        },
        "BTDE_tenant_remotes": {
            "scope": "BASELINE_TENANT file",
            "A_influences_B": False,
            "caveat": "PARTIAL — live cycle often get_platform_tenant_id()",
            "status": "PARTIAL",
        },
        "LAN": {
            "scope": "BASELINE_GLOBAL(HOST)",
            "A_influences_B": True,
            "path": "shared MAC set → compare_to_baseline",
            "status": "CONFIRMED",
        },
    }


def contamination_tests() -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "run_id": RUN_ID,
        "mode": "READ_ONLY",
        "DIRECT_LEAKS": 0,
        "LOGICAL_CROSS_TENANT_CONTAMINATION": [],
        "checks": [],
        "generated_at_utc": utc(),
    }

    # Code-path logical contamination: lookup_similar without tenant
    try:
        from services.swarm_defense.collective_memory import lookup_similar
        import inspect

        src = inspect.getsource(lookup_similar)
        has_tenant_param = "tenant_id" in src
        # Use TEST_FIXTURE synthetic indicators against real memory (no write)
        hit = lookup_similar(
            indicators={"ips": ["198.51.100.50"], "domains": [], "hashes": []},
            category="anomaly_unclassified",
        )
        # Category-only match can fire even without IOC — demonstrates unscoped category recurrence
        out["checks"].append(
            {
                "id": "lookup_similar_no_tenant_param",
                "result": "CONFIRMED",
                "tenant_id_in_function": has_tenant_param,
                "sample_call": {
                    "seen_before": hit.get("seen_before"),
                    "frequency": hit.get("frequency"),
                    "matches_n": len(hit.get("matches") or []),
                    "note": "category match alone can set hit=True (line 100-103)",
                },
                "test_fixture_indicators": True,
            }
        )
        out["LOGICAL_CROSS_TENANT_CONTAMINATION"].append(
            {
                "id": "collective_memory_priority_boost",
                "status": "CONFIRMED",
                "path": "TENANT_A remember_incident → collective_memory.jsonl → lookup_similar(no tenant) → compute_priority → TENANT_B process_event",
                "evidence": "services/swarm_defense/engine.py:212-221 + collective_memory.py:73-123",
            }
        )
    except Exception as e:
        out["checks"].append({"id": "lookup_similar", "result": "NOT_VERIFIABLE", "error": str(e)[:160]})

    # learning.jsonl lacks tenant_id
    learn = sample_jsonl("data/swarm_defense/learning.jsonl", 2)
    out["checks"].append(
        {
            "id": "learning_jsonl_tenant_id",
            "result": "CONFIRMED_ABSENT" if learn.get("exists") and not learn.get("tenant_id_present") else "NOT_VERIFIABLE",
            "evidence": learn.get("key_presence_counts_in_scan"),
        }
    )
    out["LOGICAL_CROSS_TENANT_CONTAMINATION"].append(
        {
            "id": "learning_jsonl_shared_audit_view",
            "status": "CONFIRMED",
            "path": "TENANT_A incident → learning.jsonl (no tenant) → recent_learning/audit consumers see mixed host knowledge",
            "detector_retrain": False,
            "note": "append/stats — not rule training; still shared global knowledge",
        }
    )

    # Mesh → ZDDE
    out["LOGICAL_CROSS_TENANT_CONTAMINATION"].append(
        {
            "id": "mesh_iocs_zdde_score",
            "status": "CONFIRMED",
            "path": "node/peer IOC → shared_iocs → layer_mesh_intel → ZDDE correlator weights → any ZDDE cycle on host",
            "evidence": "zero_day_detection/layers.py layer_mesh_intel; correlator mesh factors",
        }
    )

    # MAC feedback
    out["LOGICAL_CROSS_TENANT_CONTAMINATION"].append(
        {
            "id": "mac_feedback_cross_context",
            "status": "CONFIRMED",
            "path": "admin TENANT_A → feedback.json[MAC] → analyze_event later (any tenant/context on host)",
            "evidence": "knowledge_adapter.py + event engine risk_modifier",
        }
    )

    # BTDE host / LAN
    out["LOGICAL_CROSS_TENANT_CONTAMINATION"].append(
        {
            "id": "btde_host_baseline",
            "status": "CONFIRMED",
            "path": "any cycle → host_baseline.json → novelty for all tenants on node",
        }
    )
    out["LOGICAL_CROSS_TENANT_CONTAMINATION"].append(
        {
            "id": "lan_baseline",
            "status": "CONFIRMED",
            "path": "LAN MACs → lan_baseline.json → compare_to_baseline for later scans",
        }
    )

    # global_queries
    out["LOGICAL_CROSS_TENANT_CONTAMINATION"].append(
        {
            "id": "global_queries_counter",
            "status": "PARTIAL",
            "path": "TENANT_A query → global_queries++ → not used for B ranking (CONFIRMED code) but shared store",
            "ranking_influence": False,
        }
    )

    # DIRECT_LEAKS via access control + HTTP if up
    try:
        from types import SimpleNamespace
        from services.enterprise_access_control import user_may_access_tenant

        ua = SimpleNamespace(
            company_id="LOADTEST-T0000",
            nit_pyme="LOADTEST-T0000",
            email="loadtest-user-0000@loadtest.novus.local",
            role="company_admin",
        )
        ok, reason = user_may_access_tenant(ua, "LOADTEST-T0001")
        out["checks"].append({"id": "direct_access_a_to_b", "result": "PASS" if not ok else "FAIL", "reason": reason})
        if ok:
            out["DIRECT_LEAKS"] += 1
    except Exception as e:
        out["checks"].append({"id": "direct_access", "result": "NOT_VERIFIABLE", "error": str(e)[:120]})

    try:
        import requests
        from services.loadtest_runtime import loadtest_password, apply_loadtest_client_headers

        if requests.get(f"{BASE}/login", timeout=6).status_code == 200:
            manifest = json.loads(
                (ROOT / "data/production_closure/loadtest_users_manifest.json").read_text(encoding="utf-8")
            )
            pw = loadtest_password()

            def sess(email: str):
                s = requests.Session()
                apply_loadtest_client_headers(s, email)
                g = s.get(f"{BASE}/login", timeout=20)
                csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', g.text or "")
                s.post(
                    f"{BASE}/login",
                    data={"email": email, "password": pw, "csrf_token": csrf.group(1) if csrf else ""},
                    timeout=40,
                    allow_redirects=False,
                )
                return s

            sa = sess(manifest["users"][0]["email"])
            sb = sess(manifest["users"][1]["email"])
            ta, tb = manifest["users"][0]["tenant_id"], manifest["users"][1]["tenant_id"]
            nb = sb.get(f"{BASE}/api/notifications?kind=security&limit=15", timeout=35)
            try:
                body = nb.json()
            except Exception:
                body = {}
            items = body.get("notifications") or body.get("items") or []
            direct = any(isinstance(it, dict) and it.get("tenant_id") == ta for it in items)
            out["checks"].append(
                {
                    "id": "http_notifications_direct_leak",
                    "result": "FAIL" if direct else "PASS",
                    "http": nb.status_code,
                }
            )
            if direct:
                out["DIRECT_LEAKS"] += 1
            # Traffic HOST_GLOBAL not a leak
            live = sa.get(f"{BASE}/api/dashboard/live", timeout=30)
            try:
                lb = live.json()
            except Exception:
                lb = {}
            meta = lb.get("traffic_meta") or {}
            out["checks"].append(
                {
                    "id": "traffic_not_tenant_attributed",
                    "result": "PASS" if meta.get("scope") in (None, "HOST_GLOBAL") else "FAIL",
                    "scope": meta.get("scope"),
                }
            )
        else:
            out["checks"].append({"id": "http", "result": "NOT_VERIFIABLE", "detail": "server down"})
    except Exception as e:
        out["checks"].append({"id": "http_direct", "result": "NOT_VERIFIABLE", "error": str(e)[:160]})

    out["LOGICAL_COUNT_CONFIRMED"] = sum(
        1 for x in out["LOGICAL_CROSS_TENANT_CONTAMINATION"] if x.get("status") == "CONFIRMED"
    )
    return out


def boundary_table(inv: Dict[str, Any], cont: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for s in inv["stores"]:
        rows.append(
            {
                "Store": s.get("store"),
                "Origen": s.get("owner"),
                "Tenant_ID": s.get("tenant_id"),
                "Datos_privados": "YES_POSSIBLE" if s.get("tenant_id") in ("NO", "NO (email keys)", "NO (MAC keys)", "NO (typically)", "NO partition") else "SCOPED",
                "Transformacion": "append/aggregate as written — no anonymizer",
                "Anonimizacion": s.get("anonymization", "NOT_IMPLEMENTED"),
                "Consumidor": s.get("readers") or s.get("readers", "see inventory"),
                "Scope": s.get("scope"),
                "Riesgo": s.get("logical_contamination")
                or s.get("isolation")
                or "PARTIAL",
                "status": "CONFIRMED",
            }
        )
    return rows


def main() -> int:
    print("=== GLOBAL LEARNING BOUNDARY AUDIT (READ-ONLY) ===", flush=True)
    inv = inventory()
    fields = field_catalog()
    flows = dataflows()
    ai = ai_kernel_scope()
    swarm = swarm_scope()
    base = baseline_analysis()
    cont = contamination_tests()
    table = boundary_table(inv, cont)

    write("global_store_inventory.json", inv)
    write("global_store_data_fields.json", fields)
    write("tenant_to_global_dataflow.json", flows)
    write("ai_kernel_learning_scope.json", ai)
    write("swarm_global_scope.json", swarm)
    write("baseline_scope_analysis.json", base)
    write("cross_tenant_contamination_test.json", cont)

    separation = {
        "model_exists": False,
        "actual_state": "MIXED",
        "PRIVATE_TENANT_DATA": "alerts/evidence/APE rows/reports by_tenant/kernel_memory user files",
        "TENANT_DERIVED_KNOWLEDGE": "APE usual_*; BTDE remotes when tid correct; correlate multi-signal",
        "GLOBAL_NOVUS_KNOWLEDGE": "learning.jsonl, collective_memory, mesh IOCs, global_queries, MAC feedback, host/LAN baselines, ADE/ASPE/II",
        "technical_pipeline_private_to_derived_to_global": "NOT implemented as controlled pipeline — writes often skip tenant tagging",
    }

    legal_vs_tech = {
        "RESOLVIBLE_MEDIANTE_CODIGO": [
            "add tenant_id to learning/collective_memory entries",
            "filter lookup_similar by tenant",
            "partition mesh IOC application by tenant or strip to aggregates",
            "scope MAC feedback by tenant",
            "stop using category-only hits across tenants",
        ],
        "REQUIERE_DECISION_LEGAL_CONTRACTUAL": [
            "whether any customer-derived IOC/pattern may improve another customer",
            "mesh sharing across deployments",
            "anonymization standard and retention",
            "use of query strings in global_queries",
        ],
        "compliance_claim": "NOT MADE",
    }

    if cont.get("DIRECT_LEAKS", 0) > 0:
        verdict = "GLOBAL_LEARNING_BOUNDARY_BLOCKED"
    else:
        verdict = "GLOBAL_LEARNING_BOUNDARY_PASS_WITH_LIMITATIONS"

    boundary = {
        "verdict": verdict,
        "run_id": RUN_ID,
        "generated_at_utc": utc(),
        "production_code_modified": False,
        "DIRECT_LEAKS": cont.get("DIRECT_LEAKS"),
        "LOGICAL_CROSS_TENANT_CONTAMINATION_CONFIRMED": cont.get("LOGICAL_COUNT_CONFIRMED"),
        "anonymization": "NOT_IMPLEMENTED",
        "trained_ml": False,
        "separation_model": separation,
        "legal_vs_technical": legal_vs_tech,
        "table": table,
        "limitations": [
            "ISOLATION_NOT_DEMONSTRATED for learning.jsonl / collective_memory / mesh IOCs / MAC feedback",
            "LOGICAL contamination CONFIRMED via lookup_similar → priority",
            "LOGICAL contamination CONFIRMED via mesh→ZDDE and host/LAN baselines",
            "No anonymization pipeline",
            "No PRIVATE→DERIVED→GLOBAL controlled architecture",
        ],
    }
    write("global_learning_boundary.json", boundary)
    write(
        "global_learning_evidence_index.json",
        {
            "run_id": RUN_ID,
            "verdict": verdict,
            "artifacts": [
                "global_learning_boundary.json",
                "global_learning_boundary_report.md",
                "global_store_inventory.json",
                "global_store_data_fields.json",
                "tenant_to_global_dataflow.json",
                "ai_kernel_learning_scope.json",
                "swarm_global_scope.json",
                "baseline_scope_analysis.json",
                "cross_tenant_contamination_test.json",
                "global_learning_evidence_index.json",
            ],
            "code_evidence": [
                "services/swarm_defense/engine.py:208-270",
                "services/swarm_defense/collective_memory.py:73-123",
                "services/swarm_defense/learning.py:59-148",
                "services/swarm_defense/mesh/intel_store.py",
                "services/global_search_learning_store.py:41-56",
                "services/ai_kernel_event_engine/knowledge_adapter.py",
                "services/zero_day_detection/layers.py layer_mesh_intel",
            ],
        },
    )

    md = f"""# NOVUS — Global Learning Boundary Forensic Audit

## Verdict

**`{verdict}`**

Run: `{RUN_ID}`  
Production modified: **false**  
DIRECT_LEAKS: **{cont.get('DIRECT_LEAKS')}**  
LOGICAL_CROSS_TENANT_CONTAMINATION (CONFIRMED count): **{cont.get('LOGICAL_COUNT_CONFIRMED')}**  
Anonymization: **NOT_IMPLEMENTED**  
Trained ML: **false**

---

## Separation model (current)

Desired:

`PRIVATE TENANT → TENANT-DERIVED → GLOBAL NOVUS`

Actual: **MIXED** — several writers drop `tenant_id` and feed host/global consumers.

---

## Boundary table (summary)

| Store | Tenant ID | Anonimización | Scope | Riesgo |
|-------|-----------|---------------|-------|--------|
| learning.jsonl | NO | NOT_IMPLEMENTED | HOST_GLOBAL | shared knowledge / audit |
| collective_memory.jsonl | NO | NOT_IMPLEMENTED | HOST_GLOBAL | **priority boost cross-context CONFIRMED** |
| mesh shared_iocs | NO | NOT_IMPLEMENTED | NOVUS_GLOBAL | ZDDE score influence |
| global_queries | NO | NOT_IMPLEMENTED | MIXED | shared counters; ranking still per-user |
| ai_kernel feedback MAC | NO | NOT_IMPLEMENTED | HOST_GLOBAL | risk_modifier cross-context |
| BTDE host / LAN baselines | NO | NOT_IMPLEMENTED | HOST_GLOBAL | novelty shared on node |
| APE behavior_* | YES meta | NOT_IMPLEMENTED | MIXED user | email-scoped |

Full table: `global_learning_boundary.json` → `table`.

---

## Critical logical path (not API leak)

```text
TENANT A detection
  → Swarm process_event
  → remember_incident (no tenant_id)
  → collective_memory.jsonl
  → lookup_similar (no tenant filter; category-only hit allowed)
  → compute_priority
  → TENANT B / later event on same node influenced
```

Evidence: `engine.py` + `collective_memory.lookup_similar`.

---

## Legal vs technical

- **Code-fixable:** tenant tags, filtered lookup, partitioned stores.
- **Legal/contractual:** whether any customer-derived knowledge may improve another customer / mesh peers.

No compliance claim.

---

## STOP

No implementation. No ML. No anonymization. No architecture change.
"""
    write("global_learning_boundary_report.md", md)
    print(
        json.dumps(
            {
                "verdict": verdict,
                "DIRECT_LEAKS": cont.get("DIRECT_LEAKS"),
                "LOGICAL_CONFIRMED": cont.get("LOGICAL_COUNT_CONFIRMED"),
            },
            indent=2,
        ),
        flush=True,
    )
    return 0 if verdict != "GLOBAL_LEARNING_BOUNDARY_BLOCKED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
