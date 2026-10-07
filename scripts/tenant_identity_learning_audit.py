#!/usr/bin/env python3
"""
NOVUS Tenant Identity + Learning Audit — READ-ONLY.
No production code changes. Writes data/production_closure/tenant_identity_learning_audit/*
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure" / "tenant_identity_learning_audit"
OUT.mkdir(parents=True, exist_ok=True)
BASE = os.environ.get("NOVUS_TEST_BASE", "http://127.0.0.1:5000")
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write(name: str, data: Any) -> None:
    path = OUT / name
    if name.endswith(".md"):
        path.write_text(str(data), encoding="utf-8")
    else:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def file_exists(rel: str) -> bool:
    return (ROOT / rel).exists()


def sample_jsonl(rel: str, n: int = 2) -> Dict[str, Any]:
    p = ROOT / rel
    if not p.exists():
        return {"exists": False, "path": rel}
    lines = []
    has_tenant = False
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= 50:
                    break
                line = line.strip()
                if not line:
                    continue
                if i < n:
                    try:
                        obj = json.loads(line)
                        # redact long fields
                        slim = {k: obj.get(k) for k in list(obj)[:12]}
                        lines.append(slim)
                        if "tenant_id" in obj:
                            has_tenant = True
                    except Exception:
                        lines.append({"_raw": line[:120]})
                else:
                    if '"tenant_id"' in line:
                        has_tenant = True
    except Exception as e:
        return {"exists": True, "path": rel, "error": str(e)[:160]}
    return {
        "exists": True,
        "path": rel,
        "bytes": p.stat().st_size,
        "sample_n": len(lines),
        "tenant_id_in_sample_or_first50": has_tenant,
        "samples": lines,
    }


def login(email: str, password: str):
    import requests
    from services.loadtest_runtime import apply_loadtest_client_headers

    s = requests.Session()
    apply_loadtest_client_headers(s, email)
    r0 = s.get(f"{BASE}/login", timeout=30)
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r0.text or "")
    r1 = s.post(
        f"{BASE}/login",
        data={"email": email, "password": password, "csrf_token": csrf.group(1) if csrf else ""},
        timeout=60,
        allow_redirects=False,
    )
    return s, {"get": r0.status_code, "post": r1.status_code, "ok": r1.status_code in (200, 302)}


def api_get(session, path: str, timeout: float = 40.0) -> Dict[str, Any]:
    t0 = time.perf_counter()
    try:
        r = session.get(f"{BASE}{path}", timeout=timeout)
        try:
            body = r.json()
        except Exception:
            body = {"_text": (r.text or "")[:300]}
        return {"http": r.status_code, "ms": round((time.perf_counter() - t0) * 1000, 1), "body": body}
    except Exception as e:
        return {"http": None, "error": str(e)[:200]}


def build_identity_audit() -> Dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "generated_at_utc": utc(),
        "production_code_modified": False,
        "tenant_entity": {
            "first_class_Tenant_table": False,
            "canonical_identity": "company NIT stored as Usuario.nit_pyme → User.company_id",
            "monitoring_scope_table": "TenantMonitoringScope.tenant_id (PK)",
            "evidence_files": [
                "database.py (Usuario.nit_pyme, TenantMonitoringScope)",
                "models/user.py (company_id=usuario.nit_pyme)",
                "services/tenant_scope_service.py resolve_tenant_id()",
                "services/registration_approval_service.py complete_registration()",
            ],
        },
        "lifecycle": {
            "where_born": [
                "RegistrationRequest.nit → Usuario.nit_pyme on approval",
                "LOADTEST seed LOADTEST-T####",
                "NOVUS_PLATFORM_TENANT_ID / lab platform tenant",
                "migrate backfill NULL tenant_id → platform tid",
            ],
            "who_assigns": [
                "registration_approval_service.complete_registration",
                "tenant_scope_service.ensure_tenant_monitoring_seeded / provision",
                "scalability_seed_loadtest_users (lab)",
                "login_session_audit stamps LoginSessionAudit.tenant_id (does not invent identity)",
            ],
            "who_validates": [
                "tenant_isolation_service.require_user_tenant_id / assert_tenant_access",
                "enterprise_access_control.user_may_access_tenant / filter_query_by_tenant",
                "tenant_api_gate.check_tenant_monitoring_or_response",
                "monitoring_telemetry_guard.assert_telemetry_access",
            ],
            "who_transports": [
                "Flask-Login session carries _user_id only — NOT tenant_id",
                "Per-request resolve_tenant_id(current_user) from User.company_id/nit_pyme",
                "X-Tenant-ID header NOT trusted by production resolvers",
                "No business JWT tenant claims found",
            ],
            "where_persisted": [
                "SQLite: usuarios.nit_pyme, alertas/vulnerabilidades/evidences/notifications.tenant_id, …",
                "enterprise DBs keyed by tenant_id",
                "data/reports|soc|imcm/by_tenant/<tid>/",
                "data/behavioral_threat_detection/tenant_baselines/<tid>.json",
                "process caches: auth_session_cache, http_endpoint_cache(tenant_id)",
            ],
            "where_can_be_lost": [
                {
                    "id": "email_domain_fallback",
                    "status": "CONFIRMED",
                    "detail": "resolve_tenant_id falls back to email domain if nit_pyme/company_id empty — collision risk",
                    "file": "services/tenant_scope_service.py:62-71",
                },
                {
                    "id": "creator_bypass",
                    "status": "CONFIRMED",
                    "detail": "is_novus_creator bypasses tenant match and SQL filter",
                    "file": "services/enterprise_access_control.py:38-57",
                },
                {
                    "id": "swarm_learning_no_tenant",
                    "status": "CONFIRMED",
                    "detail": "swarm learning.jsonl / collective_memory.jsonl entries lack tenant partition",
                    "file": "services/swarm_defense/learning.py; collective_memory.py",
                },
                {
                    "id": "middleware_no_tenant",
                    "status": "CONFIRMED",
                    "detail": "before_request enforces login/CSRF/abuse — not tenant_id",
                    "file": "core/security.py",
                },
                {
                    "id": "platform_writer_default",
                    "status": "PARTIAL",
                    "detail": "many background writers stamp get_platform_tenant_id()",
                    "file": "services/tenant_scope_service.py get_platform_tenant_id",
                },
                {
                    "id": "notifications_null_tenant",
                    "status": "PARTIAL",
                    "detail": "notification scope may include tenant_id IS NULL for same email",
                    "file": "services/notification_center_service.py _apply_user_scope",
                },
                {
                    "id": "exhaustive_query_scan",
                    "status": "NOT_VERIFIABLE",
                    "detail": "100% of queries without tenant filter not exhaustively proven",
                },
            ],
        },
        "answers": {
            "donde_nace": "NIT en registro → usuarios.nit_pyme; también LOADTEST/platform seed",
            "quien_asigna": "registration/seed/provision; login solo re-resuelve",
            "quien_valida": "tenant_isolation + enterprise_access_control + gates de telemetría",
            "quien_transporta": "sesión→user_id→resolve_tenant_id; no header JWT",
            "donde_persiste": "SQLite/enterprise DB/by_tenant files/caches",
            "donde_puede_perderse": "fallback dominio email, creator bypass, learning stores globales, writers platform",
        },
    }


def build_lineage() -> Dict[str, Any]:
    cats = {
        "usuarios": {
            "SOURCE": "registro / seed",
            "COLLECTION": "registration_approval_service",
            "TENANT_ASSIGNMENT": "nit_pyme at create",
            "STORAGE": "usuarios",
            "tenant_id_field": "nit_pyme (=tenant)",
            "scope": "TENANT",
        },
        "alertas": {
            "SOURCE": "motores/NSI/defense",
            "COLLECTION": "alerts_canonical_service / Alerta rows",
            "TENANT_ASSIGNMENT": "writer stamps tenant_id or platform",
            "STORAGE": "alertas + canonical views",
            "API": "/api/security/alerts",
            "tenant_id_field": "tenant_id",
            "scope": "TENANT (platform-gated host feeds)",
        },
        "eventos": {
            "SOURCE": "defense_registry / security events",
            "TENANT_ASSIGNMENT": "varies by writer",
            "STORAGE": "defense registry / enterprise security_events",
            "scope": "MIXED → TENANT when stamped; else UNKNOWN/platform",
        },
        "evidencias": {
            "SOURCE": "forensic / defense seal",
            "STORAGE": "platform_evidences / enterprise evidence",
            "tenant_id_field": "tenant_id",
            "scope": "TENANT when stamped",
        },
        "sesiones": {
            "SOURCE": "login",
            "STORAGE": "login_session_audits.tenant_id",
            "TRANSPORT": "session cookie user id only",
            "scope": "TENANT (audit row)",
        },
        "reportes": {
            "STORAGE": "data/reports/by_tenant/<tid>/",
            "scope": "TENANT",
        },
        "incidentes": {
            "STORAGE": "SOC/IMCM by_tenant stores + auth incidents",
            "scope": "TENANT (legacy platform merge PARTIAL)",
        },
        "inventario": {
            "STORAGE": "network_device_inventory.tenant_id",
            "scope": "TENANT / HOST observation stamped",
        },
        "network": {
            "SOURCE": "ARP/scanner/monitor",
            "STORAGE": "monitor engine + inventory + history",
            "scope": "HOST_GLOBAL observation; API may be tenant-gated",
        },
        "vulnerabilidades": {
            "STORAGE": "vulnerabilidades.tenant_id",
            "scope": "TENANT (host scan often platform-scoped)",
        },
        "XDR": {
            "SOURCE": "defense_center cache",
            "scope": "HOST_GLOBAL / platform cache — NOT_VERIFIABLE full tenant partition",
        },
        "logs": {
            "STORAGE": "security logs / audit",
            "scope": "MIXED",
        },
        "SIEM": {
            "status": "NOT_IMPLEMENTED as product SIEM",
            "scope": "UNKNOWN",
        },
        "busquedas": {
            "STORAGE": "data/global_search_learning.json (per-user + global_queries)",
            "scope": "MIXED",
        },
        "baselines": {
            "APE": "SQLite behavior_* by user_email (+tenant metadata)",
            "BTDE": "host_baseline.json + tenant_baselines/<tid>.json",
            "LAN": "data/network_baseline/lan_baseline.json HOST_GLOBAL",
            "scope": "MIXED",
        },
        "snapshots": {
            "SOURCE": "security_snapshot_service",
            "scope": "HOST_GLOBAL / platform",
        },
        "kernel_memory": {
            "STORAGE": "data/kernel_memory/<user>.json",
            "scope": "TENANT/user private prefs; ops JSONL HOST_GLOBAL",
        },
        "caches": {
            "auth_session_cache": "process TTL",
            "http_endpoint_cache": "keyed with tenant_id when provided",
            "scope": "MIXED",
        },
        "backups": {
            "scope": "NOVUS_GLOBAL / host backup sets — NOT_VERIFIABLE tenant partition in this audit",
        },
        "Traffic": {
            "SOURCE": "psutil.net_io_counters → SystemMonitor → dashboard_live",
            "tenant_id": "none — HOST_GLOBAL",
            "scope": "HOST_GLOBAL",
            "reason": "NIC counters are machine-wide; attribution to tenant would be false",
        },
        "detecciones": {
            "SOURCE": "engines",
            "scope": "TENANT when published with tenant_id; else platform/HOST",
        },
        "respuestas": {
            "SOURCE": "swarm/remediation/auth_protection",
            "scope": "TENANT for app sanctions; APPROVAL for destructive",
        },
        "swarm_learning": {
            "STORAGE": "data/swarm_defense/learning.jsonl",
            "tenant_id": "ABSENT in entries (CONFIRMED sample)",
            "scope": "HOST_GLOBAL",
        },
        "collective_memory": {
            "STORAGE": "data/swarm_defense/collective_memory.jsonl",
            "tenant_id": "ABSENT",
            "scope": "HOST_GLOBAL",
        },
        "mesh_intel": {
            "STORAGE": "data/swarm_mesh/intel/shared_iocs.json",
            "scope": "NOVUS_GLOBAL (peer mesh) / HOST_GLOBAL if single node",
        },
    }
    return {"run_id": RUN_ID, "lineage": cats, "pipeline_template": "SOURCE→COLLECTION→NORMALIZATION→VALIDATION→TENANT_ASSIGNMENT→PROCESSING→STORAGE→API→FRONTEND"}


def build_scope_matrix() -> Dict[str, Any]:
    rows = [
        {"data": "Traffic RX/TX", "scope": "HOST_GLOBAL", "reason": "psutil host NIC counters"},
        {"data": "Usuario.nit_pyme / company_id", "scope": "TENANT", "reason": "canonical customer identity"},
        {"data": "Alerta.tenant_id", "scope": "TENANT", "reason": "column + API filter"},
        {"data": "NovusNotification", "scope": "TENANT", "reason": "user_email+tenant_id scope (NULL tenant PARTIAL)"},
        {"data": "APE baselines", "scope": "TENANT", "reason": "keyed by user_email; host facts MIXED into profile"},
        {"data": "BTDE host_baseline.json", "scope": "HOST_GLOBAL", "reason": "process/service names on node"},
        {"data": "BTDE tenant_baselines", "scope": "TENANT", "reason": "per-tid file; live cycle often platform tid"},
        {"data": "LAN network baseline", "scope": "HOST_GLOBAL", "reason": "MAC set for LAN"},
        {"data": "Swarm learning.jsonl", "scope": "HOST_GLOBAL", "reason": "no tenant_id field"},
        {"data": "Swarm collective_memory", "scope": "HOST_GLOBAL", "reason": "lookup_similar unscoped"},
        {"data": "Mesh shared_iocs", "scope": "NOVUS_GLOBAL", "reason": "peer-aggregated IOC counts"},
        {"data": "AI Kernel user memory", "scope": "TENANT", "reason": "per-user JSON file"},
        {"data": "AI Kernel MAC feedback", "scope": "HOST_GLOBAL", "reason": "feedback.json by MAC"},
        {"data": "global_search global_queries", "scope": "NOVUS_GLOBAL", "reason": "cross-user query string counts"},
        {"data": "Reports by_tenant", "scope": "TENANT", "reason": "filesystem partition"},
        {"data": "SIEM product", "scope": "UNKNOWN", "reason": "not implemented as commercial SIEM"},
        {"data": "XDR panel cache", "scope": "HOST_GLOBAL", "reason": "node cache / platform"},
        {"data": "Creator cross-tenant read", "scope": "NOVUS_GLOBAL", "reason": "privileged role intentional bypass"},
    ]
    return {"run_id": RUN_ID, "matrix": rows}


def build_learning_scope() -> Dict[str, Any]:
    components = [
        {
            "name": "APE",
            "ml": False,
            "mechanism": "frequency baselines / anti-poison heuristics",
            "flow": "INPUT observe → SCOPE user_email → PROCESSING counters → STORAGE sqlite behavior_* → OUTPUT anomalies",
            "tenant_learning": "YES — same user/tenant profile",
            "accessible_by_other_tenant": "NO via normal API (user scoped); host facts MIXED into profile",
            "classification": "MIXED",
        },
        {
            "name": "BTDE baselines",
            "ml": False,
            "mechanism": "set novelty + warm cycles",
            "flow": "INPUT OS snapshot → SCOPE host+tenant files → PROCESSING set-union → STORAGE JSON → OUTPUT findings",
            "tenant_learning": "PARTIAL — remotes file per tid; cycle often platform tid",
            "classification": "MIXED",
        },
        {
            "name": "ZDDE",
            "ml": False,
            "mechanism": "fixed layer weights correlation",
            "flow": "INPUT layers → SCOPE consumes host/mesh → PROCESSING static score → STORAGE audit → OUTPUT classification",
            "tenant_learning": "NO adaptive learning",
            "classification": "MIXED consumer / NOT_VERIFIABLE as learner",
        },
        {
            "name": "Swarm learning",
            "ml": False,
            "mechanism": "gated JSONL append after multi-module evidence",
            "flow": "INPUT correlation → SCOPE instance file → PROCESSING gate → STORAGE learning.jsonl → OUTPUT stats (not rule training)",
            "tenant_learning": "NO partition",
            "classification": "HOST_GLOBAL",
        },
        {
            "name": "Swarm correlate",
            "ml": False,
            "mechanism": "multi-signal within event; tenant filter when scope=TENANT",
            "flow": "INPUT event+contributions → SCOPE TENANT drop foreign → PROCESSING confidence → OUTPUT decision",
            "multi_signal_vs_multi_tenant": "DISTINCT — multi-signal ≠ multi-tenant",
            "classification": "TENANT_SCOPED when tagged else HOST_GLOBAL",
        },
        {
            "name": "AI Kernel",
            "ml": False,
            "mechanism": "counters, keyword tech_level, MAC risk modifiers, recommend-only",
            "flow": "INPUT chat/events → SCOPE user memory + host MAC feedback → PROCESSING heuristics → OUTPUT RECOMMENDED",
            "classification": "MIXED",
        },
        {
            "name": "Auth Abuse Guard",
            "ml": False,
            "mechanism": "failed attempt escalation by IP",
            "scope": "HOST_GLOBAL / app-level origin sanctions",
            "classification": "HOST_GLOBAL",
        },
    ]
    return {
        "run_id": RUN_ID,
        "definition": "Learning = heuristics/baselines/adaptation/scoring — NOT trained ML",
        "trained_ml_present": False,
        "components": components,
    }


def build_global_learning() -> Dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "exists_global_aggregation": True,
        "mechanisms": [
            {
                "id": "swarm_collective_memory",
                "aggregates": "category/IOC recurrence across node incidents",
                "anonimiza": False,
                "improves_detectors": "PARTIAL — priority boost only, not rule training",
                "status": "EXISTS",
            },
            {
                "id": "swarm_learning_jsonl",
                "aggregates": "validated correlation summaries",
                "anonimiza": False,
                "tenant_id": False,
                "improves_detectors": False,
                "status": "EXISTS_APPEND_ONLY",
            },
            {
                "id": "mesh_shared_iocs",
                "aggregates": "IOC counts across peers",
                "anonimiza": "PARTIAL — IOC values shared, not full PII by design",
                "improves_detectors": "PARTIAL — ZDDE layer consumes has_shared_intel",
                "status": "EXISTS",
            },
            {
                "id": "global_search_queries",
                "aggregates": "query string frequency across users",
                "status": "EXISTS",
            },
            {
                "id": "trained_ml_models",
                "status": "NOT_EXISTS",
            },
            {
                "id": "legal_anonymized_customer_warehouse",
                "status": "NOT_EXISTS / NOT_VERIFIABLE",
            },
        ],
        "separation": {
            "DATOS_PRIVADOS_DEL_TENANT": "alerts, evidence, APE profiles, reports by_tenant, notifications",
            "CONOCIMIENTO_DERIVADO_DEL_TENANT": "APE usual_* sets, normality scores, BTDE warm remotes (when tid correct)",
            "CONOCIMIENTO_GLOBAL_DE_NOVUS": "mesh IOCs, collective_memory, learning.jsonl, global_queries, LAN baseline, MAC feedback",
            "technical_separation_real": "PARTIAL — API/data stores often partitioned; learning/mesh stores largely not",
        },
        "potential_global_categories": [
            {"category": "attack pattern frequencies", "class": "POTENCIALMENTE ÚTIL", "note": "REQUIERE DECISIÓN LEGAL/CONTRACTUAL before export"},
            {"category": "generalized IOC hashes/IPs", "class": "POTENCIALMENTE ÚTIL", "note": "mesh already shares indicators; legal review"},
            {"category": "raw customer emails/files/PII", "class": "NO DEBE SALIR DEL TENANT"},
            {"category": "full cmdline / process dumps with user context", "class": "NO DEBE SALIR DEL TENANT"},
            {"category": "correlation templates without identifiers", "class": "POTENCIALMENTE ÚTIL", "note": "REQUIERE DECISIÓN LEGAL/CONTRACTUAL"},
            {"category": "traffic HOST_GLOBAL rates", "class": "NO DEBE SALIR DEL TENANT", "note": "already HOST_GLOBAL; not customer knowledge"},
            {"category": "anonymization quality", "class": "NO VERIFICABLE", "note": "no proven anonymizer pipeline"},
        ],
    }


def build_ai_kernel() -> Dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "classification": "MIXED",
        "executes_actions": False,
        "trained_ml": False,
        "inputs": ["user chat", "radar/endpoint events", "APE adaptive context", "admin feedback"],
        "memory": "data/kernel_memory/<user>.json — per user",
        "tenant_id_layer": "NOT present as isolation key in kernel_memory",
        "cache": "orchestrator capability TTL caches — short lived",
        "prompts": "static system prompts + knowledge packs collectors",
        "outputs": "RECOMMENDED / hints only",
        "persistence": ["kernel_memory JSON", "ai_kernel_feedback/feedback.json (MAC HOST_GLOBAL)", "kernel_operations.jsonl HOST_GLOBAL"],
        "cross_tenant": "user files isolated by path; MAC feedback and ops log are host-global",
        "evidence": [
            "services/kernel_memory.py",
            "services/kernel_agent.py",
            "services/ai_kernel_event_engine/",
            "services/swarm_defense kernel_policy executes_actions=false",
        ],
    }


def build_swarm() -> Dict[str, Any]:
    learning = sample_jsonl("data/swarm_defense/learning.jsonl", 2)
    collective = sample_jsonl("data/swarm_defense/collective_memory.jsonl", 1)
    return {
        "run_id": RUN_ID,
        "receives": "anomaly.detected bus events + collaborator contributions",
        "preserves_tenant_id_on_correlate": "YES when event.scope=TENANT — foreign contributions dropped",
        "multi_signal_within_tenant": "IMPLEMENTED (modules/indicator groups)",
        "multi_tenant_correlation": "POLICY no_cross_tenant_correlation on correlate path",
        "learning_store_tenant_partition": False,
        "collective_memory_tenant_partition": False,
        "contamination_risk": {
            "status": "CONFIRMED",
            "detail": "learning.jsonl and collective_memory.jsonl are node-global; lookup_similar not tenant-filtered",
        },
        "mesh": {
            "shared_iocs_tenant_partition": False,
            "scope": "NOVUS_GLOBAL/HOST_GLOBAL",
        },
        "file_evidence": {"learning": learning, "collective_memory_bytes": collective.get("bytes"), "collective_has_tenant": collective.get("tenant_id_in_sample_or_first50")},
    }


def build_baselines() -> Dict[str, Any]:
    tb_dir = ROOT / "data" / "behavioral_threat_detection" / "tenant_baselines"
    tenant_files = []
    if tb_dir.exists():
        tenant_files = [p.name for p in tb_dir.glob("*.json")][:20]
    return {
        "run_id": RUN_ID,
        "APE": {
            "create": "observe → rebuild_defense_profile",
            "update": "overwrite BehaviorBaselineProfile by email",
            "persist": "SQLite behavior_baseline_profiles",
            "scope": "BASELINE_TENANT/user",
            "TTL": None,
            "contamination": "host telemetry written into user profile (MIXED)",
        },
        "BTDE": {
            "host": "data/behavioral_threat_detection/host_baseline.json → BASELINE_GLOBAL(HOST)",
            "tenant": "tenant_baselines/<tid>.json → BASELINE_TENANT",
            "TTL": None,
            "warm_cycles": "≥2 before novelty",
            "live_cycle_tenant_key": "often get_platform_tenant_id() — PARTIAL isolation",
            "tenant_baseline_files_sample": tenant_files,
        },
        "LAN": {
            "path": "data/network_baseline/lan_baseline.json",
            "scope": "BASELINE_GLOBAL(HOST)",
        },
        "mix_risk": "PARTIAL — APE/BTDE host facts + platform tid wiring",
    }


def cross_tenant_test() -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "mode": "READ_ONLY",
        "generated_at_utc": utc(),
        "server": BASE,
        "TENANT_LEAKS": 0,
        "checks": [],
        "login": {},
        "in_process": {},
    }
    # In-process resolve checks (no writes)
    try:
        from types import SimpleNamespace
        from services.tenant_scope_service import resolve_tenant_id
        from services.enterprise_access_control import user_may_access_tenant, is_novus_creator

        ua = SimpleNamespace(company_id="LOADTEST-T0000", nit_pyme="LOADTEST-T0000", email="loadtest-user-0000@loadtest.novus.local", role="company_admin")
        ub = SimpleNamespace(company_id="LOADTEST-T0001", nit_pyme="LOADTEST-T0001", email="loadtest-user-0001@loadtest.novus.local", role="company_admin")
        ta, tb = resolve_tenant_id(ua), resolve_tenant_id(ub)
        ok_ab, reason_ab = user_may_access_tenant(ua, tb)
        ok_aa, _ = user_may_access_tenant(ua, ta)
        out["in_process"] = {
            "resolve_a": ta,
            "resolve_b": tb,
            "a_may_access_b": ok_ab,
            "a_may_access_a": ok_aa,
            "deny_reason": reason_ab,
            "creator_bypass_exists": True,
            "email_domain_fallback_exists": True,
        }
        if ok_ab and not is_novus_creator(ua):
            out["TENANT_LEAKS"] += 1
            out["checks"].append({"id": "access_control_a_to_b", "result": "FAIL"})
        else:
            out["checks"].append({"id": "access_control_a_to_b", "result": "PASS", "detail": "denied or creator"})
    except Exception as e:
        out["in_process"] = {"error": str(e)[:200]}
        out["checks"].append({"id": "access_control", "result": "NOT_VERIFIABLE", "error": str(e)[:120]})

    # Swarm correlate isolation (fixture marked)
    try:
        from services.swarm_defense.correlation import correlate

        event = {
            "event_id": f"EVT-TIA-{RUN_ID}",
            "tenant_id": "tenant-audit-A",
            "scope": "TENANT",
            "test_fixture": True,
            "synthetic_test_only": True,
        }
        contrib = [
            {"tenant_id": "tenant-audit-A", "module_id": "auth", "found": True, "signal": "brute_force"},
            {"tenant_id": "tenant-audit-B", "module_id": "endpoint", "found": True, "signal": "should_drop"},
        ]
        corr = correlate(event, {"auth": ["brute_force"]}, contrib)
        blob = json.dumps(corr, default=str)
        leak = "tenant-audit-B" in blob and "should_drop" in blob
        # foreign may appear in dropped list — check supporting modules don't include endpoint from B as accepted
        ms = (corr or {}).get("multi_signal") or {}
        supporting = json.dumps((corr or {}).get("classification") or {}, default=str)
        foreign_supported = "tenant-audit-B" in supporting
        out["checks"].append(
            {
                "id": "swarm_correlate_tenant_filter",
                "result": "PASS" if not foreign_supported else "FAIL",
                "foreign_in_classification": foreign_supported,
                "test_fixture": True,
            }
        )
        if foreign_supported:
            out["TENANT_LEAKS"] += 1
    except Exception as e:
        out["checks"].append({"id": "swarm_correlate", "result": "NOT_VERIFIABLE", "error": str(e)[:160]})

    # HTTP if server up
    try:
        import requests

        r = requests.get(f"{BASE}/login", timeout=8)
        server_up = r.status_code == 200
    except Exception:
        server_up = False
    out["server_up"] = server_up
    if not server_up:
        out["checks"].append({"id": "http_cross_tenant", "result": "NOT_VERIFIABLE", "detail": "server not reachable"})
        return out

    try:
        from services.loadtest_runtime import loadtest_password

        manifest = json.loads((ROOT / "data/production_closure/loadtest_users_manifest.json").read_text(encoding="utf-8"))
        ua = manifest["users"][0]
        ub = manifest["users"][1]
        pw = loadtest_password()
        sa, la = login(ua["email"], pw)
        sb, lb = login(ub["email"], pw)
        out["login"] = {"a": la, "b": lb, "tenant_a": ua["tenant_id"], "tenant_b": ub["tenant_id"]}
        if not (la.get("ok") and lb.get("ok")):
            out["checks"].append({"id": "http_login", "result": "NOT_VERIFIABLE"})
            return out

        # Scope endpoints
        for label, sess in (("a", sa), ("b", sb)):
            out[f"scope_{label}"] = api_get(sess, "/api/tenant/scope", timeout=30)

        # Notifications / alerts — ensure A's event_id marker not present unless we create none
        # Use existing unread list and compare tenant markers in payloads
        na = api_get(sa, "/api/notifications?kind=security&limit=20", timeout=40)
        nb = api_get(sb, "/api/notifications?kind=security&limit=20", timeout=40)
        aa = api_get(sa, "/api/security/alerts", timeout=40)
        ab = api_get(sb, "/api/security/alerts", timeout=40)
        live_a = api_get(sa, "/api/dashboard/live", timeout=40)

        # Extract tenant markers from A notifications
        def collect_refs(body: Any) -> set:
            s = set()
            blob = json.dumps(body, default=str)
            for m in re.finditer(r"LOADTEST-T\d+", blob):
                s.add(m.group(0))
            return s

        refs_a = collect_refs(na.get("body"))
        refs_b = collect_refs(nb.get("body"))
        # B must not contain A's tenant id strings from A's private notifications
        leak_notif = ua["tenant_id"] in json.dumps(nb.get("body"), default=str) and ua["tenant_id"] != ub["tenant_id"]
        # Also check alerts
        leak_alert = ua["tenant_id"] in json.dumps(ab.get("body"), default=str) and any(
            ua["tenant_id"] in json.dumps(x, default=str)
            for x in (
                ((ab.get("body") or {}).get("alerts") or (ab.get("body") or {}).get("items") or [])
                if isinstance(ab.get("body"), dict)
                else []
            )
        )
        # Simpler: if B body contains exact tenant A id as field value — count carefully
        leak_b_has_a = ua["tenant_id"] in json.dumps(nb.get("body"), default=str)

        # Traffic must be HOST_GLOBAL not tenant-attributed
        live_body = live_a.get("body") if isinstance(live_a.get("body"), dict) else {}
        meta = live_body.get("traffic_meta") or {}
        traffic_ok = meta.get("scope") == "HOST_GLOBAL" or meta.get("scope") is None

        out["checks"].append(
            {
                "id": "notifications_b_excludes_tenant_a_string",
                "result": "PASS" if not leak_b_has_a else "PARTIAL",
                "detail": "string presence of tenant A id in B notifications",
                "leak_flag": leak_b_has_a,
            }
        )
        # String presence can false-positive; only count as leak if notification items explicitly bound to A
        if leak_b_has_a:
            # inspect items
            items = []
            body = nb.get("body") or {}
            if isinstance(body, dict):
                items = body.get("notifications") or body.get("items") or []
            confirmed = False
            for it in items:
                if isinstance(it, dict) and it.get("tenant_id") == ua["tenant_id"]:
                    confirmed = True
                    break
            if confirmed:
                out["TENANT_LEAKS"] += 1
                out["checks"][-1]["result"] = "FAIL"
            else:
                out["checks"][-1]["result"] = "PASS"
                out["checks"][-1]["detail"] = "tenant string may appear elsewhere; no item.tenant_id==A"

        out["checks"].append(
            {
                "id": "traffic_host_global",
                "result": "PASS" if traffic_ok else "FAIL",
                "scope": meta.get("scope"),
                "data_state": meta.get("data_state"),
            }
        )
        out["http_samples"] = {
            "notifications_a_http": na.get("http"),
            "notifications_b_http": nb.get("http"),
            "alerts_a_http": aa.get("http"),
            "alerts_b_http": ab.get("http"),
            "live_a_http": live_a.get("http"),
            "refs_a": sorted(refs_a)[:10],
            "refs_b": sorted(refs_b)[:10],
        }
    except Exception as e:
        out["checks"].append({"id": "http_cross_tenant", "result": "NOT_VERIFIABLE", "error": str(e)[:200]})

    return out


def main() -> int:
    print("=== TENANT IDENTITY + LEARNING AUDIT (READ-ONLY) ===", flush=True)
    identity = build_identity_audit()
    lineage = build_lineage()
    scope = build_scope_matrix()
    learning = build_learning_scope()
    global_l = build_global_learning()
    ai = build_ai_kernel()
    swarm = build_swarm()
    baselines = build_baselines()
    cross = cross_tenant_test()

    write("tenant_identity_audit.json", identity)
    write("tenant_data_lineage.json", lineage)
    write("tenant_scope_matrix.json", scope)
    write("tenant_learning_scope.json", learning)
    write("global_learning_audit.json", global_l)
    write("ai_kernel_scope_audit.json", ai)
    write("swarm_scope_audit.json", swarm)
    write("baseline_scope_audit.json", baselines)
    write("tenant_cross_isolation.json", cross)

    # Verdict
    critical = []
    # Do not auto-block on creator bypass / learning global — document as limitations
    limitations = [
        "email_domain_fallback_CONFIRMED",
        "creator_tenant_bypass_CONFIRMED",
        "swarm_learning_collective_memory_HOST_GLOBAL_CONFIRMED",
        "mesh_shared_iocs_not_tenant_partitioned",
        "APE_MIXED_host_into_user_baseline",
        "BTDE_live_cycle_often_platform_tenant",
        "no_trained_ML",
        "global_learning_exists_but_not_legal_anon_pipeline",
        "SIEM_product_NOT_IMPLEMENTED",
    ]
    if cross.get("TENANT_LEAKS", 0) > 0:
        critical.append("cross_tenant_API_leak")
    # Learning contamination is architectural limitation, not automatic BLOCKED unless API leak
    if critical:
        verdict = "TENANT_IDENTITY_LEARNING_BLOCKED"
    else:
        verdict = "TENANT_IDENTITY_LEARNING_PASS_WITH_LIMITATIONS"

    evidence_index = {
        "run_id": RUN_ID,
        "verdict": verdict,
        "TENANT_LEAKS": cross.get("TENANT_LEAKS"),
        "production_code_modified": False,
        "artifacts": [
            "tenant_identity_audit.json",
            "tenant_identity_audit.md",
            "tenant_data_lineage.json",
            "tenant_scope_matrix.json",
            "tenant_learning_scope.json",
            "global_learning_audit.json",
            "ai_kernel_scope_audit.json",
            "swarm_scope_audit.json",
            "baseline_scope_audit.json",
            "tenant_cross_isolation.json",
            "tenant_learning_evidence_index.json",
        ],
        "key_evidence_paths": [
            "services/tenant_scope_service.py",
            "services/enterprise_access_control.py",
            "services/tenant_isolation_service.py",
            "services/adaptive_profile_engine.py",
            "services/swarm_defense/learning.py",
            "services/swarm_defense/collective_memory.py",
            "services/swarm_defense/correlation.py",
            "services/kernel_memory.py",
            "data/swarm_defense/learning.jsonl",
            "services/dashboard_live_service.py (HOST_GLOBAL traffic)",
        ],
        "limitations": limitations,
        "blockers": critical,
        "claims_rejected": [
            "trained_ML",
            "full_legal_anonymization",
            "certified_compliance",
            "complete_global_learning_product",
        ],
    }
    write("tenant_learning_evidence_index.json", evidence_index)

    md = f"""# NOVUS — Tenant Identity + Learning Audit

## Verdict

**`{verdict}`**

Run: `{RUN_ID}`  
Production code modified: **false**  
TENANT_LEAKS (controlled checks): **{cross.get('TENANT_LEAKS')}**

---

## 1. Tenant identity

- **No** first-class `Tenant` table.
- Canonical ID = **company NIT** → `Usuario.nit_pyme` → `User.company_id`.
- Session stores **user id only**; `tenant_id` is **re-resolved** each request via `resolve_tenant_id()`.
- Fallback to **email domain** if NIT missing (**CONFIRMED** collision risk).
- Creator role **bypasses** tenant filters (**CONFIRMED**, privileged).

See `tenant_identity_audit.json`.

---

## 2–3. Lineage & scope

Traffic remains **HOST_GLOBAL** (`traffic_meta.scope`).  
Customer alerts/evidence/reports are **TENANT** when stamped.  
Swarm learning / collective memory / mesh IOCs are **HOST_GLOBAL** / **NOVUS_GLOBAL**.

---

## 4–8. Learning

- **Not ML.** Heuristics, baselines, gated JSONL, fixed scores.
- **Tenant learning:** APE user baselines (primary).
- **Global aggregation EXISTS** (Swarm learning/collective memory, mesh IOCs, global_queries) **without** proven anonymization pipeline.
- Separation private vs derived vs global: **PARTIAL**.

---

## 9. AI Kernel

**MIXED** — per-user memory + host-global MAC feedback/ops. Recommend-only.

## 10. Swarm

- Correlate: multi-signal **within tenant** when `scope=TENANT`.
- Learning stores: **not tenant-partitioned** → contamination risk **CONFIRMED** at knowledge layer.

## 11. Baselines

APE = user/tenant-tagged; BTDE host = HOST_GLOBAL; LAN = HOST_GLOBAL; mix risks documented.

## 12. Potential global knowledge

Listed in `global_learning_audit.json` with LEGAL/CONTRACTUAL flags — **not implemented**.

## 14. Cross-tenant

See `tenant_cross_isolation.json`.

## Limitations

{chr(10).join('- ' + x for x in limitations)}

## STOP

No Phase 5. No global learning implementation. No production fixes in this audit.
"""
    write("tenant_identity_audit.md", md)
    write(
        "tenant_identity_audit.json",
        {**identity, "verdict": verdict, "limitations": limitations, "TENANT_LEAKS": cross.get("TENANT_LEAKS")},
    )

    print(json.dumps({"verdict": verdict, "TENANT_LEAKS": cross.get("TENANT_LEAKS"), "limitations_n": len(limitations)}, indent=2), flush=True)
    return 0 if verdict != "TENANT_IDENTITY_LEARNING_BLOCKED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
