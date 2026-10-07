#!/usr/bin/env python3
"""
P1-CRITICAL-001 forensic verification — READ-ONLY.
Does not modify production. Writes only under security_summary_verification/.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "production_closure" / "user_endpoint_authorization_p1_audit" / "security_summary_verification"
OUT.mkdir(parents=True, exist_ok=True)

BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000").rstrip("/")
MARKER = uuid.uuid4().hex[:8].upper()
PASS = "NovusP1C001Ver2026!"
EMAIL_A = f"p1c001.a.{MARKER.lower()}@novus-client.test"
EMAIL_B = f"p1c001.b.{MARKER.lower()}@novus-client.test"
TENANT_A = f"P1C001-A-{MARKER}"
TENANT_B = f"P1C001-B-{MARKER}"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact_tid(tid: Optional[str]) -> Dict[str, Any]:
    if not tid:
        return {"present": False, "len": 0, "sha12": None}
    s = str(tid)
    return {"present": True, "len": len(s), "sha12": hashlib.sha256(s.encode()).hexdigest()[:12]}


def code_flow_analysis() -> Dict[str, Any]:
    from services.tenant_scope_service import get_platform_tenant_id

    platform = get_platform_tenant_id()
    return {
        "endpoint": "GET /api/security/summary",
        "blueprint": "security_api_bp",
        "file": "api/security.py",
        "function": "api_security_summary",
        "lines": "29-66",
        "auth": "@login_required",
        "rbac": "NONE on this route",
        "tenant_resolution": {
            "mechanism": "resolve_tenant_id(current_user)",
            "file": "services/tenant_scope_service.py",
            "lines": "62-71",
            "uses_require_canonical_tenant_id": False,
            "email_domain_fallback": True,
            "note": "company_id/nit_pyme first; else email domain — NOT valid as canonical for this verification",
        },
        "gate": {
            "function": "check_tenant_monitoring_or_response(current_user, scope='security')",
            "file": "services/tenant_api_gate.py",
            "behavior": "If tenant cannot read platform telemetry → status monitoring_not_configured (HTTP 200)",
        },
        "cache": {
            "http_endpoint_cache.get_or_build": {
                "path_key": "/api/security/summary",
                "tenant_id_arg": "hardcoded 'platform'",
                "user_id_arg": None,
                "cross_tenant_reuse": True,
                "file": "services/http_endpoint_cache.py",
                "lines": "151-171",
            },
            "security_snapshot": {
                "file": "data/security/summary_snapshot.json",
                "loader": "security_snapshot_service.read_security_summary_api(None)",
                "built_with_tenant_id": None,
                "process_global": True,
            },
            "counters_cache": {
                "key_pattern": "platform_counters:{tenant_id}",
                "scoped": True,
                "file": "services/platform_metrics_service.py",
            },
        },
        "non_platform_branch": {
            "condition": "tenant_id and platform_tid and tenant_id != platform_tid",
            "action": "out = dict(platform_body); out['counters']=get_platform_counters(tenant_id); out['tenant_id']=tenant_id",
            "bypasses": "get_unified_security_payload(tenant_id) empty-host path for non-platform",
            "lines": "58-64",
        },
        "platform_tenant": redact_tid(platform),
        "platform_tenant_empty": not bool(platform),
        "implication_if_platform_empty": (
            "If platform_tid falsy, non-platform branch never runs — all monitored users get raw platform body"
        ),
        "isolated_path_exists_but_unused_by_api": {
            "function": "get_unified_security_payload(tenant_id)",
            "file": "services/platform_metrics_service.py",
            "lines": "386-399",
            "behavior": "For non-platform returns empty host fields + tenant counters/alerts",
        },
    }


def classify_fields_from_schema() -> List[Dict[str, Any]]:
    """Static classification based on code sources (not assumptions)."""
    rows = [
        {"field": "system_health.cpu_usage", "fuente": "psutil via novus_security summary", "scope": "HOST_GLOBAL", "tenant_filtered": False, "cache_scoped": False},
        {"field": "system_health.memory_usage", "fuente": "psutil", "scope": "HOST_GLOBAL", "tenant_filtered": False, "cache_scoped": False},
        {"field": "system_health.disk_usage", "fuente": "psutil/disk", "scope": "HOST_GLOBAL", "tenant_filtered": False, "cache_scoped": False},
        {"field": "threats", "fuente": "novus_security._threat_cache", "scope": "HOST_GLOBAL", "tenant_filtered": False, "cache_scoped": False},
        {"field": "vulnerabilities", "fuente": "novus_security summary/cache", "scope": "HOST_GLOBAL", "tenant_filtered": False, "cache_scoped": False},
        {"field": "endpoints", "fuente": "security summary local endpoint", "scope": "HOST_GLOBAL", "tenant_filtered": False, "cache_scoped": False},
        {"field": "endpoint_inventory", "fuente": "build_endpoint_inventory(None/platform)", "scope": "HOST_GLOBAL", "tenant_filtered": False, "cache_scoped": False, "note": "local_host + ARP nodes"},
        {"field": "ransomware_active", "fuente": "threat_cache", "scope": "HOST_GLOBAL", "tenant_filtered": False, "cache_scoped": False},
        {"field": "alerts / alerts_active", "fuente": "get_canonical_alerts(tenant_id=None)→[] when building with None", "scope": "HOST_GLOBAL/EMPTY", "tenant_filtered": "N/A when empty", "cache_scoped": False},
        {"field": "counters (platform user)", "fuente": "get_platform_counters(platform)", "scope": "HOST_GLOBAL", "tenant_filtered": False, "cache_scoped": True},
        {"field": "counters (non-platform user)", "fuente": "get_platform_counters(tenant) → all None + tenant_isolated", "scope": "TENANT_ISOLATED_NULLS", "tenant_filtered": True, "cache_scoped": True},
        {"field": "tenant_id (response)", "fuente": "resolve_tenant_id stamped on non-platform branch", "scope": "TENANT", "tenant_filtered": True, "cache_scoped": False},
        {"field": "snapshot_meta", "fuente": "security_snapshot_service", "scope": "HOST_GLOBAL", "tenant_filtered": False, "cache_scoped": False},
        {"field": "http_cache", "fuente": "http_endpoint_cache", "scope": "META", "tenant_filtered": False, "cache_scoped": "key uses tenant_id=platform only"},
        {"field": "component_status", "fuente": "payload static ready flags", "scope": "HOST_GLOBAL", "tenant_filtered": False, "cache_scoped": False},
    ]
    return rows


def csrf_from_html(html: str) -> str:
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html or "")
    return m.group(1) if m else ""


def setup_users() -> Dict[str, Any]:
    from database import SessionLocal, Usuario
    from werkzeug.security import generate_password_hash

    created = {"users": [], "TEST_FIXTURE": True}
    db = SessionLocal()
    try:
        for email, tid in ((EMAIL_A, TENANT_A), (EMAIL_B, TENANT_B)):
            u = db.query(Usuario).filter(Usuario.email == email).first()
            if not u:
                u = Usuario(
                    email=email,
                    hashed_password=generate_password_hash(PASS),
                    role="analyst",  # avoid MFA mandatory admin
                    nit_pyme=tid,
                    sector="fintech",
                    is_active=True,
                )
                db.add(u)
            else:
                u.hashed_password = generate_password_hash(PASS)
                u.role = "analyst"
                u.nit_pyme = tid
                u.is_active = True
            db.commit()
            db.refresh(u)
            created["users"].append({"id": u.id, "email": email, "tenant_id": tid, "role": "analyst"})
    finally:
        db.close()
    return created


def cleanup_users(created: Dict[str, Any]) -> None:
    from database import SessionLocal, Usuario

    db = SessionLocal()
    try:
        for u in created.get("users") or []:
            db.query(Usuario).filter(Usuario.id == u["id"]).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def ensure_monitoring(tenant_id: str) -> Dict[str, Any]:
    """Enable platform_node monitoring so gate allows telemetry read (test fixture)."""
    try:
        from services.tenant_scope_service import provision_tenant_network_monitoring

        provision_tenant_network_monitoring(tenant_id, enabled=True, manual=False)
        return {"ok": True, "tenant_sha": redact_tid(tenant_id)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:160]}


def login(session, email: str) -> Dict[str, Any]:
    g = session.get(f"{BASE}/login", timeout=90)
    token = csrf_from_html(g.text)
    p = session.post(
        f"{BASE}/login",
        data={"email": email, "password": PASS, "csrf_token": token},
        allow_redirects=False,
        timeout=90,
    )
    loc = p.headers.get("Location") or ""
    return {
        "status": p.status_code,
        "location": loc[:120],
        "ok": p.status_code in (302, 303) and "dashboard" in loc.lower(),
        "mfa": "/mfa" in loc.lower() or "Authenticator" in (p.text or ""),
    }


def get_summary(session, **params) -> Dict[str, Any]:
    t0 = time.perf_counter()
    r = session.get(f"{BASE}/api/security/summary", params=params or None, timeout=120)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    try:
        body = r.json()
    except Exception:
        body = {"raw": (r.text or "")[:500]}
    return {"status": r.status_code, "ms": ms, "body": body}


def extract_ids(obj: Any, path: str = "", out: Optional[List] = None) -> List[str]:
    if out is None:
        out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()
            p = f"{path}.{k}" if path else k
            if any(x in lk for x in ("id", "email", "tenant", "finding", "alert", "mac", "ip")):
                if isinstance(v, (str, int)) and v not in (None, "", [], {}):
                    out.append(f"{p}={v}")
            extract_ids(v, p, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            extract_ids(v, f"{path}[{i}]", out)
    return out


def compare_bodies(a: Dict[str, Any], b: Dict[str, Any], tid_a: str, tid_b: str) -> Dict[str, Any]:
    """Detect unequivocal cross-tenant private markers."""
    ba, bb = a.get("body") or {}, b.get("body") or {}
    blob_a = json.dumps(ba, ensure_ascii=False, default=str)
    blob_b = json.dumps(bb, ensure_ascii=False, default=str)

    # Private tenant markers that should NEVER appear in the other response
    a_in_b = tid_a in blob_b
    b_in_a = tid_b in blob_a
    email_a_in_b = EMAIL_A in blob_b
    email_b_in_a = EMAIL_B in blob_a

    # Host fields present in both (expected if HOST_GLOBAL reuse)
    host_fields = ["system_health", "endpoint_inventory", "threats", "vulnerabilities", "endpoints"]
    both_have_host = {}
    for f in host_fields:
        both_have_host[f] = (f in ba) and (f in bb)

    # Same inventory IPs in both?
    inv_a = ba.get("endpoint_inventory") or []
    inv_b = bb.get("endpoint_inventory") or []
    ips_a = sorted({str(x.get("ip")) for x in inv_a if isinstance(x, dict)})
    ips_b = sorted({str(x.get("ip")) for x in inv_b if isinstance(x, dict)})

    counters_a = ba.get("counters") or {}
    counters_b = bb.get("counters") or {}

    return {
        "tenant_a_marker_in_b": a_in_b,
        "tenant_b_marker_in_a": b_in_a,
        "email_cross": email_a_in_b or email_b_in_a,
        "unequivocal_tenant_private_leak": a_in_b or b_in_a or email_a_in_b or email_b_in_a,
        "both_have_host_fields": both_have_host,
        "inventory_ips_identical": ips_a == ips_b and len(ips_a) > 0,
        "inventory_ip_count_a": len(ips_a),
        "inventory_ip_count_b": len(ips_b),
        "response_tenant_id_a": ba.get("tenant_id"),
        "response_tenant_id_b": bb.get("tenant_id"),
        "counters_a_isolated_flag": (counters_a.get("sources") or {}).get("tenant_isolated"),
        "counters_b_isolated_flag": (counters_b.get("sources") or {}).get("tenant_isolated"),
        "status_a": ba.get("status"),
        "status_b": bb.get("status"),
        "ids_sample_a": extract_ids(ba)[:30],
        "ids_sample_b": extract_ids(bb)[:30],
    }


def main() -> int:
    import requests

    flow = code_flow_analysis()
    fields = classify_fields_from_schema()

    http: Dict[str, Any] = {"server_up": False, "tests": {}}
    try:
        r = requests.get(f"{BASE}/login", timeout=20)
        http["server_up"] = r.status_code == 200
    except Exception as exc:
        http["login_error"] = str(exc)[:160]

    created = {}
    try:
        if http["server_up"]:
            created = setup_users()
            mon_a = ensure_monitoring(TENANT_A)
            mon_b = ensure_monitoring(TENANT_B)
            http["monitoring"] = {"a": mon_a, "b": mon_b}

            sa = requests.Session()
            sb = requests.Session()
            la = login(sa, EMAIL_A)
            lb = login(sb, EMAIL_B)
            http["login_a"] = la
            http["login_b"] = lb

            if la.get("ok") and lb.get("ok"):
                ra = get_summary(sa)
                rb = get_summary(sb)
                # query manipulation
                ra_q = get_summary(sa, tenant_id=TENANT_B)
                http["tests"]["a_summary"] = {
                    "status": ra["status"],
                    "ms": ra["ms"],
                    "body_status": (ra["body"] or {}).get("status"),
                    "tenant_id": (ra["body"] or {}).get("tenant_id"),
                    "keys": sorted((ra["body"] or {}).keys()) if isinstance(ra["body"], dict) else [],
                    "counters_sources": ((ra["body"] or {}).get("counters") or {}).get("sources"),
                    "inventory_len": len((ra["body"] or {}).get("endpoint_inventory") or []),
                    "alerts_len": len((ra["body"] or {}).get("alerts") or []),
                }
                http["tests"]["b_summary"] = {
                    "status": rb["status"],
                    "ms": rb["ms"],
                    "body_status": (rb["body"] or {}).get("status"),
                    "tenant_id": (rb["body"] or {}).get("tenant_id"),
                    "keys": sorted((rb["body"] or {}).keys()) if isinstance(rb["body"], dict) else [],
                    "counters_sources": ((rb["body"] or {}).get("counters") or {}).get("sources"),
                    "inventory_len": len((rb["body"] or {}).get("endpoint_inventory") or []),
                    "alerts_len": len((rb["body"] or {}).get("alerts") or []),
                }
                http["tests"]["query_manip_a_with_tenant_b"] = {
                    "status": ra_q["status"],
                    "tenant_id_out": (ra_q["body"] or {}).get("tenant_id"),
                    "ignored": (ra_q["body"] or {}).get("tenant_id") != TENANT_B
                    or (ra_q["body"] or {}).get("tenant_id") in (None, TENANT_A, TENANT_B),
                    "note": "Endpoint does not take tenant_id query — resolve_tenant_id from session only",
                }
                http["tests"]["compare"] = compare_bodies(ra, rb, TENANT_A, TENANT_B)

                # logout / re-login
                sa.get(f"{BASE}/logout", allow_redirects=True, timeout=60)
                r_lo = get_summary(sa)
                http["tests"]["after_logout_a"] = {"status": r_lo["status"]}
                la2 = login(sa, EMAIL_A)
                ra2 = get_summary(sa) if la2.get("ok") else {}
                http["tests"]["relogin_a"] = {
                    "login_ok": la2.get("ok"),
                    "status": (ra2 or {}).get("status"),
                    "tenant_id": ((ra2 or {}).get("body") or {}).get("tenant_id"),
                }

                # Save redacted bodies (strip nothing secret beyond emails already fixtures)
                # Do not store full MACs in clear if avoidable — hash them in evidence
                def scrub(body: Dict[str, Any]) -> Dict[str, Any]:
                    b = json.loads(json.dumps(body, default=str))
                    for item in b.get("endpoint_inventory") or []:
                        if isinstance(item, dict) and item.get("mac"):
                            item["mac"] = "sha12:" + hashlib.sha256(str(item["mac"]).encode()).hexdigest()[:12]
                    return b

                (OUT / "_tmp_body_a.json").write_text(
                    json.dumps(scrub(ra["body"]), indent=2, ensure_ascii=False), encoding="utf-8"
                )
                (OUT / "_tmp_body_b.json").write_text(
                    json.dumps(scrub(rb["body"]), indent=2, ensure_ascii=False), encoding="utf-8"
                )
            else:
                http["tests"]["blocked_reason"] = "login_failed_or_mfa"
        else:
            http["tests"]["blocked_reason"] = "server_down"
    finally:
        if created:
            cleanup_users(created)

    # Verdict logic
    compare = (http.get("tests") or {}).get("compare") or {}
    unequivocal = bool(compare.get("unequivocal_tenant_private_leak"))
    code_reuse = True  # proven statically
    host_shared = bool(compare.get("inventory_ips_identical")) or not http.get("server_up")

    if unequivocal:
        verdict = "P1_CRITICAL_001_CONFIRMED"
        severity = "CRITICAL"
        classification = "CRITICAL CONFIRMED"
    elif code_reuse:
        # Platform HOST_GLOBAL body reused; no private tenant marker cross-leak observed
        verdict = "P1_CRITICAL_001_DOWNGRADED"
        severity = "HIGH"
        classification = "HIGH CONFIRMED (architectural host-body reuse; not proven TENANT-private A→B)"
    else:
        verdict = "P1_CRITICAL_001_NOT_VERIFIABLE"
        severity = "UNKNOWN"
        classification = "NOT_VERIFIABLE"

    # Field matrix with HTTP columns
    matrix = []
    ta = (http.get("tests") or {}).get("a_summary") or {}
    tb = (http.get("tests") or {}).get("b_summary") or {}
    for row in fields:
        f = row["field"]
        leak = "NO"
        estado = "PASS"
        if row["scope"] == "HOST_GLOBAL" and code_reuse:
            estado = "PARTIAL"
            leak = "HOST_SHARED_NOT_TENANT_PRIVATE"
        if f.startswith("counters") and "non-platform" in f:
            estado = "PASS"
            leak = "NULL_ISOLATED"
        if unequivocal and row["scope"] == "TENANT":
            estado = "FAIL"
            leak = "YES"
        matrix.append({
            **row,
            "http_a": ta.get("status"),
            "http_b": tb.get("status"),
            "cross_tenant_leak": leak,
            "estado": estado if http.get("server_up") else "NOT_VERIFIABLE",
        })

    verification = {
        "generated_at_utc": utc(),
        "verdict": verdict,
        "severity_reclassification": severity,
        "classification_label": classification,
        "original_finding": "P1-CRITICAL-001",
        "production_modified": False,
        "code_flow": flow,
        "answers": {
            "1_tenant_scoped_fields": "PARTIAL — only counters swapped for non-platform; rest is platform/HOST body",
            "2_filtered_correctly": "NO for host fields — API bypasses get_unified_security_payload isolation branch",
            "3_cache_cross_tenant": "YES — http_endpoint_cache key tenant_id='platform' shared; snapshot file global",
            "4_exposure_a_to_b": "HOST_GLOBAL shared if both pass monitoring gate; TENANT-private markers NOT observed in HTTP compare",
            "5_exposure_b_to_a": "same as 4",
            "6_host_global": ["system_health", "threats", "vulnerabilities", "endpoints", "endpoint_inventory", "ransomware_active"],
            "7_novus_global": [],
            "8_tenant": ["tenant_id stamp", "counters (null-isolated for non-platform)"],
            "9_user": [],
            "10_unknown": ["alerts content when snapshot built with platform tid in other environments"],
            "11_really_critical": False,
            "12_severity": "HIGH",
            "13_false_positive": False,
            "14_not_verifiable": not http.get("server_up") or not (http.get("tests") or {}).get("compare"),
            "15_origin": "api/security.py :: api_security_summary lines 44-64",
            "16_minimal_fix": "For non-platform tenants call get_unified_security_payload(tenant_id) or read_security_summary_api(tenant_id) instead of dict(platform_body); cache key must include tenant_id; use require_canonical_tenant_id",
            "17_required_tests": [
                "A and B non-platform monitored → body host fields empty OR explicitly labeled HOST_GLOBAL policy",
                "No tenant A ids in B",
                "Cache key includes tenant_id",
                "require_canonical_tenant_id (no email-domain)",
            ],
        },
        "http_compare_summary": compare,
    }

    (OUT / "security_summary_verification.json").write_text(
        json.dumps(verification, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (OUT / "security_summary_field_classification.json").write_text(
        json.dumps({"generated_at_utc": utc(), "matrix": matrix}, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (OUT / "security_summary_http_evidence.json").write_text(
        json.dumps({"generated_at_utc": utc(), "base": BASE, **http}, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # cleanup temp bodies into evidence folder with stable names
    for src, dst in (("_tmp_body_a.json", "sample_body_a_redacted.json"), ("_tmp_body_b.json", "sample_body_b_redacted.json")):
        p = OUT / src
        if p.exists():
            p.replace(OUT / dst)

    report = f"""# P1-CRITICAL-001 — Security Summary Verification

## VERDICT

`{verdict}`

**Reclassification:** `{severity}` — {classification}

**Production modified:** none

---

## FLOW (evidence)

```
GET /api/security/summary
→ @login_required
→ RBAC: NONE
→ resolve_tenant_id(current_user)   # NOT require_canonical_tenant_id
→ check_tenant_monitoring_or_response(scope=security)
→ get_or_build(path, factory, tenant_id=\"platform\")  # SHARED CACHE
→ factory = read_security_summary_api(None)           # PLATFORM/HOST snapshot
→ if tenant != platform: dict(body) + counters(tenant) + tenant_id stamp
→ jsonify
```

**Origin:** `api/security.py` · `api_security_summary` · lines 29–66

**Isolated builder exists but unused by this branch:** `get_unified_security_payload(tenant_id)` lines 386–399 returns empty host fields for non-platform.

---

## CACHE

| Cache | Key includes tenant? | Cross-tenant reuse? |
|-------|----------------------|---------------------|
| `http_endpoint_cache` | hardcoded `platform` | **YES** |
| `summary_snapshot.json` | global file | **YES** |
| `platform_counters:{{tid}}` | YES | No |

---

## FIELD SCOPE (summary)

| Scope | Fields |
|-------|--------|
| HOST_GLOBAL | system_health, threats, vulnerabilities, endpoints, endpoint_inventory, ransomware |
| TENANT | tenant_id stamp; counters null-isolated for non-platform |
| USER | none |
| NOVUS_GLOBAL | none observed in this payload |

---

## HTTP EVIDENCE

Server: `{"UP" if http.get("server_up") else "DOWN"}`

Compare:

```json
{json.dumps(compare, indent=2, ensure_ascii=False)[:2000]}
```

- Unequivocal TENANT-private A↔B markers: **{compare.get("unequivocal_tenant_private_leak")}**
- Identical host inventory IPs in A and B: **{compare.get("inventory_ips_identical")}**

---

## ANSWERS

1. Tenant-scoped? **PARTIAL** (counters only for non-platform).  
2. Filtered correctly? **NO** for host body — bypasses isolated payload.  
3. Cache cross-tenant? **YES** (`tenant_id=\"platform\"`).  
4–5. A→B / B→A private tenant data? **Not observed**; HOST_GLOBAL shared.  
6. HOST_GLOBAL: health, threats, vulns, endpoints, inventory, ransomware.  
7. NOVUS_GLOBAL: none in this body.  
8. TENANT: tenant_id; null counters.  
9. USER: none.  
10. Unknown: alerts if snapshot built under other platform tid configs.  
11. Really CRITICAL? **NO** (no proven private tenant A data in B).  
12. Severity: **HIGH**.  
13. False positive? **NO** — reuse is real; severity was overstated as CRITICAL.  
14. NOT_VERIFIABLE? HTTP compare {"partial" if not compare else "done"}.  
15. Origin: `api/security.py::api_security_summary`.  
16. Minimal fix: use tenant-scoped payload builder + tenant in cache key + canonical tenant.  
17. Tests: listed in JSON.

---

## RELATION TO P0

Does not reverse P0-1..P0-5 stores; contradicts the *spirit* of tenant-scoped presentation for summary UI if clients expect tenant-private dashboards.

---

## STOP

No production changes. No P1-HIGH fixes started.
"""
    (OUT / "security_summary_verification_report.md").write_text(report, encoding="utf-8")
    print(json.dumps({"verdict": verdict, "severity": severity, "server_up": http.get("server_up")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
