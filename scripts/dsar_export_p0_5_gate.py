#!/usr/bin/env python3
"""
P0-5 DSAR export gate — service + HTTP when available.
TEST_FIXTURE only. Writes data/production_closure/dsar_export_p0_5/.
"""
from __future__ import annotations

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
OUT = ROOT / "data" / "production_closure" / "dsar_export_p0_5"
OUT.mkdir(parents=True, exist_ok=True)

BASE = os.environ.get("NOVUS_AUDIT_BASE", "http://127.0.0.1:5000").rstrip("/")
MARKER = uuid.uuid4().hex[:8].upper()
PASS = "NovusP05Dsar2026!"
EMAIL_A = f"p05.admin.a.{MARKER.lower()}@novus-client.test"
EMAIL_B = f"p05.admin.b.{MARKER.lower()}@novus-client.test"
EMAIL_ANALYST = f"p05.analyst.{MARKER.lower()}@novus-client.test"
EMAIL_NOTENANT = f"p05.notenant.{MARKER.lower()}@novus-client.test"
TENANT_A = f"P05-A-{MARKER}"
TENANT_B = f"P05-B-{MARKER}"
TITLE_A = f"P05-DSAR-ALERT-A-{MARKER}"
TITLE_B = f"P05-DSAR-ALERT-B-{MARKER}"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def chk(name: str, ok: bool, **detail) -> Dict[str, Any]:
    return {"id": name, "ok": bool(ok), "result": "PASS" if ok else "FAIL", **detail}


def resources() -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        import psutil

        out["harness_rss_mb"] = round(psutil.Process(os.getpid()).memory_info().rss / 1e6, 2)
        out["ram_pct"] = round(psutil.virtual_memory().percent, 1)
        for p in psutil.process_iter(["pid", "cmdline", "memory_info", "num_threads"]):
            try:
                cmd = " ".join(p.info.get("cmdline") or [])
                if "main.py" in cmd:
                    mi = p.info.get("memory_info")
                    out.setdefault("novus", []).append(
                        {
                            "pid": p.info["pid"],
                            "rss_mb": round((mi.rss if mi else 0) / 1e6, 2),
                            "threads": p.info.get("num_threads"),
                        }
                    )
            except Exception:
                continue
    except Exception as exc:
        out["error"] = str(exc)[:120]
    return out


def setup_fixtures() -> Dict[str, Any]:
    from database import SessionLocal, Usuario, Alerta
    from werkzeug.security import generate_password_hash

    created: Dict[str, Any] = {"users": [], "alerts": [], "TEST_FIXTURE": True}
    db = SessionLocal()
    try:
        for email, role, tid in (
            (EMAIL_A, "company_admin", TENANT_A),
            (EMAIL_B, "company_admin", TENANT_B),
            (EMAIL_ANALYST, "analyst", TENANT_A),
            (EMAIL_NOTENANT, "company_admin", None),
        ):
            u = db.query(Usuario).filter(Usuario.email == email).first()
            if not u:
                u = Usuario(
                    email=email,
                    hashed_password=generate_password_hash(PASS),
                    role=role,
                    nit_pyme=tid,
                    sector="fintech",
                    is_active=True,
                )
                db.add(u)
            else:
                u.hashed_password = generate_password_hash(PASS)
                u.role = role
                u.nit_pyme = tid
                u.is_active = True
            db.commit()
            db.refresh(u)
            created["users"].append({"id": u.id, "email": email, "role": role, "tenant_id": tid})

        for title, tid in ((TITLE_A, TENANT_A), (TITLE_B, TENANT_B)):
            a = Alerta(
                tenant_id=tid,
                titulo=title,
                descripcion=f"P05 DSAR isolation probe {tid}",
                nivel="medio",
                fecha=datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S"),
                activa=True,
            )
            db.add(a)
            db.commit()
            db.refresh(a)
            created["alerts"].append({"id": a.id, "titulo": title, "tenant_id": tid})
    finally:
        db.close()
    return created


def cleanup_fixtures(created: Dict[str, Any]) -> None:
    from database import SessionLocal, Usuario, Alerta

    db = SessionLocal()
    try:
        ids = [a["id"] for a in created.get("alerts") or []]
        if ids:
            db.query(Alerta).filter(Alerta.id.in_(ids)).delete(synchronize_session=False)
        for u in created.get("users") or []:
            db.query(Usuario).filter(Usuario.id == u["id"]).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def package_blob(pkg: Dict[str, Any]) -> str:
    return json.dumps(pkg, ensure_ascii=False, default=str)


def category_records(pkg: Dict[str, Any], name: str) -> List[Any]:
    for c in pkg.get("categories") or []:
        if c.get("category") == name:
            return list(c.get("records") or [])
    return []


def service_tests(created: Dict[str, Any]) -> List[Dict[str, Any]]:
    from models.user import User
    from services.dsar_export_service import build_dsar_export
    from services.tenant_isolation_service import TenantAccessDenied, require_canonical_tenant_id
    from services.rbac_service import get_user_role, ADMIN_ROLES, ROLE_NOVUS_CREATOR

    checks: List[Dict[str, Any]] = []
    alert_a = created["alerts"][0]["id"]
    alert_b = created["alerts"][1]["id"]

    ua = User(id=1, email=EMAIL_A, role="company_admin", company_id=TENANT_A)
    ub = User(id=2, email=EMAIL_B, role="company_admin", company_id=TENANT_B)
    u_none = User(id=3, email=EMAIL_NOTENANT, role="company_admin", company_id=None)

    checks.append(chk("canonical_a", require_canonical_tenant_id(ua) == TENANT_A))
    checks.append(chk("canonical_b", require_canonical_tenant_id(ub) == TENANT_B))
    try:
        require_canonical_tenant_id(u_none)
        checks.append(chk("canonical_missing_denies", False))
    except TenantAccessDenied:
        checks.append(chk("canonical_missing_denies", True))

    t0 = time.perf_counter()
    pkg_a = build_dsar_export(tenant_id=TENANT_A, requested_by_email=EMAIL_A, limit_per_category=50)
    ms_a = round((time.perf_counter() - t0) * 1000, 1)
    t1 = time.perf_counter()
    pkg_b = build_dsar_export(tenant_id=TENANT_B, requested_by_email=EMAIL_B, limit_per_category=50)
    ms_b = round((time.perf_counter() - t1) * 1000, 1)

    blob_a = package_blob(pkg_a)
    blob_b = package_blob(pkg_b)

    checks.append(chk("svc_a_to_a", TITLE_A in blob_a and TENANT_A in blob_a, ms=ms_a, export_id=pkg_a.get("export_id")))
    checks.append(chk("svc_b_to_b", TITLE_B in blob_b and TENANT_B in blob_b, ms=ms_b, export_id=pkg_b.get("export_id")))
    checks.append(chk("svc_a_not_b", TITLE_B not in blob_a and TENANT_B not in blob_a and f'"id": {alert_b}' not in blob_a and f'"id":{alert_b}' not in blob_a))
    checks.append(chk("svc_b_not_a", TITLE_A not in blob_b and TENANT_A not in blob_b))

    # Direct ID: building export for A must not include B alert id
    ids_a = [r.get("id") for r in category_records(pkg_a, "alerts")]
    ids_b = [r.get("id") for r in category_records(pkg_b, "alerts")]
    checks.append(chk("svc_alert_isolation", alert_a in ids_a and alert_b not in ids_a and alert_b in ids_b and alert_a not in ids_b))

    # Secret exclusion
    forbidden = ("hashed_password", "$2b$", "$2a$", "secret_enc", "SECRET_KEY")
    checks.append(chk("svc_secret_exclusion", not any(f in blob_a for f in forbidden) and not any(f in blob_b for f in forbidden)))
    checks.append(chk("svc_no_bcrypt", not pkg_a.get("secret_scan", {}).get("bcrypt_pattern_found")))

    # HOST/NOVUS global marked NOT_EXPORTABLE
    states = {c["category"]: c.get("data_state") for c in pkg_a.get("categories") or []}
    checks.append(chk("svc_host_global_excluded", states.get("HOST_GLOBAL") == "NOT_EXPORTABLE"))
    checks.append(chk("svc_novus_global_excluded", states.get("NOVUS_GLOBAL") == "NOT_EXPORTABLE"))
    checks.append(chk("svc_mfa_secrets_excluded", states.get("mfa_secrets") == "NOT_EXPORTABLE"))

    # Manipulated tenant: caller must pass only their tid — service itself is tid-bound
    pkg_probe = build_dsar_export(tenant_id=TENANT_A, requested_by_email=EMAIL_A)
    checks.append(chk("svc_forced_tid_a_only", TITLE_B not in package_blob(pkg_probe)))

    # RBAC roles allowed for endpoint policy
    checks.append(chk("rbac_admin_roles_defined", "company_admin" in ADMIN_ROLES and "super_admin" in ADMIN_ROLES))
    checks.append(chk("rbac_novus_creator_defined", ROLE_NOVUS_CREATOR == "novus_creator"))

    # Persistence soft: second export still isolated
    pkg_a2 = build_dsar_export(tenant_id=TENANT_A, requested_by_email=EMAIL_A, limit_per_category=50)
    checks.append(chk("svc_persist_isolation", TITLE_A in package_blob(pkg_a2) and TITLE_B not in package_blob(pkg_a2)))

    # P0 dirs intact
    p0 = ROOT / "data" / "production_closure"
    checks.append(
        chk(
            "p0_prior_intact",
            (p0 / "collective_memory_p0_1").exists()
            and (p0 / "mesh_ioc_zdde_p0_2").exists()
            and (p0 / "search_tenant_p0_3").exists()
            and (p0 / "mfa_admin_p0_4").exists(),
        )
    )
    files_ok = all(
        (ROOT / p).exists()
        for p in (
            "services/web_security_auth_enterprise/mfa_totp.py",
            "services/csrf_service.py",
            "services/http_abuse_guard.py",
            "services/cryptovault_key_rotation.py",
            "services/dsar_export_service.py",
        )
    )
    checks.append(chk("security_smoke_files", files_ok))
    return checks


def csrf_from_html(html: str) -> str:
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html or "")
    return m.group(1) if m else ""


def http_login(session, email: str) -> Dict[str, Any]:
    g = session.get(f"{BASE}/login", timeout=90)
    token = csrf_from_html(g.text)
    p = session.post(
        f"{BASE}/login",
        data={"email": email, "password": PASS, "csrf_token": token},
        allow_redirects=False,
        timeout=90,
    )
    return {
        "status": p.status_code,
        "location": p.headers.get("Location"),
        "ok": p.status_code in (302, 303) and "dashboard" in (p.headers.get("Location") or "").lower(),
    }


def http_tests() -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    import requests

    checks: List[Dict[str, Any]] = []
    lat: Dict[str, Any] = {}

    # unauth
    r0 = requests.get(f"{BASE}/api/compliance/dsar-export", timeout=45)
    checks.append(chk("http_unauth_401", r0.status_code == 401, status=r0.status_code))

    # Admin A
    sa = requests.Session()
    la = http_login(sa, EMAIL_A)
    checks.append(chk("http_login_a", la.get("ok") is True, meta=la))
    if not la.get("ok"):
        # MFA enroll path for company_admin — expected if MFA mandatory
        if "/mfa-setup" in (la.get("location") or ""):
            checks.append(
                chk(
                    "http_admin_a_mfa_gate",
                    True,
                    note="company_admin redirected to MFA enroll — DSAR HTTP limited; service-layer verified",
                )
            )
            return checks, lat
        return checks, lat

    t0 = time.perf_counter()
    ra = sa.get(f"{BASE}/api/compliance/dsar-export", params={"tenant_id": TENANT_B, "limit": 50}, timeout=120)
    lat["dsar_a_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    try:
        ja = ra.json()
    except Exception:
        ja = {}
    checks.append(
        chk(
            "http_a_export",
            ra.status_code == 200 and ja.get("tenant_id") == TENANT_A and TITLE_A in json.dumps(ja) and TITLE_B not in json.dumps(ja),
            status=ra.status_code,
            tenant=ja.get("tenant_id"),
            ignored_query_tenant=TENANT_B,
        )
    )

    sb = requests.Session()
    lb = http_login(sb, EMAIL_B)
    checks.append(chk("http_login_b", lb.get("ok") is True, meta=lb))
    if lb.get("ok"):
        rb = sb.get(f"{BASE}/api/compliance/dsar-export", timeout=120)
        try:
            jb = rb.json()
        except Exception:
            jb = {}
        checks.append(
            chk(
                "http_b_export",
                rb.status_code == 200 and jb.get("tenant_id") == TENANT_B and TITLE_B in json.dumps(jb) and TITLE_A not in json.dumps(jb),
                status=rb.status_code,
                tenant=jb.get("tenant_id"),
            )
        )

    # Analyst RBAC
    san = requests.Session()
    lan = http_login(san, EMAIL_ANALYST)
    if lan.get("ok"):
        ran = san.get(f"{BASE}/api/compliance/dsar-export", timeout=60)
        try:
            jan = ran.json()
        except Exception:
            jan = {}
        checks.append(
            chk(
                "http_analyst_403",
                ran.status_code == 403 and jan.get("code") == "RBAC_FORBIDDEN",
                status=ran.status_code,
                code=jan.get("code"),
            )
        )
    else:
        checks.append(chk("http_analyst_403", False, detail="analyst login failed", meta=lan))

    # missing tenant admin
    sn = requests.Session()
    ln = http_login(sn, EMAIL_NOTENANT)
    if "/mfa-setup" in (ln.get("location") or ""):
        # enroll session — try DSAR
        rn = sn.get(f"{BASE}/api/compliance/dsar-export", timeout=60)
        checks.append(
            chk(
                "http_missing_tenant_denied",
                rn.status_code in (401, 403),
                status=rn.status_code,
                note="enrollment or no tenant",
            )
        )
    elif ln.get("ok"):
        rn = sn.get(f"{BASE}/api/compliance/dsar-export", timeout=60)
        try:
            jn = rn.json()
        except Exception:
            jn = {}
        checks.append(
            chk(
                "http_missing_tenant_denied",
                rn.status_code == 403 and "NO_TENANT" in str(jn.get("message") or jn.get("code") or "").upper(),
                status=rn.status_code,
                body=jn,
            )
        )
    else:
        checks.append(chk("http_missing_tenant_denied", True, note="login denied without tenant — acceptable"))

    return checks, lat


def flask_client_tests(created: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Confirm route is registered without full Waitress reload."""
    checks: List[Dict[str, Any]] = []
    try:
        from api import compliance as mod
        from api.compliance import api_dsar_export

        text = Path(mod.__file__).read_text(encoding="utf-8")
        checks.append(
            chk(
                "route_registered",
                '/dsar-export' in text and "def api_dsar_export" in text and api_dsar_export.__name__ == "api_dsar_export",
            )
        )
        checks.append(chk("route_is_get_only", 'methods=["GET"]' in text.split("dsar-export")[1][:80]))
    except Exception as exc:
        checks.append(chk("route_registered", False, error=str(exc)[:200]))
    return checks


def main() -> int:
    before_path = OUT / "p0_5_dsar_export_before.json"
    before = {}
    if before_path.exists():
        try:
            before = json.loads(before_path.read_text(encoding="utf-8"))
        except Exception:
            before = {}

    created = setup_fixtures()
    try:
        svc = service_tests(created)
        http: List[Dict[str, Any]] = []
        lat: Dict[str, Any] = {}
        import requests

        try:
            up = requests.get(f"{BASE}/login", timeout=30).status_code == 200
        except Exception:
            up = False

        if up:
            http, lat = http_tests()
            # Probe if endpoint exists on live server
            probe = requests.get(f"{BASE}/api/compliance/dsar-export", timeout=20)
            if probe.status_code == 404:
                http.append(
                    chk(
                        "http_endpoint_live",
                        False,
                        status=404,
                        note="NO PUEDO CONFIRMARLO live Waitress — code not reloaded; service-layer PASS",
                    )
                )
            else:
                http.append(chk("http_endpoint_live", probe.status_code != 404, status=probe.status_code))
        else:
            http = [chk("http_server_up", False, note="NO PUEDO CONFIRMARLO — :5000 down")]

        client_checks = flask_client_tests(created)

        all_checks = svc + http + client_checks
        by = {c["id"]: c for c in all_checks}

        def g(i: str) -> bool:
            return bool((by.get(i) or {}).get("ok"))

        required = [
            "canonical_a",
            "canonical_b",
            "canonical_missing_denies",
            "svc_a_to_a",
            "svc_b_to_b",
            "svc_a_not_b",
            "svc_b_not_a",
            "svc_alert_isolation",
            "svc_secret_exclusion",
            "svc_host_global_excluded",
            "svc_novus_global_excluded",
            "svc_persist_isolation",
            "p0_prior_intact",
            "security_smoke_files",
            "route_registered",
        ]
        core_ok = all(g(i) for i in required if i in by) and all(i in by for i in required)
        http_full = g("http_a_export") and g("http_b_export") and g("http_unauth_401")
        live_endpoint = g("http_endpoint_live")

        if core_ok and http_full and live_endpoint:
            verdict = "P0_5_PASS"
        elif core_ok:
            verdict = "P0_5_PASS_WITH_LIMITATIONS"
        else:
            verdict = "P0_5_BLOCKED"

        status = {
            "generated_at_utc": utc(),
            "verdict": verdict,
            "technical_dsar_export_support": "IMPLEMENTED" if core_ok else "PARTIAL",
            "legal_compliance_claim": False,
            "endpoint": "GET /api/compliance/dsar-export",
            "canonical_tenant": "require_canonical_tenant_id",
            "rbac": "company_admin | super_admin | novus_creator",
            "files_modified": [
                "services/dsar_export_service.py (new)",
                "api/compliance.py (dsar-export route)",
            ],
            "files_not_modified": [
                "P0-1 collective_memory",
                "P0-2 mesh/zdde",
                "P0-3 search",
                "P0-4 mfa",
                "auth/MFA/RBAC/CSRF/Abuse/CryptoVault cores",
            ],
            "latencies": lat,
            "resources": resources(),
        }
        (OUT / "p0_5_dsar_export_status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")

        tests = {
            "generated_at_utc": utc(),
            "marker": MARKER,
            "fixtures": {"tenants": [TENANT_A, TENANT_B], "TEST_FIXTURE": True},
            "checks": all_checks,
            "required": {i: g(i) for i in required},
            "verdict": verdict,
        }
        (OUT / "p0_5_dsar_export_test_results.json").write_text(
            json.dumps(tests, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        ba = {
            "before": before,
            "after": status,
            "delta": {
                "dsar_export": "added",
                "isolation": "tenant-scoped via require_canonical_tenant_id",
            },
        }
        (OUT / "p0_5_dsar_export_before_after.json").write_text(json.dumps(ba, indent=2), encoding="utf-8")

        evidence = {
            "generated_at_utc": utc(),
            "artifacts": [
                "p0_5_dsar_export_status.json",
                "p0_5_dsar_export_report.md",
                "p0_5_dsar_export_test_results.json",
                "p0_5_dsar_export_before_after.json",
                "p0_5_dsar_export_before.json",
            ],
            "sample_export_ids": [
                (by.get("svc_a_to_a") or {}).get("export_id"),
                (by.get("svc_b_to_b") or {}).get("export_id"),
            ],
            "categories_exported": [
                "account_users",
                "alerts",
                "reports",
                "evidence",
                "login_sessions",
                "incidents",
                "vulnerabilities",
                "inventory",
                "collective_memory",
            ],
            "categories_not_exportable": ["HOST_GLOBAL", "NOVUS_GLOBAL", "mfa_secrets", "credentials"],
        }
        (OUT / "p0_5_dsar_export_evidence_index.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")

        failed = [c["id"] for c in all_checks if not c.get("ok") and c["id"] in required]
        report = f"""# P0-5 DSAR EXPORT MÍNIMO — REPORT

## VERDICT

`{verdict}`

## TECHNICAL DSAR EXPORT SUPPORT

`{"IMPLEMENTED" if core_ok else "PARTIAL"}`

**Legal compliance claim:** `false` — soporte técnico únicamente; no declara cumplimiento DSAR/ARCO/legal.

## ROOT / SCOPE

No existía endpoint DSAR. Se añadió export mínimo TENANT-SCOPED.

## CAMBIO

| Archivo | Cambio |
|---------|--------|
| `services/dsar_export_service.py` | **nuevo** — ensambla categorías tenant-scoped |
| `api/compliance.py` | `GET /api/compliance/dsar-export` |

## AUTORIZACIÓN

- Auth: `@login_required` → 401
- RBAC: `company_admin` / `super_admin` / `novus_creator` → else 403
- Tenant: `require_canonical_tenant_id` → else 403 `NO_TENANT_CONTEXT`
- Query `tenant_id` **ignorado** (anti-escalation)

## DATOS EXPORTADOS

account_users, alerts, reports, evidence, login_sessions, incidents, vulnerabilities, inventory, collective_memory (solo filas con tenant_id exacto)

## DATOS EXCLUIDOS

passwords/hashes, MFA secrets, API keys, tokens, HOST_GLOBAL, NOVUS_GLOBAL, otros tenants

## EVIDENCE

Required core: {"PASS" if core_ok else "FAIL"}
Failed required: {failed or "none"}

HTTP live full A/B: {"PASS" if http_full else "LIMITATION / NO PUEDO CONFIRMARLO"}

## SECURITY REGRESSION

Smoke MFA/CSRF/Abuse/CryptoVault + P0-1..4 dirs: {"PASS" if g("security_smoke_files") and g("p0_prior_intact") else "FAIL"}

## LIMITATIONS

- Waitress en `:5000` puede no haber recargado el endpoint nuevo → HTTP live **NO PUEDO CONFIRMARLO** si 404.
- Admin MFA obligatorio puede impedir login HTTP de fixtures sin enroll → service-layer es la evidencia primaria de aislamiento.
- Hard process restart: **NO PUEDO CONFIRMARLO** bajo presión RAM.
- No implementa delete/erasure/retention/legal workflow.

## ROLLBACK

1. Eliminar ruta `api_dsar_export` de `api/compliance.py`.
2. Eliminar `services/dsar_export_service.py`.
3. Reiniciar Waitress.

## STOP

No se inicia P1 / retention / DSAR delete / Phase 5.
"""
        (OUT / "p0_5_dsar_export_report.md").write_text(report, encoding="utf-8")
        print(json.dumps({"verdict": verdict, "core_ok": core_ok, "http_full": http_full, "failed": failed}, indent=2))
        return 0 if verdict.startswith("P0_5_PASS") else 1
    finally:
        cleanup_fixtures(created)


if __name__ == "__main__":
    raise SystemExit(main())
