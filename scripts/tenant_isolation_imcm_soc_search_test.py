#!/usr/bin/env python3
"""Verificación aislamiento IMCM, SOC y búsqueda global (capa servicio)."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "data" / "novus_compliance_audit"
RUN = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
MA = f"TEST-A-{RUN}"
MB = f"TEST-B-{RUN}"


def _ensure_client_tenant(db, label: str) -> tuple:
    """Tenant CLIENT de prueba — no usa IDs QA bloqueados en runtime cliente."""
    import uuid
    from werkzeug.security import generate_password_hash
    from database import Usuario

    tenant_id = f"CLIENT-ISO-{label}-{uuid.uuid4().hex[:6].upper()}"
    email = f"iso.{label.lower()}.{tenant_id.lower()}@novus-client.test"
    user = db.query(Usuario).filter(Usuario.email == email).first()
    if not user:
        user = Usuario(
            email=email,
            hashed_password=generate_password_hash("NovusIso2026!"),
            is_active=True,
            nit_pyme=tenant_id,
            sector="fintech",
            role="admin",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user, tenant_id


def main():
    from database import SessionLocal, Usuario
    from services.tenant_scope_service import resolve_tenant_id
    from services.imcm.engine import create_incident, get_incident, search_incidents
    from services.imcm.store import save_incident, load_incidents
    from services.soc.store import save_hunt, load_hunts
    from services.soc.hunting import hunt
    from services.global_search_index import search_dynamic, global_search

    db = SessionLocal()
    ua, ta = _ensure_client_tenant(db, "A")
    ub, tb = _ensure_client_tenant(db, "B")
    db.close()

    inc_a = {
        "id": MA,
        "tenant_id": ta,
        "title": f"Isolation test A {MA}",
        "threat_type": "test_isolation",
        "source_engine": "tenant_test",
        "severity": "BAJO",
        "estado": "nuevo",
        "evidence": {"marker": MA, "tenant_id": ta},
    }
    inc_b = {
        "id": MB,
        "tenant_id": tb,
        "title": f"Isolation test B {MB}",
        "threat_type": "test_isolation",
        "source_engine": "tenant_test",
        "severity": "BAJO",
        "estado": "nuevo",
        "evidence": {"marker": MB, "tenant_id": tb},
    }
    save_incident(inc_a, tenant_id=ta)
    save_incident(inc_b, tenant_id=tb)
    save_hunt({"query": MA, "category": "test", "count": 1, "marker": MA}, tenant_id=ta)
    save_hunt({"query": MB, "category": "test", "count": 1, "marker": MB}, tenant_id=tb)

    tests = []

    def chk(name, ok, detail=None):
        tests.append({"test": name, "verdict": "VERIFIED" if ok else "FAIL", "detail": detail})

    ids_a = {i.get("id") for i in load_incidents(tenant_id=ta, limit=500)}
    ids_b = {i.get("id") for i in load_incidents(tenant_id=tb, limit=500)}
    chk("IMCM A load no B", MA in ids_a and MB not in ids_a)
    chk("IMCM B load no A", MB in ids_b and MA not in ids_b)
    chk("IMCM A get B blocked", get_incident(MB, tenant_id=ta) is None)
    chk("IMCM B get A blocked", get_incident(MA, tenant_id=tb) is None)

    sa = search_incidents(keyword=MA, limit=50, tenant_id=ta)
    sb = search_incidents(keyword=MB, limit=50, tenant_id=tb)
    chk("IMCM search A scoped", any(i.get("id") == MA for i in sa) and not any(i.get("id") == MB for i in sa))
    chk("IMCM search B scoped", any(i.get("id") == MB for i in sb) and not any(i.get("id") == MA for i in sb))

    ha = load_hunts(tenant_id=ta, limit=50)
    hb = load_hunts(tenant_id=tb, limit=50)
    chk("SOC hunts A no B", not any(h.get("marker") == MB for h in ha))
    chk("SOC hunts B no A", not any(h.get("marker") == MA for h in hb))

    hunt_a = hunt(MA, "test", limit=10, tenant_id=ta)
    hunt_b = hunt(MB, "test", limit=10, tenant_id=tb)
    chk("SOC hunt A no B marker", MB not in json.dumps(hunt_a))
    chk("SOC hunt B no A marker", MA not in json.dumps(hunt_b))

    dyn_a = search_dynamic(MA, limit=50, tenant_id=ta)
    dyn_b = search_dynamic(MB, limit=50, tenant_id=tb)
    dyn_a_ids = {r.get("id") for r in dyn_a}
    dyn_b_ids = {r.get("id") for r in dyn_b}
    chk("search_dynamic A finds own IMCM", f"imcm-{MA}" in dyn_a_ids or MA in json.dumps(dyn_a))
    chk("search_dynamic A no B IMCM", f"imcm-{MB}" not in dyn_a_ids)
    chk("search_dynamic B finds own IMCM", f"imcm-{MB}" in dyn_b_ids or MB in json.dumps(dyn_b))
    chk("search_dynamic B no A IMCM", f"imcm-{MA}" not in dyn_b_ids)

    chk("search_dynamic empty without tenant", search_dynamic("test", tenant_id=None) == [])
    chk("global_search empty without tenant", global_search("test", tenant_id=None) == [])

    gs_a = global_search(MA, limit=30, tenant_id=ta)
    gs_b = global_search(MB, limit=30, tenant_id=tb)
    chk("global_search A no B marker", MB not in json.dumps(gs_a))
    chk("global_search B no A marker", MA not in json.dumps(gs_b))

    overall = "VERIFIED" if all(t["verdict"] == "VERIFIED" for t in tests) else "FAIL"
    report = {
        "run_id": RUN,
        "tenant_a": ta,
        "tenant_b": tb,
        "fixtures": [MA, MB],
        "tests": tests,
        "overall": overall,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    out_path = OUT / f"TENANT_ISOLATION_IMCM_SOC_SEARCH_{RUN}.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if overall == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
