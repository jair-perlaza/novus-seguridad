#!/usr/bin/env python3
"""Verifica arquitectura de datos empresarial NOVUS."""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> int:
    fails = []
    print("=== verify_enterprise_data_architecture ===")

    from core.enterprise_databases.bootstrap import initialize_enterprise_databases

    init = initialize_enterprise_databases()
    for domain, status in (init.get("domains") or {}).items():
        if status != "ok":
            fails.append(f"init:{domain}")
        else:
            print("domain ok", domain)

    from core.enterprise_databases.paths import DOMAIN_LABELS

    for key, (_, path) in DOMAIN_LABELS.items():
        if not os.path.isfile(path):
            fails.append(f"missing_file:{key}")

    from services.enterprise_data_service import (
        get_architecture_status,
        record_audit_domain,
        record_security_event_domain,
    )

    record_audit_domain(action="verify_enterprise_architecture", outcome="test", detail={"verified": True})
    eid = record_security_event_domain(
        event_type="network_alert",
        tenant_id="verify-tenant",
        motor="verify_script",
        evidence={"verified": True, "test": True},
        legacy_ref="verify-enterprise-once",
    )
    if not eid:
        fails.append("security_event_write")

    st = get_architecture_status()
    if not st.get("domains"):
        fails.append("architecture_status")

    try:
        from core.app import create_app

        app = create_app("development")
        rules = {r.rule for r in app.url_map.iter_rules()}
        for route in (
            "/api/enterprise/architecture/status",
            "/api/enterprise/study-cases",
            "/centro-casos-estudio-novus",
        ):
            if route not in rules:
                fails.append(f"route:{route}")
    except Exception as exc:
        fails.append(f"app:{exc}")

    from services.rbac_service import MODULE_ACCESS, ROLE_NOVUS_CREATOR

    if ROLE_NOVUS_CREATOR not in MODULE_ACCESS.get("centro_casos_estudio_novus", ()):
        fails.append("rbac_creator_module")

    if fails:
        print("FAIL", fails)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
