"""
Prueba integración Swarm Defense Engine — solo evidencia verificable.
Evita escaneos pesados; colaboradores son solo lectura.
"""
from __future__ import annotations

import sys
import traceback

sys.path.insert(0, r"C:\NOVUS")


def main() -> int:
    errors = []
    print("=== Swarm Defense Engine integration ===")

    try:
        from services.swarm_defense import swarm_defense_engine

        st = swarm_defense_engine.status()
        assert st["ok"] and st["replaces_existing_engines"] is False
        assert len(st["collaborators"]) >= 8
        print("OK status collaborators=", len(st["collaborators"]))
    except Exception:
        errors.append("status")
        traceback.print_exc()

    try:
        event = {
            "motor": "integration_test_ndr",
            "action": "port_scan_detected",
            "phase": "detect",
            "outcome": "detected",
            "threat_type": "port_scan",
            "finding_id": "TEST-SWARM-001",
            "detail": "Integration test event ip=127.0.0.1",
            "evidence": {
                "verified": True,
                "ip": "127.0.0.1",
                "severity": "medium",
                "source": "verify_swarm_defense_engine",
            },
            "user_email": "test@novus.local",
        }
        corr = swarm_defense_engine.process_event(event)
        assert corr is not None
        if corr.get("deduplicated"):
            event["finding_id"] = "TEST-SWARM-002"
            corr = swarm_defense_engine.process_event(event)
        assert "confidence" in corr
        assert "contributions" in corr
        assert corr.get("policy") == "real_evidence_only"
        print(
            "OK correlation confidence=",
            (corr.get("confidence") or {}).get("level"),
            "modules=",
            (corr.get("classification") or {}).get("supporting_modules"),
        )
        for c in corr.get("contributions") or []:
            if c.get("found"):
                assert c.get("sources") or c.get("facts"), c
        print("OK no fabricated contributions without sources/facts")
    except Exception:
        errors.append("process")
        traceback.print_exc()

    try:
        from services.swarm_defense.engine import _in_swarm, _enter_swarm, _leave_swarm
        from services.swarm_defense import notify_detection

        _enter_swarm()
        try:
            assert notify_detection({"motor": "x", "evidence": {"verified": True}}) is None
            print("OK reentrancy guard")
        finally:
            _leave_swarm()
        assert not _in_swarm()
    except Exception:
        errors.append("reentrancy")
        traceback.print_exc()

    try:
        from services.defense_coordinator import record_detection

        r = record_detection(
            motor="integration_test_hook",
            action="swarm_hook_check",
            evidence={"verified": True, "ip": "127.0.0.1", "note": "hook test"},
            phase="detect",
            outcome="detected",
            threat_type="test_hook",
            finding_id="TEST-SWARM-HOOK-3",
            detail="defense_coordinator swarm hook",
        )
        print("OK defense_coordinator hook status=", r.get("status") if isinstance(r, dict) else r)
    except Exception:
        errors.append("hook")
        traceback.print_exc()

    try:
        reply = swarm_defense_engine.answer_kernel_query("estado del swarm defense engine")
        assert reply and "Swarm Defense Engine" in reply
        print("OK kernel query hook")
    except Exception:
        errors.append("kernel")
        traceback.print_exc()

    try:
        res = swarm_defense_engine.execute_action(
            "block_ip",
            correlation={
                "indicators": {"ips": ["127.0.0.1"]},
                "confidence": {"level": "high"},
                "contributions": [],
                "classification": {},
            },
            origin_event={"motor": "test", "action": "test"},
            confirmed=False,
            reason="integration",
        )
        assert res.get("status") == "needs_approval"
        print("OK approval gate for block_ip")
    except Exception:
        errors.append("approval")
        traceback.print_exc()

    try:
        from services.ai_capability_registry import capability_registry

        assert "security.threats" in capability_registry.CAPABILITY_CATALOG
        print("OK legacy engines intact")
    except Exception:
        errors.append("legacy")
        traceback.print_exc()

    if errors:
        print("FAILED:", errors)
        return 1
    print("ALL SWARM INTEGRATION CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
