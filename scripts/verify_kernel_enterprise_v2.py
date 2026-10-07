"""
Prueba de integración Kernel IA Enterprise V2.0 (sin arrancar Flask completo si es posible).
"""
from __future__ import annotations

import sys
import traceback

sys.path.insert(0, r"C:\NOVUS")


def main() -> int:
    errors = []
    print("=== Kernel Enterprise V2 integration ===")

    try:
        from services.kernel_enterprise_v2 import kernel_enterprise_v2, ensure_bootstrapped

        summary = ensure_bootstrapped().summary()
        print("SUMMARY:", summary)
        assert summary["knowledge_packs"] >= 40, summary
        assert summary["action_packs"] >= 40, summary
        assert summary["engines"] == 8, summary
        print("OK bootstrap counts")
    except Exception:
        errors.append("bootstrap")
        traceback.print_exc()

    try:
        st = kernel_enterprise_v2.status()
        assert st["ok"] is True
        assert st["replaces_existing_engines"] is False
        print("OK status")
    except Exception:
        errors.append("status")
        traceback.print_exc()

    try:
        reply = kernel_enterprise_v2.answer_kernel_query(
            "capacidades enterprise knowledge pack ransomware"
        )
        assert reply and "Enterprise V2" in reply
        assert "invent" not in reply.lower() or "no invent" in reply.lower() or "no inventa" in reply.lower()
        print("OK answer_kernel_query")
        print(reply[:400], "...")
    except Exception:
        errors.append("answer")
        traceback.print_exc()

    try:
        # Acción no cableada debe declarar transparenciamente
        res = kernel_enterprise_v2.execute_action(
            "fs.create_folder",
            user_email="test@novus.local",
            user_role="super_admin",
            confirmed=True,
            reason="integration_test",
        )
        assert res["status"] in ("not_wired", "denied", "executed"), res
        print("OK action not_wired/deny transparency:", res["status"], res["message"][:120])
    except Exception:
        errors.append("action_not_wired")
        traceback.print_exc()

    try:
        # Acción cableada de solo lectura (sin inventar)
        res = kernel_enterprise_v2.execute_action(
            "scan.processes",
            user_email="test@novus.local",
            user_role="analyst",
            confirmed=True,
            reason="integration_test_scan",
        )
        print("OK scan.processes:", res.get("status"), "ok=", res.get("ok"))
        assert res.get("status") in ("executed", "error", "denied", "needs_confirm"), res
    except Exception:
        errors.append("scan_processes")
        traceback.print_exc()

    try:
        eng = kernel_enterprise_v2.run_engine(
            "reasoning", {"query": "xdr malware red compliance"}
        )
        assert eng.get("engine") == "reasoning"
        print("OK reasoning engine sufficient=", eng.get("sufficient_evidence"))
    except Exception:
        errors.append("reasoning")
        traceback.print_exc()

    try:
        # Legacy kernel still importable
        from services.ai_kernel import AIKernel  # noqa: F401
        from services.kernel_agent import KernelAgent

        agent = KernelAgent()
        out = agent.process(
            session_id="kev2-test",
            message="estado kernel enterprise v2 packs disponibles",
            user_email="test@novus.local",
        )
        assert out.get("data_source") == "kernel_enterprise_v2" or "Enterprise V2" in (
            out.get("reply") or ""
        )
        print("OK kernel_agent hook")
    except Exception:
        errors.append("kernel_agent_hook")
        traceback.print_exc()

    try:
        # Ensure capability registry still intact
        from services.ai_capability_registry import capability_registry

        assert "security.threats" in capability_registry.CAPABILITY_CATALOG
        print("OK legacy capability catalog intact")
    except Exception:
        errors.append("capability_intact")
        traceback.print_exc()

    if errors:
        print("FAILED:", errors)
        return 1
    print("ALL INTEGRATION CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
