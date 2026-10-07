"""
Auditoría UCE + ASPE — verifica integración con motores reales de NOVUS.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_audit(email=None):
    from services.universal_compatibility_engine import uce
    from services.adaptive_sector_protection_engine import aspe, CONFIDENCE_MATRIX, PROTECTION_MODULES
    from services.sector_shield_service import resolve_sector_for_user

    sector = resolve_sector_for_user(email)
    infra = uce.detect_infrastructure(email, persist=True)
    init = aspe.initialize_sector_protection(email)
    panel = aspe.get_sector_protection_panel(email)
    audit = aspe.generate_audit_report(email)

    tests = {
        "uce_detects_os": bool((infra.get("categories") or {}).get("sistema_operativo", {}).get("detected")),
        "aspe_initializes": init.get("status") == "success",
        "aspe_has_active_modules": len(panel.get("protecciones_activas") or []) > 0,
        "aspe_has_standby": len(panel.get("protecciones_standby") or []) > 0,
        "sector_resolved": panel.get("sector_key") == sector,
        "confidence_matrix_defined": len(CONFIDENCE_MATRIX) >= 5,
        "protection_modules_real": len(PROTECTION_MODULES) >= 10,
    }

    # Simular evaluación con hallazgo credential stuffing (motores reales)
    finding = {
        "id": "AUDIT-CRED-STUFF-001",
        "tipo": "credential stuffing",
        "descripcion": "Intento de credential stuffing detectado en API login",
        "verified": True,
        "evidence": {"source": "audit_script"},
    }
    eval_result = aspe.evaluate_incident(finding, user_email=email, source="audit_script")
    tests["aspe_evaluates_incident"] = eval_result.get("status") in ("success", "no_action")
    tests["threat_classified"] = eval_result.get("threat_type") == "credential_stuffing"

    passed = sum(1 for v in tests.values() if v)
    report = {
        "status": "success" if passed == len(tests) else "partial",
        "tests_passed": passed,
        "tests_total": len(tests),
        "tests": tests,
        "sector": sector,
        "uce": {
            "technologies": infra.get("technologies"),
            "count": infra.get("technologies_count"),
        },
        "aspe_panel": {
            "activas": len(panel.get("protecciones_activas") or []),
            "standby": len(panel.get("protecciones_standby") or []),
            "dinamicas": len(panel.get("protecciones_dinamicas") or []),
        },
        "audit": audit,
        "eval_sample": {
            "threat_type": eval_result.get("threat_type"),
            "dynamic_activated": len(eval_result.get("dynamic_activated") or []),
        },
    }

    out_path = os.path.join(os.path.dirname(__file__), "uce_aspe_audit_results.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report


if __name__ == "__main__":
    email = sys.argv[1] if len(sys.argv) > 1 else None
    run_audit(email)
