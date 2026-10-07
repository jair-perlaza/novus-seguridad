"""Auditoría fortalecimiento defensa NOVUS — motores, ASPE, ADE, NDR, UCE."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Base, engine
Base.metadata.create_all(bind=engine)

RESULTS = {"tests": [], "mechanisms": [], "strengthened": [], "limitations": []}


def check(name, fn):
    try:
        ok = bool(fn())
        RESULTS["tests"].append({"name": name, "pass": ok})
        print(f"[{'OK' if ok else 'FAIL'}] {name}")
        return ok
    except Exception as exc:
        RESULTS["tests"].append({"name": name, "pass": False, "error": str(exc)})
        print(f"[FAIL] {name}: {exc}")
        return False


def main():
    from main import app
    from services.adaptive_sector_protection_engine import (
        aspe, classify_threat_type, EVIDENCE_MIN_FOR_DYNAMIC, _evidence_factor,
    )
    from services.adaptive_defense_engine import adaptive_defense, _has_critical_evidence
    from services.novus_security_integration import novus_security
    from services.universal_compatibility_engine import uce
    from services.network_ndr_service import analyze_behavior, build_ndr_payload
    from services.sector_shield_service import normalize_sector

    client = app.test_client()
    client.post(
        "/login",
        data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!"},
        follow_redirects=True,
    )

    MECHS = [
        "novus_security_integration", "advanced_detector_service", "security_engine",
        "adaptive_defense_engine", "adaptive_sector_protection_engine",
        "universal_compatibility_engine", "sector_shield_service",
        "network_ndr_service", "vulnerability_analyst_service", "ai_kernel",
    ]
    RESULTS["mechanisms"] = MECHS

    check("normalize_sector default otros", lambda: normalize_sector(None) == "otros")
    check("ASPE evidence min threshold", lambda: EVIDENCE_MIN_FOR_DYNAMIC >= 0.70)
    check("classify motor network_ndr", lambda: classify_threat_type({"motor": "network_ndr"}) == "iot_anomaly")
    check("evidence factor with evidencia", lambda: _evidence_factor({"evidencia": {"x": 1}}) >= 0.60)
    check("ADE no critico sin evidencia", lambda: not _has_critical_evidence({"riesgo": "CRITICO"}))

    threats = novus_security.detect_threats_realtime(force=True)
    check("security realtime scan", lambda: isinstance(threats, dict))
    vulns = novus_security.scan_vulnerabilities()
    check("vulnerability scan", lambda: isinstance(vulns, list))

    init = aspe.initialize_sector_protection("novus.qa.jul2026@example.com")
    check("ASPE init", lambda: init.get("status") == "success")

    if vulns:
        ev = aspe.evaluate_incident(vulns[0], user_email="novus.qa.jul2026@example.com", source="audit")
        check("ASPE evaluate incident", lambda: ev.get("status") in ("success", "ok", None) or "threat_type" in ev)

    infra = uce.detect_infrastructure(user_email="novus.qa.jul2026@example.com", persist=False)
    check("UCE infrastructure", lambda: infra.get("status") == "success")

    panel = adaptive_defense.get_adaptive_defense_panel()
    check("Adaptive Defense panel", lambda: isinstance(panel, dict))

    from services.sector_shield_service import scan_sector
    scan = scan_sector("novus.qa.jul2026@example.com")
    check("sector shield scan", lambda: scan.get("status") == "success")

    payload = build_ndr_payload(force_refresh=False)
    nodes = payload.get("nodes") or []
    alerts = analyze_behavior(nodes, payload.get("meta") or {})
    check("NDR behavior analysis", lambda: isinstance(alerts, list))

    r = client.get("/api/ai/status")
    check("Kernel IA status API", lambda: r.status_code == 200)

    STRENGTHENED = [
        "ASPE: evidencia real en invocación de módulos sectoriales",
        "ASPE: umbral evidencia 70% para activación dinámica cross-sector",
        "ASPE: clasificación por motor antes de keywords",
        "Runtime threats → ASPE evaluate_incident",
        "NDR alertas riesgo/crítico → ASPE",
        "NDR: downgrade IP change DHCP (mismo vendor)",
        "Adaptive Defense: notificación Kernel IA en acciones",
        "Adaptive Defense: evidencia ampliada (evidencia field)",
        "advanced_detector: puertos 22,80,443,3306,5432,8080,8443",
        "advanced_detector: persistencia Windows en vuln scan",
        "Filesystem sampling: temp + perfil usuario",
        "UCE: rescan seguridad si cache puertos vacía",
        "Sector shield: motores con hallazgo real + ASPE en respuesta",
        "Sector default: otros (no fintech)",
        "Kernel explain vuln → vulnerability_analyst_service",
        "ASPE: guard telemetría — standby sin evidencia IoT/móvil",
        "NDR: detección conflicto ARP (misma IP, MACs distintas)",
        "NDR: patrón escaneo puertos sensibles",
        "Auth: LOGIN_FAILED en auditoría + detección brute force/credential stuffing",
        "Kernel: routing consultas amenazas runtime → novus_security",
    ]
    RESULTS["strengthened"] = STRENGTHENED

    LIMITATIONS = [
        "Sin inspección de paquetes — NDR basado en ARP/psutil",
        "Firewall Adaptive Defense solo Windows (netsh)",
        "MITM requiere NOVUS_EXPECTED_CERT_PIN",
        "Motores sectoriales móvil requieren telemetría de app (sin agente móvil)",
        "BEC/Phishing requieren integración email OAuth para evidencia completa",
        "VirusTotal opcional (sin API key = solo hash local)",
        "IP block Adaptive Defense es registro DB, no OS-level para remotos",
    ]
    RESULTS["limitations"] = LIMITATIONS

    passed = sum(1 for t in RESULTS["tests"] if t["pass"])
    total = len(RESULTS["tests"])
    RESULTS["summary"] = {"passed": passed, "total": total, "all_pass": passed == total}

    out = os.path.join(os.path.dirname(__file__), "defense_hardening_audit.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(RESULTS, fh, ensure_ascii=False, indent=2)

    print(f"\n=== DEFENSE HARDENING: {passed}/{total} ===")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
