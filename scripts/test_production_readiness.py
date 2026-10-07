#!/usr/bin/env python3
"""
Pruebas de preparación para producción — evidencia verificable, sin suposiciones.
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Base, SessionLocal, Log, IPBloqueada, engine, registrar_log_seguridad

Base.metadata.create_all(bind=engine)

RESULTS = {"tests": [], "evidence": [], "limitations": []}


def check(name: str, how: str, fn):
    try:
        ok, evidence = fn()
        RESULTS["tests"].append({
            "name": name, "pass": bool(ok), "how": how,
            "evidence": str(evidence)[:400],
        })
        print(f"[{'OK' if ok else 'FAIL'}] {name}")
        if ok:
            RESULTS["evidence"].append({"test": name, "result": evidence})
        return bool(ok)
    except Exception as exc:
        RESULTS["tests"].append({"name": name, "pass": False, "how": how, "error": str(exc)})
        print(f"[FAIL] {name}: {exc}")
        return False


def main():
    from main import app
    from services.defense_evidence_registry import (
        record_defense_event, list_recent_events, get_registry_summary, event_exists,
    )
    from services.adaptive_defense_engine import (
        classify_risk_level, _has_critical_evidence, revert_containment,
        activate_after_failed_remediation,
    )

    print("\n=== REGISTRO DE EVIDENCIAS ===")
    ev = record_defense_event(
        phase="audit", action="production_test", motor="test_production_readiness",
        outcome="success", detail="Prueba registro trazable",
    )
    check("registry write", "record_defense_event", lambda: (
        bool(ev.get("id")), f"id={ev.get('id')}",
    ))
    check("registry read", "event_exists", lambda: (
        event_exists(ev.get("id", "")), f"id={ev.get('id')}",
    ))
    check("registry summary", "get_registry_summary", lambda: (
        "by_phase" in get_registry_summary(), get_registry_summary().get("by_phase"),
    ))

    print("\n=== DEFENSA ACTIVA — GATES DE EVIDENCIA ===")
    check("critico sin evidencia downgrade", "classify_risk_level", lambda: (
        classify_risk_level({"riesgo": "CRITICO"}) != "CRITICO",
        classify_risk_level({"riesgo": "CRITICO"}),
    ))
    check("partial isolation gate", "_has_critical_evidence", lambda: (
        not _has_critical_evidence({"riesgo": "CRITICO"}),
        "sin evidencia = no aislamiento",
    ))

    finding_port = {
        "id": "TEST-PORT-9999", "riesgo": "ALTO", "ip": "203.0.113.50",
        "evidencia": {"puerto": 9999}, "motor": "test",
    }
    ade = activate_after_failed_remediation(
        "TEST-PORT-9999", finding_port, user_email="novus.qa.jul2026@example.com",
    )
    check("ADE activación trazable", "activate_after_failed_remediation", lambda: (
        ade.get("status") in ("active", "resolved_by_remediation", "adaptive_response")
        or "actions" in ade or "level" in ade,
        f"status={ade.get('status')} level={ade.get('level')}",
    ))

    print("\n=== CONTENCIÓN AUTH + RECUPERACIÓN ===")
    test_ip = "203.0.113.99"
    db = SessionLocal()
    try:
        for _ in range(6):
            registrar_log_seguridad(db, "LOGIN_FAILED", f"email=test@x.com ip={test_ip}")
        db.commit()
    finally:
        db.close()

    from services.novus_security_integration import novus_security
    anomalies = novus_security._detect_auth_anomalies()
    bf = [t for t in anomalies if t.get("type") == "brute_force" and test_ip in str(t)]
    check("detección brute force", "_detect_auth_anomalies", lambda: (
        len(bf) >= 1, bf[0].get("details", {}) if bf else "no detectado",
    ))

    db = SessionLocal()
    try:
        blocked = db.query(IPBloqueada).filter(IPBloqueada.direccion_ip == test_ip).first()
        check("contención IP brute force", "IPBloqueada", lambda: (
            blocked is not None, f"blocked={blocked is not None}",
        ))
    finally:
        db.close()

    rev = revert_containment(test_ip, "block_ip")
    check("recuperación unblock IP", "revert_containment", lambda: (
        rev.get("status") == "success", rev.get("detail"),
    ))

    print("\n=== ENTORNO HOSTIL ===")
    from services.network_ndr_service import analyze_behavior
    hostile_nodes = [
        {"ip": f"10.0.0.{i}", "mac": f"aa:bb:cc:dd:ee:{i:02x}", "open_ports": []}
        for i in range(1, 11)
    ]
    alerts = analyze_behavior(hostile_nodes, {"gateway": "10.0.0.1", "local_ip": "10.0.0.2"})
    hostile_alerts = [a for a in alerts if "HOSTILE" in a.get("id", "")]
    check("NDR alertas entorno hostil", "analyze_behavior 10 unknown", lambda: (
        len(hostile_alerts) >= 1, [a.get("title") for a in hostile_alerts],
    ))

    print("\n=== RATE LIMITING + API ===")
    client = app.test_client()
    client.post(
        "/login",
        data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!"},
        follow_redirects=True,
    )
    r = client.get("/api/system/defense-registry")
    check("API defense-registry", "GET /api/system/defense-registry", lambda: (
        r.status_code == 200 and r.get_json().get("status") == "success",
        f"HTTP {r.status_code}",
    ))

    print("\n=== MOTORES CORE (regresión) ===")
    check("ASPE init", "aspe.initialize", lambda: (
        __import__("services.adaptive_sector_protection_engine", fromlist=["aspe"]).aspe
        .initialize_sector_protection("novus.qa.jul2026@example.com").get("status") == "success",
        "success",
    ))
    check("threat scan", "detect_threats_realtime", lambda: (
        isinstance(novus_security.detect_threats_realtime(force=True), dict), "dict",
    ))

    RESULTS["limitations"] = [
        "Sin IDS/packet inspection — DNS/DHCP spoofing no verificable en host",
        "Bloqueo IP remoto en SQLite — sin enforcement firewall OS para todos los escenarios",
        "Sector móvil sin agente/SDK",
        "BEC/Phishing sin OAuth email en producción",
        "MITM completo requiere NOVUS_EXPECTED_CERT_PIN",
        "Escalabilidad >100 dispositivos no validada en laboratorio real",
    ]

    passed = sum(1 for t in RESULTS["tests"] if t["pass"])
    total = len(RESULTS["tests"])
    RESULTS["summary"] = {"passed": passed, "total": total, "all_pass": passed == total}

    out = os.path.join(os.path.dirname(__file__), "production_readiness_tests.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(RESULTS, fh, ensure_ascii=False, indent=2)

    print(f"\n=== PRODUCTION READINESS: {passed}/{total} ===")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
