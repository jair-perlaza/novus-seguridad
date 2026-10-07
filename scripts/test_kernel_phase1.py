#!/usr/bin/env python3
"""
Pruebas funcionales Fase 1 — Kernel IA NOVUS.

Valida: intención, planificador, orquestador, contexto de sesión, priorización.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime

sys.path.insert(0, ".")

from services.kernel_intent_interpreter import interpret_intent
from services.kernel_planner import build_plan
from services.kernel_session_context import kernel_session_context
from services.ai_orchestrator import kernel_orchestrator
from services.soc_report_builder import _prioritize_findings, build_soc_report

SESSION = "phase1-test-session"


def test_intent_scenarios():
    """Planificador + intérprete — sin ejecutar motores."""
    cases = [
        {
            "message": "Mi computador está lento.",
            "expect_intent": "performance_slow",
            "min_caps": 8,
            "scenario": "performance_investigation",
        },
        {
            "message": "Escanea mi portátil.",
            "expect_intent": "deep_scan",
            "workflow": "full",
            "scenario": "full_device_scan",
        },
        {
            "message": "Revisa mi red.",
            "expect_intent": "network_status",
            "network_only": True,
            "scenario": "network_only",
        },
        {
            "message": "¿Hay algo raro?",
            "expect_intent": "malware",
            "min_caps": 5,
            "scenario": "anomaly_suspicion",
        },
    ]
    passed = 0
    for c in cases:
        plan = build_plan(c["message"], session_id=SESSION)
        ok = plan.intent_id == c["expect_intent"]
        if c.get("scenario"):
            ok = ok and plan.scenario_id == c["scenario"]
        if c.get("min_caps"):
            ok = ok and len(plan.capabilities) >= c["min_caps"]
        if c.get("workflow"):
            ok = ok and plan.workflow_profile == c["workflow"]
        if c.get("network_only"):
            net_caps = {"network.radar", "network.scanner", "connections.active", "traffic.stats", "firewall.ports", "network.events"}
            caps = set(plan.capabilities)
            ok = ok and caps.issubset(net_caps | {"scan_network"}) and len(caps) >= 4
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {c['message']!r} → intent={plan.intent_id} caps={len(plan.capabilities)} scenario={plan.scenario_id}")
        if not ok:
            print(f"         plan caps: {plan.capabilities[:10]}")
            print(f"         internal_plan steps: {len(plan.internal_plan)}")
        if ok:
            passed += 1
    return passed, len(cases)


def test_contextual_problem():
    """Referencia contextual — 'Analiza este problema' usa intención previa."""
    sid = "phase1-ctx-test"
    kernel_session_context.update_before_plan(sid, "Mi computador está lento.", "performance_slow", "Rendimiento")
    kernel_session_context.update_after_operation(
        sid, "op1", "performance_slow", ["system.metrics"], "MEDIO", anomalies=["CPU alta"]
    )
    resolved = kernel_session_context.resolve_message("Analiza este problema.", sid)
    base = kernel_orchestrator.analyze_intent(resolved)
    ctx = kernel_session_context.get(sid)
    enriched = interpret_intent(resolved, base, ctx, [])
    plan = build_plan("Analiza este problema.", session_id=sid, history=[
        {"role": "user", "content": "Mi computador está lento."},
        {"role": "assistant", "content": "Análisis de rendimiento iniciado."},
    ])
    ok = plan.intent_id == "performance_slow" and plan.scenario_id == "contextual_problem"
    print(f"  [{'PASS' if ok else 'FAIL'}] Contextual → intent={plan.intent_id} scenario={plan.scenario_id}")
    return 1 if ok else 0, 1


def test_prioritization():
    vulns = [
        {"id": "PORT-445", "nombre": "Puerto SMB", "riesgo": "MEDIO"},
        {"id": "PROC-999", "nombre": "Proceso sospechoso", "riesgo": "ALTO"},
        {"id": "VULN-1", "nombre": "Parche pendiente", "riesgo": "CRITICO"},
    ]
    sus = [{"pid": 1234, "name": "weird.exe", "description": "Alto CPU"}]
    ordered = _prioritize_findings(vulns, sus)
    ids = [x.get("id") for x in ordered]
    ok = ids[0] == "VULN-1" and "PROC" in str(ids[1])
    print(f"  [{'PASS' if ok else 'FAIL'}] Priorización → orden: {ids}")
    return 1 if ok else 0, 1


def test_report_no_invented_data():
    report = build_soc_report(
        intent={"primary_intent": "performance_slow", "primary_label": "Rendimiento", "capabilities": []},
        data={"system": {"cpu": 45, "ram": 60}, "capabilities_executed": ["system.metrics"], "modules_queried": []},
        message="Mi computador está lento.",
    )
    ok = "45" in report["reply"] and report["risk_level"] in ("NOMINAL", "BAJO", "MEDIO", "ALTO")
    no_fake = "9999" not in report["reply"]
    print(f"  [{'PASS' if ok and no_fake else 'FAIL'}] Informe basado en evidencia (risk={report['risk_level']})")
    return 1 if ok and no_fake else 0, 1


def test_internal_plan_hidden():
    plan = build_plan("Mi computador está lento.", session_id=SESSION)
    ok = len(plan.internal_plan) >= 5 and plan.intent_confidence > 0
    print(f"  [{'PASS' if ok else 'FAIL'}] Plan interno ({len(plan.internal_plan)} pasos, conf={plan.intent_confidence})")
    return 1 if ok else 0, 1


def main():
    print("=" * 70)
    print("NOVUS Kernel IA — Pruebas Fase 1")
    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 70)

    total_pass = 0
    total = 0

    print("\n▸ Escenarios de intención")
    p, t = test_intent_scenarios()
    total_pass += p
    total += t

    print("\n▸ Contexto de sesión")
    p, t = test_contextual_problem()
    total_pass += p
    total += t

    print("\n▸ Priorización de hallazgos")
    p, t = test_prioritization()
    total_pass += p
    total += t

    print("\n▸ Informes profesionales")
    p, t = test_report_no_invented_data()
    total_pass += p
    total += t

    print("\n▸ Planificador interno")
    p, t = test_internal_plan_hidden()
    total_pass += p
    total += t

    print("\n" + "=" * 70)
    print(f"Resultado: {total_pass}/{total} pruebas PASS")
    print("=" * 70)
    return 0 if total_pass == total else 1


if __name__ == "__main__":
    sys.exit(main())
