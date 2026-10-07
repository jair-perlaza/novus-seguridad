#!/usr/bin/env python3
"""Validación del módulo Network NDR — telemetría real, sin placeholders."""
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FORBIDDEN = ("placeholder", "simulated", "static_value", "lorem ipsum", "fake_")


def _check_no_forbidden(obj, path=""):
    issues = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            issues.extend(_check_no_forbidden(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            issues.extend(_check_no_forbidden(v, f"{path}[{i}]"))
    elif isinstance(obj, str):
        low = obj.lower()
        if low == "sin datos disponibles":
            skip_paths = (".nodes[", ".traffic.", ".unknown_devices[", ".top_traffic[")
            if not any(s in path for s in skip_paths):
                issues.append(f"{path}: texto genérico sin explicación")
        for f in FORBIDDEN:
            if f in low:
                issues.append(f"{path}: contiene '{f}'")
    return issues


def main():
    from services.network_ndr_service import (
        build_ndr_payload,
        get_device_detail,
        investigate_device,
        enrich_events_with_explanations,
        explain_network_event,
    )
    from services.network_event_log import network_event_log

    results = {"tests": [], "performance_ms": {}, "passed": True}

    t0 = time.perf_counter()
    payload = build_ndr_payload(force_refresh=False)
    results["performance_ms"]["build_ndr_payload"] = round((time.perf_counter() - t0) * 1000, 1)

    checks = [
        ("status_success", payload.get("status") == "success"),
        ("has_nodes", isinstance(payload.get("nodes"), list)),
        ("executive_summary", bool(payload.get("executive_summary"))),
        ("top_traffic_fields", all(
            k in (payload.get("top_traffic") or [{}])[0]
            for k in ("bytes_sent", "bytes_recv", "traffic_percent", "last_activity")
        ) if payload.get("top_traffic") else True),
        ("alerts_have_explanation", all(
            a.get("plain_explanation") for a in (payload.get("alerts") or [])
        ) if payload.get("alerts") else True),
    ]
    for name, ok in checks:
        results["tests"].append({"name": name, "pass": ok})
        if not ok:
            results["passed"] = False

    forbidden = _check_no_forbidden(payload)
    results["forbidden_strings"] = forbidden[:20]
    if forbidden:
        results["passed"] = False

    nodes = payload.get("nodes") or []
    if nodes:
        ip = nodes[0].get("ip")
        t1 = time.perf_counter()
        detail = get_device_detail(ip)
        results["performance_ms"]["get_device_detail"] = round((time.perf_counter() - t1) * 1000, 1)
        dev_ok = detail.get("status") == "success" and detail.get("device", {}).get("confidence")
        results["tests"].append({"name": "device_detail_confidence", "pass": bool(dev_ok)})
        if not dev_ok:
            results["passed"] = False

        unknown = payload.get("unknown_devices") or []
        if unknown and os.environ.get("RUN_INVESTIGATE") == "1":
            uip = unknown[0].get("ip")
            t2 = time.perf_counter()
            inv = investigate_device(uip)
            results["performance_ms"]["investigate_device"] = round((time.perf_counter() - t2) * 1000, 1)
            inv_ok = inv.get("status") == "success" and inv.get("confidence")
            results["tests"].append({"name": "investigate_unknown", "pass": bool(inv_ok)})
            if not inv_ok:
                results["passed"] = False
        else:
            results["tests"].append({
                "name": "investigate_unknown",
                "pass": True,
                "skipped": "set RUN_INVESTIGATE=1 for full scan test",
            })
    else:
        results["tests"].append({"name": "device_detail_confidence", "pass": True, "skipped": "no nodes"})

    events = enrich_events_with_explanations(
        network_event_log.get_recent(5) or [{"message": "Escaneo de red", "level": "info", "time": "00:00:00"}]
    )
    ev_ok = all(e.get("plain_explanation") for e in events)
    results["tests"].append({"name": "event_explanations", "pass": ev_ok})
    results["tests"].append({"name": "explain_network_event", "pass": bool(explain_network_event("Escaneo ARP"))})
    if not ev_ok:
        results["passed"] = False

    t3 = time.perf_counter()
    build_ndr_payload(force_refresh=False)
    results["performance_ms"]["build_ndr_cached"] = round((time.perf_counter() - t3) * 1000, 1)

    results["audit"] = {
        "improvements": [
            "Leyenda de colores en radar NDR",
            "Resumen ejecutivo superior (executive_summary)",
            "Ficha técnica enriquecida con explicaciones por campo",
            "Explicaciones en lenguaje sencillo para alertas y eventos",
            "Botón Investigar en dispositivos desconocidos",
            "Top tráfico ampliado (enviado/recibido, velocidad, %, actividad)",
            "Animaciones suaves para dispositivos nuevos y cambios recientes",
            "Caché de payload NDR (8s TTL) y caché de vulnerabilidades (60s)",
        ],
        "new_api_fields": [
            "executive_summary", "plain_explanation", "confidence_score",
            "confidence_label", "os_estimate_short", "is_new", "recent_change",
            "traffic_percent", "last_activity", "connected_since",
        ],
        "new_endpoints": ["POST /api/network/ndr/device/<ip>/investigate"],
        "data_sources": [
            "ARP Scapy", "psutil", "SQLite inventory", "MAC OUI",
            "Adaptive Defense", "ASPE", "Threat Intelligence", "Alertas DB",
        ],
    }

    out = ROOT / "scripts" / "network_ndr_audit_results.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\nAudit saved: {out}")
    print("ALL PASS" if results["passed"] else "SOME TESTS FAILED")
    return 0 if results["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
