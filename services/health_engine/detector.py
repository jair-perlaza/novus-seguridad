#!/usr/bin/env python3
"""Detección de fallos/anomalías a partir de telemetría real."""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from services.health_engine.catalog import NA, STATUS_ACTIVE, STATUS_DEGRADED, STATUS_STOPPED, STATUS_UNAVAILABLE
from services.health_engine.store import load_memory_baseline, save_memory_baseline

CPU_HIGH = float(os.environ.get("NOVUS_HEALTH_CPU_HIGH", "90"))
RAM_HIGH = float(os.environ.get("NOVUS_HEALTH_RAM_HIGH", "85"))
DISK_HIGH = float(os.environ.get("NOVUS_HEALTH_DISK_HIGH", "90"))
QUEUE_HIGH = int(os.environ.get("NOVUS_HEALTH_QUEUE_HIGH", "1000"))
ERROR_REPEAT = int(os.environ.get("NOVUS_HEALTH_ERROR_REPEAT", "5"))
MEM_LEAK_GROWTH_MB = float(os.environ.get("NOVUS_HEALTH_MEM_LEAK_MB", "400"))
LATENCY_HIGH_MS = float(os.environ.get("NOVUS_HEALTH_LATENCY_MS", "5000"))


def _num(v: Any) -> Optional[float]:
    if v is None or v == NA:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def detect_issues(probe_result: Dict[str, Any], previous: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    host = probe_result.get("host") or {}
    components = probe_result.get("components") or []

    cpu = _num(host.get("cpu_percent"))
    ram = _num(host.get("ram_percent"))
    disk = _num(host.get("disk_percent"))
    rss = _num(host.get("process_rss_mb"))

    if cpu is not None and cpu >= CPU_HIGH:
        issues.append(
            {
                "code": "cpu_saturated",
                "severity": "high",
                "component_id": "host",
                "message": f"CPU host saturada: {cpu}% (umbral {CPU_HIGH}%)",
                "metric": {"cpu_percent": cpu},
            }
        )
    if ram is not None and ram >= RAM_HIGH:
        issues.append(
            {
                "code": "ram_high",
                "severity": "high",
                "component_id": "host",
                "message": f"RAM host alta: {ram}% (umbral {RAM_HIGH}%)",
                "metric": {"ram_percent": ram},
            }
        )
    if disk is not None and disk >= DISK_HIGH:
        issues.append(
            {
                "code": "disk_high",
                "severity": "medium",
                "component_id": "host",
                "message": f"Disco alto: {disk}% (umbral {DISK_HIGH}%)",
                "metric": {"disk_percent": disk},
            }
        )

    # Tendencia de memoria (fuga potencial)
    baseline = load_memory_baseline()
    if rss is not None:
        base_rss = _num(baseline.get("process_rss_mb"))
        samples = int(baseline.get("samples") or 0) + 1
        if base_rss is None:
            save_memory_baseline({"process_rss_mb": rss, "samples": 1, "peak_rss_mb": rss})
        else:
            peak = max(base_rss, rss, _num(baseline.get("peak_rss_mb")) or rss)
            save_memory_baseline({"process_rss_mb": base_rss, "samples": samples, "peak_rss_mb": peak, "last_rss_mb": rss})
            growth = rss - base_rss
            if samples >= 3 and growth >= MEM_LEAK_GROWTH_MB:
                issues.append(
                    {
                        "code": "memory_leak_suspected",
                        "severity": "high",
                        "component_id": "host",
                        "message": f"Crecimiento RSS sospechoso: +{round(growth,1)} MB desde baseline",
                        "metric": {"baseline_mb": base_rss, "current_mb": rss, "growth_mb": round(growth, 1)},
                    }
                )

    prev_map = {}
    if previous:
        for c in previous.get("components") or []:
            prev_map[c.get("component_id")] = c

    failed_components = 0
    for c in components:
        cid = c.get("component_id")
        st = c.get("status")
        if st in (STATUS_STOPPED, STATUS_UNAVAILABLE):
            failed_components += 1
            issues.append(
                {
                    "code": "service_down" if st == STATUS_STOPPED else "service_unavailable",
                    "severity": "critical" if st == STATUS_STOPPED else "medium",
                    "component_id": cid,
                    "message": f"Componente {c.get('label')} en estado {c.get('status_label')}",
                    "metric": {"status": st, "last_error": c.get("last_error")},
                }
            )
        elif st == STATUS_DEGRADED:
            issues.append(
                {
                    "code": "service_degraded",
                    "severity": "medium",
                    "component_id": cid,
                    "message": f"Componente {c.get('label')} degradado",
                    "metric": {"status": st, "last_error": c.get("last_error")},
                }
            )

        err = _num(c.get("error_count"))
        exc = _num(c.get("exception_count"))
        if (err is not None and err >= ERROR_REPEAT) or (exc is not None and exc >= ERROR_REPEAT):
            issues.append(
                {
                    "code": "repetitive_errors",
                    "severity": "high",
                    "component_id": cid,
                    "message": f"Errores/excepciones repetitivos en {c.get('label')}",
                    "metric": {"error_count": err, "exception_count": exc},
                }
            )

        q = _num(c.get("queue_pending"))
        if q is not None and q >= QUEUE_HIGH:
            issues.append(
                {
                    "code": "queue_saturated",
                    "severity": "high",
                    "component_id": cid,
                    "message": f"Cola saturada en {c.get('label')}: {int(q)}",
                    "metric": {"queue_pending": q},
                }
            )

        lat = _num(c.get("latency_ms")) or _num(c.get("response_time_ms"))
        if lat is not None and lat >= LATENCY_HIGH_MS:
            issues.append(
                {
                    "code": "high_latency",
                    "severity": "medium",
                    "component_id": cid,
                    "message": f"Latencia alta en {c.get('label')}: {lat} ms",
                    "metric": {"latency_ms": lat},
                }
            )

        # Motor sin actividad (si antes tenía actividad)
        prev = prev_map.get(cid) or {}
        if (
            st == STATUS_ACTIVE
            and prev.get("last_activity") not in (None, NA, "")
            and c.get("last_activity") in (None, NA, "")
        ):
            issues.append(
                {
                    "code": "engine_no_activity",
                    "severity": "medium",
                    "component_id": cid,
                    "message": f"Motor {c.get('label')} sin actividad reciente",
                    "metric": {},
                }
            )

        # Detalle de workers detenidos
        details = c.get("details") or {}
        if cid == "background_workers" and details.get("possibly_stopped"):
            for w in details.get("possibly_stopped") or []:
                issues.append(
                    {
                        "code": "worker_stopped",
                        "severity": "high",
                        "component_id": cid,
                        "message": f"Worker/orquestador posiblemente detenido: {w}",
                        "metric": {"worker": w},
                    }
                )

    if failed_components >= 3:
        issues.append(
            {
                "code": "multi_component_failure",
                "severity": "critical",
                "component_id": "platform",
                "message": f"Fallos múltiples: {failed_components} componentes detenidos/no disponibles",
                "metric": {"failed_components": failed_components},
                "elevate_swarm_risk": True,
            }
        )

    return issues


def build_alerts(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts = []
    for iss in issues:
        if iss.get("severity") in ("high", "critical") or iss.get("code") in (
            "service_down",
            "cpu_saturated",
            "ram_high",
            "repetitive_errors",
            "queue_saturated",
            "worker_stopped",
        ):
            alerts.append(
                {
                    "alert_id": f"{iss.get('code')}:{iss.get('component_id')}",
                    "severity": iss.get("severity"),
                    "component_id": iss.get("component_id"),
                    "code": iss.get("code"),
                    "message": iss.get("message"),
                    "metric": iss.get("metric") or {},
                    "source": "health_engine",
                    "invented": False,
                }
            )
    return alerts
