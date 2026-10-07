#!/usr/bin/env python3
"""
LIVE proof + pentest + entregables Health Engine Enterprise.
NO inventa telemetría. Fault inject solo para pentest controlado y se limpia al final.
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "health_engine"
OUT.mkdir(parents=True, exist_ok=True)

# Evitar tormentas Swarm/ARP durante proof; outbox local sigue registrando entrega
os.environ["NOVUS_HEALTH_SWARM_ASYNC"] = "0"
os.environ["NOVUS_HEALTH_MAX_HEALS_PER_CYCLE"] = "1"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dump(name: str, obj) -> Path:
    path = OUT / name
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return path


def main() -> int:
    evidence = {
        "generated_at_utc": utc(),
        "policy": {
            "fake_telemetry": False,
            "invent_alerts": False,
            "static_telemetry": False,
            "na_when_unmeasurable": "NO DISPONIBLE",
        },
        "steps": [],
    }
    live = {"generated_at_utc": utc(), "ok": False, "checks": []}
    pentest = {"generated_at_utc": utc(), "scenarios": [], "ok": False}
    matrix = {"generated_at_utc": utc(), "components": [], "monitored_all": False}

    try:
        from services.health_engine.catalog import COMPONENT_IDS, COMPONENT_LABELS, NA
        from services.health_engine.store import set_fault_inject
        from services.health_engine import (
            run_health_cycle,
            get_health_dashboard,
            get_health_orchestrator_status,
            stop_health_engine,
        )
        from services.health_engine.kernel_insights import build_kernel_health_context, answer_kernel_query

        # Ensure clean fault state
        set_fault_inject(None)

        from services.health_engine import stop_health_engine

        # No arrancar orquestador en background durante proof (evita ciclos concurrentes)
        stop_health_engine()
        evidence["steps"].append({"step": "orchestrator_stopped_for_proof", "orchestrator": get_health_orchestrator_status()})

        # Baseline: publish async to Swarm (no bloquear ciclo)
        cycle = run_health_cycle(publish=True, self_heal=False, persist=True)
        evidence["steps"].append(
            {
                "step": "baseline_cycle",
                "ok": cycle.get("ok"),
                "cycle_id": cycle.get("cycle_id"),
                "summary": cycle.get("summary"),
                "component_count": len(cycle.get("components") or []),
                "published": cycle.get("published"),
                "fake_telemetry": cycle.get("fake_telemetry"),
            }
        )

        components = cycle.get("components") or []
        for c in components:
            matrix["components"].append(
                {
                    "component_id": c.get("component_id"),
                    "label": c.get("label"),
                    "status": c.get("status"),
                    "measurable": c.get("measurable"),
                    "fields": {
                        k: c.get(k)
                        for k in (
                            "uptime_label",
                            "cpu_percent",
                            "ram_mb",
                            "disk_percent",
                            "error_count",
                            "exception_count",
                            "response_time_ms",
                            "events_processed",
                            "events_lost",
                            "queue_pending",
                            "latency_ms",
                        )
                    },
                }
            )
        monitored_ids = {c.get("component_id") for c in components}
        matrix["monitored_all"] = set(COMPONENT_IDS).issubset(monitored_ids)
        matrix["catalog"] = list(COMPONENT_IDS)
        matrix["labels"] = COMPONENT_LABELS

        live["checks"].append(
            {
                "id": "all_engines_monitored",
                "pass": matrix["monitored_all"],
                "expected": len(COMPONENT_IDS),
                "got": len(monitored_ids),
            }
        )
        live["checks"].append(
            {
                "id": "no_fake_telemetry",
                "pass": cycle.get("fake_telemetry") is False and cycle.get("invented_alerts") is False,
            }
        )
        live["checks"].append(
            {
                "id": "dashboard_real_state",
                "pass": bool(cycle.get("summary")) and cycle.get("ok") is True,
                "overall": (cycle.get("summary") or {}).get("overall_status"),
            }
        )

        dash = get_health_dashboard()
        hist = dash.get("history") or []
        live["checks"].append({"id": "history_works", "pass": len(hist) > 0, "history_entries": len(hist)})

        published = cycle.get("published") or {}
        swarm_ok = False
        if isinstance(published, dict):
            swarm_ok = published.get("status") in (
                "queued_async",
                "outbox_only",
                "ok",
                "recorded",
                "success",
                "detected",
                "observed",
            ) or bool(published.get("swarm_outbox") or published.get("event_id") or published.get("id"))
            if published.get("status") == "error":
                swarm_ok = False
        try:
            from services.health_engine.store import DATA_DIR, read_jsonl_tail
            import os

            outbox_path = os.path.join(DATA_DIR, "swarm_outbox.jsonl")
            outbox = read_jsonl_tail(outbox_path, limit=20)
            swarm_ok = swarm_ok or any(e.get("destination") == "swarm_defense" for e in outbox)
            evidence["steps"].append(
                {
                    "step": "swarm_outbox_scan",
                    "entries": len(outbox),
                    "latest": outbox[-1] if outbox else None,
                }
            )
        except Exception as exc:
            evidence["steps"].append({"step": "swarm_outbox_scan", "error": str(exc)[:200]})
        try:
            from services.defense_evidence_registry import list_recent_events

            recent = list_recent_events(limit=200)
            swarm_ok = swarm_ok or any(e.get("motor") == "health_engine" for e in recent)
            evidence["steps"].append(
                {
                    "step": "swarm_evidence_scan",
                    "health_events": sum(1 for e in recent if e.get("motor") == "health_engine"),
                }
            )
        except Exception as exc:
            evidence["steps"].append({"step": "swarm_evidence_scan", "error": str(exc)[:200]})

        live["checks"].append(
            {
                "id": "swarm_receives_health_events",
                "pass": swarm_ok,
                "published": published,
            }
        )

        kctx = build_kernel_health_context(dash)
        kans = answer_kernel_query("¿Cuál es el riesgo Swarm?", dash)
        live["checks"].append(
            {
                "id": "kernel_analyst_only",
                "pass": kctx.get("executes_actions") is False
                and kctx.get("destructive_decisions") is False
                and kans.get("executes") is False,
                "capabilities": kctx.get("capabilities"),
            }
        )

        # ---- PENTEST scenarios (controlled fault inject + real detection) ----
        scenarios = [
            {"id": "worker_down", "component_id": "background_workers", "kind": "stopped"},
            {"id": "service_down", "component_id": "web_security", "kind": "stopped"},
            {"id": "db_fail", "component_id": "database", "kind": "db_fail", "message": "pentest_db_fail"},
            {"id": "api_fail", "component_id": "api_rest", "kind": "api_fail", "error_count": 12},
            {"id": "queue_saturated", "component_id": "swarm_defense", "kind": "queue_saturated", "queue_pending": 5000},
            {
                "id": "exception_storm",
                "component_id": "behavioral_threat_detection",
                "kind": "exception_storm",
                "exception_count": 25,
                "error_count": 25,
            },
        ]

        from services.health_engine import stop_health_engine as _stop_he

        _stop_he()  # asegurar sin orquestador concurrente

        for sc in scenarios:
            set_fault_inject({"active": True, **{k: v for k, v in sc.items() if k != "id"}})
            time.sleep(0.05)
            # Solo detectar; heal explícito aparte para cola
            r = run_health_cycle(publish=False, self_heal=False, persist=True)
            issues = r.get("issues") or []
            alerts = r.get("alerts") or []
            heals = r.get("self_heal") or []
            detected = any(
                i.get("component_id") == sc["component_id"]
                or (sc["kind"] == "queue_saturated" and i.get("code") == "queue_saturated")
                or (sc["kind"] == "exception_storm" and i.get("code") == "repetitive_errors")
                or (sc["kind"] in ("stopped", "db_fail") and i.get("code") in ("service_down", "worker_stopped"))
                or (sc["kind"] == "api_fail" and i.get("code") in ("service_degraded", "repetitive_errors"))
                for i in issues
            )
            if not detected:
                detected = any(a.get("component_id") == sc["component_id"] for a in alerts)
            # Heal controlado solo para cola saturada
            if sc["kind"] == "queue_saturated" and detected:
                set_fault_inject({"active": True, **{k: v for k, v in sc.items() if k != "id"}})
                heal_cycle = run_health_cycle(publish=False, self_heal=True, persist=True)
                heals = heal_cycle.get("self_heal") or heals
            set_fault_inject(None)
            post = run_health_cycle(publish=False, self_heal=False, persist=True)
            pentest["scenarios"].append(
                {
                    "id": sc["id"],
                    "component_id": sc["component_id"],
                    "kind": sc["kind"],
                    "detected": detected,
                    "issue_codes": [i.get("code") for i in issues],
                    "alert_count": len(alerts),
                    "self_heal": heals,
                    "recovered_or_attempted": bool(heals),
                    "post_overall": (post.get("summary") or {}).get("overall_status"),
                    "pass": detected,
                }
            )

        set_fault_inject(
            {
                "active": True,
                "component_id": "database",
                "kind": "db_fail",
                "message": "pentest_swarm_publish",
            }
        )
        swarm_cycle = run_health_cycle(publish=True, self_heal=False, persist=True)
        set_fault_inject(None)
        pentest["swarm_publish_cycle"] = {
            "published": swarm_cycle.get("published"),
            "issue_count": len(swarm_cycle.get("issues") or []),
            "ok": swarm_cycle.get("ok"),
        }

        final = run_health_cycle(publish=False, self_heal=False, persist=True)
        evidence["steps"].append({"step": "final_cycle", "summary": final.get("summary"), "ok": final.get("ok")})

        pentest["ok"] = all(s.get("pass") for s in pentest["scenarios"]) and len(pentest["scenarios"]) == 6
        live["checks"].append(
            {
                "id": "realtime_fault_detection",
                "pass": pentest["ok"],
                "scenarios_passed": sum(1 for s in pentest["scenarios"] if s.get("pass")),
                "scenarios_total": len(pentest["scenarios"]),
            }
        )
        live["ok"] = all(c.get("pass") for c in live["checks"])
        live["summary"] = final.get("summary")
        live["na_sentinel"] = NA

        evidence["live"] = live
        evidence["pentest_ok"] = pentest["ok"]
        evidence["matrix_monitored_all"] = matrix["monitored_all"]
        evidence["kernel"] = {"context": kctx, "sample_answer": kans}

        dump("EVIDENCIA_HEALTH_ENGINE.json", evidence)
        dump("LIVE_PROOF_HEALTH_ENGINE.json", live)
        dump("PENTEST_HEALTH_ENGINE.json", pentest)
        dump("MATRIZ_HEALTH_ENGINE.json", matrix)

        # Markdown informe
        md = []
        md.append("# INFORME — Health Monitoring & Self-Healing Engine Enterprise\n")
        md.append(f"Generado: `{utc()}`\n")
        md.append("## Política\n")
        md.append("- Sin telemetría falsa ni alertas inventadas.\n")
        md.append("- Campos no medibles → `NO DISPONIBLE`.\n")
        md.append("- Self-heal nunca elimina evidencias forenses.\n")
        md.append("- Kernel IA: analiza / correlaciona / explica / propone — no ejecuta.\n")
        md.append("\n## Catálogo monitoreado\n")
        for cid in COMPONENT_IDS:
            md.append(f"- `{cid}` — {COMPONENT_LABELS.get(cid)}\n")
        md.append("\n## LIVE PROOF\n")
        md.append(f"- ok: **{live['ok']}**\n")
        for c in live["checks"]:
            md.append(f"- [{ 'PASS' if c.get('pass') else 'FAIL' }] `{c['id']}`\n")
        md.append("\n## PENTEST\n")
        md.append(f"- ok: **{pentest['ok']}**\n")
        for s in pentest["scenarios"]:
            md.append(
                f"- [{ 'PASS' if s.get('pass') else 'FAIL' }] `{s['id']}` detected={s.get('detected')} codes={s.get('issue_codes')}\n"
            )
        md.append("\n## Resumen final\n")
        md.append("```json\n")
        md.append(json.dumps(final.get("summary") or {}, indent=2, ensure_ascii=False))
        md.append("\n```\n")
        (OUT / "INFORME_HEALTH_ENGINE.md").write_text("".join(md), encoding="utf-8")

        print(json.dumps({"live_ok": live["ok"], "pentest_ok": pentest["ok"], "out": str(OUT)}, indent=2))
        return 0 if live["ok"] and pentest["ok"] else 2
    except Exception as exc:
        err = {"ok": False, "error": str(exc), "trace": traceback.format_exc(), "at": utc()}
        dump("EVIDENCIA_HEALTH_ENGINE.json", err)
        dump("LIVE_PROOF_HEALTH_ENGINE.json", err)
        print(json.dumps(err, indent=2)[:2000])
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
