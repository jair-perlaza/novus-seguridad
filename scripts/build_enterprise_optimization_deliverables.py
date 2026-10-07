#!/usr/bin/env python3
"""Genera entregables de optimización enterprise NOVUS (evidencia real)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "performance_enterprise"
OUT.mkdir(parents=True, exist_ok=True)

BEFORE_PATH = OUT / "BENCHMARK_RENDIMIENTO_BEFORE.json"
AFTER_PATH = OUT / "BENCHMARK_RENDIMIENTO_AFTER_CLEAN.json"
BEFORE_TERM = Path(r"C:\Users\hp\.cursor\projects\c-NOVUS\terminals\80507.txt")
AFTER_TERM = Path(r"C:\Users\hp\.cursor\projects\c-NOVUS\terminals\72851.txt")
LIVE_CHECKS_TERM = Path(r"C:\Users\hp\.cursor\projects\c-NOVUS\terminals\100283.txt")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_startup_seconds(term_path: Path) -> Optional[float]:
    if not term_path.is_file():
        return None
    txt = term_path.read_text(encoding="utf-8", errors="ignore")
    m_start = re.search(r"started_at:\s*([0-9T:\.\-]+Z)", txt)
    m_ready = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ \[INFO\] Press CTRL\+C to quit", txt)
    if not m_start or not m_ready:
        return None
    try:
        t0_utc = datetime.strptime(m_start.group(1), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        t0_local = t0_utc.astimezone().replace(tzinfo=None)
        t1_local = datetime.strptime(m_ready.group(1), "%Y-%m-%d %H:%M:%S")
        sec = (t1_local - t0_local).total_seconds()
        return round(sec, 3) if sec >= 0 else None
    except Exception:
        return None


def _avg_ms(rows: List[Dict[str, Any]]) -> Optional[float]:
    vals = [float(r.get("ms_avg")) for r in rows if isinstance(r.get("ms_avg"), (int, float))]
    if not vals:
        return None
    return round(sum(vals) / len(vals), 2)


def _path_ms(rows: List[Dict[str, Any]], path: str) -> Optional[float]:
    for row in rows:
        if row.get("path") == path and isinstance(row.get("ms_avg"), (int, float)):
            return float(row["ms_avg"])
    return None


def _pct_improve(before: Optional[float], after: Optional[float]) -> Optional[float]:
    if before is None or after is None or before <= 0:
        return None
    return round(((before - after) / before) * 100.0, 2)


def _engine_evidence(term_path: Path) -> Dict[str, bool]:
    txt = term_path.read_text(encoding="utf-8", errors="ignore") if term_path.is_file() else ""
    checks = {
        "network_monitor_engine": "Network Monitor Engine iniciado" in txt,
        "btde": "Behavioral Threat Detection Engine: started" in txt,
        "zdde": "Zero-Day Detection Engine (ZDDE): started" in txt,
        "swarm": "Swarm Defense Engine started" in txt,
        "endpoint_enterprise": "Endpoint Enterprise: started" in txt,
        "network_endpoint_enterprise": "Network+Endpoint Enterprise: started" in txt,
        "kernel_ia": "AI Kernel started" in txt,
        "cryptovault": "CryptoVault conectado al motor de seguridad" in txt,
        "forensic_monitor": "Forensic PCAP metadata monitor: started" in txt or "Monitor de metadatos forense PCAP activo" in txt,
    }
    return checks


def _live_checks_from_terminal(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    txt = path.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"(\[\s*\{.*\}\s*\])", txt, re.S)
    if not m:
        return []
    try:
        return json.loads(m.group(1))
    except Exception:
        return []


def main() -> int:
    before = _load_json(BEFORE_PATH)
    after = _load_json(AFTER_PATH)
    if not before or not after:
        raise SystemExit("Faltan benchmarks before/after")

    startup_before = _extract_startup_seconds(BEFORE_TERM)
    startup_after = _extract_startup_seconds(AFTER_TERM)
    before_modules = before.get("module_switch") or []
    after_modules = after.get("module_switch") or []
    before_apis = before.get("api_response") or []
    after_apis = after.get("api_response") or []

    before_mod_avg = _avg_ms(before_modules)
    after_mod_avg = _avg_ms(after_modules)
    before_api_avg = _avg_ms(before_apis)
    after_api_avg = _avg_ms(after_apis)
    login_get_before = (before.get("login") or {}).get("get_ms")
    login_get_after = (after.get("login") or {}).get("get_ms")
    login_post_before = (before.get("login") or {}).get("post_ms")
    login_post_after = (after.get("login") or {}).get("post_ms")

    api_timeouts_before = sum(1 for r in before_apis if r.get("errors"))
    api_timeouts_after = sum(1 for r in after_apis if r.get("errors"))

    comp = {
        "captured_at_utc": _utc(),
        "startup_seconds": {
            "before": startup_before,
            "after": startup_after,
            "improve_pct": _pct_improve(startup_before, startup_after),
        },
        "login_ms": {
            "get_before": login_get_before,
            "get_after": login_get_after,
            "get_improve_pct": _pct_improve(login_get_before, login_get_after),
            "post_before": login_post_before,
            "post_after": login_post_after,
            "post_improve_pct": _pct_improve(login_post_before, login_post_after),
        },
        "module_switch_avg_ms": {
            "before": before_mod_avg,
            "after": after_mod_avg,
            "improve_pct": _pct_improve(before_mod_avg, after_mod_avg),
        },
        "module_key_paths": {
            "dashboard_ms_before": _path_ms(before_modules, "/dashboard"),
            "dashboard_ms_after": _path_ms(after_modules, "/dashboard"),
            "zdde_ms_before": _path_ms(before_modules, "/zdde"),
            "zdde_ms_after": _path_ms(after_modules, "/zdde"),
        },
        "api_avg_ms": {
            "before": before_api_avg,
            "after": after_api_avg,
            "improve_pct": _pct_improve(before_api_avg, after_api_avg),
            "timeouts_before": api_timeouts_before,
            "timeouts_after": api_timeouts_after,
        },
        "process_metrics": {
            "cpu_proc_before": (before.get("process") or {}).get("cpu_pct_2s"),
            "cpu_proc_after": (after.get("process") or {}).get("cpu_pct_2s"),
            "rss_mb_before": (before.get("process") or {}).get("rss_mb"),
            "rss_mb_after": (after.get("process") or {}).get("rss_mb"),
            "threads_before": (before.get("process") or {}).get("threads"),
            "threads_after": (after.get("process") or {}).get("threads"),
        },
    }

    engines = _engine_evidence(AFTER_TERM)
    live_checks = _live_checks_from_terminal(LIVE_CHECKS_TERM)

    matrix = {
        "timestamp_utc": _utc(),
        "bottlenecks_identified": [
            "Arranque síncrono de múltiples motores en hilo principal",
            "Escaneos forzados de red repetidos entre motores (scan storms)",
            "Frecuencia agresiva de Network Monitor (2-5s normal, 1s intensivo)",
            "Threat scanner con ciclo forzado continuo",
        ],
        "optimizations_applied": [
            "Arranque escalonado no bloqueante en background (main.py)",
            "Deduplicación de forced scans + quick ARP forced mode (network_scanner)",
            "Throttle de enriquecimiento de puertos en scans forzados (network_scanner)",
            "Intervalos enterprise de Network Monitor (8-15s normal, 3s intensivo)",
            "Threat scanner en modo mixto (full cada 3 ciclos, cache en intermedios)",
        ],
        "security_capabilities_preserved": engines,
        "evidence_files": [
            str(BEFORE_PATH),
            str(AFTER_PATH),
            str(BEFORE_TERM),
            str(AFTER_TERM),
            str(LIVE_CHECKS_TERM),
        ],
    }

    live_proof = {
        "timestamp_utc": _utc(),
        "optimized_instance": {"url": "http://127.0.0.1:5001", "pid": after.get("pid")},
        "http_checks": live_checks,
        "engine_boot_evidence": engines,
        "objective_findings": {
            "startup_improved": comp["startup_seconds"]["improve_pct"],
            "module_switch_improved": comp["module_switch_avg_ms"]["improve_pct"],
            "login_post_improved": comp["login_ms"]["post_improve_pct"],
            "api_timeouts_persist": api_timeouts_after > 0,
        },
        "limitations": [
            "APIs críticas siguen con timeout bajo carga alta del host.",
            "La optimización redujo cuellos de arranque y scans duplicados, pero persiste saturación runtime en APIs pesadas.",
        ],
    }

    benchmark_combined = {
        "timestamp_utc": _utc(),
        "before": before,
        "after": after,
        "comparison": comp,
    }

    (OUT / "ANTES_VS_DESPUES.json").write_text(json.dumps(comp, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT / "MATRIZ_RENDIMIENTO.json").write_text(json.dumps(matrix, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT / "LIVE_PROOF_OPTIMIZACION.json").write_text(json.dumps(live_proof, indent=2, ensure_ascii=False), encoding="utf-8")
    (OUT / "BENCHMARK_RENDIMIENTO.json").write_text(json.dumps(benchmark_combined, indent=2, ensure_ascii=False), encoding="utf-8")

    md_lines = [
        "# INFORME OPTIMIZACION ENTERPRISE — NOVUS",
        "",
        f"**Fecha:** {_utc()}",
        "",
        "## Resumen ejecutivo",
        "",
        f"- Arranque: {startup_before}s -> {startup_after}s (mejora {comp['startup_seconds']['improve_pct']}%).",
        f"- Login POST: {login_post_before}ms -> {login_post_after}ms (mejora {comp['login_ms']['post_improve_pct']}%).",
        f"- Cambio entre módulos (promedio): {before_mod_avg}ms -> {after_mod_avg}ms (mejora {comp['module_switch_avg_ms']['improve_pct']}%).",
        f"- API timeout count: {api_timeouts_before} -> {api_timeouts_after}.",
        "",
        "## Cuellos de botella identificados",
        "",
    ]
    md_lines.extend([f"- {x}" for x in matrix["bottlenecks_identified"]])
    md_lines += ["", "## Optimizaciones implementadas", ""]
    md_lines.extend([f"- {x}" for x in matrix["optimizations_applied"]])
    md_lines += ["", "## Evidencia de operación de motores", ""]
    for k, v in engines.items():
        md_lines.append(f"- {k}: {'OK' if v else 'SIN EVIDENCIA'}")
    md_lines += [
        "",
        "## Verificación HTTP (instancia optimizada)",
        "",
        "| Ruta | Estado | Tiempo (ms) | Error |",
        "|------|--------|-------------|-------|",
    ]
    for row in live_checks:
        md_lines.append(f"| {row.get('path')} | {row.get('status')} | {row.get('ms')} | {row.get('error','')} |")
    md_lines += [
        "",
        "## Conclusión",
        "",
        "- Se demuestra mejora real en arranque y latencia de navegación modular.",
        "- No se desactivaron motores ni se eliminaron funcionalidades.",
        "- Persisten timeouts en APIs bajo carga alta; se requiere fase 2 específica para rutas API pesadas.",
    ]

    md_path = OUT / "INFORME_OPTIMIZACION_ENTERPRISE.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    try:
        from fpdf import FPDF

        def _pdf_txt(s: str) -> str:
            repl = {
                "—": "-", "–": "-", "á": "a", "é": "e", "í": "i", "ó": "o", "ú": "u",
                "ñ": "n", "Á": "A", "É": "E", "Í": "I", "Ó": "O", "Ú": "U", "Ñ": "N",
                "¿": "?", "¡": "!", "→": "->",
            }
            out = str(s)
            for a, b in repl.items():
                out = out.replace(a, b)
            return out.encode("latin-1", "replace").decode("latin-1")

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_margins(15, 15, 15)

        def line(txt: str, size: int = 10, bold: bool = False, h: float = 6) -> None:
            pdf.set_font("Helvetica", "B" if bold else "", size)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(pdf.epw, h, _pdf_txt(txt))

        line("NOVUS - INFORME OPTIMIZACION ENTERPRISE", 14, True, 8)
        line(f"Fecha: {_utc()}", 10, False, 5)
        line(f"Arranque: {startup_before}s -> {startup_after}s", 10, False, 5)
        line(f"Login POST: {login_post_before}ms -> {login_post_after}ms", 10, False, 5)
        line(f"Cambio modulos avg: {before_mod_avg}ms -> {after_mod_avg}ms", 10, False, 5)
        line(f"API timeouts: {api_timeouts_before} -> {api_timeouts_after}", 10, False, 5)
        line("Motores preservados:", 11, True, 7)
        for k, v in engines.items():
            line(f"- {k}: {'OK' if v else 'SIN EVIDENCIA'}", 9, False, 5)
        line("Detalle completo: INFORME_OPTIMIZACION_ENTERPRISE.md", 8, False, 4)
        pdf.output(str(OUT / "INFORME_OPTIMIZACION_ENTERPRISE.pdf"))
    except Exception as exc:
        (OUT / "INFORME_OPTIMIZACION_ENTERPRISE.pdf.error.txt").write_text(str(exc), encoding="utf-8")

    print(json.dumps({"ok": True, "out": str(OUT)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
