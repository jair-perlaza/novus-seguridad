#!/usr/bin/env python3
"""
Auditoría de consistencia: diferencial Fase 2 Protección de Datos vs auditoría maestra.
No modifica código de producto. Corrige solo la evaluación si la maestra usaba constantes obsoletas.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

OUT = ROOT / "data" / "audit_consistency_oficial"
OUT.mkdir(parents=True, exist_ok=True)
OFF = ROOT / "data" / "audit_security_capabilities_20260725"
MASTER = ROOT / "data" / "audit_master_novus"
BUILD = ROOT / "scripts" / "build_security_capabilities_audit_reports.py"

STARTED = datetime.now().isoformat(timespec="seconds")


def _load_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _latin(s: str) -> str:
    return (s or "").encode("latin-1", "replace").decode("latin-1")


def write_pdf(path: Path, title: str, lines: list[str]) -> None:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.multi_cell(190, 7, _latin(title))
    pdf.ln(2)
    pdf.set_font("Helvetica", size=8)
    for ln in lines:
        pdf.multi_cell(190, 4, _latin(str(ln)[:240]))
    pdf.output(str(path))


def component_inventory() -> dict:
    """Paso 4: existencia actual de componentes (solo lectura)."""
    items = {}

    def add(name: str, path: str, symbol: str, note: str = "") -> None:
        p = ROOT / path
        exists = p.is_file()
        line = None
        if exists and symbol:
            try:
                text = p.read_text(encoding="utf-8", errors="replace").splitlines()
                for i, ln in enumerate(text, 1):
                    if symbol in ln:
                        line = i
                        break
            except Exception as exc:  # noqa: BLE001
                note = f"{note} read_err={exc}"[:200]
        items[name] = {
            "exists": exists,
            "file": path,
            "line": line,
            "symbol": symbol,
            "note": note,
            "left_codebase": (not exists),
        }

    add("DPAPI", "services/key_protection_service.py", "def _dpapi_protect", "CryptProtectData")
    add("Keyring", "data/cryptovault/keyring.json", "", "archivo runtime")
    add("AES Wrapped", "services/key_protection_service.py", "def wrap_secret", "NOVUSWRAP1")
    add("Rotación automática", "services/cryptovault_key_rotation.py", "def maybe_rotate_on_schedule", "aes_key_max_age_days")
    add("Re-cifrado", "services/key_reencryption_service.py", "def reencrypt_all_after_rotation", "")
    add("Backup cifrado", "services/encrypted_backup_service.py", "def create_encrypted_backup", "")
    add("CryptoVault", "crypto_vault.py", "class CryptoVault", "verify_health")
    add("TLS verificado", "services/tls_channel_service.py", "def probe_public_https", "")
    add("SECRET_KEY protegido", "services/flask_secret_service.py", "def flask_secret_status", "hardcoded_fallback_removed")
    add("SESSION_COOKIE_SECURE", "core/app.py", "SESSION_COOKIE_SECURE", "production→True development→False")
    add("Token Vault", "services/mail_shield_token_vault.py", "def", "Mail Shield vault")
    add("Gmail Vault", "services/gmail_oauth_service.py", "vault primero", "vault-first")
    add("DB at-rest equivalente", "services/db_at_rest_encryption.py", "def verify_at_rest_container", ".novusenc")
    return items


def criterion_comparison() -> list[dict]:
    matriz_f2 = _load_json(OFF / "MATRIZ_DIFERENCIAL_FASE2.json")
    master_ev = _load_json(MASTER / "EVIDENCIA_MAESTRA.json")
    # Fallback to official evidence if master area missing
    if not master_ev.get("areas"):
        master_ev = _load_json(OFF / "EVIDENCE_SECURITY_CAPABILITIES.json")

    master_dp = next((a for a in (master_ev.get("areas") or []) if a.get("area") == "Protección de Datos"), {})
    master_by = {c["criterio"]: c for c in (master_dp.get("criterios") or [])}
    rows = []
    for c in matriz_f2.get("criterios") or []:
        name = c.get("criterio")
        m = master_by.get(name) or {}
        f2_ok = bool(c.get("fase2_cumplido"))
        m_ok = bool(m.get("cumplido"))
        rows.append(
            {
                "criterio": name,
                "diferencial_fase2": f2_ok,
                "auditoria_maestra_antes": m_ok,
                "coincide": f2_ok == m_ok,
                "evidencia_fase2": c.get("evidencia"),
                "evidencia_maestra": m.get("evidencia"),
                "archivo_fase2": "data/audit_security_capabilities_20260725/run_fase2_readonly_differential.py + LIVE_READONLY_PROBE_FASE2.json",
                "archivo_maestra": "scripts/build_security_capabilities_audit_reports.py (antes: constantes False hardcodeadas)",
                "funcion_fase2": "score rows desde refresh_probe()",
                "funcion_maestra": "score_area Protección de Datos",
                "motivo_divergencia": (
                    None
                    if f2_ok == m_ok
                    else (
                        "La maestra usaba valor booleano HARDCODEADO del baseline 2026-07-25 "
                        f"(cumplido={m_ok}, evidencia congelada={m.get('evidencia')!r}) "
                        "e ignoraba la sonda LIVE / implementaciones Fase 1–2."
                    )
                ),
            }
        )
    return rows


def diagnose(rows: list[dict], components: dict) -> dict:
    diverged = [r for r in rows if not r["coincide"]]
    build_src = BUILD.read_text(encoding="utf-8")
    still_hardcoded = (
        'False, "NoEncryption / raw master_aes.key"' in build_src
        or 'False, "Fallback clave_secreta_definitiva_para_novus_2026"' in build_src
    )
    has_live_scorer = "def score_data_protection_criteria" in build_src
    return {
        "causa_raiz": (
            "La auditoría maestra NO leía una matriz JSON antigua de Fase 2; "
            "evaluaba Protección de Datos con CONSTANTES BOOLEANAS congeladas del baseline "
            "oficial 2026-07-25 (8/17 = 47.1%) dentro de build_security_capabilities_audit_reports.py. "
            "La diferencial Fase 2 sí evaluaba desde LIVE_READONLY_PROBE_FASE2.json "
            "(y LIVE_PROOF_DATA_PROTECTION_PHASE2.json) → 17/17 = 100%."
        ),
        "archivo_proceso": str(BUILD),
        "mecanismo": "hardcoded False + strings de evidencia obsoletas; no cache Redis; no rama git distinta requerida",
        "maestra_desactualizada": True,
        "maestra_ignoraba_implementaciones": True,
        "maestra_ignoraba_evidencias_fase2": True,
        "usaba_matriz_antigua_json": False,
        "usaba_directorio_diferente": (
            "Parcial: maestra escribe data/audit_master_novus pero el score oficial "
            "viene de build_security_capabilities_audit_reports.py + LIVE_READONLY_PROBE.json "
            "(incompleta en campos DP); Fase 2 usa LIVE_READONLY_PROBE_FASE2.json"
        ),
        "criterios_divergentes": len(diverged),
        "divergentes": [r["criterio"] for r in diverged],
        "fix_aplicado": has_live_scorer and not still_hardcoded,
        "still_hardcoded_literals": still_hardcoded,
        "componentes_todos_presentes": all(v.get("exists") for v in components.values() if v.get("file")),
        "componentes": components,
    }


def refresh_fase2_probe() -> dict:
    """Re-ejecuta sonda solo-lectura Fase 2 (sin mutar producto)."""
    path = OFF / "run_fase2_readonly_differential.py"
    spec = importlib.util.spec_from_file_location("fase2_diff", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    probe = mod.refresh_probe()
    (OFF / "LIVE_READONLY_PROBE_FASE2.json").write_text(
        json.dumps(probe, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    return {
        "ok": True,
        "aes_gcm": (probe.get("cryptovault") or {}).get("aes_gcm_roundtrip"),
        "aes_key_wrapped": (probe.get("cryptovault") or {}).get("aes_key_wrapped"),
        "max_age": (probe.get("key_rotation") or {}).get("aes_key_max_age_days"),
        "tls_1_3": (probe.get("tls") or {}).get("tls_1_3_verified"),
        "db_verify": ((probe.get("db_at_rest") or {}).get("verify") or {}).get("ok"),
        "backups": (probe.get("backups") or {}).get("count"),
    }


def main() -> int:
    # Snapshot BEFORE (maestra inconsistente) — comparison uses current master files on disk
    rows_before = criterion_comparison()
    components = component_inventory()
    diagnosis = diagnose(rows_before, components)

    fuentes = {
        "diferencial_fase2": {
            "script": "data/audit_security_capabilities_20260725/run_fase2_readonly_differential.py",
            "builder_alt": "scripts/build_phase2_differential_audit.py",
            "probe": "data/audit_security_capabilities_20260725/LIVE_READONLY_PROBE_FASE2.json",
            "proof": "data/audit_security_capabilities_20260725/LIVE_PROOF_DATA_PROTECTION_PHASE2.json",
            "matriz": "data/audit_security_capabilities_20260725/MATRIZ_DIFERENCIAL_FASE2.json",
            "evidencia": "data/audit_security_capabilities_20260725/EVIDENCIA_DIFERENCIAL_FASE2.json",
            "informe": "data/audit_security_capabilities_20260725/INFORME_DIFERENCIAL_PROTECCION_DATOS_FASE2.md",
            "resultado_area": "100.0% (17/17)",
        },
        "auditoria_maestra": {
            "script_orquestador": "scripts/run_master_audit_novus.py",
            "script_oficial_score": "scripts/build_security_capabilities_audit_reports.py",
            "probe_master": "data/audit_master_novus/LIVE_READONLY_PROBE_MASTER.json",
            "probe_oficial": "data/audit_security_capabilities_20260725/LIVE_READONLY_PROBE.json",
            "matriz": "data/audit_master_novus/MATRIZ_MAESTRA_NOVUS.json",
            "evidencia": "data/audit_master_novus/EVIDENCIA_MAESTRA.json",
            "resultado_area_antes": "47.1% (8/17)",
            "causa": "constantes hardcodeadas False en score Protección de Datos",
        },
        "metodologia_comun": {
            "criterios": 17,
            "binario": True,
            "parcial_igual_no_cumplido": True,
            "formula": "round(100.0 * met / total, 1)",
            "classify": ">=85 Enterprise; >=70 Empresarial; >=55 Avanzado; >=40 Intermedio",
        },
    }

    (OUT / "FUENTES_UTILIZADAS.json").write_text(
        json.dumps(fuentes, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (OUT / "COMPARACION_CRITERIO_POR_CRITERIO.json").write_text(
        json.dumps(
            {
                "fecha": STARTED,
                "antes_correccion": True,
                "diferencial_pct": 100.0,
                "maestra_pct": 47.1,
                "criterios": rows_before,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    diag_md = [
        "# Diagnóstico causa raíz — inconsistencia Protección de Datos",
        "",
        f"**Fecha:** {STARTED}",
        "",
        "## Veredicto",
        "",
        diagnosis["causa_raiz"],
        "",
        f"**Archivo/proceso:** `{diagnosis['archivo_proceso']}`",
        "",
        "## Qué NO era",
        "",
        "- No era una rama git distinta (mismo repo).",
        "- No era un cache Redis/memoria de porcentajes.",
        "- No era que DPAPI/Keyring/CryptoVault hubieran dejado de existir.",
        "- No era que la maestra leyera `MATRIZ_DIFERENCIAL_FASE2.json` y la ignorara: **nunca la leía**.",
        "",
        "## Qué SÍ era",
        "",
        "1. `build_security_capabilities_audit_reports.py` tenía 9 criterios DP con `False` literal y evidencias del baseline 47.1%.",
        "2. Solo leía de la sonda `aes_gcm_roundtrip` y ECC; el resto estaba congelado.",
        "3. La sonda maestra (`LIVE_READONLY_PROBE.json`) además venía incompleta (`key_rotation: {}`, sin `db_at_rest`/`backups`/`cookies`).",
        "4. Fase 2 usaba `refresh_probe()` completo → 100%.",
        "",
        "## Criterios divergentes",
        "",
    ]
    for name in diagnosis["divergentes"]:
        diag_md.append(f"- {name}")
    diag_md += [
        "",
        "## Componentes en código actual",
        "",
    ]
    for name, info in components.items():
        diag_md.append(
            f"- **{name}**: exists={info['exists']} file=`{info['file']}` line={info['line']} ({info['symbol']})"
        )
    (OUT / "DIAGNOSTICO_CAUSA_RAIZ.md").write_text("\n".join(diag_md) + "\n", encoding="utf-8")

    # Refresh Fase2 probe + re-run official + master deliverables
    probe_summary = refresh_fase2_probe()
    import subprocess

    r1 = subprocess.run([sys.executable, str(BUILD)], cwd=str(ROOT), capture_output=True, text=True)
    r2 = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "refresh_master_deliverables.py")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )

    official = _load_json(OFF / "EVIDENCE_SECURITY_CAPABILITIES.json")
    master = _load_json(MASTER / "EVIDENCIA_MAESTRA.json")
    dp_official = next((a for a in (official.get("areas") or []) if a.get("area") == "Protección de Datos"), {})
    rows_after = []
    f2 = _load_json(OFF / "MATRIZ_DIFERENCIAL_FASE2.json")
    after_by = {c["criterio"]: c for c in (dp_official.get("criterios") or [])}
    for c in f2.get("criterios") or []:
        name = c.get("criterio")
        a = after_by.get(name) or {}
        rows_after.append(
            {
                "criterio": name,
                "diferencial_fase2": bool(c.get("fase2_cumplido")),
                "auditoria_maestra_despues": bool(a.get("cumplido")),
                "coincide_despues": bool(c.get("fase2_cumplido")) == bool(a.get("cumplido")),
                "evidencia_maestra_despues": a.get("evidencia"),
            }
        )

    glob = official.get("global") or {}
    corrected_md = [
        "# Auditoría Maestra Corregida — NOVUS",
        "",
        f"**Fecha:** {datetime.now().isoformat(timespec='seconds')}",
        "**Corrección:** evaluación LIVE de Protección de Datos (sin cambiar criterios/fórmula).",
        "",
        "## Madurez global",
        "",
        f"- **{glob.get('porcentaje')}%** — {glob.get('clasificacion')}",
        f"- Cumplidos: **{glob.get('criterios_cumplidos')}/{glob.get('criterios_totales')}**",
        "",
        "## Protección de Datos",
        "",
        f"- **{dp_official.get('porcentaje')}%** — {dp_official.get('clasificacion')}",
        f"- Cumplidos: **{dp_official.get('cumplidos')}/{dp_official.get('total_criterios')}**",
        f"- Pendientes: **{dp_official.get('pendientes')}**",
        "",
        "## Criterios DP",
        "",
        "| Criterio | Cumplido | Evidencia |",
        "|----------|----------|-----------|",
    ]
    for c in dp_official.get("criterios") or []:
        corrected_md.append(
            f"| {c.get('criterio')} | {'SÍ' if c.get('cumplido') else 'NO'} | `{str(c.get('evidencia'))[:80]}` |"
        )
    corrected_md += [
        "",
        "## Matriz global por área",
        "",
        "| Área | % | Clase | Cumplidos |",
        "|------|---|-------|-----------|",
    ]
    for a in official.get("areas") or []:
        corrected_md.append(
            f"| {a.get('area')} | {a.get('porcentaje')}% | {a.get('clasificacion')} | "
            f"{a.get('cumplidos')}/{a.get('total_criterios')} |"
        )
    (OUT / "AUDITORIA_MAESTRA_CORREGIDA.md").write_text("\n".join(corrected_md) + "\n", encoding="utf-8")
    write_pdf(
        OUT / "AUDITORIA_MAESTRA_CORREGIDA.pdf",
        "Auditoria Maestra Corregida NOVUS",
        [
            f"Global {glob.get('porcentaje')}% ({glob.get('clasificacion')})",
            f"Criterios {glob.get('criterios_cumplidos')}/{glob.get('criterios_totales')}",
            f"Proteccion de Datos {dp_official.get('porcentaje')}% ({dp_official.get('cumplidos')}/{dp_official.get('total_criterios')})",
            "",
        ]
        + [f"{a.get('area')}: {a.get('porcentaje')}%" for a in (official.get("areas") or [])],
    )

    consistency = {
        "fecha": STARTED,
        "diagnosis": diagnosis,
        "probe_refresh": probe_summary,
        "build_exit": r1.returncode,
        "build_stdout_tail": (r1.stdout or "")[-800:],
        "build_stderr_tail": (r1.stderr or "")[-800:],
        "refresh_master_exit": r2.returncode,
        "refresh_master_stdout": (r2.stdout or "")[-500:],
        "antes": {"proteccion_datos_maestra": 47.1, "proteccion_datos_fase2": 100.0, "global_maestra": 79.2},
        "despues": {
            "proteccion_datos_oficial": dp_official.get("porcentaje"),
            "proteccion_datos_cumplidos": f"{dp_official.get('cumplidos')}/{dp_official.get('total_criterios')}",
            "global": glob,
            "master_global": (master.get("global") or {}),
        },
        "comparacion_despues": rows_after,
        "alineacion_fase2": all(r["coincide_despues"] for r in rows_after),
    }
    (OUT / "EVIDENCIA_CONSISTENCIA.json").write_text(
        json.dumps(consistency, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    (OUT / "COMPARACION_CRITERIO_POR_CRITERIO.json").write_text(
        json.dumps(
            {
                "fecha": STARTED,
                "antes": rows_before,
                "despues": rows_after,
                "fase2_pct": 100.0,
                "maestra_antes_pct": 47.1,
                "maestra_despues_pct": dp_official.get("porcentaje"),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    informe = [
        "# Informe de Consistencia Oficial — Auditorías NOVUS",
        "",
        f"**Fecha:** {STARTED}",
        "",
        "## Resumen ejecutivo",
        "",
        "La diferencia **100% (Fase 2)** vs **47.1% (Maestra)** en Protección de Datos NO indica",
        "regresión de producto. La maestra evaluaba con **constantes hardcodeadas** del baseline",
        "2026-07-25 en `build_security_capabilities_audit_reports.py`, mientras Fase 2 medía",
        "sonda LIVE completa.",
        "",
        f"**Tras corrección de fuente (sin cambiar criterios/fórmula):** Protección de Datos "
        f"**{dp_official.get('porcentaje')}%** ({dp_official.get('cumplidos')}/{dp_official.get('total_criterios')}); "
        f"Global **{glob.get('porcentaje')}%** ({glob.get('criterios_cumplidos')}/{glob.get('criterios_totales')}) — "
        f"{glob.get('clasificacion')}.",
        "",
        "## Causa raíz",
        "",
        diagnosis["causa_raiz"],
        "",
        f"- Fix aplicado: `{diagnosis['fix_aplicado']}`",
        f"- Alineación post-fix con Fase 2: `{consistency['alineacion_fase2']}`",
        "",
        "## Comparación criterio × criterio (antes)",
        "",
        "| Criterio | Fase2 | Maestra | Motivo |",
        "|----------|-------|---------|--------|",
    ]
    for r in rows_before:
        motivo = (r.get("motivo_divergencia") or "—")[:90]
        informe.append(
            f"| {r['criterio']} | {'SÍ' if r['diferencial_fase2'] else 'NO'} | "
            f"{'SÍ' if r['auditoria_maestra_antes'] else 'NO'} | {motivo} |"
        )
    informe += [
        "",
        "## Después de corregir la fuente",
        "",
        "| Criterio | Fase2 | Maestra | Coincide |",
        "|----------|-------|---------|----------|",
    ]
    for r in rows_after:
        informe.append(
            f"| {r['criterio']} | {'SÍ' if r['diferencial_fase2'] else 'NO'} | "
            f"{'SÍ' if r['auditoria_maestra_despues'] else 'NO'} | "
            f"{'SÍ' if r['coincide_despues'] else 'NO'} |"
        )
    informe += [
        "",
        "## Entregables",
        "",
        "- `INFORME_CONSISTENCIA_AUDITORIAS.md` / `.pdf`",
        "- `COMPARACION_CRITERIO_POR_CRITERIO.json`",
        "- `FUENTES_UTILIZADAS.json`",
        "- `DIAGNOSTICO_CAUSA_RAIZ.md`",
        "- `AUDITORIA_MAESTRA_CORREGIDA.md` / `.pdf`",
        "- `EVIDENCIA_CONSISTENCIA.json`",
        "",
        f"Probe refresh: `{probe_summary}`",
        f"build exit={r1.returncode} refresh_master exit={r2.returncode}",
    ]
    (OUT / "INFORME_CONSISTENCIA_AUDITORIAS.md").write_text("\n".join(informe) + "\n", encoding="utf-8")
    write_pdf(
        OUT / "INFORME_CONSISTENCIA_AUDITORIAS.pdf",
        "Informe Consistencia Auditorias NOVUS",
        [
            "Causa: constantes hardcodeadas en build_security_capabilities_audit_reports.py",
            f"Antes DP maestra 47.1% vs Fase2 100%",
            f"Despues DP {dp_official.get('porcentaje')}% Global {glob.get('porcentaje')}%",
            f"Alineacion Fase2={consistency['alineacion_fase2']}",
            f"Fix aplicado={diagnosis['fix_aplicado']}",
        ],
    )

    print(
        json.dumps(
            {
                "ok": r1.returncode == 0 and r2.returncode == 0,
                "out": str(OUT),
                "dp_despues": dp_official.get("porcentaje"),
                "global_despues": glob.get("porcentaje"),
                "alineacion": consistency["alineacion_fase2"],
                "fix": diagnosis["fix_aplicado"],
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0 if r1.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
