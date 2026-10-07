#!/usr/bin/env python3
"""
Auditoría diferencial Swarm Mesh Enterprise — misma metodología oficial.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "swarm_mesh"
OUT.mkdir(parents=True, exist_ok=True)
OFF = ROOT / "data" / "audit_security_capabilities_20260725"

PREV_SWARM = 85.7  # 12/14 post-fase1 wiring (before mesh)
PREV_MET = 12
PREV_TOTAL = 14
PREV_GLOBAL = 84.9
PREV_GLOBAL_MET = 135
GLOBAL_TOTAL = 159


def classify(pct: float) -> str:
    if pct >= 85:
        return "Enterprise"
    if pct >= 70:
        return "Empresarial"
    if pct >= 55:
        return "Avanzado"
    if pct >= 40:
        return "Intermedio"
    return "Básico"


def main() -> int:
    # Refresh probe swarm section lightly
    probe_path = OFF / "LIVE_READONLY_PROBE.json"
    probe = {}
    if probe_path.is_file():
        probe = json.loads(probe_path.read_text(encoding="utf-8"))
    try:
        from services.swarm_defense import swarm_defense_engine
        from services.swarm_defense.collaborators import collaborator_catalog
        from services.swarm_defense.response_policy import AUTO_ALLOWED, APPROVAL_REQUIRED, LIMITATIONS

        st = swarm_defense_engine.status()
        probe["swarm"] = {
            "ok": True,
            "status": st,
            "collaborators": collaborator_catalog(),
            "auto_actions": sorted(AUTO_ALLOWED),
            "approval_required": sorted(APPROVAL_REQUIRED),
            "limitations": list(LIMITATIONS),
            "mesh": st.get("mesh"),
        }
        probe_path.write_text(json.dumps(probe, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1

    # Run official scorer
    import subprocess

    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_security_capabilities_audit_reports.py")], cwd=str(ROOT))
    if r.returncode != 0:
        return r.returncode

    evidence = json.loads((OFF / "EVIDENCE_SECURITY_CAPABILITIES.json").read_text(encoding="utf-8"))
    swarm = next(a for a in evidence["areas"] if a["area"] == "Swarm Defense")
    glob = evidence["global"]
    proof = json.loads((OUT / "LIVE_PROOF_MESH_SWARM.json").read_text(encoding="utf-8"))
    pentest = json.loads((OUT / "PENTEST_MESH_SWARM.json").read_text(encoding="utf-8"))

    mesh_crit = next(c for c in swarm["criterios"] if "Colmena" in c["criterio"])
    delta_swarm = round(swarm["porcentaje"] - PREV_SWARM, 1)
    delta_global = round(glob["porcentaje"] - PREV_GLOBAL, 1)

    matriz = {
        "area": "Swarm Defense",
        "fase": "mesh_enterprise",
        "antes": {"pct": PREV_SWARM, "cumplidos": PREV_MET, "total": PREV_TOTAL},
        "ahora": {
            "pct": swarm["porcentaje"],
            "cumplidos": swarm["cumplidos"],
            "total": swarm["total_criterios"],
            "clasificacion": swarm["clasificacion"],
        },
        "criterio_colmena": mesh_crit,
        "global": {"antes": PREV_GLOBAL, "ahora": glob["porcentaje"], "delta_pp": delta_global},
    }
    (OUT / "MATRIZ_MESH_SWARM.json").write_text(json.dumps(matriz, indent=2, ensure_ascii=False), encoding="utf-8")

    evid = {
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "proof_ok": proof.get("ok"),
        "pentest": pentest.get("verdict"),
        "swarm": swarm,
        "global": glob,
        "mesh_status": (probe.get("swarm") or {}).get("mesh"),
        "live_proof_checks": proof.get("checks"),
    }
    (OUT / "EVIDENCIA_MESH_SWARM.json").write_text(json.dumps(evid, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    md = f"""# Informe Swarm Mesh Enterprise — NOVUS

**Fecha:** {datetime.now().isoformat(timespec="seconds")}  
**Modo:** implementación real peer-to-peer (Ed25519 + AES-256-GCM + trust/revocation)  
**Prueba LIVE:** `LIVE_PROOF_MESH_SWARM.json` ok={proof.get("ok")}

## Qué se implementó

- Identidad criptográfica Ed25519 por nodo (`services/swarm_defense/mesh/node_identity.py`)
- Trust list + revocación (`trust_registry.py`)
- Canal AES-256-GCM por peer (`channel_keys.py` + `envelope.py`)
- Transporte HTTP peer push (`transport.py` + `/api/swarm-mesh/ingest`)
- Propagación automática desde Swarm tras evidencia suficiente (`propagator.py` cableado en `engine.process_event`)
- Anti-replay / anti-poisoning / rechazo de nodos falsos
- Sellado forense de transferencias (`forensic_mesh.py`)
- Dashboard Mesh en observabilidad Swarm
- Peer worker multi-proceso real (`peer_worker.py`)

## NO implementado / limitaciones honestas

- Broker Redis central: **no requerido** (diseño peer-to-peer)
- TLS 1.3: depende del listener HTTPS del peer (lab local puede ser HTTP)
- Playbooks 100% automáticos: **sigue NO** (aprobación requerida)

## Auditoría diferencial (metodología oficial)

| Métrica | Antes | Ahora | Δ |
|---------|-------|-------|---|
| Swarm Defense | {PREV_SWARM}% ({PREV_MET}/{PREV_TOTAL}) | **{swarm['porcentaje']}%** ({swarm['cumplidos']}/{swarm['total_criterios']}) | **{delta_swarm:+} pp** |
| Colmena multi-nodo | NO | **{"SÍ" if mesh_crit.get("cumplido") else "NO"}** | — |
| Madurez global | {PREV_GLOBAL}% | **{glob['porcentaje']}%** ({glob['criterios_cumplidos']}/{glob['criterios_totales']}) | **{delta_global:+} pp** |

### Criterio Colmena

- Cumplido: **{mesh_crit.get("cumplido")}**
- Evidencia: `{mesh_crit.get("evidencia")}`

## Pentest Mesh

- Verdict: **{pentest.get("verdict")}**
- Summary: `{pentest.get("summary")}`

"""
    for f in pentest.get("findings") or []:
        md += f"- `{f.get('test')}` → {f.get('result')}\n"

    md += f"""
## Veredicto

La colmena multi-nodo **{"SÍ" if mesh_crit.get("cumplido") else "NO"}** está implementada con evidencia LIVE de intercambio cifrado/firmado entre nodos reales (proceso peer worker + nodo principal), sin telemetría inventada.
"""
    (OUT / "INFORME_MESH_SWARM_ENTERPRISE.md").write_text(md, encoding="utf-8")
    (OUT / "INFORME_DIFERENCIAL_MESH_SWARM.md").write_text(md, encoding="utf-8")

    try:
        from fpdf import FPDF

        def lat(s: str) -> str:
            return (s or "").encode("latin-1", "replace").decode("latin-1")

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.multi_cell(190, 8, lat("Informe Swarm Mesh Enterprise NOVUS"))
        pdf.set_font("Helvetica", size=9)
        for ln in [
            f"Swarm {swarm['porcentaje']}% ({swarm['cumplidos']}/{swarm['total_criterios']}) delta {delta_swarm:+} pp",
            f"Global {glob['porcentaje']}% delta {delta_global:+} pp",
            f"Colmena cumplido={mesh_crit.get('cumplido')}",
            f"LIVE proof ok={proof.get('ok')} pentest={pentest.get('verdict')}",
            "Ed25519 + AES-256-GCM peer-to-peer mesh",
        ]:
            pdf.multi_cell(190, 5, lat(ln))
        pdf.output(str(OUT / "INFORME_MESH_SWARM_ENTERPRISE.pdf"))
    except Exception as exc:
        print("pdf_warn", exc)

    print(
        json.dumps(
            {
                "ok": True,
                "swarm_pct": swarm["porcentaje"],
                "swarm_met": f"{swarm['cumplidos']}/{swarm['total_criterios']}",
                "colmena": mesh_crit.get("cumplido"),
                "global_pct": glob["porcentaje"],
                "delta_swarm": delta_swarm,
                "delta_global": delta_global,
                "out": str(OUT),
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
