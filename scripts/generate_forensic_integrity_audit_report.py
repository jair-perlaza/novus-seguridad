#!/usr/bin/env python3
"""Informe de auditoría del sistema forense de integridad."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "data", "forensic_integrity_audit")


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    from services.forensic_evidence_integrity_service import (
        HASH_ALGORITHM,
        SIGN_ALGORITHM,
        get_system_summary,
        run_full_verifier,
    )
    from services.forensic_evidence_keys import ensure_forensic_signing_key

    key_id = ensure_forensic_signing_key()
    summary = get_system_summary()
    verification = run_full_verifier()

    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hash_algorithm": HASH_ALGORITHM,
        "sign_algorithm": SIGN_ALGORITHM,
        "signature_key_id": key_id,
        "chain_mechanism": "prev_chain_hash + chain_hash SHA-256 por registro sellado",
        "immutable_store": "data/forensic_ledger/records.jsonl (solo append)",
        "tamper_detection": [
            "Recálculo content_hash_sha256",
            "Verificación firma Ed25519",
            "Enlace prev_chain_hash",
            "Coincidencia chain_head.json",
            "Registro en integrity_incidents.jsonl",
        ],
        "limitations": [
            "Sin WORM hardware",
            "Clave local en data/forensic_keys",
            "Legacy sin migrar no verificable en ledger hasta batch migrate",
        ],
        "summary": summary,
        "last_full_verification": {
            "total": verification.get("total"),
            "verified": verification.get("verified"),
            "compromised": verification.get("compromised"),
            "chain_breaks": verification.get("chain_breaks"),
        },
        "compliance_note": "No se certifica ISO 27037/NIST; mecanismos descritos son los implementados en código.",
    }
    json_path = os.path.join(OUT, "forensic_integrity_audit.json")
    md_path = os.path.join(OUT, "FORENSIC_INTEGRITY_AUDIT.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    md = [
        "# Auditoría — Sistema forense de integridad NOVUS",
        "",
        f"Generado: {report['generated_at']}",
        "",
        f"- Hash: **{HASH_ALGORITHM}**",
        f"- Firma: **{SIGN_ALGORITHM}** (key `{key_id}`)",
        f"- Registros sellados: **{summary.get('record_count')}**",
        f"- Última verificación: {verification.get('verified')} OK / {verification.get('compromised')} comprometidos",
        "",
        "## Cadena",
        report["chain_mechanism"],
        "",
        "## Inmutabilidad",
        report["immutable_store"],
        "",
        "## Detección de modificaciones",
        *[f"- {x}" for x in report["tamper_detection"]],
        "",
        "## Limitaciones",
        *[f"- {x}" for x in report["limitations"]],
    ]
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    print("Wrote", md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
