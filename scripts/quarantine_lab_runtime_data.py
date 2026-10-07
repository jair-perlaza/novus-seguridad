#!/usr/bin/env python3
"""Mueve datos lab/QA fuera del runtime de producción (no borra evidencia de auditoría)."""
from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QUARANTINE = ROOT / "data" / "lab_quarantine"
MANIFEST = QUARANTINE / "quarantine_manifest.json"

MOVES = [
    (ROOT / "data" / "imcm" / "by_tenant" / "QA-NOVUS-2026", QUARANTINE / "imcm" / "by_tenant" / "QA-NOVUS-2026"),
    (ROOT / "data" / "imcm" / "by_tenant" / "901.567.123-4", QUARANTINE / "imcm" / "by_tenant" / "901.567.123-4"),
    (ROOT / "data" / "imcm" / "incidents.jsonl", QUARANTINE / "imcm" / "incidents.jsonl"),
    (ROOT / "data" / "imcm" / "timeline.jsonl", QUARANTINE / "imcm" / "timeline.jsonl"),
    (ROOT / "data" / "imcm" / "comments.jsonl", QUARANTINE / "imcm" / "comments.jsonl"),
    (ROOT / "data" / "imcm" / "history.jsonl", QUARANTINE / "imcm" / "history.jsonl"),
    (ROOT / "data" / "kernel_memory" / "email_novus.qa.jul2026_at_example.com.json", QUARANTINE / "kernel_memory" / "email_novus.qa.jul2026_at_example.com.json"),
]


def _move_test_reports() -> list:
    moved = []
    reports = ROOT / "data" / "reports"
    if not reports.is_dir():
        return moved
    dest_dir = QUARANTINE / "reports"
    dest_dir.mkdir(parents=True, exist_ok=True)
    for path in reports.glob("*.json"):
        name = path.name.upper()
        if "TEST" in name or "QA-NOVUS" in name:
            target = dest_dir / path.name
            if path.exists():
                shutil.move(str(path), str(target))
                moved.append(str(path.relative_to(ROOT)))
    return moved


def main() -> int:
    QUARANTINE.mkdir(parents=True, exist_ok=True)
    actions = []
    for src, dst in MOVES:
        if not src.exists():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            actions.append({"src": str(src.relative_to(ROOT)), "action": "skip_exists", "dst": str(dst.relative_to(ROOT))})
            continue
        shutil.move(str(src), str(dst))
        actions.append({"src": str(src.relative_to(ROOT)), "action": "moved", "dst": str(dst.relative_to(ROOT))})

    report_moves = _move_test_reports()
    for rel in report_moves:
        actions.append({"src": rel, "action": "moved", "dst": f"data/lab_quarantine/reports/{Path(rel).name}"})

    manifest = {
        "quarantined_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "actions": actions,
        "note": "Datos preservados para auditoría; excluidos del runtime sin NOVUS_ALLOW_LAB_RUNTIME.",
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
