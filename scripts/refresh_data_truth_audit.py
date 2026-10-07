#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import platform_hardening_global_audit as ph

truth = ph.data_truth_audit()
OUT = ROOT / "data" / "platform_hardening"
(OUT / "DATA_TRUTH_AUDIT.json").write_text(json.dumps(truth, indent=2, ensure_ascii=False), encoding="utf-8")
lines = [
    "# DATA TRUTH AUDIT — NOVUS",
    f"\nResultado: **{truth['overall_result']}**",
    f"\nProducción ficticia: {truth['classified_fake_scan']['production_fictitious_count']}",
    "\n## Clasificación",
]
for cls, cnt in truth["classified_fake_scan"]["by_classification"].items():
    lines.append(f"- {cls}: {cnt}")
(OUT / "DATA_TRUTH_AUDIT.md").write_text("\n".join(lines), encoding="utf-8")
print(json.dumps({"overall": truth["overall_result"], "fictitious": truth["classified_fake_scan"]["production_fictitious_count"]}))
