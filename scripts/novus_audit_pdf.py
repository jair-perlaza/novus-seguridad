import json
import re
from pathlib import Path

from fpdf import FPDF

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "novus_master_capability_audit"


def clean(t: str) -> str:
    t = str(t).replace("\u2014", "-").replace("\u2192", "->")
    return re.sub(r"[^\x20-\x7e\n]", "", t)


def main() -> None:
    cap = json.loads((OUT / "CAPABILITY_MATRIX.json").read_text(encoding="utf-8"))
    pdf = FPDF()
    pdf.set_auto_page_break(True, 12)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "NOVUS Master Capability Audit", ln=1)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, clean("Generated from live verification at http://127.0.0.1:5000"))
    pdf.ln(3)
    for k, v in cap["counts"].items():
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, clean(f"{k}: {v}"), ln=1)
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Module Status Summary", ln=1)
    pdf.set_font("Courier", "", 7)
    for r in cap["modules"]:
        st = clean(r["status"])
        mod = clean(r["module"])[:36]
        pdf.cell(0, 4, f"{mod}  {st}", ln=1)
    pdf_path = OUT / "MASTER_CAPABILITY_AUDIT.pdf"
    pdf.output(str(pdf_path))
    print(f"Wrote {pdf_path} ({pdf_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
