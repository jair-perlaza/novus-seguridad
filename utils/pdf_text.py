"""Normalización de texto para PDF (Helvetica / Latin-1 en fpdf2)."""
from __future__ import annotations

import re
import unicodedata
from typing import Any

# Sustituciones explícitas antes de NFKD (tipografía Unicode frecuente en informes ES).
_UNICODE_MAP = {
    "\u2014": "-",  # em dash
    "\u2013": "-",  # en dash
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2026": "...",
    "\u00a0": " ",
    "\u2022": "-",
    "\u2212": "-",
}


def normalize_pdf_text(value: Any) -> str:
    """Texto seguro para fpdf2 con fuentes core (Latin-1)."""
    if value is None:
        return ""
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    for src, dst in _UNICODE_MAP.items():
        text = text.replace(src, dst)
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("latin-1", errors="replace").decode("latin-1")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", text)
    return re.sub(r"[ \t]+", " ", text).strip()


def normalize_pdf_multiline(value: Any) -> str:
    text = normalize_pdf_text(value)
    return re.sub(r"\n+", "\n", text.replace("\n", " ")).strip()
