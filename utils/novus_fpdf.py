"""PDF base class: normalización Unicode en cada celda (fpdf2 + Helvetica / Latin-1)."""
from __future__ import annotations

from utils.logger import logger
from utils.pdf_text import normalize_pdf_text


def create_novus_pdf():
    from fpdf import FPDF

    class NovusPDF(FPDF):
        def _norm(self, text):
            if text is None:
                return ""
            if not isinstance(text, str):
                text = str(text)
            return normalize_pdf_text(text)

        def cell(self, *args, **kwargs):
            if len(args) >= 3:
                args = (args[0], args[1], self._norm(args[2])) + args[3:]
            if "text" in kwargs:
                kwargs = dict(kwargs)
                kwargs["text"] = self._norm(kwargs["text"])
            return super().cell(*args, **kwargs)

        def multi_cell(self, *args, **kwargs):
            if len(args) >= 3:
                args = (args[0], args[1], self._norm(args[2])) + args[3:]
            if "text" in kwargs:
                kwargs = dict(kwargs)
                kwargs["text"] = self._norm(kwargs["text"])
            return super().multi_cell(*args, **kwargs)

        def write(self, h, text="", *args, **kwargs):
            return super().write(h, self._norm(text), *args, **kwargs)

        def safe_output(self, dest: str = ""):
            try:
                return self.output(dest)
            except Exception as exc:
                logger.error("FPDF output failed: %s", exc, exc_info=True)
                raise

    return NovusPDF()
