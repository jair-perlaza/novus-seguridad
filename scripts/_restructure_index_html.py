#!/usr/bin/env python3
"""Mueve inline script al final del body y restaura Tailwind original + fallback jsDelivr."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "templates" / "index.html"

TAILWIND_BLOCK = """
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
    (function () {
      var loaded = false;
      function loadFallback() {
        if (loaded) return;
        loaded = true;
        var s = document.createElement('script');
        s.src = 'https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4';
        document.head.appendChild(s);
      }
      document.addEventListener('DOMContentLoaded', function () {
        if (window.tailwind && typeof window.tailwind.refresh === 'function') {
          window.tailwind.refresh();
        }
      });
      var primary = document.querySelector('script[src="https://cdn.tailwindcss.com"]');
      if (primary) {
        primary.addEventListener('error', loadFallback);
        setTimeout(function () {
          if (!window.tailwind) loadFallback();
        }, 2500);
      } else {
        loadFallback();
      }
    })();
    </script>
""".strip(
    "\n"
)


def main() -> None:
    text = INDEX.read_text(encoding="utf-8")
    head_end = text.index("</head>") + len("</head>")
    body_start = text.index("<body", head_end)
    between = text[head_end:body_start]
    if "<script>" in between:
        s = between.index("<script>")
        e = between.index("</script>", s) + len("</script>")
        inline = between[s:e].strip()
        head_part = text[:head_end]
        body_part = text[body_start:]
    else:
        inline = ""
        head_part = text[:head_end]
        body_part = text[body_start:]

    head_part = re.sub(
        r"<!-- Tailwind browser:.*?@tailwindcss/browser@4\"></script>\s*",
        "",
        head_part,
        flags=re.S,
    )
    head_part = re.sub(
        r'<script src="https://cdn\.tailwindcss\.com"></script>\s*',
        "",
        head_part,
    )
    head_part = re.sub(
        r'<script src="https://cdn\.jsdelivr\.net/npm/@tailwindcss/browser@4"></script>\s*',
        "",
        head_part,
    )
    chart_tag = '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>'
    if chart_tag in head_part:
        head_part = head_part.replace(chart_tag, TAILWIND_BLOCK + "\n    " + chart_tag, 1)
    else:
        head_part = head_part.replace("</head>", TAILWIND_BLOCK + "\n</head>", 1)

    marker = "{% include 'partials/global_search.html' %}"
    if inline and marker in body_part and inline not in body_part:
        body_part = body_part.replace(
            "    " + marker,
            inline + "\n\n    " + marker,
            1,
        )

    new_text = head_part + "\n\n" + body_part
    INDEX.write_text(new_text, encoding="utf-8")
    print("OK: index.html restructured; inline_script_moved=", bool(inline))


if __name__ == "__main__":
    main()
