"""
Path sandbox para AI delete/analyze — solo rutas bajo allowlist NOVUS.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]

# Raíces permitidas (relativas al repo / datos NOVUS)
DEFAULT_ALLOW = [
    ROOT / "data",
    ROOT / "quarantine",
    ROOT / "uploads",
    ROOT / "tmp",
]


def resolve_allowed_roots() -> list:
    extra = os.environ.get("NOVUS_AI_PATH_ALLOW", "")
    roots = list(DEFAULT_ALLOW)
    for p in extra.split(os.pathsep):
        p = p.strip()
        if p:
            roots.append(Path(p).resolve())
    return [r.resolve() for r in roots if r]


def is_path_allowed(filepath: str) -> Tuple[bool, str]:
    if not filepath or not str(filepath).strip():
        return False, "empty_path"
    try:
        target = Path(filepath).resolve()
    except Exception as exc:
        return False, f"resolve_error:{exc}"
    # Bloquear path traversal obvio ya resuelto
    for root in resolve_allowed_roots():
        try:
            root.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        try:
            target.relative_to(root)
            return True, str(target)
        except ValueError:
            continue
    return False, "outside_allowlist"


def sandbox_check(filepath: str) -> Dict[str, Any]:
    ok, detail = is_path_allowed(filepath)
    return {
        "allowed": ok,
        "detail": detail if ok else detail,
        "resolved": detail if ok else None,
        "allowlist_roots": [str(r) for r in resolve_allowed_roots()],
        "verified": True,
    }
