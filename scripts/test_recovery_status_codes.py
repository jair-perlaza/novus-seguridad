#!/usr/bin/env python3
"""Verifica que recovery no enmascare 401/403 en API."""
from __future__ import annotations

import json
import sys

import requests

BASE = "http://127.0.0.1:5000"


def main() -> int:
    r = requests.get(BASE + "/api/dashboard/live", timeout=30)
    body = {}
    try:
        body = r.json()
    except Exception:
        pass
    ok = r.status_code == 401 and not body.get("_novusRecovery")
    print(json.dumps({"http": r.status_code, "recovery": bool(body.get("_novusRecovery")), "pass": ok}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
