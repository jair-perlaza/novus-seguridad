#!/usr/bin/env python3
"""Phase1 profiling — read-only diagnostics."""
from __future__ import annotations

import sqlite3
import time
import urllib.request
from pathlib import Path

ROOT = Path(r"C:\NOVUS")
DB = ROOT / "novus_vault_v2.db"


def main() -> None:
    c = sqlite3.connect(str(DB))
    cur = c.cursor()
    for t in [
        "novus_notifications",
        "alertas",
        "logs",
        "usuarios",
        "tenant_monitoring_scope",
    ]:
        try:
            n = cur.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            print(f"COUNT {t}={n}")
        except Exception as exc:
            print(f"COUNT {t}=ERR {exc}")

    print("INDEXES novus_notifications:")
    for name, sql in cur.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='novus_notifications'"
    ):
        print(f"  {name}: {(sql or '')[:140]}")

    plan = cur.execute(
        "EXPLAIN QUERY PLAN SELECT * FROM novus_notifications "
        "WHERE (user_email=? OR user_email IS NULL) "
        "AND (tenant_id=? OR tenant_id IS NULL) "
        "AND status!='archived' "
        "ORDER BY created_at DESC LIMIT 50",
        ("x", "y"),
    ).fetchall()
    print("QUERY_PLAN:", plan)

    # Null-heavy rows amplify OR filters
    nulls = cur.execute(
        "SELECT "
        "SUM(CASE WHEN user_email IS NULL THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN tenant_id IS NULL THEN 1 ELSE 0 END), "
        "COUNT(*) "
        "FROM novus_notifications"
    ).fetchone()
    print(f"NULL_user_email={nulls[0]} NULL_tenant_id={nulls[1]} TOTAL={nulls[2]}")
    c.close()

    t0 = time.time()
    try:
        r = urllib.request.urlopen("http://127.0.0.1:5000/login", timeout=10)
        print(f"SERVER login={r.status} ms={round((time.time()-t0)*1000,1)}")
    except Exception as exc:
        print(f"SERVER_FAIL {type(exc).__name__}: {str(exc)[:160]} ms={round((time.time()-t0)*1000,1)}")


if __name__ == "__main__":
    main()
