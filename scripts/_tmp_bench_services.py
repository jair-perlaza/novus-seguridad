import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

EMAIL = "operaciones@novapay-fintech.co"


def bench(label, fn, n=5):
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    print(f"{label}: p50={sorted(times)[len(times)//2]:.1f}ms max={max(times):.1f}ms")


from services.notification_center_service import list_notifications, unread_count

bench("unread_count", lambda: unread_count(EMAIL, notification_kind="security"))
bench("list_notifications", lambda: list_notifications(EMAIL, notification_kind="security", limit=50))

from services.defense_center_service import get_dashboard_summary

bench("manual_defense_summary", lambda: get_dashboard_summary(1), n=3)
