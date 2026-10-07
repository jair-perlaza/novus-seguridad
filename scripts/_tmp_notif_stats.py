import sqlite3
from pathlib import Path

db = Path(__file__).resolve().parents[1] / "novus_vault_v2.db"
c = sqlite3.connect(db)
cur = c.cursor()
cur.execute("SELECT COUNT(*) FROM novus_notifications")
print("total", cur.fetchone()[0])
cur.execute("SELECT COUNT(*) FROM novus_notifications WHERE status='unread'")
print("unread", cur.fetchone()[0])
cur.execute(
    "SELECT user_email, COUNT(*) c FROM novus_notifications GROUP BY user_email ORDER BY c DESC LIMIT 10"
)
print("top users", cur.fetchall())
cur.execute("SELECT COUNT(*) FROM novus_notifications WHERE user_email IS NULL")
print("null user", cur.fetchone()[0])
cur.execute(
    "SELECT COUNT(*) FROM novus_notifications WHERE status='unread' AND (user_email IS NULL OR user_email='')"
)
print("unread broadcast", cur.fetchone()[0])
