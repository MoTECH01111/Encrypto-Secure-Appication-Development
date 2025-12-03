import sqlite3

conn = sqlite3.connect("insecure.db")
c = conn.cursor()

try:
    c.execute("ALTER TABLE users ADD COLUMN last_seen DATETIME")
    print("Added last_seen column.")
except sqlite3.OperationalError as e:
    print("last_seen already exists or failed:", e)

try:
    c.execute("ALTER TABLE users ADD COLUMN is_online INTEGER DEFAULT 0")
    print("Added is_online column.")
except sqlite3.OperationalError as e:
    print("is_online already exists or failed:", e)

c.execute("UPDATE users SET last_seen = CURRENT_TIMESTAMP")

conn.commit()
conn.close()
