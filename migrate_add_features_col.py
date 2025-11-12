# migrate_add_features_col.py
import sqlite3, os

db_path = os.path.join(os.path.dirname(__file__), "phishing_logs.db")
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Check if column already exists
cur.execute("PRAGMA table_info(logs)")
cols = [c[1] for c in cur.fetchall()]

if "features_json" not in cols:
    cur.execute("ALTER TABLE logs ADD COLUMN features_json TEXT")
    conn.commit()
    print("✅ Added 'features_json' column to logs table.")
else:
    print("✅ 'features_json' column already exists — nothing to change.")

conn.close()
