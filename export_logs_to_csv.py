import sqlite3
import pandas as pd
from pathlib import Path

# Path to your SQLite database
DB_PATH = Path("phishing_logs.db")

if not DB_PATH.exists():
    print("❌ Database not found:", DB_PATH.resolve())
else:
    print("✅ Found database:", DB_PATH.resolve())

    # Connect to database
    conn = sqlite3.connect(DB_PATH)
    
    # Show available tables
    tables = pd.read_sql_query("SELECT name FROM sqlite_master WHERE type='table';", conn)
    print("\n📋 Tables in DB:\n", tables)

    # Load data from logs table
    df = pd.read_sql_query("SELECT * FROM logs;", conn)
    print(f"\n✅ Loaded {len(df)} rows from 'logs' table")

    # Export suspicious URLs (phishing_score > 70)
    suspicious = df[df['phishing_score'] > 70]
    Path("data").mkdir(exist_ok=True)
    suspicious['url'].dropna().to_csv("data/phish_raw.txt", index=False, header=False)

    print(f"\n💾 Exported {len(suspicious)} suspicious URLs to data/phish_raw.txt")

    conn.close()
