# auto_retrain.py
import os
import sqlite3
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import json
from modules.features import extract_features_from_url

ROOT = os.path.dirname(__file__)
DB_PATH = os.path.join(ROOT, "phishing_logs.db")
DATA_CSV = os.path.join(ROOT, "data", "labeled_urls.csv")  # expected columns: url,label
MODEL_PATH = os.path.join(ROOT, "rf_model.joblib")
BLACKLIST_PATH = os.path.join(ROOT, "blacklist.txt")

# thresholds
POSITIVE_SCORE_THRESHOLD = 70.0   # logs with phishing_score >= this considered positive phishing examples
MIN_POSITIVE = 10                 # require at least this many positive new examples to retrain
RANDOM_STATE = 42

def ensure_retrain_table(conn):
    conn.execute(
        """CREATE TABLE IF NOT EXISTS retrain_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER UNIQUE,
            used_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.commit()

def fetch_new_examples(conn):
    # pick logs with high phishing_score and not used before
    cur = conn.cursor()
    cur.execute(
        "SELECT id, url, phishing_score, features_json FROM logs WHERE phishing_score >= ? ORDER BY id ASC",
        (POSITIVE_SCORE_THRESHOLD,),
    )
    rows = cur.fetchall()
    # filter out those that exist in retrain_history
    good = []
    for r in rows:
        log_id = r[0]
        # check retrain_history
        cur2 = conn.cursor()
        cur2.execute("SELECT 1 FROM retrain_history WHERE log_id = ?", (log_id,))
        if cur2.fetchone():
            continue
        url = r[1]
        # attempt label=1 (phishing)
        good.append({"url": url, "label": 1, "log_id": log_id})
    return good

def load_labeled_csv():
    if os.path.exists(DATA_CSV):
        df = pd.read_csv(DATA_CSV)
        if "url" in df.columns and "label" in df.columns:
            return df[["url", "label"]].copy()
    return pd.DataFrame(columns=["url", "label"])

def extract_features_for_df(df):
    features = []
    for _, r in df.iterrows():
        f = extract_features_from_url(r["url"])
        features.append(f)
    X = pd.DataFrame(features).fillna(0)
    return X

def mark_logs_used(conn, log_ids):
    cur = conn.cursor()
    for lid in log_ids:
        cur.execute("INSERT OR IGNORE INTO retrain_history (log_id) VALUES (?)", (lid,))
    conn.commit()

def maybe_blacklist(domains):
    # append to blacklist file if not present
    if not domains:
        return
    existing = set()
    if os.path.exists(BLACKLIST_PATH):
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
            existing = set(l.strip() for l in f if l.strip())
    appended = []
    with open(BLACKLIST_PATH, "a", encoding="utf-8") as f:
        for d in domains:
            d = d.strip().lower()
            if not d or d in existing:
                continue
            f.write(d + "\n")
            appended.append(d)
    return appended

def main():
    conn = sqlite3.connect(DB_PATH)
    ensure_retrain_table(conn)

    # 1) load labeled CSV (existing dataset)
    df_csv = load_labeled_csv()

    # 2) pull new high-confidence positive logs
    new_examples = fetch_new_examples(conn)
    df_new = pd.DataFrame(new_examples) if new_examples else pd.DataFrame(columns=["url", "label"])
    if not df_csv.empty:
        # unify
        df_all = pd.concat([df_csv.rename(columns={"url": "url", "label": "label"}), df_new[["url", "label"]]], ignore_index=True)
    else:
        df_all = df_new[["url", "label"]].copy()

    # need at least some positives and negatives
    if df_all.empty:
        print("No training data found (no CSV or new positive logs).")
        return

    # if too few positive examples, abort unless CSV already has good data
    if df_all['label'].sum() < 5:
        print("Not enough positive labeled examples to retrain (need >=5). Found:", int(df_all['label'].sum()))
        return

    # 3) extract features
    print("Extracting features for", len(df_all), "rows...")
    X = extract_features_for_df(df_all)
    y = df_all['label'].astype(int).values

    # 4) train/test split and train
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, stratify=y, random_state=RANDOM_STATE)
    print("Training RandomForest...")
    model = RandomForestClassifier(n_estimators=200, random_state=RANDOM_STATE)
    model.fit(X_train, y_train)

    # 5) evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print("Accuracy:", acc)
    print(classification_report(y_test, y_pred))

    # 6) save model with columns
    payload = {"model": model, "columns": list(X.columns)}
    joblib.dump(payload, MODEL_PATH)
    print("Saved model to", MODEL_PATH)

    # 7) mark used logs as used
    if not df_new.empty:
        mark_logs_used(conn, df_new['log_id'].tolist())
        # optionally add domains with very high score to blacklist
        # For simplicity, add the domain names (hostname portion)
        domains_to_blacklist = []
        for u in df_new['url']:
            host = u
            if host.startswith("http://") or host.startswith("https://"):
                host = urlparse(host).hostname or host
            domains_to_blacklist.append(host)
        appended = maybe_blacklist(domains_to_blacklist)
        if appended:
            print("Added to blacklist:", appended)

    print("Retrain complete.")

if __name__ == "__main__":
    main()
