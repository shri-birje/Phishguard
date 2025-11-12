# train_model.py
"""
Train or retrain the PhishGuard model using extracted URL features.
✅ Works with modules/features.py
✅ Produces rf_model.joblib (with {'model', 'columns'})
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
from modules.features import extract_features_from_url
import random

# -------------------------
# Configuration
# -------------------------
DATA_PATH = os.path.join("data", "labeled_urls.csv")  # must exist or will generate synthetic
MODEL_PATH = "rf_model.joblib"
TRUSTED_PATH = "trusted_domains.txt"

os.makedirs("data", exist_ok=True)

# -------------------------
# Load or generate dataset
# -------------------------
def load_or_generate_dataset():
    if os.path.exists(DATA_PATH):
        print(f"📊 Loading dataset from {DATA_PATH}")
        df = pd.read_csv(DATA_PATH)
        if 'url' not in df.columns or 'label' not in df.columns:
            raise ValueError("CSV must have columns: url,label")
        return df
    else:
        print("⚠️ No labeled_urls.csv found. Generating minimal synthetic dataset...")
        benign = ["https://google.com", "https://amazon.com", "https://paypal.com"]
        phishing = ["https://g00gle.com", "https://paypa1.com", "https://secure-amazon-login.xyz"]
        urls = benign + phishing
        labels = [0, 0, 0, 1, 1, 1]
        df = pd.DataFrame({"url": urls, "label": labels})
        df.to_csv(DATA_PATH, index=False)
        return df

# -------------------------
# Feature extraction
# -------------------------
def extract_all_features(df):
    trusted = []
    if os.path.exists(TRUSTED_PATH):
        with open(TRUSTED_PATH, "r", encoding="utf-8") as f:
            trusted = [x.strip() for x in f if x.strip()]

    print("🔍 Extracting features for", len(df), "URLs...")
    rows = []
    for i, row in df.iterrows():
        url = row["url"]
        label = row["label"]
        try:
            feats = extract_features_from_url(url, trusted_domains=trusted)
            feats["label"] = int(label)
            feats["url"] = url
            rows.append(feats)
        except Exception as e:
            print(f"[WARN] {url}: {e}")
    df_feat = pd.DataFrame(rows).fillna(0)
    return df_feat

# -------------------------
# Train and evaluate
# -------------------------
def train_model(df_feat):
    X = df_feat.drop(columns=["label", "url"], errors="ignore")
    y = df_feat["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("📈 Training RandomForest model...")
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    print("✅ Accuracy:", round(accuracy_score(y_test, y_pred), 3))
    print(classification_report(y_test, y_pred, digits=3))

    # Save model with feature column order
    joblib.dump({"model": model, "columns": list(X.columns)}, MODEL_PATH)
    print(f"💾 Model saved to {MODEL_PATH} (with {len(X.columns)} features)")

# -------------------------
# Main entry
# -------------------------
def main():
    df = load_or_generate_dataset()
    df_feat = extract_all_features(df)
    train_model(df_feat)
    print("🎯 Done. You can now run: python app.py")

if __name__ == "__main__":
    main()
