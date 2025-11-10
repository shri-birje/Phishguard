import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
from modules.features import extract_features_from_url  # or modules.homoglyph if you prefer

# 1️⃣ Load dataset (should have columns 'domain' or 'url' and 'label')
df = pd.read_csv("data/labeled_urls.csv")

# If dataset uses 'domain' instead of 'url'
if 'url' not in df.columns and 'domain' in df.columns:
    df = df.rename(columns={'domain': 'url'})

print(f"✅ Loaded {len(df)} samples")

# 2️⃣ Extract features
feature_list = []
labels = []

for _, row in df.iterrows():
    url = row['url']
    features = extract_features_from_url(url)
    feature_list.append(features)
    labels.append(row['label'])

X = pd.DataFrame(feature_list)
y = np.array(labels)

print(f"Extracted {X.shape[1]} features for {X.shape[0]} samples")

# 3️⃣ Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# 4️⃣ Train Random Forest
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# 5️⃣ Evaluate
y_pred = model.predict(X_test)
print("\n📊 Model Evaluation:")
print("Accuracy:", round(accuracy_score(y_test, y_pred), 4))
print(classification_report(y_test, y_pred))

# 6️⃣ Save model
joblib.dump(model, "rf_model.joblib")
print("\n✅ Model saved as rf_model.joblib")
