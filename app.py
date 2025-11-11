# app.py — full corrected version
import os
import sqlite3
import datetime
from flask import Flask, request, g, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
import pandas as pd
import joblib

# -------------------------
# Config
# -------------------------
async_mode = "gevent"
DB_PATH = os.path.join(os.path.dirname(__file__), "phishing_logs.db")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "rf_model.joblib")
WEB_DIR = "web"

app = Flask(__name__, static_folder=WEB_DIR, static_url_path="")
CORS(app)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "phishguard-final-secret")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=async_mode)

# -------------------------
# Load model
# -------------------------
model = None
model_columns = None
if os.path.exists(MODEL_PATH):
    try:
        loaded = joblib.load(MODEL_PATH)
        if isinstance(loaded, dict) and "model" in loaded and "columns" in loaded:
            model = loaded["model"]
            model_columns = loaded["columns"]
            print("✅ AI Model Loaded Successfully (with columns)!")
        else:
            model = loaded
            print("⚠️ Model loaded without columns metadata.")
    except Exception as e:
        print("❌ Error loading model:", e)
else:
    print("⚠️ Model not found! Run train_model.py first.")

# -------------------------
# Database helpers
# -------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                url TEXT,
                homoglyph_score REAL,
                behavior_score REAL,
                phishing_score REAL,
                risk_level TEXT,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP
            )""")
        db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                url TEXT,
                level TEXT,
                message TEXT,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP
            )""")
        db.commit()
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# -------------------------
# Frontend routes
# -------------------------
@app.route("/")
def serve_index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/<path:path>")
def serve_static_files(path):
    return send_from_directory(app.static_folder, path)

@app.route("/assets/<path:filename>")
def serve_assets(filename):
    return send_from_directory(os.path.join(app.static_folder, "assets"), filename)

# -------------------------
# Core API
# -------------------------
@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.json or {}
    url = data.get("url", "")
    behavior = data.get("behavior", {})

    trusted_path = os.path.join(os.path.dirname(__file__), "trusted_domains.txt")
    try:
        with open(trusted_path, "r", encoding="utf-8") as f:
            trusted = [x.strip() for x in f if x.strip()]
    except Exception:
        trusted = []

    from modules.homoglyph import analyze_homoglyph
    from modules.behavior import analyze_behavior
    from modules.features import extract_features_from_url

    homoglyph_score = analyze_homoglyph(url, trusted)
    behavior_score = analyze_behavior(behavior)

    phishing_score = 0.0
    prediction = 0

    if model:
        try:
            features = extract_features_from_url(url, trusted_domains=trusted)
            X_df = pd.DataFrame([features]).fillna(0)

            # ensure all expected cols exist
            if model_columns:
                for c in model_columns:
                    if c not in X_df.columns:
                        X_df[c] = 0.0
                X_df = X_df[model_columns]

            proba = model.predict_proba(X_df)[0]
            classes = model.classes_.tolist() if hasattr(model, "classes_") else []
            if len(proba) == 1:
                if classes and classes[0] == 1:
                    probability = float(proba[0])
                else:
                    probability = 1.0 - float(proba[0])
            else:
                probability = float(proba[1])

            # normalize homoglyph score to 0–1 range if needed
            if homoglyph_score > 1:
                homoglyph_score = homoglyph_score / 100.0

            # blend scores — 90% model + 10% homoglyph
            phishing_score = round(((probability * 0.9) + (homoglyph_score * 0.1)) * 100, 2)

            prediction = int(model.predict(X_df)[0])
            print(f"[DEBUG] ML prob={probability:.3f}, homoglyph_score={homoglyph_score}, blended={phishing_score}%")
        except Exception as e:
            print("[WARN] Model error:", e)
            phishing_score = round(0.7 * homoglyph_score + 0.3 * behavior_score, 2)
            prediction = 1 if phishing_score >= 50 else 0
    else:
        phishing_score = round(0.7 * homoglyph_score + 0.3 * behavior_score, 2)
        prediction = 1 if phishing_score >= 50 else 0

    # risk classification
    if phishing_score < 20:
        risk, action = "Low", "Allow"
    elif phishing_score < 60:
        risk, action = "Medium", "Warn"
    else:
        risk, action = "High", "Block"

    # log results
    db = get_db()
    db.execute(
        "INSERT INTO logs (session_id, url, homoglyph_score, behavior_score, phishing_score, risk_level, ts)"
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("static", url, homoglyph_score, behavior_score, phishing_score, risk, datetime.datetime.utcnow().isoformat()))
    db.commit()

    if risk in ("Medium", "High"):
        db.execute(
            "INSERT INTO alerts (session_id, url, level, message, ts)"
            "VALUES (?, ?, ?, ?, ?)",
            ("static", url, risk, f"{risk} risk detected for {url}", datetime.datetime.utcnow().isoformat()))
        db.commit()

    return jsonify({
        "url": url,
        "homoglyph_score": round(homoglyph_score * 100, 2),
        "behavior_score": round(behavior_score, 2),
        "phishing_score": phishing_score,
        "risk_level": risk,
        "action": action
    })

# -------------------------
# SocketIO (optional)
# -------------------------
@socketio.on("connect")
def on_connect():
    emit("connected", {"msg": "connected", "session_id": request.sid})

@socketio.on("join")
def on_join(data):
    room = data.get("room") or request.sid
    join_room(room)
    emit("joined", {"room": room}, room=request.sid)

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    print("⚙️ Using gevent async mode")
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)
