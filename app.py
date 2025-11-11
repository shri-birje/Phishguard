# app.py — full ready-to-paste file
import os
import sqlite3
import datetime
import json
from flask import Flask, request, g, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
import pandas as pd
import joblib

# -------------------------
# Configuration
# -------------------------
async_mode = "gevent"  # keep gevent as you used
DB_PATH = os.path.join(os.path.dirname(__file__), "phishing_logs.db")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "rf_model.joblib")
WEB_DIR = "web"  # your frontend folder
ML_WEIGHT = float(os.environ.get("ML_WEIGHT", 0.7))        # weight for ML probability (0..1)
HOMOGLYPH_WEIGHT = float(os.environ.get("HOMOGLYPH_WEIGHT", 0.3))  # weight for homoglyph score (0..100)

# -------------------------
# Flask app (serve frontend)
# -------------------------
app = Flask(__name__, static_folder=WEB_DIR, static_url_path="")
CORS(app)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "phishguard-final-secret")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=async_mode)

# -------------------------
# Load trained model (supports saved dict with 'model' and 'columns')
# -------------------------
model = None
model_columns = None
try:
    if os.path.exists(MODEL_PATH):
        loaded = joblib.load(MODEL_PATH)
        if isinstance(loaded, dict) and "model" in loaded and "columns" in loaded:
            model = loaded["model"]
            model_columns = loaded["columns"]
            print("✅ AI Model Loaded Successfully (with columns)!")
        else:
            model = loaded
            model_columns = None
            print("⚠️ AI Model loaded (no column metadata).")
    else:
        print("⚠️ Model file not found at", MODEL_PATH)
except Exception as e:
    model = None
    model_columns = None
    print("❌ Error loading model:", e)

# -------------------------
# DB helpers
# -------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.execute(
            """CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                url TEXT,
                homoglyph_score REAL,
                behavior_score REAL,
                phishing_score REAL,
                risk_level TEXT,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                url TEXT,
                level TEXT,
                message TEXT,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )
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
# Debug endpoint (inspect features & model outputs)
# POST JSON: { "url": "https://paypa1.com" }
# -------------------------
@app.route("/api/debug_features", methods=["POST"])
def api_debug_features():
    data = request.json or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "missing url"}), 400

    # load trusted list
    trusted_path = os.path.join(os.path.dirname(__file__), "trusted_domains.txt")
    try:
        with open(trusted_path, "r", encoding="utf-8") as f:
            trusted = [x.strip() for x in f if x.strip()]
    except Exception:
        trusted = []

    # compute homoglyph score + features
    try:
        from modules.homoglyph import analyze_homoglyph
        from modules.features import extract_features_from_url
    except Exception as e:
        return jsonify({"error": "missing modules.homoglyph or modules.features", "exception": str(e)}), 500

    homoglyph_score = analyze_homoglyph(url, trusted)
    features = extract_features_from_url(url, trusted_domains=trusted)

    result = {
        "url": url,
        "homoglyph_score": homoglyph_score,
        "features": features,
        "model_loaded": bool(model),
        "model_columns_present": bool(model_columns)
    }

    if model:
        try:
            X_df = pd.DataFrame([features]).fillna(0)
            if model_columns:
                # ensure all training columns exist in the DF
                for c in model_columns:
                    if c not in X_df.columns:
                        X_df[c] = 0.0
                X_df = X_df[model_columns]
            proba = model.predict_proba(X_df)[0].tolist()
            classes = model.classes_.tolist() if hasattr(model, "classes_") else []
            # robust single-class handling
            if len(proba) == 1:
                # model.predict_proba returned single value (rare). deduce which class is present
                if classes and classes[0] == 1:
                    probability_class1 = float(proba[0])
                else:
                    probability_class1 = 1.0 - float(proba[0])
            else:
                probability_class1 = float(proba[1])
            # blended phishing percent (scale probability to percent)
            blended_percent = round((probability_class1 * 100.0 * ML_WEIGHT) + (homoglyph_score * HOMOGLYPH_WEIGHT), 4)
            result.update({
                "predict_proba": proba,
                "classes": classes,
                "probability_class1": probability_class1,
                "blended_percent": blended_percent
            })
        except Exception as e:
            result["model_error"] = str(e)
    return jsonify(result)

# -------------------------
# Core API: /api/check
# -------------------------
@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.json or {}
    url = data.get("url", "")
    behavior = data.get("behavior", {})

    # load trusted domains
    trusted_path = os.path.join(os.path.dirname(__file__), "trusted_domains.txt")
    try:
        with open(trusted_path, "r", encoding="utf-8") as f:
            trusted = [x.strip() for x in f if x.strip()]
    except Exception:
        trusted = []

    # import local analyzers (they must exist)
    from modules.homoglyph import analyze_homoglyph
    from modules.behavior import analyze_behavior
    from modules.features import extract_features_from_url

    homoglyph_score = analyze_homoglyph(url, trusted)
    behavior_score = analyze_behavior(behavior)

    # default values
    phishing_score = 0.0
    prediction = 0

    if model:
        try:
            features = extract_features_from_url(url, trusted_domains=trusted)
            X_df = pd.DataFrame([features]).fillna(0)
            if model_columns:
                for c in model_columns:
                    if c not in X_df.columns:
                        X_df[c] = 0.0
                X_df = X_df[model_columns]

            proba = model.predict_proba(X_df)[0]
            classes = model.classes_.tolist() if hasattr(model, "classes_") else []
            if len(proba) == 1:
                single_class = classes[0] if classes else None
                if single_class == 1:
                    probability = float(proba[0])
                else:
                    probability = 1.0 - float(proba[0])
            else:
                probability = float(proba[1])

            # combine probabilities correctly (probability in 0..1, homoglyph_score 0..100)
            # Final phishing_score is percent (0..100)
            phishing_score = round((probability * 0.9) + (homoglyph_score * 0.1), 2)

            prediction = int(model.predict(X_df)[0])  # 0 or 1

            print(f"[DEBUG] ML raw probability for {url}: {probability:.6f}, homoglyph_score: {homoglyph_score}, blended_percent: {phishing_score}%, label_pred: {prediction}")

        except Exception as e:
            print("[WARN] model inference error:", e)
            # fallback heuristic
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

    # log
    db = get_db()
    db.execute(
        "INSERT INTO logs (session_id, url, homoglyph_score, behavior_score, phishing_score, risk_level, ts) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("static", url, homoglyph_score, behavior_score, phishing_score, risk, datetime.datetime.utcnow().isoformat()),
    )
    db.commit()

    if risk in ("Medium", "High"):
        db.execute(
            "INSERT INTO alerts (session_id, url, level, message, ts) VALUES (?, ?, ?, ?, ?)",
            ("static", url, risk, f"{risk} risk detected for {url}", datetime.datetime.utcnow().isoformat()),
        )
        db.commit()

    return jsonify({
        "url": url,
        "homoglyph_score": round(homoglyph_score, 2),
        "behavior_score": round(behavior_score, 2),
        "phishing_score": phishing_score,
        "risk_level": risk,
        "action": action
    })

# -------------------------
# SocketIO events (unchanged)
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

