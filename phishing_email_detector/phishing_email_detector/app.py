"""
app.py
-------
Flask web app for the Phishing Email Detection Model.

Loads the trained pipeline (TF-IDF + numeric features + Random Forest)
and lets a user paste email text to get a Phishing / Safe classification
with a confidence score and the red-flag features detected. Also
displays the model's accuracy and confusion matrix from training.
"""

import os
import json

import joblib
from flask import Flask, render_template, request, jsonify

from features import extract_numeric_features, FEATURE_NAMES

APP_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(APP_DIR, "model", "phishing_model.joblib")
METRICS_PATH = os.path.join(APP_DIR, "model", "metrics.json")

app = Flask(__name__)

_model = None
_metrics = None


def get_model():
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                "Model not found. Run 'python generate_dataset.py' then 'python train_model.py' first."
            )
        _model = joblib.load(MODEL_PATH)
    return _model


def get_metrics():
    global _metrics
    if _metrics is None and os.path.exists(METRICS_PATH):
        with open(METRICS_PATH) as f:
            _metrics = json.load(f)
    return _metrics or {}


@app.route("/")
def index():
    return render_template("index.html", metrics=get_metrics())


@app.route("/api/classify", methods=["POST"])
def api_classify():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()

    if not text:
        return jsonify({"error": "Please paste some email text to analyze."}), 400

    try:
        model = get_model()
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 500

    pred = model.predict([text])[0]
    proba = model.predict_proba([text])[0]  # [prob_safe, prob_phishing]

    numeric = extract_numeric_features(text)
    feature_breakdown = dict(zip(FEATURE_NAMES, numeric))

    result = {
        "label": "Phishing" if pred == 1 else "Safe",
        "is_phishing": bool(pred == 1),
        "confidence": round(float(max(proba)), 4),
        "probability_phishing": round(float(proba[1]), 4),
        "probability_safe": round(float(proba[0]), 4),
        "feature_breakdown": feature_breakdown,
    }
    return jsonify(result)


@app.route("/api/metrics")
def api_metrics():
    metrics = get_metrics()
    if not metrics:
        return jsonify({"error": "No metrics found. Train the model first."}), 404
    return jsonify(metrics)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5002)
