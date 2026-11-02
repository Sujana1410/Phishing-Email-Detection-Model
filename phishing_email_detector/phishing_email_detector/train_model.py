"""
train_model.py
----------------
Trains a phishing-email classifier using Scikit-learn.

Pipeline:
  - TF-IDF vectorization of the raw email text
  - Hand-crafted numeric features (URL count, suspicious keywords, etc.)
    combined via FeatureUnion
  - Random Forest classifier

Outputs:
  - model/phishing_model.joblib   (trained pipeline)
  - model/confusion_matrix.png    (visualization)
  - model/metrics.json            (accuracy, precision, recall, f1)

Run:
    python generate_dataset.py   # once, to create data/emails.csv
    python train_model.py
"""

import os
import json

import pandas as pd
import matplotlib
matplotlib.use("Agg")  # headless rendering
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)
import joblib

from features import NumericFeatureExtractor

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(APP_DIR, "data", "emails.csv")
MODEL_DIR = os.path.join(APP_DIR, "model")
STATIC_DIR = os.path.join(APP_DIR, "static")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")
CM_PATH = os.path.join(STATIC_DIR, "confusion_matrix.png")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")


def build_pipeline() -> Pipeline:
    # TfidfVectorizer accepts the raw list of email strings directly, so it
    # can sit straight inside the FeatureUnion alongside our numeric
    # extractor — no extra passthrough step needed.
    combined_features = FeatureUnion([
        ("tfidf", TfidfVectorizer(max_features=3000, ngram_range=(1, 2), stop_words="english")),
        ("numeric", NumericFeatureExtractor()),
    ])

    pipeline = Pipeline([
        ("features", combined_features),
        ("clf", RandomForestClassifier(n_estimators=200, max_depth=None, random_state=42, n_jobs=-1)),
    ])
    return pipeline


def plot_confusion_matrix(cm, labels=("Safe", "Phishing")):
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Confusion Matrix")

    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=14, fontweight="bold")

    fig.colorbar(im, ax=ax)
    fig.tight_layout()
    fig.savefig(CM_PATH, dpi=150)
    plt.close(fig)


def main():
    if not os.path.exists(DATA_PATH):
        raise SystemExit(
            f"Dataset not found at {DATA_PATH}. Run 'python generate_dataset.py' first."
        )

    df = pd.read_csv(DATA_PATH)
    X = df["text"].astype(str).tolist()
    y = df["label"].astype(int).tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = build_pipeline()
    print("Training model...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 score:  {f1:.4f}")
    print("\nClassification report:\n", classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))
    print("Confusion matrix:\n", cm)

    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(STATIC_DIR, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    plot_confusion_matrix(cm)

    metrics = {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": cm.tolist(),
        "labels": ["Safe", "Phishing"],
        "train_size": len(X_train),
        "test_size": len(X_test),
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nSaved model to {MODEL_PATH}")
    print(f"Saved confusion matrix plot to {CM_PATH}")
    print(f"Saved metrics to {METRICS_PATH}")


if __name__ == "__main__":
    main()
