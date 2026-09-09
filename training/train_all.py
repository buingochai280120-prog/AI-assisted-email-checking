import os
import json
import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)

# =========================
# PATH CONFIGURATION
# =========================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(
    BASE_DIR,
    "data",
    "training_data.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

REPORT_DIR = os.path.join(
    BASE_DIR,
    "data"
)

os.makedirs(MODEL_DIR, exist_ok=True)


# =========================
# LOAD DATASET
# =========================

print("=" * 60)
print("EMAIL GUARD AI - TEXT MODEL TRAINING")
print("=" * 60)

print("\n[1] Loading dataset...")

df = pd.read_csv(DATA_PATH)

# Kiểm tra các cột bắt buộc
required_columns = {"text", "label"}

if not required_columns.issubset(df.columns):
    raise ValueError(
        f"Dataset must contain columns: {required_columns}"
    )

# Xóa dữ liệu rỗng
df = df.dropna(subset=["text", "label"])

# Chuyển text về string
df["text"] = df["text"].astype(str)

# Chuyển label về integer
df["label"] = df["label"].astype(int)

print(f"Dataset size: {len(df)} emails")

print("\nLabel distribution:")
print(df["label"].value_counts())


# =========================
# FEATURES / LABEL
# =========================

X = df["text"]
y = df["label"]


# =========================
# TRAIN / TEST SPLIT
# =========================

print("\n[2] Splitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print(f"Training samples: {len(X_train)}")
print(f"Testing samples: {len(X_test)}")


# =========================
# TEXT MODEL
# TF-IDF + MULTINOMIAL NB
# =========================

print("\n[3] Training Text Model...")

text_model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True
        )
    ),
    (
        "classifier",
        MultinomialNB()
    )
])

text_model.fit(X_train, y_train)

print("Text Model training completed.")


# =========================
# EVALUATION
# =========================

print("\n[4] Evaluating model...")

y_pred = text_model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)
recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)
f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)

print("\nModel Performance")
print("-" * 40)
print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)


# =========================
# SAVE TEXT MODEL
# =========================

model_path = os.path.join(
    MODEL_DIR,
    "text_model.pkl"
)

joblib.dump(text_model, model_path)

print(f"\n[5] Model saved to:")
print(model_path)


# =========================
# SAVE MODEL REPORT
# =========================

report = {
    "model": "TF-IDF + Multinomial Naive Bayes",
    "dataset": "data/training_data.csv",
    "total_samples": int(len(df)),
    "training_samples": int(len(X_train)),
    "testing_samples": int(len(X_test)),
    "metrics": {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1)
    }
}

report_path = os.path.join(
    REPORT_DIR,
    "model_report.json"
)

with open(
    report_path,
    "w",
    encoding="utf-8"
) as f:
    json.dump(
        report,
        f,
        indent=4,
        ensure_ascii=False
    )

print(f"\n[6] Report saved to:")
print(report_path)

print("\n" + "=" * 60)
print("TEXT MODEL TRAINING FINISHED")
print("=" * 60)
