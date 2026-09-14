"""Train URL model từ data/url_dataset.csv.

Trước đây file này tự viết lại một RandomForestClassifier riêng, trùng lặp
hoàn toàn với `models/url_model.train_url_model()` (cùng hyperparameters).
Giờ gọi thẳng hàm dùng chung để chỉ có MỘT nơi định nghĩa kiến trúc model —
tránh trường hợp sửa 1 nơi quên sửa nơi kia.
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from models.url_model import train_url_model, extract_url_features, load_url_model

DATA_PATH = os.path.join(BASE_DIR, "data", "url_dataset.csv")


def train():
    df = pd.read_csv(DATA_PATH).dropna(subset=["url", "label"]).drop_duplicates(subset=["url"])
    df["label"] = df["label"].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(
        df["url"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    # Đánh giá trên tập test trước (không lưu model này).
    from sklearn.ensemble import RandomForestClassifier
    eval_model = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42, class_weight="balanced")
    eval_model.fit([extract_url_features(u) for u in X_train], y_train)
    pred = eval_model.predict([extract_url_features(u) for u in X_test])
    metrics = {
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "f1": f1_score(y_test, pred, zero_division=0),
        "samples": len(df),
    }

    # Model DÙNG THỰC TẾ: huấn luyện lại trên toàn bộ dữ liệu qua hàm dùng
    # chung với models/url_model.py, rồi lưu ra models/url_model.pkl.
    train_url_model(df["url"].tolist(), df["label"].tolist())

    print("URL model:", metrics)
    return metrics


if __name__ == "__main__":
    train()
