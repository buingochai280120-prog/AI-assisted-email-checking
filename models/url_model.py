"""Random-Forest URL classifier and feature extractor."""
from __future__ import annotations
import os, re, joblib
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "url_model.pkl")


def extract_url_features(url: str):
    url = str(url or "").strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.lower().split("@")[ -1 ].split(":")[0]
    path = parsed.path.lower()
    return [
        len(url), len(domain), len(path),
        int("@" in url), int("-" in domain),
        int(re.search(r"\d", domain) is not None),
        int(domain.count(".") >= 3),
        int(domain.endswith((".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf"))),
        int(parsed.scheme.lower() == "https"),
        int(bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain))),
        int(any(k in path for k in ("login", "verify", "secure", "account", "password", "otp"))),
    ]


def train_url_model(urls, labels):
    model = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42, class_weight="balanced")
    model.fit([extract_url_features(u) for u in urls], labels)
    joblib.dump(model, MODEL_PATH)
    return model


def load_url_model():
    if not os.path.exists(MODEL_PATH):
        return None
    try:
        return joblib.load(MODEL_PATH)
    except Exception:
        return None
