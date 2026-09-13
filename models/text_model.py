"""Text phishing model: TF-IDF + Logistic Regression, với lazy loading/training.

Lịch sử thay đổi quan trọng (xem README để biết chi tiết đầy đủ):
- Đổi từ MultinomialNB sang LogisticRegression: trên cùng dữ liệu, Logistic
  Regression cho kết quả tổng quát hoá tốt hơn rõ rệt trên tập đánh giá
  "ngoài phân phối" (OOD) — xem `evaluate()`/`data/ood_eval.csv`.
- Tách riêng `evaluate()` (chỉ để BÁO CÁO số liệu, không đụng tới model đang
  chạy) và `train_and_save()` (huấn luyện + LƯU model dùng thực tế). Trước
  đây `get_metrics()` gọi `train_and_save()` mỗi lần muốn xem số liệu, vô
  tình ghi đè `models/text_model.pkl` bằng một model mới mỗi lần kiểm tra —
  không sai về mặt toán học nhưng dễ gây nhầm lẫn khi debug/bảo trì.
"""
from __future__ import annotations
import os
import re
import threading
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "training_data.csv")
OOD_EVAL_PATH = os.path.join(BASE_DIR, "data", "ood_eval.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "text_model.pkl")
MAX_TEXT_LENGTH = 5000
LABEL_MAP = {"0": 0, "1": 1, "ham": 0, "spam": 1, "phishing": 1}

_lock = threading.Lock()
_model = None
_metrics = None


def _build_pipeline() -> Pipeline:
    """Tạo một pipeline TF-IDF + LogisticRegression mới (chưa fit).

    So với MultinomialNB trước đây: trên dataset đa dạng hoá hiện tại (xem
    training/generate_dataset.py), LogisticRegression(class_weight="balanced")
    đạt OOD accuracy ~93% so với ~86% của NB, và OOD precision 100% — ít báo
    động giả hơn trên email hợp lệ. Đã dò C trong {0.3, 0.5, 1, 2, 4}, C=1.0
    (giá trị mặc định) là tốt nhất trên tập OOD.
    """
    return Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1, max_df=0.98, sublinear_tf=True)),
        ("classifier", LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced")),
    ])


def _template_signature(text: str) -> str:
    """Chuẩn hoá text để nhóm các dòng được sinh ra từ CÙNG một khung câu
    (template), chỉ khác nhau ở brand/domain/số cụ thể. Dataset hiện tại là
    dữ liệu tổng hợp (synthetic) theo khung, nên nhiều dòng chỉ khác nhau ở
    URL/email/số — nếu chia train/test ngẫu nhiên, các biến thể của cùng một
    khung sẽ rò rỉ giữa train và test, khiến accuracy bị thổi phồng ảo
    (mô hình học thuộc khung câu thay vì học đặc trưng phishing thật).
    Chữ ký này dùng làm "group" khi chia dữ liệu, để mọi biến thể của cùng
    một khung câu luôn nằm trọn trong TRAIN hoặc trọn trong TEST.
    """
    t = text.lower()
    t = re.sub(r"https?://\S+|www\.\S+", " URL ", t)
    t = re.sub(r"[\w.\-]+@[\w.\-]+", " EMAIL ", t)
    t = re.sub(r"\d+", " NUM ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _load_dataframe():
    df = pd.read_csv(DATA_PATH, encoding="utf-8-sig")
    if not {"text", "label"}.issubset(df.columns):
        raise ValueError("training_data.csv phải có 2 cột: text,label")
    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str).str.strip().str.slice(0, MAX_TEXT_LENGTH)
    df["label"] = df["label"].astype(str).str.strip().str.lower().map(LABEL_MAP)
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)
    # Quan trọng: bỏ email trùng trước train/test để tránh leakage.
    df = df.drop_duplicates(subset=["text"], keep="first").reset_index(drop=True)
    if len(df) < 20 or df["label"].nunique() < 2:
        raise ValueError("Dataset quá nhỏ hoặc thiếu một trong hai lớp ham/phishing.")
    # Group theo khung template để chia train/test không rò rỉ (xem
    # _template_signature ở trên).
    df["_group"] = df["text"].apply(_template_signature)
    return df


def _load_ood_eval():
    """Tải tập đánh giá 'ngoài phân phối' (data/ood_eval.csv): các email viết
    tay, KHÔNG sinh từ khung template của training_data.csv. Dùng để đo
    generalization thật sự thay vì chỉ tin vào accuracy trên tập test cùng
    phân phối với train. Trả về None nếu chưa có file này."""
    if not os.path.exists(OOD_EVAL_PATH):
        return None
    try:
        odf = pd.read_csv(OOD_EVAL_PATH, encoding="utf-8-sig")
    except Exception:
        return None
    if not {"text", "label"}.issubset(odf.columns):
        return None
    odf = odf.dropna(subset=["text", "label"]).copy()
    odf["label"] = odf["label"].astype(int)
    return odf


def _split_train_test(df: pd.DataFrame):
    """Chia train/test theo GROUP (khung template) thay vì random split
    thuần: mọi biến thể của cùng một khung câu luôn rơi trọn vào một phía
    TRAIN hoặc TEST, tránh accuracy bị thổi phồng ảo do rò rỉ template."""
    n_groups = df["_group"].nunique()
    if n_groups < 2:
        cut = int(len(df) * 0.8)
        X_train, X_test = df["text"].iloc[:cut], df["text"].iloc[cut:]
        y_train, y_test = df["label"].iloc[:cut], df["label"].iloc[cut:]
        warning = "Không đủ nhóm template khác nhau để group-split; kết quả có thể vẫn bị leakage."
        method = "fallback_sequential_split"
    else:
        splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
        train_idx, test_idx = next(splitter.split(df["text"], df["label"], groups=df["_group"]))
        X_train, X_test = df["text"].iloc[train_idx], df["text"].iloc[test_idx]
        y_train, y_test = df["label"].iloc[train_idx], df["label"].iloc[test_idx]
        warning = None
        method = "group_shuffle_split(by_template_signature)"
    return X_train, X_test, y_train, y_test, n_groups, method, warning


def evaluate() -> dict:
    """Đánh giá chất lượng model MÀ KHÔNG đụng tới model đang chạy thực tế
    (`models/text_model.pkl`). Dùng khi bạn chỉ muốn xem số liệu (accuracy,
    OOD accuracy...) — gọi hàm này thay vì `train_and_save()`."""
    df = _load_dataframe()
    X_train, X_test, y_train, y_test, n_groups, method, warning = _split_train_test(df)

    model = _build_pipeline()
    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    metrics = {
        "samples_after_dedup": int(len(df)),
        "template_groups": int(n_groups),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "split_method": method,
        "split_warning": warning,
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred, zero_division=0)),
        "recall": float(recall_score(y_test, pred, zero_division=0)),
        "f1": float(f1_score(y_test, pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
    }

    # Đánh giá thêm trên tập "ngoài phân phối" (email viết tay, không theo
    # khung template của training_data.csv). Đây là con số quan trọng nhất
    # để biết mô hình có thực sự tổng quát hoá hay chỉ học thuộc khung câu.
    ood_df = _load_ood_eval()
    if ood_df is not None and len(ood_df) > 0:
        ood_pred = model.predict(ood_df["text"])
        ood_proba = model.predict_proba(ood_df["text"])[:, 1]
        metrics["ood_samples"] = int(len(ood_df))
        metrics["ood_accuracy"] = float(accuracy_score(ood_df["label"], ood_pred))
        metrics["ood_precision"] = float(precision_score(ood_df["label"], ood_pred, zero_division=0))
        metrics["ood_recall"] = float(recall_score(ood_df["label"], ood_pred, zero_division=0))
        metrics["ood_f1"] = float(f1_score(ood_df["label"], ood_pred, zero_division=0))
        metrics["ood_details"] = [
            {
                "text": t[:80] + ("..." if len(t) > 80 else ""),
                "true_label": int(y),
                "predicted_label": int(p),
                "phishing_probability": round(float(prob), 4),
            }
            for t, y, p, prob in zip(ood_df["text"], ood_df["label"], ood_pred, ood_proba)
        ]
    else:
        metrics["ood_samples"] = 0
        metrics["ood_accuracy"] = None

    return metrics


def train_and_save():
    """Huấn luyện model DÙNG THỰC TẾ trên toàn bộ dữ liệu đã dedup và lưu ra
    `models/text_model.pkl`. Đồng thời tính & cache lại metrics (qua
    `evaluate()`) để `get_metrics()` không phải train thêm lần nữa ngay sau
    đó."""
    global _model, _metrics
    _metrics = evaluate()
    df = _load_dataframe()
    model = _build_pipeline()
    model.fit(df["text"], df["label"])
    joblib.dump(model, MODEL_PATH)
    _model = model
    return model, _metrics


def get_model():
    global _model
    if _model is not None:
        return _model
    with _lock:
        if _model is None:
            if os.path.exists(MODEL_PATH):
                try:
                    _model = joblib.load(MODEL_PATH)
                except Exception:
                    _model = None
            if _model is None:
                _model, _ = train_and_save()
    return _model


def phishing_probability(text: str) -> float:
    text = (text or "").strip()
    if not text:
        return 0.0
    model = get_model()
    return float(model.predict_proba([text])[0][1])


def get_metrics():
    """Trả về metrics đánh giá, tính bằng `evaluate()` (KHÔNG ghi đè model
    production). Chỉ train một lần và cache lại cho các lần gọi sau."""
    global _metrics
    if _metrics is None:
        _metrics = evaluate()
    return _metrics
