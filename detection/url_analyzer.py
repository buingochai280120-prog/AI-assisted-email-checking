from __future__ import annotations
import re
from urllib.parse import urlparse
from models.url_model import extract_url_features, load_url_model

URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)
SUSPICIOUS_TLDS = (".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".loan")


def extract_urls(text=""):
    return URL_RE.findall(str(text or ""))


def _heuristic_probability(url: str):
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.lower().split("@")[ -1 ].split(":")[0]
    score = 0
    reasons = []
    if parsed.scheme.lower() != "https":
        score += 25; reasons.append(f"Liên kết '{domain or url}' không sử dụng HTTPS")
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
        score += 35; reasons.append(f"Liên kết dùng địa chỉ IP '{domain}' thay vì tên miền")
    if "@" in url:
        score += 25; reasons.append("URL chứa ký tự @ có thể che giấu tên miền thật")
    if domain.endswith(SUSPICIOUS_TLDS):
        score += 20; reasons.append(f"Tên miền '{domain}' dùng TLD có rủi ro cao")
    if any(k in parsed.path.lower() for k in ("login", "verify", "secure", "account", "password", "otp")):
        score += 15; reasons.append(f"Đường dẫn '{parsed.path}' chứa từ khóa nhạy cảm")
    return min(score, 100) / 100.0, reasons


def analyze_urls(text=""):
    urls = extract_urls(text)
    if not urls:
        return {"score": 0, "probability": 0.0, "urls": [], "reasons": [], "model_used": False}
    model = load_url_model()
    probs, reasons = [], []
    for url in urls:
        heuristic_p, rs = _heuristic_probability(url)
        reasons.extend(rs)
        if model is not None:
            try:
                ml_p = float(model.predict_proba([extract_url_features(url)])[0][1])
                p = 0.65 * ml_p + 0.35 * heuristic_p
            except Exception:
                p = heuristic_p
        else:
            p = heuristic_p
        probs.append(p)
    probability = max(probs) if probs else 0.0
    return {
        "score": round(probability * 100),
        "probability": probability,
        "urls": urls,
        "reasons": list(dict.fromkeys(reasons)),
        "model_used": model is not None,
    }
