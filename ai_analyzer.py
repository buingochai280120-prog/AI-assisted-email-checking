import re
import joblib
from urllib.parse import urlparse


# =========================
# LOAD MODELS
# =========================

text_model = joblib.load("models/text_model.pkl")
url_model = joblib.load("models/url_model.pkl")
meta_model = joblib.load("models/meta_model.pkl")


# =========================
# URL FEATURE EXTRACTION
# =========================

def extract_url_features(url):
    url = str(url).strip()

    try:
        parsed = urlparse(
            url if "://" in url else "http://" + url
        )

        domain = parsed.netloc.lower()
        path = parsed.path.lower()

    except Exception:
        domain = ""
        path = ""

    return [
        len(url),
        len(domain),
        len(path),
        int("@" in url),
        int("-" in domain),
        int(re.search(r"\d", domain) is not None),
        int(domain.count(".") >= 3),
        int(
            domain.endswith(
                (".xyz", ".top", ".click", ".tk", ".ml")
            )
        ),
        int(parsed.scheme == "https"),
    ]


# =========================
# EXTRACT URL FROM EMAIL
# =========================

def extract_urls(text):
    if not text:
        return []

    pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"

    return re.findall(pattern, str(text))


# =========================
# RULE SCORE
# =========================

def calculate_rule_score(text):
    text = str(text).lower()

    score = 0
    reasons = []

    urgent_words = [
        "urgent",
        "khẩn cấp",
        "ngay lập tức",
        "immediately",
        "24 hours",
        "24h",
        "suspended",
        "blocked",
        "khoa",
        "khóa",
    ]

    credential_words = [
        "password",
        "mat khau",
        "mật khẩu",
        "otp",
        "cvv",
        "credit card",
        "the ngan hang",
        "thẻ ngân hàng",
    ]

    money_words = [
        "lottery",
        "trúng thưởng",
        "trung thuong",
        "prize",
        "winner",
        "500 million",
        "tiền",
        "money",
    ]

    for word in urgent_words:
        if word in text:
            score += 15
            reasons.append("Có nội dung khẩn cấp hoặc đe dọa")

            break

    for word in credential_words:
        if word in text:
            score += 25
            reasons.append("Yêu cầu thông tin bảo mật")

            break

    for word in money_words:
        if word in text:
            score += 20
            reasons.append("Có dấu hiệu liên quan đến tiền hoặc phần thưởng")

            break

    urls = extract_urls(text)

    for url in urls:
        try:
            domain = urlparse(
                url if "://" in url else "http://" + url
            ).netloc.lower()

            if domain.endswith(
                (".xyz", ".top", ".click", ".tk", ".ml")
            ):
                score += 20
                reasons.append("URL sử dụng tên miền đáng ngờ")

            if re.match(
                r"^https?://\d+\.\d+\.\d+\.\d+",
                url
            ):
                score += 25
                reasons.append("URL sử dụng địa chỉ IP")

        except Exception:
            pass

    return min(score, 100), reasons


# =========================
# RISK LEVEL
# =========================

def get_risk_level(score):

    if score < 30:
        return "SAFE"

    if score < 60:
        return "SUSPICIOUS"

    return "DANGEROUS"


# =========================
# MAIN ANALYSIS
# =========================

def analyze_email(subject="", body=""):

    text = f"{subject} {body}".strip()

    if not text:
        return {
            "score": 0,
            "risk_level": "SAFE",
            "ml_probability": 0,
            "url_probability": 0,
            "reasons": []
        }

    # Text model
    text_probability = float(
        text_model.predict_proba([text])[0][1]
    )

    # URL model
    urls = extract_urls(text)

    if urls:
        url_probabilities = []

        for url in urls:
            features = extract_url_features(url)

            probability = float(
                url_model.predict_proba([features])[0][1]
            )

            url_probabilities.append(probability)

        url_probability = max(url_probabilities)

    else:
        url_probability = 0.0

    # Rule detection
    rule_score, reasons = calculate_rule_score(text)

    rule_probability = rule_score / 100

    # Meta model
    meta_probability = float(
        meta_model.predict_proba(
            [[
                text_probability,
                url_probability,
                rule_probability
            ]]
        )[0][1]
    )

    # Final risk score
    final_score = round(meta_probability * 100)

    # Add rule contribution
    final_score = round(
        final_score * 0.7 +
        rule_score * 0.3
    )

    final_score = min(max(final_score, 0), 100)

    risk_level = get_risk_level(final_score)

    return {
        "score": final_score,
        "risk_level": risk_level,
        "ml_probability": round(text_probability, 4),
        "url_probability": round(url_probability, 4),
        "meta_probability": round(meta_probability, 4),
        "rule_score": rule_score,
        "reasons": reasons
    }


# =========================
# TEST
# =========================

if __name__ == "__main__":

    result = analyze_email(
        "URGENT: Your account has been suspended",
        "Click here to verify your password and OTP: http://secure-account.xyz"
    )

    print("\nEmail Guard AI Result")
    print("=====================")
    print("Score:", result["score"])
    print("Risk:", result["risk_level"])
    print("ML Probability:", result["ml_probability"])
    print("URL Probability:", result["url_probability"])
    print("Meta Probability:", result["meta_probability"])
    print("Rule Score:", result["rule_score"])
    print("Reasons:")

    for reason in result["reasons"]:
        print("-", reason)