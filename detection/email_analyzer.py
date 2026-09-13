import re
from urllib.parse import urlparse


# =========================
# EMAIL ANALYZER
# =========================

def extract_urls(text):
    """
    Extract URLs from email subject/body.
    """
    if not text:
        return []

    pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
    return re.findall(pattern, str(text))


def analyze_email_content(subject="", body=""):
    """
    Analyze email content for common phishing indicators.
    """

    subject = subject or ""
    body = body or ""

    text = f"{subject} {body}".lower()

    reasons = []
    score = 0

    # -------------------------
    # Urgency / threat
    # -------------------------
    urgent_words = [
        "urgent",
        "immediately",
        "24 hours",
        "24h",
        "suspended",
        "blocked",
        "verify now",
        "act now",
        "khẩn cấp",
        "ngay lập tức",
        "khóa tài khoản",
        "khoá tài khoản",
    ]

    if any(word in text for word in urgent_words):
        score += 20
        reasons.append("Có nội dung khẩn cấp hoặc đe dọa")

    # -------------------------
    # Credential requests
    # -------------------------
    credential_words = [
        "password",
        "passcode",
        "otp",
        "cvv",
        "credit card",
        "card number",
        "login",
        "username",
        "mật khẩu",
        "mã otp",
        "thẻ ngân hàng",
        "thông tin đăng nhập",
    ]

    if any(word in text for word in credential_words):
        score += 20
        reasons.append("Yêu cầu thông tin bảo mật")

    # -------------------------
    # Money / reward scams
    # -------------------------
    money_words = [
        "lottery",
        "winner",
        "prize",
        "reward",
        "payment",
        "transfer",
        "money",
        "trúng thưởng",
        "giải thưởng",
        "chuyển khoản",
        "tiền",
    ]

    if any(word in text for word in money_words):
        score += 15
        reasons.append("Có dấu hiệu liên quan đến tiền hoặc phần thưởng")

    # -------------------------
    # Suspicious URLs
    # -------------------------
    urls = extract_urls(text)

    suspicious_tlds = (
        ".xyz",
        ".top",
        ".click",
        ".tk",
        ".ml",
        ".ga",
        ".cf"
    )

    suspicious_url = False

    for url in urls:
        try:
            parsed = urlparse(
                url if "://" in url else "http://" + url
            )

            domain = parsed.netloc.lower()

            if (
                "@" in url
                or "-" in domain
                or re.search(r"\d", domain)
                or domain.count(".") >= 3
                or domain.endswith(suspicious_tlds)
            ):
                suspicious_url = True
                break

        except Exception:
            continue

    if suspicious_url:
        score += 20
        reasons.append("URL sử dụng tên miền đáng ngờ")

    # -------------------------
    # Login / verification
    # -------------------------
    verification_words = [
        "verify your account",
        "confirm your account",
        "security verification",
        "verify identity",
        "xác minh tài khoản",
        "xác nhận tài khoản",
        "xác minh danh tính",
    ]

    if any(word in text for word in verification_words):
        score += 15
        reasons.append("Yêu cầu xác minh tài khoản hoặc danh tính")

    # -------------------------
    # Limit score
    # -------------------------
    score = min(score, 100)

    # -------------------------
    # Risk level
    # -------------------------
    if score < 30:
        risk_level = "SAFE"
    elif score < 60:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "DANGEROUS"

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "urls": urls
    }


# =========================
# TEST
# =========================

if __name__ == "__main__":

    subject = "URGENT: Verify your account"
    body = """
    Your account has been suspended.
    Please login immediately at https://example.xyz
    and verify your password.
    """

    result = analyze_email_content(subject, body)

    print("Email Analyzer Result")
    print("---------------------")
    print("Score:", result["score"])
    print("Risk:", result["risk_level"])
    print("URLs:", result["urls"])

    print("Reasons:")
    for reason in result["reasons"]:
        print("-", reason)