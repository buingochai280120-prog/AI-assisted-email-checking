import re
from urllib.parse import urlparse


# =========================
# SENDER ANALYZER
# =========================

def extract_email_domain(email_address):
    """
    Extract domain from an email address.
    """
    if not email_address:
        return ""

    match = re.search(
        r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        str(email_address)
    )

    if match:
        return match.group(1).lower()

    return ""


def analyze_sender(
    sender="",
    reply_to="",
    return_path="",
    authentication_results=""
):
    """
    Analyze sender information for suspicious indicators.
    """

    reasons = []
    score = 0

    sender = str(sender or "").strip()
    reply_to = str(reply_to or "").strip()
    return_path = str(return_path or "").strip()
    authentication_results = str(
        authentication_results or ""
    ).lower()

    sender_domain = extract_email_domain(sender)
    reply_domain = extract_email_domain(reply_to)
    return_domain = extract_email_domain(return_path)

    # =========================
    # Sender domain
    # =========================

    if sender and not sender_domain:
        score += 20
        reasons.append("Địa chỉ người gửi không hợp lệ")

    # =========================
    # Reply-To mismatch
    # =========================

    if sender_domain and reply_domain:
        if sender_domain != reply_domain:
            score += 25
            reasons.append(
                "Reply-To khác tên miền người gửi"
            )

    # =========================
    # Return-Path mismatch
    # =========================

    if sender_domain and return_domain:
        if sender_domain != return_domain:
            score += 15
            reasons.append(
                "Return-Path khác tên miền người gửi"
            )

    # =========================
    # Suspicious domain
    # =========================

    suspicious_tlds = (
        ".xyz",
        ".top",
        ".click",
        ".tk",
        ".ml",
        ".ga",
        ".cf"
    )

    if sender_domain.endswith(suspicious_tlds):
        score += 20
        reasons.append(
            "Tên miền người gửi đáng ngờ"
        )

    # =========================
    # Numeric / strange domain
    # =========================

    if sender_domain:
        if re.search(r"\d", sender_domain):
            score += 5
            reasons.append(
                "Tên miền người gửi chứa nhiều dấu hiệu bất thường"
            )

        if sender_domain.count(".") >= 3:
            score += 10
            reasons.append(
                "Tên miền người gửi có cấu trúc bất thường"
            )

    # =========================
    # Authentication results
    # =========================

    if authentication_results:

        if re.search(r"spf\s*=\s*fail", authentication_results):
            score += 20
            reasons.append("SPF xác thực thất bại")

        if re.search(r"dkim\s*=\s*fail", authentication_results):
            score += 20
            reasons.append("DKIM xác thực thất bại")

        if re.search(r"dmarc\s*=\s*fail", authentication_results):
            score += 20
            reasons.append("DMARC xác thực thất bại")

    # =========================
    # Limit score
    # =========================

    score = min(score, 100)

    # =========================
    # Risk level
    # =========================

    if score < 30:
        risk_level = "SAFE"
    elif score < 60:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "DANGEROUS"

    return {
        "score": score,
        "risk_level": risk_level,
        "sender": sender,
        "sender_domain": sender_domain,
        "reply_to": reply_to,
        "return_path": return_path,
        "reasons": reasons
    }


# =========================
# TEST
# =========================

if __name__ == "__main__":

    result = analyze_sender(
        sender="Microsoft Security <security@microsoft-login.xyz>",
        reply_to="support@gmail.com",
        return_path="security@microsoft-login.xyz",
        authentication_results=(
            "spf=fail dkim=fail dmarc=fail"
        )
    )

    print("Sender Analyzer Result")
    print("----------------------")
    print("Score:", result["score"])
    print("Risk:", result["risk_level"])
    print("Sender domain:", result["sender_domain"])

    print("Reasons:")
    for reason in result["reasons"]:
        print("-", reason)