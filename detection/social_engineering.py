import re


# =========================
# SOCIAL ENGINEERING ANALYZER
# =========================

def analyze_social_engineering(subject="", body=""):
    """
    Detect common social engineering techniques
    used in phishing emails.
    """

    subject = str(subject or "")
    body = str(body or "")

    text = f"{subject} {body}".lower()

    score = 0
    reasons = []

    # =========================
    # 1. URGENCY / PRESSURE
    # =========================

    urgency_patterns = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bas soon as possible\b",
        r"\b24 hours?\b",
        r"\bwithin \d+ hours?\b",
        r"khẩn cấp",
        r"ngay lập tức",
        r"trong vòng \d+ giờ",
        r"càng sớm càng tốt",
    ]

    if any(re.search(pattern, text) for pattern in urgency_patterns):
        score += 20
        reasons.append(
            "Sử dụng áp lực thời gian để thúc giục người dùng"
        )

    # =========================
    # 2. FEAR / THREAT
    # =========================

    threat_patterns = [
        r"\bsuspended\b",
        r"\bblocked\b",
        r"\bterminated\b",
        r"\bclosed\b",
        r"\bsecurity alert\b",
        r"\baccount will be closed\b",
        r"tài khoản.*bị khóa",
        r"tài khoản.*bị đình chỉ",
        r"tài khoản.*sẽ bị khóa",
        r"cảnh báo bảo mật",
    ]

    if any(re.search(pattern, text) for pattern in threat_patterns):
        score += 20
        reasons.append(
            "Sử dụng sợ hãi hoặc đe dọa để gây áp lực"
        )

    # =========================
    # 3. CREDENTIAL REQUEST
    # =========================

    credential_patterns = [
        r"\bpassword\b",
        r"\bpasscode\b",
        r"\botp\b",
        r"\bcvv\b",
        r"\bpin\b",
        r"\busername\b",
        r"\blogin\b",
        r"mật khẩu",
        r"mã otp",
        r"thông tin đăng nhập",
        r"mã pin",
    ]

    if any(re.search(pattern, text) for pattern in credential_patterns):
        score += 20
        reasons.append(
            "Có dấu hiệu yêu cầu thông tin đăng nhập hoặc bảo mật"
        )

    # =========================
    # 4. MONEY / REWARD
    # =========================

    money_patterns = [
        r"\blottery\b",
        r"\bprize\b",
        r"\breward\b",
        r"\bbonus\b",
        r"\bpayment\b",
        r"\btransfer\b",
        r"\bmoney\b",
        r"trúng thưởng",
        r"giải thưởng",
        r"tiền thưởng",
        r"chuyển khoản",
        r"thanh toán",
    ]

    if any(re.search(pattern, text) for pattern in money_patterns):
        score += 15
        reasons.append(
            "Có dấu hiệu dụ dỗ bằng tiền hoặc phần thưởng"
        )

    # =========================
    # 5. AUTHORITY IMPERSONATION
    # =========================

    authority_patterns = [
        r"\bsecurity team\b",
        r"\bsecurity department\b",
        r"\badministrator\b",
        r"\badmin\b",
        r"\bsupport team\b",
        r"\bIT department\b",
        r"\bbank\b",
        r"\bpolice\b",
        r"\bgovernment\b",
        r"bộ phận bảo mật",
        r"quản trị viên",
        r"ngân hàng",
        r"cơ quan chức năng",
    ]

    if any(re.search(pattern, text) for pattern in authority_patterns):
        score += 15
        reasons.append(
            "Có dấu hiệu giả mạo tổ chức hoặc người có thẩm quyền"
        )

    # =========================
    # 6. VERIFICATION REQUEST
    # =========================

    verification_patterns = [
        r"\bverify your account\b",
        r"\bconfirm your identity\b",
        r"\bverify your identity\b",
        r"\bconfirm your account\b",
        r"verify now",
        r"verify immediately",
        r"xác minh tài khoản",
        r"xác nhận tài khoản",
        r"xác minh danh tính",
    ]

    if any(re.search(pattern, text) for pattern in verification_patterns):
        score += 15
        reasons.append(
            "Yêu cầu xác minh tài khoản hoặc danh tính"
        )

    # =========================
    # LIMIT SCORE
    # =========================

    score = min(score, 100)

    # =========================
    # RISK LEVEL
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
        "reasons": reasons
    }


# =========================
# TEST
# =========================

if __name__ == "__main__":

    subject = "URGENT: Your account will be suspended"

    body = """
    Your account has been suspended.
    Please verify your identity immediately.
    Enter your password and OTP within 24 hours.
    """

    result = analyze_social_engineering(subject, body)

    print("Social Engineering Analyzer Result")
    print("----------------------------------")
    print("Score:", result["score"])
    print("Risk:", result["risk_level"])

    print("Reasons:")
    for reason in result["reasons"]:
        print("-", reason)