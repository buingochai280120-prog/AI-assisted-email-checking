
"""
ai_analyzer.py
--------------
Bộ phân tích AI phát hiện Spam/Phishing Email.

Kiến trúc (chia làm 2 file):

    model_training.py     Machine Learning: TF-IDF + MultinomialNB
    ai_analyzer.py  (file này) Rule-based/Heuristic + kết hợp Hybrid

Rule-based / Heuristic kiểm tra:
   - Từ khóa (khẩn cấp, yêu cầu thông tin nhạy cảm, tiền thưởng...)
   - URL (IP thay domain, '@' ẩn hostname, TLD đáng chú ý, không HTTPS...)
   - Sender / Reply-To (display name giả mạo, brand giả mạo)
   - SPF/DKIM/DMARC (Authentication-Results)

Hybrid Risk Score:
   - Kết hợp ML + Rule -> điểm rủi ro 0-100

Kết quả của analyze_email():
{
    "score": int,
    "risk_level": str,
    "ml_probability": float,
    "rule_score": int,
    "reasons": list[str]
}

Lưu ý:
- score là ĐIỂM RỦI RO 0-100, không phải xác suất.
- ml_probability là xác suất do MultinomialNB ước lượng (xem model_training.py).
"""

import re
import unicodedata
from urllib.parse import urlparse

from model_training import (
    get_model_metrics,       # noqa: F401  (re-export, giữ tương thích ngược)
    ml_phishing_probability,
    print_model_metrics,     # noqa: F401  (re-export, giữ tương thích ngược)
)


# ============================================================================
# 1. TỪ KHÓA / DANH SÁCH TĨNH
# ============================================================================

# ----------------------------------------------------------------------------
# Từ khóa tạo cảm giác khẩn cấp
# ----------------------------------------------------------------------------

URGENCY_KEYWORDS = [

    "khẩn cấp",
    "khan cap",

    "ngay lập tức",
    "ngay lap tuc",

    "hết hạn",
    "het han",

    "24 giờ",
    "24 gio",

    "cảnh báo",
    "canh bao",

    "đình chỉ",
    "dinh chi",

    "khóa tài khoản",
    "khoa tai khoan",

    "urgent",
    "immediately",
    "suspended",
    "act now",
    "expires today",
    "final notice",
]


# ----------------------------------------------------------------------------
# Từ khóa thông tin nhạy cảm
# ----------------------------------------------------------------------------

CREDENTIAL_REQUEST_KEYWORDS = [

    "mật khẩu",
    "mat khau",

    "otp",

    "mã xác minh",
    "ma xac minh",

    "cvv",

    "số thẻ",
    "so the",

    "tài khoản ngân hàng",
    "tai khoan ngan hang",

    "password",

    "verify your account",

    "bank details",

    "social security",

    "số cccd",
    "so cccd",

    "căn cước công dân",
    "can cuoc cong dan",
]


# ----------------------------------------------------------------------------
# Tiền thưởng / xổ số
# ----------------------------------------------------------------------------

MONEY_LOTTERY_KEYWORDS = [

    "trúng thưởng",
    "trung thuong",

    "quà tặng miễn phí",
    "qua tang mien phi",

    "chuyển tiền",
    "chuyen tien",

    "hoàn tiền",
    "hoan tien",

    "lottery",
    "prize",

    "free gift",

    "you won",

    "inheritance",

    "million usd",
]


# ----------------------------------------------------------------------------
# TLD đáng chú ý
#
# Không có nghĩa TLD này = phishing. Chỉ sử dụng như tín hiệu phụ.
# ----------------------------------------------------------------------------

ATTENTION_TLDS = [
    ".xyz", ".top", ".click", ".club", ".gq", ".tk", ".loan",
]


# ============================================================================
# DOMAIN CHÍNH THỨC
#
# LƯU Ý QUAN TRỌNG: mỗi thương hiệu trong BRAND_NAMES (bên dưới) PHẢI có
# ít nhất một domain tương ứng ở đây. Nếu thiếu, mọi email nhắc tới
# thương hiệu đó — kể cả email hợp lệ — sẽ luôn bị gắn cờ "brand/domain
# mismatch" vì không có domain nào để đối chiếu. Đây chính là bug đã
# phát hiện với facebook/instagram ở bản gốc (đã vá bằng cách bổ sung
# domain bên dưới). Hàm `validate_brand_domain_consistency()` ở cuối
# phần này giúp phát hiện sớm nếu lỗi tương tự lặp lại.
# ============================================================================

KNOWN_OFFICIAL_DOMAINS = [

    "google.com",
        "googleusercontent.com",
        "youtube.com",
        "microsoft.com",
        "live.com",
        "outlook.com",
        "office.com",
        "apple.com",
        "icloud.com",
        "amazon.com",
        "aws.amazon.com",
        "github.com",
        "gitlab.com",
        "stackoverflow.com",
        "mozilla.org",
        "adobe.com",
        "canva.com",
        "openai.com",
        "chatgpt.com",
        "anthropic.com",
    
        # AI
        "claude.ai",
        "gemini.google.com",
        "deepseek.com",
        "perplexity.ai",
        "huggingface.co",
    
        # Social Media
        "facebook.com",
        "instagram.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "tiktok.com",
        "reddit.com",
        "pinterest.com",
        "snapchat.com",
        "threads.net",
        "telegram.org",
        "t.me",
        "whatsapp.com",
        "discord.com",
    
        # E-commerce
        "amazon.com",
        "ebay.com",
        "walmart.com",
        "aliexpress.com",
        "alibaba.com",
        "etsy.com",
        "shopify.com",
        "rakuten.com",
        "bestbuy.com",
        "target.com",
    
        # Payment / Finance
        "paypal.com",
        "stripe.com",
        "visa.com",
        "mastercard.com",
        "americanexpress.com",
        "wise.com",
        "revolut.com",
        "coinbase.com",
        "binance.com",
        "kraken.com",
    
        # News / Information
        "wikipedia.org",
        "yahoo.com",
        "yahoo.co.jp",
        "bing.com",
        "duckduckgo.com",
        "cnn.com",
        "bbc.com",
        "nytimes.com",
        "forbes.com",
        "reuters.com",
    
        # Cloud / Business
        "dropbox.com",
        "box.com",
        "zoom.us",
        "slack.com",
        "notion.so",
        "salesforce.com",
        "oracle.com",
        "ibm.com",
        "sap.com",
        "hubspot.com",
    
        # Vietnam
        "vietcombank.com.vn",
        "techcombank.com",
        "bidv.com.vn",
        "mbbank.com.vn",
        "acb.com.vn",
        "vpbank.com.vn",
        "tpb.vn",
        "vib.com.vn",
        "shb.com.vn",
        "momo.vn",
        "viettel.com.vn",
        "viettel.vn",
        "vinaphone.com.vn",
        "vnpt.com.vn",
        "mobifone.vn",
        "fpt.com",
        "fpt.vn",
        "shopee.vn",
        "lazada.vn",
        "tiki.vn",
        "thegioididong.com",
        "dienmayxanh.com",
        "bachhoaxanh.com",
        "cellphones.com.vn",
        "fptshop.com.vn",
        "nguyenkim.com",
        "dienmaycholon.vn",
    
        # =========================
        # VIỆT NAM - DỊCH VỤ
        # =========================
        "grab.com",
        "grab.com.vn",
        "be.com.vn",
        "baemin.vn",
        "vietnamairlines.com",
        "vietjetair.com",
        "booking.com",
    
        # =========================
        # VIỆT NAM - BÁO CHÍ
        # =========================
        "vnexpress.net",
        "tuoitre.vn",
        "thanhnien.vn",
        "dantri.com.vn",
        "vietnamnet.vn",
        "24h.com.vn",
        "zing.vn",
        "plo.vn",
        "vtv.vn",
        "vov.vn", 
]


# ============================================================================
# Tên tổ chức
# ============================================================================

ORG_NAME_HINTS = [

    "ngân hàng", "ngan hang",
    "bank",
    "công ty", "cong ty",
    "tập đoàn", "tap doan",
    "dịch vụ", "dich vu",
    "hỗ trợ", "ho tro",
    "chăm sóc khách hàng", "cham soc khach hang",
    "bảo mật", "bao mat",
    "support",
    "security",
    "team",
    "service",
    "customer care",
    "billing",
    "payment",
    "account",
    "verification",
]


# ============================================================================
# Thương hiệu
# ============================================================================

BRAND_NAMES = [
    "vietcombank", "techcombank", "bidv",
    "paypal", "amazon",
    "apple", "microsoft",
    "momo",
    "google",
    "facebook", "instagram",
]


def validate_brand_domain_consistency():
    """
    Kiểm tra: mỗi thương hiệu trong BRAND_NAMES phải có ít nhất một
    domain chứa tên thương hiệu đó trong KNOWN_OFFICIAL_DOMAINS.

    Đây chính là loại lỗi đã xảy ra với "facebook"/"instagram" ở bản
    gốc: brand có mặt trong BRAND_NAMES nhưng không có domain nào tương
    ứng, khiến `_brand_domain_mismatch` luôn trả về cảnh báo, kể cả với
    email hợp lệ.

    Trả về danh sách brand đang THIẾU domain tương ứng (rỗng = ổn).
    """

    return [
        brand
        for brand in BRAND_NAMES
        if not any(brand in domain for domain in KNOWN_OFFICIAL_DOMAINS)
    ]


# ============================================================================
# Regex URL
# ============================================================================

URL_REGEX = re.compile(
    r"""(https?://[^\s<>"']+|www\.[^\s<>"']+)""",
    re.IGNORECASE
)

IP_URL_REGEX = re.compile(
    r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?",
    re.IGNORECASE
)


# ============================================================================
# 2. TEXT / EMAIL / URL HELPERS
# ============================================================================

def _strip_diacritics(text: str) -> str:

    normalized = unicodedata.normalize("NFD", text)

    return "".join(
        char for char in normalized
        if unicodedata.category(char) != "Mn"
    )


def _normalize_text(text: str) -> str:

    text = text or ""
    text = _strip_diacritics(text.lower())

    return re.sub(r"\s+", " ", text).strip()


def _extract_urls(text: str):
    return URL_REGEX.findall(text or "")


def _domain_of(url: str) -> str:

    if not url:
        return ""

    url = url.strip().rstrip(".,;:!?)]}")

    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        return parsed.hostname.lower() if parsed.hostname else ""
    except Exception:
        return ""


def _is_ip_domain(domain: str) -> bool:

    if not domain:
        return False

    parts = domain.split(".")

    if len(parts) != 4:
        return False

    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _is_subdomain_or_same(child: str, parent: str) -> bool:

    child = (child or "").lower().strip(".")
    parent = (parent or "").lower().strip(".")

    return bool(
        child and parent
        and (child == parent or child.endswith("." + parent))
    )


def _is_trusted_domain(domain: str) -> bool:
    """
    Kiểm tra domain có thuộc nhóm domain chính thức đã biết hay không.

    Ví dụ:
        accounts.google.com          -> True
        login.accounts.google.com    -> True
        google.com.evil.com          -> False
    """

    domain = (domain or "").lower().strip(".")

    return any(
        _is_subdomain_or_same(domain, official)
        for official in KNOWN_OFFICIAL_DOMAINS
    )


def _url_has_at_in_hostname(url: str) -> bool:
    """
    Chỉ cảnh báo '@' nếu '@' nằm trong hostname.

    Đáng ngờ:      https://google.com@evil.com/login
    Không đáng ngờ: https://accounts.google.com/?email=user@ut.edu.vn
    (vì '@' ở trường hợp 2 nằm trong query parameter)
    """

    try:
        clean_url = (url or "").strip()

        if not clean_url.lower().startswith(("http://", "https://")):
            clean_url = "http://" + clean_url

        parsed = urlparse(clean_url)

        return "@" in (parsed.netloc or "")
    except Exception:
        return False


def _extract_email_and_display_name(sender: str):

    if not sender:
        return "", ""

    match = re.search(r"[\w.\-+%]+@([\w.\-]+)", sender, re.IGNORECASE)

    if not match:
        return sender.strip(), ""

    domain = match.group(1).lower()

    email_match = re.search(r"[\w.\-+%]+@[\w.\-]+", sender, re.IGNORECASE)

    display_name = sender

    if email_match:
        display_name = sender[:email_match.start()].strip()

    display_name = (
        display_name.strip().strip('"').strip("'").strip("<").strip(">").strip()
    )

    return display_name, domain


# ============================================================================
# 3. SENDER ANALYSIS
# ============================================================================

def _display_name_domain_mismatch(sender: str):
    """
    Phát hiện trường hợp tên hiển thị giống tổ chức nhưng domain gửi
    thư không hợp lý.
    """

    display_name, domain = _extract_email_and_display_name(sender)

    if not display_name or not domain:
        return None

    if _is_trusted_domain(domain):
        return None

    normalized_name = _normalize_text(display_name)
    normalized_hints = [_normalize_text(x) for x in ORG_NAME_HINTS]

    if not any(hint in normalized_name for hint in normalized_hints):
        return None

    clean_name = _strip_diacritics(display_name.lower())

    words = [
        word
        for word in re.split(r"[^a-z0-9]+", clean_name)
        if len(word) >= 3 and word not in ORG_NAME_HINTS
    ]

    if not words:
        return None

    domain_root = domain.split(".")[0]

    if any(word in domain for word in words):
        return None

    if any(word in BRAND_NAMES and word in domain for word in words):
        return None

    if domain_root in words:
        return None

    return (
        f"Tên hiển thị '{display_name}' "
        f"giống tên tổ chức nhưng domain gửi thư "
        f"là '{domain}' và không có liên hệ rõ ràng "
        f"— có khả năng giả mạo người gửi."
    )


def _brand_domain_mismatch(sender: str):
    """
    Phát hiện tên thương hiệu trong display name nhưng domain không
    phải domain chính thức. Chỉ hoạt động đúng nếu mỗi brand trong
    BRAND_NAMES có domain tương ứng trong KNOWN_OFFICIAL_DOMAINS (xem
    validate_brand_domain_consistency()).
    """

    display_name, domain = _extract_email_and_display_name(sender)

    if not display_name or not domain:
        return None

    if _is_trusted_domain(domain):
        return None

    name = _normalize_text(display_name)

    for brand in BRAND_NAMES:

        if brand not in name:
            continue

        official_domains = [
            domain_name
            for domain_name in KNOWN_OFFICIAL_DOMAINS
            if brand in domain_name
        ]

        if any(
            _is_subdomain_or_same(domain, official)
            for official in official_domains
        ):
            continue

        return (
            f"Tên người gửi có chứa thương hiệu "
            f"'{brand}' nhưng email đến từ domain "
            f"'{domain}' không phải domain chính thức "
            f"đã biết."
        )

    return None


def _check_reply_to_mismatch(sender: str, reply_to: str):

    if not sender or not reply_to:
        return None

    _, from_domain = _extract_email_and_display_name(sender)
    _, reply_domain = _extract_email_and_display_name(reply_to)

    if not from_domain or not reply_domain:
        return None

    if (
        _is_subdomain_or_same(reply_domain, from_domain)
        or _is_subdomain_or_same(from_domain, reply_domain)
    ):
        return None

    return (
        f"Reply-To ({reply_domain}) khác domain "
        f"người gửi ({from_domain}) — phản hồi có thể "
        f"được chuyển tới địa chỉ khác với nơi người "
        f"dùng tưởng."
    )


# ============================================================================
# 4. AUTHENTICATION RESULTS (SPF/DKIM/DMARC)
# ============================================================================

def _check_authentication_results(auth_results: str):
    """
    Phân tích Authentication-Results. Trả về (reason, status), với
    status là "pass" | "fail" | None.
    """

    if not auth_results:
        return None, None

    text = auth_results.lower()

    checks = {"spf": None, "dkim": None, "dmarc": None}

    for key in checks:

        match = re.search(
            rf"\b{key}="
            rf"(pass|fail|softfail|neutral|none|"
            rf"temperror|permerror)\b",
            text
        )

        if match:
            checks[key] = match.group(1)

    failed = [
        key.upper()
        for key, value in checks.items()
        if value in ("fail", "softfail", "permerror")
    ]

    passed = [
        key.upper()
        for key, value in checks.items()
        if value == "pass"
    ]

    if failed:
        return (
            "Authentication-Results cho thấy "
            "xác thực không đạt "
            f"({', '.join(failed)}). "
            "Đây là tín hiệu kỹ thuật đáng chú ý.",
            "fail"
        )

    if passed:
        return (
            "Authentication-Results cho thấy "
            "xác thực thành công "
            f"({', '.join(passed)}).",
            "pass"
        )

    return None, None


# ============================================================================
# 5. URL ANALYSIS
# ============================================================================

def _analyze_urls(text: str):
    """Trả về (score, reasons, urls). score bị giới hạn tối đa 60 điểm."""

    urls = _extract_urls(text)

    score = 0
    reasons = []

    if not urls:
        return score, reasons, urls

    domains = []

    for url in urls:

        domain = _domain_of(url)

        if not domain:
            continue

        domains.append(domain)

        trusted = _is_trusted_domain(domain)

        # 1. IP thay domain
        if _is_ip_domain(domain):
            score += 20
            reasons.append(
                f"Liên kết sử dụng địa chỉ IP '{domain}' thay vì tên miền."
            )

        # 2. '@' trong hostname
        if _url_has_at_in_hostname(url):
            score += 15
            reasons.append(
                "URL chứa '@' trong hostname, "
                "có thể che giấu domain đích thật."
            )

        # 3. URL quá dài (chỉ phạt khi domain không đáng tin)
        if len(url) > 200 and not trusted:
            score += 5
            reasons.append(
                "URL có độ dài bất thường và "
                "trỏ tới domain chưa được xác thực."
            )

        # 4. TLD đáng chú ý
        if (
            any(domain.endswith(tld) for tld in ATTENTION_TLDS)
            and not trusted
        ):
            score += 8
            reasons.append(f"Domain '{domain}' sử dụng TLD cần chú ý.")

        # 5. Không dùng HTTPS
        if not url.lower().startswith("https://"):
            score += 3
            reasons.append(f"Liên kết '{domain}' không sử dụng HTTPS.")

    unique_domains = set(domains)

    if len(urls) >= 3:
        score += 8
        reasons.append(f"Email chứa nhiều liên kết ({len(urls)} URL).")

    if len(unique_domains) >= 3:
        score += 5
        reasons.append(
            f"Email liên kết tới nhiều domain "
            f"khác nhau ({len(unique_domains)} domain)."
        )

    return min(score, 60), reasons, urls


# ============================================================================
# 6. CONTENT ANALYSIS / RULE-BASED TỔNG HỢP
# ============================================================================

def _find_keyword_hits(text: str, keywords):

    normalized = _normalize_text(text)

    return [
        keyword
        for keyword in keywords
        if _normalize_text(keyword) in normalized
    ]


def _rule_based_analysis(
    sender: str,
    subject: str,
    content: str,
    reply_to: str = "",
    auth_results: str = "",
):
    """Trả về (rule_score, reasons, auth_status)."""

    full_text = f"{subject or ''} {content or ''}"

    reasons = []
    score = 0

    # Urgency
    urgency_hits = _find_keyword_hits(full_text, URGENCY_KEYWORDS)

    if urgency_hits:
        score += min(18, 6 * len(urgency_hits))
        reasons.append(
            "Email sử dụng ngôn từ tạo cảm giác "
            "khẩn cấp/áp lực "
            f"({', '.join(urgency_hits[:3])})."
        )

    # Credential
    credential_hits = _find_keyword_hits(full_text, CREDENTIAL_REQUEST_KEYWORDS)

    if credential_hits:
        score += min(30, 12 * len(credential_hits))
        reasons.append(
            "Email có yêu cầu hoặc đề cập tới "
            "thông tin nhạy cảm "
            f"({', '.join(credential_hits[:4])})."
        )

    # Money / Lottery
    money_hits = _find_keyword_hits(full_text, MONEY_LOTTERY_KEYWORDS)

    if money_hits:
        score += min(18, 9 * len(money_hits))
        reasons.append(
            "Email có dấu hiệu dụ người nhận bằng "
            "tiền thưởng, quà tặng hoặc lợi ích bất thường."
        )

    # URL
    url_score, url_reasons, _urls = _analyze_urls(full_text)
    score += url_score
    reasons.extend(url_reasons)

    # Sender: display name giả mạo tổ chức
    mismatch_reason = _display_name_domain_mismatch(sender)

    if mismatch_reason:
        score += 20
        reasons.append(mismatch_reason)

    # Brand
    brand_reason = _brand_domain_mismatch(sender)

    if brand_reason:
        score += 20
        reasons.append(brand_reason)

    # Reply-To
    reply_to_reason = _check_reply_to_mismatch(sender, reply_to)

    if reply_to_reason:
        score += 15
        reasons.append(reply_to_reason)

    # SPF / DKIM / DMARC
    auth_reason, auth_status = _check_authentication_results(auth_results)

    if auth_status == "fail":
        score += 30
        reasons.append(auth_reason)

    elif auth_status == "pass":

        # Không cộng điểm. Authentication PASS là tín hiệu tích cực.
        reasons.append(auth_reason)

        _display_name, sender_domain = _extract_email_and_display_name(sender)

        if _is_trusted_domain(sender_domain):
            reasons.append(
                f"Domain người gửi "
                f"'{sender_domain}' thuộc nhóm "
                "domain chính thức đã biết."
            )

    # Excessive uppercase
    letters = re.findall(r"[A-Za-z]", full_text)

    if len(letters) >= 30:

        uppercase_ratio = (
            sum(1 for char in letters if char.isupper()) / len(letters)
        )

        if uppercase_ratio >= 0.55:
            score += 4
            reasons.append("Email sử dụng tỷ lệ chữ in hoa bất thường.")

    return min(score, 100), reasons, auth_status


# ============================================================================
# 7. HYBRID ANALYSIS
# ============================================================================

def analyze_email(
    sender: str,
    subject: str,
    content: str,
    reply_to: str = "",
    auth_results: str = "",
):
    """
    Phân tích email. Trả về:
    {
        "score": int,
        "risk_level": str,
        "ml_probability": float,
        "rule_score": int,
        "reasons": list[str]
    }
    """

    full_text = f"{subject or ''} {content or ''}".strip()

    # Không đủ dữ liệu
    if not full_text:
        return {
            "score": 0,
            "risk_level": "Không đủ dữ liệu",
            "ml_probability": 0.0,
            "rule_score": 0,
            "reasons": [
                "Email không có Subject hoặc nội dung để phân tích."
            ],
        }

    # ML
    ml_probability = ml_phishing_probability(full_text)

    # Rule
    rule_score, reasons, auth_status = _rule_based_analysis(
        sender, subject, content, reply_to, auth_results
    )

    # Domain information
    _display_name, sender_domain = _extract_email_and_display_name(sender)

    urls = _extract_urls(full_text)

    url_domains = [
        _domain_of(url) for url in urls if _domain_of(url)
    ]

    has_trusted_sender = _is_trusted_domain(sender_domain)

    has_only_trusted_urls = (
        bool(url_domains)
        and all(_is_trusted_domain(domain) for domain in url_domains)
    )

    # Hybrid
    if auth_status == "fail":

        # Authentication fail: header có vấn đề -> Rule được ưu tiên hơn.
        ml_weight = 0.35
        rule_weight = 0.65

        final_score = round(
            ml_weight * (ml_probability * 100) + rule_weight * rule_score
        )

    elif auth_status == "pass":

        # Authentication pass: ML vẫn giữ lại nhưng header là tín hiệu
        # kỹ thuật quan trọng.
        ml_weight = 0.40
        rule_weight = 0.60

        final_score = round(
            ml_weight * (ml_probability * 100) + rule_weight * rule_score
        )

        # SPF/DKIM/DMARC pass.
        final_score -= 20

    else:

        # Không có Authentication-Results.
        ml_weight = 0.55
        rule_weight = 0.45

        final_score = round(
            ml_weight * (ml_probability * 100) + rule_weight * rule_score
        )

    # Trusted sender
    if auth_status == "pass" and has_trusted_sender:
        final_score -= 10

    # Trusted sender + trusted URLs
    if auth_status == "pass" and has_trusted_sender and has_only_trusted_urls:
        final_score -= 5

    # Giới hạn 0-100
    final_score = max(0, min(100, final_score))

    # Risk Level
    if final_score >= 70:
        risk_level = "Nguy hiểm"
    elif final_score >= 40:
        risk_level = "Nghi ngờ"
    else:
        risk_level = "An toàn"

    # Fallback explanation
    if not reasons:

        if ml_probability >= 0.60:
            reasons.append(
                "Mô hình AI nhận thấy văn phong email "
                "tương đồng với các email phishing/spam "
                "trong dataset."
            )
        elif ml_probability >= 0.40:
            reasons.append(
                "Mô hình AI nhận thấy một số đặc điểm "
                "tương đồng với email phishing/spam."
            )
        else:
            reasons.append(
                "Không phát hiện dấu hiệu phishing rõ ràng "
                "từ các luật và mô hình hiện tại."
            )

    return {
        "score": final_score,
        "risk_level": risk_level,
        "ml_probability": round(ml_probability, 3),
        "rule_score": rule_score,
        "reasons": reasons,
    }


# ============================================================================
# 8. TỰ KIỂM TRA TÍNH NHẤT QUÁN DỮ LIỆU (chạy khi import)
#
# Cơ chế phòng ngừa để lỗi kiểu "facebook/instagram bị flag oan" (brand
# có trong BRAND_NAMES nhưng thiếu domain tương ứng trong
# KNOWN_OFFICIAL_DOMAINS) không âm thầm lặp lại nếu sau này có người
# thêm brand mới mà quên thêm domain. Dùng warnings.warn (không raise)
# để không làm sập app vì sai sót nhỏ trong dữ liệu.
# ============================================================================

import warnings  # noqa: E402  (đặt cuối để phần cấu hình ở trên rõ ràng hơn)

_missing_brand_domains = validate_brand_domain_consistency()

if _missing_brand_domains:
    warnings.warn(
        "[ai_analyzer] Các thương hiệu sau trong BRAND_NAMES chưa có "
        "domain tương ứng trong KNOWN_OFFICIAL_DOMAINS: "
        f"{_missing_brand_domains}. Mọi email HỢP LỆ nhắc tới thương "
        "hiệu này sẽ luôn bị coi là 'brand/domain mismatch'. Hãy bổ "
        "sung domain chính thức tương ứng ở KNOWN_OFFICIAL_DOMAINS.",
        stacklevel=2,
    )


# ============================================================================
# 9. TEST NHANH
# ============================================================================

if __name__ == "__main__":

    print_model_metrics()

    print()
    print("=" * 60)
    print("TEST 1 - EMAIL PHISHING")
    print("=" * 60)

    result = analyze_email(
        sender="Security Team <security@example.xyz>",
        subject="Khẩn cấp: tài khoản của bạn sắp bị khóa",
        content=(
            "Vui lòng xác minh tài khoản và nhập OTP ngay lập tức "
            "tại http://192.168.1.10/login"
        ),
        reply_to="support@random-mail.com",
        auth_results="spf=fail dkim=fail dmarc=fail",
    )

    print(f"Risk score     : {result['score']}/100")
    print(f"Risk level     : {result['risk_level']}")
    print(f"ML probability : {result['ml_probability']:.1%}")
    print(f"Rule score     : {result['rule_score']}/100")
    print()
    print("Lý do:")

    for reason in result["reasons"]:
        print(f"- {reason}")

    print()
    print("=" * 60)
    print("TEST 2 - GOOGLE")
    print("=" * 60)

    google_result = analyze_email(
        sender="Google <no-reply@accounts.google.com>",
        subject="Cảnh báo bảo mật",
        content=(
            "Google phát hiện hoạt động đăng nhập vào tài khoản của bạn. "
            "Bạn có thể kiểm tra hoạt động tài khoản tại: "
            "https://accounts.google.com/AccountChooser?"
            "Email=user@ut.edu.vn&continue="
            "https://myaccount.google.com/alert/nt/123456"
        ),
        reply_to="",
        auth_results="spf=pass dkim=pass dmarc=pass",
    )

    print(f"Risk score     : {google_result['score']}/100")
    print(f"Risk level     : {google_result['risk_level']}")
    print(f"ML probability : {google_result['ml_probability']:.1%}")
    print(f"Rule score     : {google_result['rule_score']}/100")
    print()
    print("Lý do:")

    for reason in google_result["reasons"]:
        print(f"- {reason}")

    print()
    print("=" * 60)
    print("TEST 3 - FACEBOOK (hợp lệ, kiểm tra bug đã sửa)")
    print("=" * 60)

    facebook_result = analyze_email(
        sender="Facebook <notification@facebookmail.com>",
        subject="Bạn có thông báo mới",
        content=(
            "Ai đó đã bình luận vào bài viết của bạn. "
            "Xem tại https://facebook.com/notifications"
        ),
        reply_to="",
        auth_results="spf=pass dkim=pass dmarc=pass",
    )

    print(f"Risk score     : {facebook_result['score']}/100")
    print(f"Risk level     : {facebook_result['risk_level']}")
    print(f"ML probability : {facebook_result['ml_probability']:.1%}")
    print(f"Rule score     : {facebook_result['rule_score']}/100")
    print()
    print("Lý do:")

    for reason in facebook_result["reasons"]:
        print(f"- {reason}")
