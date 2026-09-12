import re
import html


def clean_text(text):
    """
    Làm sạch nội dung email trước khi đưa vào mô hình AI.
    """

    if not text:
        return ""

    # Chuyển dữ liệu về string
    text = str(text)

    # Decode HTML entities
    text = html.unescape(text)

    # Loại bỏ HTML tag
    text = re.sub(r"<[^>]+>", " ", text)

    # Chuyển về chữ thường
    text = text.lower()

    # Chuẩn hóa URL
    text = re.sub(r"https?://\S+|www\.\S+", " URL ", text)

    # Chuẩn hóa email address
    text = re.sub(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        " EMAIL ",
        text
    )

    # Chuẩn hóa số
    text = re.sub(r"\b\d+\b", " NUMBER ", text)

    # Loại bỏ ký tự đặc biệt nhưng giữ chữ và số
    text = re.sub(r"[^a-zA-ZÀ-ỹ0-9\s]", " ", text)

    # Xóa khoảng trắng thừa
    text = re.sub(r"\s+", " ", text).strip()

    return text


def preprocess_email(subject="", body=""):
    """
    Kết hợp Subject và Body thành một chuỗi
    để đưa vào Text Model.
    """

    subject = subject or ""
    body = body or ""

    combined_text = f"{subject} {body}"

    return clean_text(combined_text)


if __name__ == "__main__":
    sample = """
    URGENT! Your account has been suspended.
    Please login at http://example.xyz and verify your password.
    """

    print("Original:")
    print(sample)

    print("\nCleaned:")
    print(clean_text(sample))
