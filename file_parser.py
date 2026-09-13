"""
file_parser.py
---------------
Trích xuất người gửi / tiêu đề / nội dung từ file email do người dùng tải lên,
để tự động điền vào form quét thay vì phải copy-paste thủ công.

Hỗ trợ 2 định dạng:
    .txt  -> xem toàn bộ nội dung file là nội dung email (không có header).
    .eml  -> file email chuẩn (RFC 822, xuất ra từ Gmail/Outlook/Thunderbird...),
             dùng thư viện chuẩn `email` của Python để tách đúng From/Subject/Body,
             kể cả email dạng multipart (có cả text và html).
"""

import re
import html
from email import policy
from email.parser import BytesParser

ALLOWED_EXTENSIONS = {"txt", "eml"}
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2MB — email văn bản không cần lớn hơn


class FileParseError(Exception):
    """Lỗi khi không đọc được file người dùng tải lên."""
    pass


def get_extension(filename: str) -> str:
    if not filename or "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


def _strip_html(raw_html: str) -> str:
    """Loại bỏ thẻ HTML thô để lấy phần văn bản đọc được (dùng khi email chỉ có bản HTML)."""
    text = re.sub(r"(?is)<(script|style).*?>.*?(</\1>)", " ", raw_html)
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</p>", "\n\n", text)
    text = re.sub(r"(?is)<[^>]+>", "", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def parse_txt(raw_bytes: bytes) -> dict:
    """File .txt: không có cấu trúc header, toàn bộ nội dung xem là thân email."""
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = raw_bytes.decode("utf-8", errors="ignore")
    return {
        "sender": "", "subject": "", "content": text.strip(),
        "reply_to": "", "return_path": "", "auth_results": "",
    }


def parse_eml(raw_bytes: bytes) -> dict:
    """File .eml chuẩn RFC 822 — tách From / Subject / Body bằng module email chuẩn.

    Ngoài nội dung hiển thị, file .eml thật (xuất từ Gmail/Outlook) còn mang theo
    các header do MÁY CHỦ NHẬN gắn vào, đáng tin cậy hơn nhiều so với việc chỉ
    đoán qua tên hiển thị:
      - Authentication-Results: kết quả kiểm tra SPF / DKIM / DMARC
      - Reply-To: địa chỉ sẽ nhận được trả lời — kẻ lừa đảo hay đặt khác với From
      - Return-Path: địa chỉ nhận thư "bounce", cũng thường bị đặt khác domain
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception as exc:
        raise FileParseError(f"Không thể đọc cấu trúc file .eml: {exc}")

    sender = (msg.get("From") or "").strip()
    subject = (msg.get("Subject") or "").strip()
    reply_to = (msg.get("Reply-To") or "").strip()
    return_path = (msg.get("Return-Path") or "").strip()
    auth_results = (msg.get("Authentication-Results") or "").strip()
    content = ""

    try:
        body_part = msg.get_body(preferencelist=("plain", "html"))
        if body_part is not None:
            raw_content = body_part.get_content()
            if body_part.get_content_type() == "text/html":
                content = _strip_html(raw_content)
            else:
                content = raw_content.strip()
    except Exception:
        content = ""

    # Dự phòng: nếu get_body không hoạt động (một số file .eml không chuẩn),
    # duyệt thủ công qua các phần của email để tìm phần văn bản.
    if not content:
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    content = part.get_content().strip()
                    break
                except Exception:
                    continue
        if not content:
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    try:
                        content = _strip_html(part.get_content())
                        break
                    except Exception:
                        continue

    return {
        "sender": sender,
        "subject": subject,
        "content": content.strip(),
        "reply_to": reply_to,
        "return_path": return_path,
        "auth_results": auth_results,
    }


def parse_uploaded_file(filename: str, raw_bytes: bytes) -> dict:
    """Điểm vào chính: chọn cách đọc phù hợp theo phần mở rộng file."""
    if len(raw_bytes) > MAX_FILE_SIZE_BYTES:
        raise FileParseError("File quá lớn (giới hạn 2MB cho file email dạng văn bản).")

    ext = get_extension(filename)
    if ext == "eml":
        result = parse_eml(raw_bytes)
    elif ext == "txt":
        result = parse_txt(raw_bytes)
    else:
        raise FileParseError("Chỉ hỗ trợ file định dạng .txt hoặc .eml.")

    if not result["content"]:
        raise FileParseError("Không tìm thấy nội dung văn bản nào trong file này.")

    return result
