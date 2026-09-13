"""Email Guard AI - orchestrator kết hợp hai project.

Kiến trúc:
- Text ML: TF-IDF + MultinomialNB (dataset lớn của bài 1, có deduplicate).
- URL ML: RandomForest + URL structural features (module của bài 2, có fallback rule).
- Detection modules: content, sender, social engineering.
- Legacy rule engine: giữ bộ luật phong phú của bài 1 (brand/domain, SPF/DKIM/DMARC...).
- Final score: hybrid rõ ràng, không dùng meta model giả lập.
"""
from models.text_model import phishing_probability, get_metrics
from detection.url_analyzer import analyze_urls
from detection.email_analyzer import analyze_email_content
from detection.sender_analyzer import analyze_sender
from detection.social_engineering import analyze_social_engineering
from detection.rule_engine_legacy import _rule_based_analysis


def _risk_level(score: int) -> str:
    if score >= 70:
        return "Nguy hiểm"
    if score >= 40:
        return "Nghi ngờ"
    return "An toàn"


def _dedup_reasons(items):
    out = []
    seen = set()
    for item in items:
        item = str(item).strip()
        key = item.lower()
        if item and key not in seen:
            seen.add(key)
            out.append(item)
    return out


def analyze_email(sender: str, subject: str, content: str, reply_to: str = "",
                  auth_results: str = "", return_path: str = ""):
    full_text = f"{subject or ''} {content or ''}".strip()
    if not full_text:
        return {
            "score": 0, "risk_level": "Không đủ dữ liệu", "ml_probability": 0.0,
            "rule_score": 0, "url_score": 0, "sender_score": 0,
            "social_score": 0, "content_score": 0,
            "reasons": ["Email không có Subject hoặc nội dung để phân tích."],
        }

    # 1) Text ML
    text_probability = phishing_probability(full_text)

    # 2) Bộ rule mạnh của bài 1
    legacy_rule_score, legacy_reasons, auth_status = _rule_based_analysis(
        sender, subject, content, reply_to, auth_results
    )

    # 3) Các module tách rời từ bài 2
    url_result = analyze_urls(full_text)
    sender_result = analyze_sender(sender, reply_to, return_path, auth_results)
    social_result = analyze_social_engineering(subject, content)
    content_result = analyze_email_content(subject, content)

    # Nhánh "rule/detection" giờ là trung bình có trọng số của TẤT CẢ các
    # module rule (không chỉ legacy + URL như trước). legacy_rule vẫn được
    # ưu tiên cao nhất vì bao quát nhất (brand/domain, auth, keyword, URL),
    # các module còn lại (URL/sender/social/content) góp phần bổ sung tín
    # hiệu riêng dù có phần trùng lặp về mặt khái niệm với legacy_rule —
    # trùng lặp này là chủ ý, để một dấu hiệu được nhiều module cùng xác
    # nhận (vd. auth fail, URL đáng ngờ) sẽ đẩy rủi ro lên rõ rệt hơn so
    # với dấu hiệu chỉ một module phát hiện.
    effective_rule = (
        0.45 * legacy_rule_score
        + 0.15 * url_result["score"]
        + 0.15 * sender_result["score"]
        + 0.15 * social_result["score"]
        + 0.10 * content_result["score"]
    )

    # Hybrid chính: text ML 45%, rule/detection 55%.
    final_score = round(0.45 * (text_probability * 100) + 0.55 * effective_rule)

    # Authentication là tín hiệu kỹ thuật mạnh. Rule engine đã tính điểm fail;
    # pass được giảm thêm nhẹ để hạn chế false positive với email hợp lệ.
    if auth_status == "pass":
        final_score -= 12
    elif auth_status == "fail":
        final_score += 5

    final_score = max(0, min(100, final_score))

    reasons = _dedup_reasons(
        legacy_reasons
        + url_result["reasons"]
        + sender_result["reasons"]
        + social_result["reasons"]
        + content_result["reasons"]
    )

    if not reasons:
        reasons = ["Không phát hiện dấu hiệu phishing nổi bật trong nội dung hoặc header."]

    return {
        "score": final_score,
        "risk_level": _risk_level(final_score),
        "ml_probability": round(text_probability, 6),
        "rule_score": int(round(effective_rule)),
        "url_score": int(url_result["score"]),
        "sender_score": int(sender_result["score"]),
        "social_score": int(social_result["score"]),
        "content_score": int(content_result["score"]),
        "url_model_used": bool(url_result["model_used"]),
        "urls": url_result["urls"],
        "reasons": reasons,
    }


def get_model_metrics():
    return get_metrics()


def print_model_metrics():
    m = get_metrics()
    print("=" * 60)
    print("ĐÁNH GIÁ TEXT MODEL (group-split theo khung template, chống leakage)")
    print("=" * 60)
    print(f"Số dòng sau dedup   : {m['samples_after_dedup']}")
    print(f"Số nhóm template    : {m.get('template_groups')}")
    print(f"Phương pháp chia    : {m.get('split_method')}")
    if m.get("split_warning"):
        print(f"CẢNH BÁO           : {m['split_warning']}")
    print(f"Train / Test samples: {m['train_samples']} / {m['test_samples']}")
    print(f"Accuracy : {m['accuracy']*100:.2f}%")
    print(f"Precision: {m['precision']*100:.2f}%")
    print(f"Recall   : {m['recall']*100:.2f}%")
    print(f"F1-score : {m['f1']*100:.2f}%")
    print("Confusion Matrix:", m["confusion_matrix"])

    print("-" * 60)
    print("ĐÁNH GIÁ NGOÀI PHÂN PHỐI (data/ood_eval.csv - email viết tay, không theo khung)")
    print("-" * 60)
    if m.get("ood_samples"):
        print(f"Số mẫu OOD: {m['ood_samples']}")
        print(f"OOD Accuracy : {m['ood_accuracy']*100:.2f}%")
        print(f"OOD Precision: {m['ood_precision']*100:.2f}%")
        print(f"OOD Recall   : {m['ood_recall']*100:.2f}%")
        print(f"OOD F1-score : {m['ood_f1']*100:.2f}%")
        for d in m["ood_details"]:
            mark = "✓" if d["true_label"] == d["predicted_label"] else "✗ SAI"
            print(f"  [{mark}] nhãn thật={d['true_label']} dự đoán={d['predicted_label']} "
                  f"(prob={d['phishing_probability']:.2f}) - {d['text']}")
    else:
        print("Không tìm thấy data/ood_eval.csv — bỏ qua đánh giá ngoài phân phối.")


if __name__ == "__main__":
    print_model_metrics()
    sample = analyze_email(
        sender="Microsoft Security <security@microsoft-login.xyz>",
        subject="KHẨN CẤP: Xác minh tài khoản",
        content="Tài khoản sẽ bị khóa. Hãy nhập OTP ngay tại http://192.168.1.10/login",
        reply_to="support@random-mail.com",
        auth_results="spf=fail dkim=fail dmarc=fail",
        return_path="bounce@microsoft-login.xyz",
    )
    print("\nTEST PHISHING")
    for k, v in sample.items():
        if k != "reasons": print(f"{k}: {v}")
    print("Lý do:")
    for r in sample["reasons"]: print("-", r)
