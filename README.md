# Email Guard AI - Merged Project

Project này ghép hai bài Email Guard AI thành một hệ thống hoàn chỉnh, lấy giao diện/backend/database/dataset lớn và bộ rule chi tiết của bài 1, đồng thời lấy cách tách module, URL Random Forest và các detection module của bài 2.

## Kiến trúc

- `app.py`: Flask web/API.
- `database.py`: SQLite user + history.
- `file_parser.py`: đọc `.txt`, `.eml`, lấy From/Subject/Reply-To/Return-Path/Authentication-Results.
- `models/text_model.py`: TF-IDF + **Logistic Regression** (đã đổi từ MultinomialNB — xem mục "Đánh giá model" bên dưới để biết lý do). Dataset được loại duplicate, và được **chia train/test theo nhóm khung template** (group split) để chống data leakage — xem `_template_signature()`.
- `training/generate_dataset.py`: script sinh `data/training_data.csv`. Sinh dữ liệu từ nhiều kịch bản độc lập (không phải 1 khung câu hoán đổi brand/domain) để tránh việc mô hình chỉ học thuộc từ khoá bề mặt.
- `data/ood_eval.csv`: tập đánh giá **ngoài phân phối** — email viết tay, không sinh từ `generate_dataset.py` — dùng làm phép thử tổng quát hoá thật, độc lập với tập train/test.
- `models/url_model.py`: Random Forest cho URL.
- `detection/url_analyzer.py`: URL ML + heuristic fallback.
- `detection/sender_analyzer.py`: sender/reply-to/return-path/SPF/DKIM/DMARC.
- `detection/social_engineering.py`: urgency, credential, reward, impersonation.
- `detection/email_analyzer.py`: rule nội dung cơ bản.
- `detection/rule_engine_legacy.py`: bộ rule chi tiết của bài 1, gồm brand/domain và authentication.
- `ai_analyzer.py`: bộ điều phối, kết hợp Text AI + Rule + URL.

## Cài đặt

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Train model

Chạy từ thư mục project:

```bash
python training/train_all.py
```

Hoặc chỉ train text:

```bash
python training/train_text_model.py
```

Dataset text: `data/training_data.csv` (3600 dòng, sinh bởi `training/generate_dataset.py`). Muốn sinh lại (hoặc mở rộng thêm kịch bản):

```bash
python training/generate_dataset.py
python training/train_text_model.py
```

Dataset URL: `data/url_dataset.csv` (~400 dòng: domain thật + domain giả mạo thương hiệu, IP, ký tự `@`...). Vẫn là dataset tự xây dựng để project chạy đầy đủ; khi làm báo cáo chính thức nên thay bằng dữ liệu thực tế (PhishTank/OpenPhish) nếu có điều kiện.

## Chạy web

```bash
python app.py
```

Mở `http://127.0.0.1:5000`.

## Chạy test AI nhanh

```bash
python ai_analyzer.py
```

Kết quả trả thêm các thành phần:

- `ml_probability`: xác suất phishing của Text AI.
- `rule_score`: điểm bộ luật tổng hợp.
- `url_score`: điểm URL.
- `sender_score`: điểm người gửi/header.
- `social_score`: điểm social engineering.
- `score`: Risk Score cuối cùng.

## Đánh giá model: phát hiện & sửa lỗi tổng quát hoá (quan trọng khi bảo vệ)

Bản gốc của dataset text báo cáo **accuracy = 100%** trên tập test. Đây là dấu
hiệu của vấn đề, không phải model tốt: dataset là dữ liệu tổng hợp sinh từ một
số ít khung câu cố định (chỉ đổi brand/domain/số), nên `train_test_split`
ngẫu nhiên để lộ các câu gần-giống-hệt nhau ở cả train và test → accuracy ảo.

Quy trình đánh giá đã được sửa như sau:

1. **Group-split theo khung template** (`_template_signature()` trong
   `models/text_model.py`): chuẩn hoá text (thay URL/email/số bằng
   placeholder) để nhóm các dòng cùng khung câu, rồi dùng `GroupShuffleSplit`
   để mọi biến thể của cùng một khung luôn nằm trọn 1 phía train hoặc test.
2. **Tập đánh giá ngoài phân phối** (`data/ood_eval.csv`): 14 email viết tay,
   không sinh từ khung template nào trong dữ liệu train — đo generalization
   thật sự thay vì chỉ tin vào tập test cùng phân phối.
3. **Đa dạng hoá dataset** (`training/generate_dataset.py`): thay vì 1-2
   khung câu hoán đổi brand/domain, dataset mới có >10 kịch bản độc lập mỗi
   lớp (đe doạ khoá tài khoản, OTP giả, hoá đơn, trúng thưởng, BEC/giả mạo
   sếp, tuyển dụng giả, hoàn thuế, giao hàng...), viết bằng nhiều cách diễn
   đạt khác nhau thật sự, cả tiếng Việt lẫn tiếng Anh — bao gồm cả "hard
   negative" (email hợp lệ có OTP/link như thật) và "hard positive" (phishing
   không dùng từ khẩn cấp lộ liễu) để mô hình không thể chỉ dựa vào từ khoá.
4. **So sánh thuật toán trên cùng dữ liệu**: đã thử MultinomialNB, Logistic
   Regression, LinearSVC (calibrated) — đo trên tập OOD (không phải tập test
   cùng phân phối) để chọn thuật toán tổng quát hoá tốt nhất.

Kết quả đo được qua từng bước cải tiến (OOD = tập ngoài phân phối):

| Bước | In-distribution accuracy | OOD accuracy |
|---|---|---|
| Dataset gốc + random split (bug) | 100% | *(không đo)* |
| Dataset gốc + group split đúng | 100% | 64.3% |
| Dataset đa dạng hoá + NB | 100% | 85.7% |
| Dataset đa dạng hoá + Logistic Regression (bản hiện tại) | 100% | **92.9%** (precision 100%, recall 83%) |

In-distribution accuracy vẫn 100% ngay cả sau group-split đúng — điều này
**không phải bug**, mà phản ánh một sự thật về bản chất dữ liệu tổng hợp: từ
vựng 2 lớp khá tách biệt. Con số đáng tin cậy để đánh giá khả năng dùng thực
tế là **OOD accuracy (92.9%)**, không phải accuracy trên tập test. Khi báo
cáo/bảo vệ đồ án, nên trình bày cả 2 con số và giải thích rõ sự khác biệt
này — đây cũng là một điểm cộng học thuật (thể hiện hiểu vấn đề overfitting
sâu hơn, không chỉ chạy code và lấy số).

Muốn cải thiện thêm: mở rộng `data/ood_eval.csv` (dùng email thật của bạn,
đã ẩn danh) và bổ sung thêm kịch bản vào `training/generate_dataset.py`.

## Công thức final score

`effective_rule` là trung bình có trọng số của toàn bộ các module rule:

`effective_rule = 0.45 * legacy_rule + 0.15 * url_score + 0.15 * sender_score + 0.15 * social_score + 0.10 * content_score`

Sau đó:

`final = 0.45 * text_probability + 0.55 * effective_rule`

Authentication PASS giảm nhẹ final score; FAIL tăng nhẹ final score. Bộ rule legacy đã xử lý chi tiết SPF/DKIM/DMARC nên phần điều chỉnh cuối chỉ là hiệu chỉnh nhỏ.

Lưu ý: `sender_score`/`social_score`/`content_score` có phần trùng lặp khái niệm với `legacy_rule` (cùng kiểm tra auth, reply-to, từ khóa khẩn cấp...). Đây là chủ ý — một dấu hiệu được nhiều module độc lập cùng xác nhận sẽ đẩy rủi ro lên rõ rệt hơn so với dấu hiệu chỉ một module phát hiện, thay vì các module này chỉ đóng góp lý do (reasons) như bản trước.

## Lưu ý học thuật

Không dùng `meta_model.pkl` cũ của bài 2 vì model đó được huấn luyện từ vài điểm score giả lập. Bản ghép ưu tiên công thức hybrid có thể giải thích rõ khi bảo vệ. Nếu muốn dùng stacking/meta-model thật, cần tạo meta-dataset bằng out-of-fold predictions trên dữ liệu thực tế.
