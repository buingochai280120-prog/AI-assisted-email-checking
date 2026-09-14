
import csv
import os
import random

random.seed(7)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(BASE_DIR, "data", "training_data.csv")

# ---------------------------------------------------------------------------
# Khối build chung
# ---------------------------------------------------------------------------
GREETINGS = [
    "Xin chào,", "Chào bạn,", "Kính gửi Quý khách,", "Dear Customer,", "Hi there,",
    "Kính gửi Anh/Chị,", "Hello,", "Chào bạn thân mến,", "", "Thân gửi,",
]
SIGNOFFS = [
    "Trân trọng.", "Thân ái.", "Best regards.", "Cảm ơn bạn.", "Xin cảm ơn.",
    "Trân trọng cảm ơn.", "Regards,\nĐội ngũ hỗ trợ", "", "Thanks,\nSupport Team",
]

PHISH_DOMAINS = [
    "secure-verify.top", "account-update.xyz", "login-confirm.click", "service-alert.tk",
    "billing-check.info", "customer-portal.ga", "auth-renew.cf", "wallet-secure.loan",
    "id-recovery.top", "payment-confirm.xyz",
]
LEGIT_DOMAINS = [
    "company.vn", "shop.vn", "university.edu.vn", "bank.com.vn", "hrportal.com.vn",
    "accounts.google.com", "support.microsoft.com", "no-reply.internal-corp.vn",
]
BRANDS = ["Ngân hàng ABC", "Techcombank", "Google", "Microsoft", "PayPal", "Amazon",
          "Viettel Post", "Shopee", "Apple", "Facebook", "Zalo Pay", "Momo"]


def pick(lst):
    return random.choice(lst)


def make_row(subject, body, brand=None, legit=False):
    domain = pick(LEGIT_DOMAINS) if legit else pick(PHISH_DOMAINS)
    sender_name = f"{brand or pick(BRANDS)}"
    local = random.choice(["support", "no-reply", "security", "service", "info", "care"])
    sender = f"{sender_name} <{local}@{domain}>"
    greet = pick(GREETINGS)
    sign = pick(SIGNOFFS)
    parts = [p for p in [f"From: {sender}", f"Subject: {subject}", greet, body, sign] if p]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# KỊCH BẢN PHISHING (label = 1)
# ---------------------------------------------------------------------------
PHISH_SCENARIOS = []

# 1. Đe doạ khoá tài khoản
PHISH_SCENARIOS.append({
    "subjects": ["Cảnh báo: tài khoản sắp bị khoá", "Account suspension notice",
                 "Yêu cầu xác minh khẩn cấp", "Immediate action required on your account"],
    "bodies": [
        "Chúng tôi phát hiện đăng nhập bất thường từ thiết bị lạ. Để tránh bị khoá vĩnh viễn, vui lòng xác minh danh tính tại {link} trong vòng 24 giờ.",
        "We detected unusual sign-in activity on your account. To prevent permanent suspension, verify your identity at {link} within 24 hours.",
        "Tài khoản của bạn đã bị tạm khoá do vi phạm điều khoản sử dụng. Nhấn vào {link} để kháng nghị và mở khoá lại.",
        "Do phát hiện dấu hiệu bất thường, hệ thống đã tạm ngưng quyền truy cập của bạn. Khôi phục ngay tại {link} để không mất dữ liệu.",
    ],
})

# 2. OTP / mã xác thực giả
PHISH_SCENARIOS.append({
    "subjects": ["Xác nhận mã OTP giao dịch", "Confirm your one-time passcode",
                 "Cảnh báo giao dịch bất thường"],
    "bodies": [
        "Có một giao dịch trị giá 15.000.000đ đang chờ xác nhận. Nếu không phải bạn thực hiện, nhập mã OTP tại {link} để huỷ giao dịch ngay.",
        "A withdrawal request of $850 is pending on your account. If this wasn't you, enter your verification code at {link} to cancel it immediately.",
        "Hệ thống ghi nhận yêu cầu đổi mật khẩu từ IP lạ. Nhập mã xác thực vừa gửi tại {link} nếu không phải bạn để bảo vệ tài khoản.",
    ],
})

# 3. Hoá đơn / thanh toán
PHISH_SCENARIOS.append({
    "subjects": ["Hoá đơn chưa thanh toán", "Outstanding invoice attached",
                 "Cập nhật thông tin thanh toán"],
    "bodies": [
        "Hoá đơn tháng này của bạn chưa được thanh toán và dịch vụ sẽ bị ngừng cung cấp. Cập nhật thẻ thanh toán tại {link} để tiếp tục sử dụng.",
        "Our system could not process your last payment. Please update your billing details at {link} to avoid service interruption.",
        "Đơn hàng #{num} của bạn phát sinh phụ phí vận chuyển. Vui lòng thanh toán khoản chênh lệch tại {link} để nhận hàng đúng hẹn.",
        "Your subscription payment failed. Update your card information at {link} within 48 hours or your account will be downgraded.",
    ],
})

# 4. Trúng thưởng / quà tặng
PHISH_SCENARIOS.append({
    "subjects": ["Chúc mừng bạn trúng thưởng", "You've won a special reward",
                 "Quà tặng tri ân khách hàng thân thiết"],
    "bodies": [
        "Chúc mừng! Số điện thoại của bạn may mắn trúng giải thưởng trị giá 10 triệu đồng trong chương trình tri ân khách hàng. Nhận quà ngay tại {link}.",
        "Congratulations, you have been selected to receive a free gift card. Claim your reward before it expires at {link}.",
        "Bạn là một trong 100 khách hàng may mắn nhận voucher mua sắm trị giá 2.000.000đ. Điền thông tin nhận thưởng tại {link}.",
    ],
})

# 5. Hỗ trợ kỹ thuật / virus giả
PHISH_SCENARIOS.append({
    "subjects": ["Cảnh báo bảo mật thiết bị", "Security alert: virus detected",
                 "Thiết bị của bạn có dấu hiệu bị xâm nhập"],
    "bodies": [
        "Hệ thống phát hiện thiết bị của bạn đã bị nhiễm mã độc. Tải công cụ quét miễn phí và đăng nhập xác thực tại {link} để loại bỏ nguy cơ.",
        "Our scan detected 3 threats on your device. Download the removal tool and sign in to confirm at {link} immediately.",
        "Trình duyệt của bạn đang gặp lỗi bảo mật nghiêm trọng. Liên hệ đội ngũ hỗ trợ kỹ thuật qua {link} để được xử lý trước khi mất dữ liệu.",
    ],
})

# 6. Giả mạo sếp / chuyển khoản nội bộ (BEC)
PHISH_SCENARIOS.append({
    "subjects": ["Yêu cầu xử lý gấp", "Quick task before my meeting", "Việc cần làm gấp trong hôm nay"],
    "bodies": [
        "Anh đang họp không tiện gọi điện. Em chuyển giúp anh khoản 25 triệu cho đối tác theo thông tin ở {link}, anh sẽ giải thích sau nhé.",
        "I'm in back to back meetings. Can you process a payment to our new vendor using the details at {link}? Need this done before noon.",
        "Chị nhờ em xử lý gấp việc thanh toán hoá đơn nhà cung cấp mới, thông tin chuyển khoản chị gửi ở {link}, đừng thông báo phòng kế toán vội.",
    ],
})

# 7. Việc làm tại nhà / tuyển dụng giả
PHISH_SCENARIOS.append({
    "subjects": ["Cơ hội việc làm thu nhập cao", "Work from home opportunity",
                 "Tuyển dụng gấp - lương hấp dẫn"],
    "bodies": [
        "Chúng tôi đang tuyển nhân viên nhập liệu tại nhà, lương 500k/ngày, không cần kinh nghiệm. Đăng ký ngay tại {link} để giữ suất.",
        "We're hiring remote data-entry workers, $80/day, no experience needed. Register your details at {link} to secure your spot today.",
        "Công ty cần tuyển cộng tác viên đặt đơn ảo hoa hồng cao. Liên hệ và nộp thông tin cá nhân tại {link} để bắt đầu công việc ngay hôm nay.",
    ],
})

# 8. Hoàn thuế / trợ cấp giả
PHISH_SCENARIOS.append({
    "subjects": ["Thông báo hoàn thuế", "Tax refund notification", "Trợ cấp hỗ trợ bạn đủ điều kiện nhận"],
    "bodies": [
        "Bạn đủ điều kiện nhận khoản hoàn thuế 3.200.000đ cho năm nay. Điền thông tin tài khoản ngân hàng tại {link} để nhận tiền trong 3 ngày.",
        "You are eligible for a tax refund of $410. Submit your banking information at {link} to receive the payment within 3 business days.",
    ],
})

# 9. "Lịch sự", không dùng từ khẩn cấp — cố tình để tránh model chỉ dựa từ khoá
PHISH_SCENARIOS.append({
    "subjects": ["Xác nhận lại thông tin tài khoản", "A small update needed on your profile",
                 "Vui lòng kiểm tra lại thông tin"],
    "bodies": [
        "Chào bạn, đội ngũ chăm sóc khách hàng của chúng tôi cần bạn xác nhận lại một vài thông tin để hồ sơ được cập nhật chính xác hơn, bạn xem qua tại {link} khi rảnh nhé.",
        "Hi, our records show your profile information may be outdated. Whenever convenient, please review and confirm the details at {link}.",
        "Nhân dịp cập nhật hệ thống mới, chúng tôi mong bạn dành chút thời gian xác nhận lại số dư và thông tin liên hệ tại {link} giúp chúng tôi nhé.",
        "Đơn hàng của bạn đang được xử lý, tuy nhiên địa chỉ giao hàng có vẻ chưa đầy đủ. Bạn vui lòng bổ sung giúp tại {link}.",
    ],
})

# 10. Giả mạo giao hàng
PHISH_SCENARIOS.append({
    "subjects": ["Đơn hàng gặp sự cố vận chuyển", "Delivery issue with your package"],
    "bodies": [
        "Kiện hàng của bạn không thể giao do thiếu phí hải quan. Thanh toán 45.000đ tại {link} để tiếp tục giao hàng, nếu không đơn sẽ bị huỷ.",
        "Your package is on hold due to an unpaid customs fee. Pay $2.99 at {link} to release your delivery before it's returned to sender.",
    ],
})

# 11. Mạng xã hội / đăng nhập lạ
PHISH_SCENARIOS.append({
    "subjects": ["Ai đó vừa cố đăng nhập vào tài khoản của bạn", "New login attempt detected"],
    "bodies": [
        "Chúng tôi ghi nhận một thiết bị lạ vừa cố đăng nhập vào tài khoản mạng xã hội của bạn. Nếu không phải bạn, đổi mật khẩu ngay tại {link}.",
        "A device we don't recognize just tried to sign in to your account. If this wasn't you, secure your account now at {link}.",
    ],
})

PHISH_LINKS = [
    "http://" + d + "/verify" for d in PHISH_DOMAINS
] + [
    "http://" + d + "/confirm?id=" + str(random.randint(1000, 9999)) for d in PHISH_DOMAINS
] + [
    "https://" + d.replace(".xyz", ".xyz-secure") + "/login" for d in PHISH_DOMAINS[:4]
]

# ---------------------------------------------------------------------------
# KỊCH BẢN HAM (label = 0)
# ---------------------------------------------------------------------------
HAM_SCENARIOS = []

HAM_SCENARIOS.append({  # họp / nội bộ
    "subjects": ["Lịch họp tuần này", "Team meeting schedule", "Thông báo lịch họp phòng ban"],
    "bodies": [
        "Chào cả team, tuần này chúng ta sẽ họp vào thứ Ba lúc 9h sáng tại phòng họp lớn để bàn về kế hoạch quý tới, mọi người chuẩn bị báo cáo giúp mình nhé.",
        "Hi team, our weekly sync is moved to Thursday 2 PM. Please bring your updates on the current sprint so we can plan the next steps together.",
        "Kính gửi các anh chị, phòng nhân sự xin thông báo lịch họp toàn công ty vào cuối tháng để tổng kết hoạt động quý vừa qua.",
    ],
})

HAM_SCENARIOS.append({  # newsletter/khuyến mãi
    "subjects": ["Bản tin tuần này", "This week's newsletter", "Ưu đãi dành cho bạn"],
    "bodies": [
        "Cảm ơn bạn đã đăng ký nhận bản tin của chúng tôi. Tuần này có nhiều bài viết thú vị về xu hướng công nghệ, mời bạn ghé thăm blog để đọc thêm.",
        "Thanks for subscribing! Here's a roundup of this week's top stories and a few discounts on products you might like, no action required.",
        "Cửa hàng chúng tôi đang có chương trình giảm giá cuối tuần cho các sản phẩm mùa hè, mời bạn ghé xem khi có thời gian rảnh.",
    ],
})

HAM_SCENARIOS.append({  # OTP thật (hard negative)
    "subjects": ["Mã xác thực đăng nhập của bạn", "Your verification code", "Mã OTP giao dịch"],
    "bodies": [
        "Mã OTP của bạn là {num}. Mã có hiệu lực trong 5 phút, vui lòng không chia sẻ mã này cho bất kỳ ai kể cả nhân viên ngân hàng.",
        "Your one-time code is {num}, valid for 10 minutes. We will never call and ask you to share this code with anyone.",
        "Đây là mã xác thực bạn yêu cầu để đăng nhập ứng dụng: {num}. Nếu không phải bạn yêu cầu, bạn có thể bỏ qua email này.",
    ],
})

HAM_SCENARIOS.append({  # password reset thật (hard negative, có link)
    "subjects": ["Yêu cầu đặt lại mật khẩu", "Password reset requested"],
    "bodies": [
        "Bạn vừa yêu cầu đặt lại mật khẩu cho tài khoản. Nhấn vào {link} để tạo mật khẩu mới, liên kết hết hạn sau 1 giờ. Nếu không phải bạn, hãy bỏ qua email này.",
        "We received a request to reset your password. Click {link} to choose a new one. This link expires in 60 minutes. If you didn't request this, no action is needed.",
    ],
})

HAM_SCENARIOS.append({  # giao hàng thật
    "subjects": ["Đơn hàng của bạn đã được giao", "Your order has shipped"],
    "bodies": [
        "Đơn hàng #{num} của bạn đã được giao cho đơn vị vận chuyển và dự kiến đến trong 2-3 ngày tới. Bạn có thể theo dõi trạng thái ngay trong ứng dụng.",
        "Good news! Your order has shipped and should arrive within 3-5 business days. Track it anytime from your order history in the app.",
        "Cảm ơn bạn đã mua hàng. Hoá đơn điện tử đã được đính kèm, không cần thao tác gì thêm từ phía bạn.",
    ],
})

HAM_SCENARIOS.append({  # hoá đơn/thanh toán thật, không đe doạ
    "subjects": ["Biên nhận thanh toán", "Your payment receipt", "Xác nhận đơn hàng"],
    "bodies": [
        "Cảm ơn bạn đã thanh toán. Đây là biên nhận cho giao dịch vừa thực hiện, bạn có thể lưu lại để đối chiếu khi cần.",
        "Thanks for your payment. This is your receipt for the recent transaction — no further action is required on your part.",
        "Đơn hàng của bạn đã được xác nhận và đang được xử lý, thời gian giao hàng dự kiến sẽ được cập nhật trong email tiếp theo.",
    ],
})

HAM_SCENARIOS.append({  # HR/payroll
    "subjects": ["Thông báo lịch nghỉ lễ", "Holiday schedule announcement", "Phiếu lương tháng này"],
    "bodies": [
        "Phòng nhân sự thông báo lịch nghỉ lễ sắp tới, các anh chị vui lòng sắp xếp công việc bàn giao trước khi nghỉ.",
        "HR would like to remind everyone of the updated holiday schedule for this quarter, please check the shared calendar for details.",
        "Phiếu lương tháng này đã được gửi vào tài khoản đăng ký của bạn, nếu có thắc mắc vui lòng liên hệ phòng kế toán trong giờ hành chính.",
    ],
})

HAM_SCENARIOS.append({  # IT/bảo trì hệ thống
    "subjects": ["Thông báo bảo trì hệ thống", "Scheduled system maintenance"],
    "bodies": [
        "Hệ thống sẽ được bảo trì định kỳ vào tối thứ Bảy này từ 22h đến 24h, một số dịch vụ có thể tạm thời gián đoạn trong khung giờ trên.",
        "We will be performing scheduled maintenance this weekend. Some services may be temporarily unavailable during that window.",
    ],
})

HAM_SCENARIOS.append({  # bạn bè/đồng nghiệp thân mật
    "subjects": ["Cuối tuần này rảnh không?", "Catching up soon?", "Cảm ơn vì hôm trước nhé"],
    "bodies": [
        "Cuối tuần này bạn có rảnh không, mình muốn rủ đi cà phê nói chuyện một chút, lâu rồi không gặp nhỉ.",
        "It was great catching up last week! Let me know if you're free sometime next week, would love to grab coffee again.",
        "Cảm ơn bạn đã giúp mình hôm trước, mình đã hoàn thành xong phần việc rồi, hẹn gặp lại ở buổi họp tuần sau nhé.",
    ],
})

HAM_SCENARIOS.append({  # webinar/education
    "subjects": ["Tài liệu buổi hội thảo", "Webinar recording and slides", "Thông báo lịch học tuần này"],
    "bodies": [
        "Cảm ơn bạn đã tham gia buổi hội thảo tuần trước, đây là bản ghi hình và slide để bạn xem lại khi cần.",
        "Thanks for joining our webinar last week! Here is the recording and slides in case you'd like to review them again.",
        "Phòng đào tạo thông báo lịch học bổ sung cho môn học tuần này, sinh viên vui lòng kiểm tra thời khoá biểu trên cổng thông tin.",
    ],
})

HAM_SCENARIOS.append({  # ngân hàng thật, thông báo sao kê
    "subjects": ["Sao kê giao dịch hàng tháng", "Your monthly account statement"],
    "bodies": [
        "Sao kê giao dịch tháng này của bạn đã sẵn sàng, bạn có thể xem chi tiết trong ứng dụng ngân hàng hoặc trên trang quản lý tài khoản.",
        "Your monthly statement is now available. You can view the full details anytime by logging into your account through our official app.",
    ],
})

HAM_SCENARIOS.append({  # hỗ trợ khách hàng thật (phản hồi ticket)
    "subjects": ["Re: Yêu cầu hỗ trợ của bạn", "Re: Your support ticket update"],
    "bodies": [
        "Cảm ơn bạn đã liên hệ. Đội ngũ hỗ trợ đã xem xét vấn đề của bạn và đã xử lý xong, nếu còn thắc mắc gì bạn cứ phản hồi lại email này nhé.",
        "Thanks for reaching out. We've looked into the issue you reported and it has been resolved — feel free to reply here if you need anything else.",
    ],
})

LEGIT_LINKS = [
    "https://" + d + "/account" for d in LEGIT_DOMAINS
] + [
    "https://" + d + "/orders" for d in LEGIT_DOMAINS
] + [
    "https://" + d + "/reset-password" for d in LEGIT_DOMAINS
]


def expand(scenarios, links, legit, n_target):
    rows = []
    seen_texts = set()
    attempts = 0
    while len(rows) < n_target and attempts < n_target * 20:
        attempts += 1
        scenario = pick(scenarios)
        subject = pick(scenario["subjects"])
        body_tpl = pick(scenario["bodies"])
        body = body_tpl.format(
            link=pick(links),
            num=random.randint(100000, 999999),
        )
        brand = pick(BRANDS) if random.random() < 0.5 else None
        text = make_row(subject, body, brand=brand, legit=legit)
        if text in seen_texts:
            continue
        seen_texts.add(text)
        rows.append(text)
    return rows


def main():
    n_per_class = 1800
    phish_rows = expand(PHISH_SCENARIOS, PHISH_LINKS, legit=False, n_target=n_per_class)
    ham_rows = expand(HAM_SCENARIOS, LEGIT_LINKS, legit=True, n_target=n_per_class)

    all_rows = [(t, 1) for t in phish_rows] + [(t, 0) for t in ham_rows]
    random.shuffle(all_rows)

    with open(OUT_PATH, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        for text, label in all_rows:
            writer.writerow([text, label])

    print(f"Đã sinh {len(all_rows)} dòng ({len(phish_rows)} phishing, {len(ham_rows)} ham) -> {OUT_PATH}")


if __name__ == "__main__":
    main()
