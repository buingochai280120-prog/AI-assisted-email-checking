"""
app.py
------
Ứng dụng web Flask: "Email Guard AI" - phân tích email và cảnh báo lừa đảo (phishing).

Chạy ứng dụng:
    pip install -r requirements.txt
    python app.py

Sau đó mở trình duyệt tại: http://127.0.0.1:5000
"""

import json
import os
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, session, jsonify, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

import database as db
from ai_analyzer import analyze_email
from file_parser import parse_uploaded_file, FileParseError, ALLOWED_EXTENSIONS

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "doi-khoa-bi-mat-nay-khi-trien-khai-that-su")
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024  # giới hạn 3MB cho file tải lên

db.init_db()


# ---------------------------------------------------------------------------
# TIỆN ÍCH XÁC THỰC
# ---------------------------------------------------------------------------

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            # Các route /api/* trả JSON 401 thay vì redirect: nếu redirect,
            # fetch() phía JS sẽ tự động theo link tới trang login.html (status
            # 200, nội dung HTML) rồi res.json() sẽ lỗi parse, khiến người
            # dùng thấy thông báo lỗi khó hiểu thay vì "vui lòng đăng nhập lại".
            if request.path.startswith("/api/"):
                return jsonify({"error": "Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại."}), 401
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_user():
    user = None
    if "user_id" in session:
        user = db.get_user_by_id(session["user_id"])
    return {"current_user": user}


# ---------------------------------------------------------------------------
# TRANG CHỦ
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# ĐĂNG KÝ
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        error = None
        if not full_name or not email or not password:
            error = "Vui lòng điền đầy đủ thông tin."
        elif "@" not in email or "." not in email:
            error = "Địa chỉ email không hợp lệ."
        elif len(password) < 6:
            error = "Mật khẩu phải có ít nhất 6 ký tự."
        elif password != confirm:
            error = "Mật khẩu xác nhận không khớp."

        if error:
            flash(error, "error")
            return render_template("register.html", full_name=full_name, email=email)

        password_hash = generate_password_hash(password)
        ok, err_msg = db.create_user(full_name, email, password_hash)
        if not ok:
            flash(err_msg, "error")
            return render_template("register.html", full_name=full_name, email=email)

        flash("Đăng ký thành công! Vui lòng đăng nhập để tiếp tục.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------------------------------------------------------------------
# ĐĂNG NHẬP / ĐĂNG XUẤT
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        user = db.get_user_by_email(email)
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Email hoặc mật khẩu không chính xác.", "error")
            return render_template("login.html", email=email)

        session.clear()
        session["user_id"] = user["id"]
        session["full_name"] = user["full_name"]
        flash(f"Chào mừng trở lại, {user['full_name']}!", "success")
        next_url = request.args.get("next") or url_for("dashboard")
        return redirect(next_url)

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Bạn đã đăng xuất.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# DASHBOARD & LỊCH SỬ (giao diện HTML)
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    history_rows = db.get_history(session["user_id"], limit=8)
    stats = db.get_stats(session["user_id"])
    return render_template("dashboard.html", recent_history=history_rows, stats=stats)


@app.route("/history")
@login_required
def history_page():
    history_rows = db.get_history(session["user_id"], limit=200)
    stats = db.get_stats(session["user_id"])
    return render_template("history.html", history=history_rows, stats=stats)


# ---------------------------------------------------------------------------
# API (JSON) — được gọi bằng JavaScript ở phía client
# ---------------------------------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    data = request.get_json(silent=True) or {}
    sender = (data.get("sender") or "").strip()
    subject = (data.get("subject") or "").strip()
    content = (data.get("content") or "").strip()
    reply_to = (data.get("reply_to") or "").strip()
    auth_results = (data.get("auth_results") or "").strip()
    return_path = (data.get("return_path") or "").strip()

    if not content:
        return jsonify({"error": "Vui lòng nhập nội dung email cần kiểm tra."}), 400

    result = analyze_email(sender, subject, content, reply_to=reply_to, auth_results=auth_results, return_path=return_path)

    check_id = db.add_check(
        user_id=session["user_id"],
        sender=sender,
        subject=subject,
        content=content,
        score=result["score"],
        risk_level=result["risk_level"],
        reasons=json.dumps(result["reasons"], ensure_ascii=False),
    )
    result["id"] = check_id
    return jsonify(result)


@app.route("/api/parse-file", methods=["POST"])
@login_required
def api_parse_file():
    """Nhận file .txt / .eml người dùng tải lên, trả về sender/subject/content
    đã trích xuất để JavaScript tự động điền vào form quét email."""
    if "file" not in request.files:
        return jsonify({"error": "Không tìm thấy file được tải lên."}), 400

    uploaded = request.files["file"]
    filename = uploaded.filename or ""

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "Chỉ hỗ trợ file định dạng .txt hoặc .eml."}), 400

    raw_bytes = uploaded.read()
    try:
        parsed = parse_uploaded_file(filename, raw_bytes)
    except FileParseError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(parsed)


@app.route("/api/history")
@login_required
def api_history():
    rows = db.get_history(session["user_id"], limit=200)
    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "sender": r["sender"],
            "subject": r["subject"],
            "content": r["content"],
            "score": r["score"],
            "risk_level": r["risk_level"],
            "reasons": json.loads(r["reasons"]) if r["reasons"] else [],
            "checked_at": r["checked_at"],
        })
    return jsonify(items)


@app.route("/api/history/<int:check_id>", methods=["DELETE"])
@login_required
def api_delete_history(check_id):
    db.delete_check(session["user_id"], check_id)
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
