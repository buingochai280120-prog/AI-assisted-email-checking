import sqlite3

DB_PATH = "instance/email_guard.db"

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

# Xem users
print("\n===== USERS =====")

users = conn.execute("""
    SELECT id, full_name, email, created_at
    FROM users
    ORDER BY id DESC
""").fetchall()

for user in users:
    print(
        user["id"],
        "|",
        user["full_name"],
        "|",
        user["email"],
        "|",
        user["created_at"]
    )


# Xem lịch sử kiểm tra email
print("\n===== CHECKS =====")

checks = conn.execute("""
    SELECT id, user_id, sender, subject, score, risk_level, checked_at
    FROM checks
    ORDER BY id DESC
""").fetchall()

for check in checks:
    print(
        check["id"],
        "| User:",
        check["user_id"],
        "|",
        check["sender"],
        "|",
        check["subject"],
        "| Score:",
        check["score"],
        "|",
        check["risk_level"]
    )

conn.close()