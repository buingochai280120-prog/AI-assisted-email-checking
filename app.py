import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "email_guard.db")


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name     TEXT NOT NULL,
            email         TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at    TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            sender        TEXT,
            subject       TEXT,
            content       TEXT NOT NULL,
            score         INTEGER NOT NULL,
            risk_level    TEXT NOT NULL,
            reasons       TEXT,
            checked_at    TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()


def create_user(full_name: str, email: str, password_hash: str):
    conn = get_connection()
    try:
        cur = conn.execute(
            "INSERT INTO users (full_name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (full_name, email.lower().strip(), password_hash, datetime.utcnow().isoformat()),
        )
        conn.commit()
        new_id = cur.lastrowid
        return True, new_id
    except sqlite3.IntegrityError:
        return False, "Email này đã được đăng ký."
    finally:
        conn.close()


def get_user_by_email(email: str):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email.lower().strip(),)
    ).fetchone()
    conn.close()
    return row


def get_user_by_id(user_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


def add_check(user_id: int, sender: str, subject: str, content: str,
              score: int, risk_level: str, reasons: str):
    conn = get_connection()
    cur = conn.execute(
        """INSERT INTO checks (user_id, sender, subject, content, score, risk_level, reasons, checked_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, sender, subject, content, score, risk_level, reasons,
         datetime.utcnow().isoformat()),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def get_history(user_id: int, limit: int = 100):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM checks WHERE user_id = ? ORDER BY id DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()
    conn.close()
    return rows


def get_stats(user_id: int):
    conn = get_connection()
    rows = conn.execute(
        "SELECT risk_level, COUNT(*) as c FROM checks WHERE user_id = ? GROUP BY risk_level",
        (user_id,),
    ).fetchall()
    conn.close()
    stats = {"An toàn": 0, "Nghi ngờ": 0, "Nguy hiểm": 0}
    for r in rows:
        stats[r["risk_level"]] = r["c"]
    return stats


def delete_check(user_id: int, check_id: int):
    conn = get_connection()
    conn.execute("DELETE FROM checks WHERE id = ? AND user_id = ?", (check_id, user_id))
    conn.commit()
    conn.close()