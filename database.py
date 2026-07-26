import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE_PATH = os.getenv("DATABASE_PATH", "reconx.db")


def get_db_connection():
    db_dir = os.path.dirname(DATABASE_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'User',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        otp_secret TEXT
    )
    """)

    profile_columns = [
        ("full_name", "TEXT"),
        ("purpose", "TEXT"),
        ("experience_level", "TEXT"),
        ("organization", "TEXT"),
        ("profile_completed", "INTEGER DEFAULT 0")
    ]

    for col, dtype in profile_columns:
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col} {dtype}")
        except sqlite3.OperationalError:
            pass

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        target TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        risk_score INTEGER NOT NULL,
        modules_run TEXT NOT NULL,
        results_json TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    )
    """)

    cursor.execute("SELECT id FROM users WHERE email=?", ("admin@reconx.local",))
    if cursor.fetchone() is None:
        cursor.execute("""
        INSERT INTO users
        (username,email,password_hash,role,profile_completed)
        VALUES (?,?,?,?,1)
        """, (
            "admin",
            "admin@reconx.local",
            generate_password_hash("Admin@ReconX2026"),
            "Admin"
        ))

    conn.commit()
    conn.close()


def create_user(username, email, password, role="User"):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO users (username,email,password_hash,role)
        VALUES (?,?,?,?)
        """, (username, email, generate_password_hash(password), role))
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_email(email):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return user


def verify_user(email, password):
    user = get_user_by_email(email)
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None


def update_user_password(user_id, new_password):
    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET password_hash=? WHERE id=?",
        (generate_password_hash(new_password), user_id)
    )
    conn.commit()
    conn.close()


def complete_user_profile(user_id, full_name, purpose, experience_level, organization):
    conn = get_db_connection()
    conn.execute("""
    UPDATE users
    SET full_name=?, purpose=?, experience_level=?, organization=?, profile_completed=1
    WHERE id=?
    """, (full_name, purpose, experience_level, organization, user_id))
    conn.commit()
    conn.close()


def save_scan(user_id, target, risk_score, modules_run, results_json):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO scans(user_id,target,risk_score,modules_run,results_json)
    VALUES (?,?,?,?,?)
    """, (user_id, target, risk_score, ",".join(modules_run), results_json))
    conn.commit()
    sid = cur.lastrowid
    conn.close()
    return sid


def get_scans_by_user(user_id):
    conn = get_db_connection()
    data = conn.execute(
        "SELECT * FROM scans WHERE user_id=? ORDER BY timestamp DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return data


def get_all_scans():
    conn = get_db_connection()
    data = conn.execute("""
    SELECT s.*,u.username
    FROM scans s
    LEFT JOIN users u ON s.user_id=u.id
    ORDER BY s.timestamp DESC
    """).fetchall()
    conn.close()
    return data


def get_scan_by_id(scan_id):
    conn = get_db_connection()
    data = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    return data


def delete_scan(scan_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()


def log_activity(user_id, action, details=None, ip_address=None):
    conn = get_db_connection()
    conn.execute("""
    INSERT INTO activity_logs(user_id,action,details,ip_address)
    VALUES (?,?,?,?)
    """, (user_id, action, details, ip_address))
    conn.commit()
    conn.close()


def get_activity_logs(limit=100):
    conn = get_db_connection()
    logs = conn.execute("""
    SELECT l.*,u.username
    FROM activity_logs l
    LEFT JOIN users u ON l.user_id=u.id
    ORDER BY l.timestamp DESC
    LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return logs


def get_dashboard_stats(user_id=None, is_admin=False):
    conn = get_db_connection()
    cur = conn.cursor()

    where = ""
    params = ()
    if user_id and not is_admin:
        where = " WHERE user_id=?"
        params = (user_id,)

    cur.execute(f"SELECT COUNT(*) FROM scans{where}", params)
    total = cur.fetchone()[0]

    if where:
        cur.execute("SELECT COUNT(*) FROM scans WHERE user_id=? AND date(timestamp)=date('now')", params)
    else:
        cur.execute("SELECT COUNT(*) FROM scans WHERE date(timestamp)=date('now')")
    today = cur.fetchone()[0]

    cur.execute(f"SELECT COUNT(DISTINCT target) FROM scans{where}", params)
    domains = cur.fetchone()[0]

    if where:
        cur.execute("SELECT COUNT(*) FROM scans WHERE user_id=? AND risk_score>=70", params)
    else:
        cur.execute("SELECT COUNT(*) FROM scans WHERE risk_score>=70")
    high = cur.fetchone()[0]

    cur.execute(f"SELECT AVG(risk_score) FROM scans{where}", params)
    avg = cur.fetchone()[0]
    avg = round(avg) if avg else 0

    cur.execute(f"SELECT id,target,timestamp,risk_score FROM scans{where} ORDER BY timestamp DESC LIMIT 5", params)
    recent = [dict(r) for r in cur.fetchall()]
    conn.close()

    return {
        "total_scans": total,
        "todays_scans": today,
        "unique_domains": domains,
        "high_risk_count": high,
        "avg_risk_score": avg,
        "recent_scans": recent,
    }
