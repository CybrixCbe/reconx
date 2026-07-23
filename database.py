import sqlite3
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE_PATH = "reconx.db"

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create Users Table
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
    
    # Add profile migration columns
    for col in [("full_name", "TEXT"), ("purpose", "TEXT"), ("experience_level", "TEXT"), ("organization", "TEXT"), ("profile_completed", "INTEGER DEFAULT 0")]:
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col[0]} {col[1]}")
        except sqlite3.OperationalError:
            pass # Column already exists
    
    # Create Scans Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        target TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        risk_score INTEGER NOT NULL,
        modules_run TEXT NOT NULL,
        results_json TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
    )
    """)
    
    # Create Activity Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
    )
    """)
    
    # Check if default Admin user exists, if not create one
    cursor.execute("SELECT * FROM users WHERE email = 'admin@reconx.local'")
    admin = cursor.fetchone()
    if not admin:
        admin_pass_hash = generate_password_hash("Admin@ReconX2026")
        cursor.execute("""
        INSERT INTO users (username, email, password_hash, role)
        VALUES ('admin', 'admin@reconx.local', ?, 'Admin')
        """, (admin_pass_hash,))
        
    conn.commit()
    conn.close()

# User Management Helpers
def create_user(username, email, password, role="User"):
    conn = get_db_connection()
    cursor = conn.cursor()
    pw_hash = generate_password_hash(password)
    try:
        cursor.execute("""
        INSERT INTO users (username, email, password_hash, role)
        VALUES (?, ?, ?, ?)
        """, (username, email, pw_hash, role))
        conn.commit()
        user_id = cursor.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def get_user_by_email(email):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user

def update_user_password(user_id, new_password):
    conn = get_db_connection()
    pw_hash = generate_password_hash(new_password)
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, user_id))
    conn.commit()
    conn.close()

def verify_user(email, password):
    user = get_user_by_email(email)
    if user and check_password_hash(user['password_hash'], password):
        return user
    return None

# Scan Management Helpers
def save_scan(user_id, target, risk_score, modules_run, results_json):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO scans (user_id, target, risk_score, modules_run, results_json)
    VALUES (?, ?, ?, ?, ?)
    """, (user_id, target, risk_score, ",".join(modules_run), results_json))
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id

def get_scans_by_user(user_id):
    conn = get_db_connection()
    scans = conn.execute("""
    SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC
    """, (user_id,)).fetchall()
    conn.close()
    return scans

def get_all_scans():
    conn = get_db_connection()
    scans = conn.execute("SELECT s.*, u.username FROM scans s LEFT JOIN users u ON s.user_id = u.id ORDER BY s.timestamp DESC").fetchall()
    conn.close()
    return scans

def get_scan_by_id(scan_id):
    conn = get_db_connection()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    return scan

def delete_scan(scan_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()

# Activity Logs Helpers
def log_activity(user_id, action, details=None, ip_address=None):
    conn = get_db_connection()
    conn.execute("""
    INSERT INTO activity_logs (user_id, action, details, ip_address)
    VALUES (?, ?, ?, ?)
    """, (user_id, action, details, ip_address))
    conn.commit()
    conn.close()

def get_activity_logs(limit=100):
    conn = get_db_connection()
    logs = conn.execute("""
    SELECT l.*, u.username FROM activity_logs l 
    LEFT JOIN users u ON l.user_id = u.id 
    ORDER BY l.timestamp DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return logs

# Dashboard Statistics Helper
def get_dashboard_stats(user_id=None, is_admin=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Filter by user if not admin
    user_filter = "WHERE user_id = ?" if (user_id and not is_admin) else ""
    user_param = (user_id,) if (user_id and not is_admin) else ()
    
    # Total Scans
    cursor.execute(f"SELECT COUNT(*) FROM scans {user_filter}", user_param)
    total_scans = cursor.fetchone()[0]
    
    # Today's Scans
    today_filter = "timestamp >= date('now')"
    if user_filter:
        cursor.execute(f"SELECT COUNT(*) FROM scans {user_filter} AND {today_filter}", user_param)
    else:
        cursor.execute(f"SELECT COUNT(*) FROM scans WHERE {today_filter}")
    todays_scans = cursor.fetchone()[0]
    
    # Unique Domains/Targets Analyzed
    cursor.execute(f"SELECT COUNT(DISTINCT target) FROM scans {user_filter}", user_param)
    unique_domains = cursor.fetchone()[0]
    
    # High-Risk Websites (Risk score >= 70 is High/Critical)
    high_risk_query = f"SELECT COUNT(*) FROM scans " + (f"{user_filter} AND risk_score >= 70" if user_filter else "WHERE risk_score >= 70")
    cursor.execute(high_risk_query, user_param)
    high_risk_count = cursor.fetchone()[0]
    
    # Average Risk Score
    cursor.execute(f"SELECT AVG(risk_score) FROM scans {user_filter}", user_param)
    avg_score_raw = cursor.fetchone()[0]
    avg_risk_score = round(avg_score_raw) if avg_score_raw is not None else 0
    
    # Recent scans list
    cursor.execute(f"SELECT id, target, timestamp, risk_score FROM scans {user_filter} ORDER BY timestamp DESC LIMIT 5", user_param)
    recent_scans = [dict(r) for r in cursor.fetchall()]
    
    conn.close()
    
    return {
        "total_scans": total_scans,
        "todays_scans": todays_scans,
        "unique_domains": unique_domains,
        "high_risk_count": high_risk_count,
        "avg_risk_score": avg_risk_score,
        "recent_scans": recent_scans
    }

def complete_user_profile(user_id, full_name, purpose, experience_level, organization):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE users 
    SET full_name = ?, purpose = ?, experience_level = ?, organization = ?, profile_completed = 1 
    WHERE id = ?
    """, (full_name, purpose, experience_level, organization, user_id))
    conn.commit()
    conn.close()
