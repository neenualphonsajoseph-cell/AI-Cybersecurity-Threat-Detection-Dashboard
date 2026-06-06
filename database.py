import sqlite3

DATABASE = "threats.db"


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        threat_level TEXT,
        threat_type TEXT,
        failed_attempts INTEGER,
        suspicious_ip TEXT,
        log_text TEXT,
        confidence_score REAL,
        ai_explanation TEXT,
        ai_recommendation TEXT
    )
    """)

    conn.commit()
    conn.close()


def save_threat(data):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO threats (
        timestamp,
        threat_level,
        threat_type,
        failed_attempts,
        suspicious_ip,
        log_text,
        confidence_score,
        ai_explanation,
        ai_recommendation
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["timestamp"],
        data["threat_level"],
        data["threat_type"],
        data["failed_attempts"],
        data["suspicious_ip"],
        data["log_text"],
        data["confidence_score"],
        data["ai_explanation"],
        data["ai_recommendation"]
    ))

    conn.commit()
    conn.close()


def get_threats():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM threats
    ORDER BY id DESC
    """)

    threats = cursor.fetchall()

    conn.close()

    return threats


def get_threat_by_id(threat_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM threats
    WHERE id = ?
    """, (threat_id,))

    threat = cursor.fetchone()

    conn.close()

    return threat
