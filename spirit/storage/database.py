import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # your friend's table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            version TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT
        )
    """)

    # scan history table for spirit report trajectory
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT,
            score REAL,
            zone TEXT,
            findings_count INTEGER,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()

def save_vulnerabilities(package_name, version, vuln_list):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = """
        INSERT INTO vulnerabilities 
        (package_name, version, cve_id, severity, description)
        VALUES (?, ?, ?, ?, ?)
    """
    for vuln in vuln_list:
        cursor.execute(query, (
            package_name,
            version,
            vuln.get("cve_id", "UNKNOWN"),
            vuln.get("severity", "UNKNOWN"),
            vuln.get("description", "No description provided.")
        ))
    conn.commit()
    conn.close()

def save_scan(path, score, zone, findings_count):
    from datetime import datetime
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO scans (path, score, zone, findings_count, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (path, score, zone, findings_count, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_scan_history(path, limit=10):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("""
        SELECT score, zone, findings_count, timestamp
        FROM scans WHERE path=?
        ORDER BY timestamp DESC LIMIT ?
    """, (path, limit)).fetchall()
    conn.close()
    return rows

# initialize on import
init_db()