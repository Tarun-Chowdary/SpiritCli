import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "storage", "scans.db")


def _init_audit_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT,
            score REAL,
            zone TEXT,
            action TEXT,
            message TEXT,
            user TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_push_attempt(path, score, zone, action, message=""):
    """
    action can be:
    APPROVED     - safe zone, push went through
    WARNING_ACCEPTED - warning zone, developer acknowledged
    BLOCKED      - quarantine zone, push rejected
    FORCE_PUSH   - security bypassed
    CANCELLED    - developer chose not to push
    """
    _init_audit_table()

    # get current user
    try:
        import getpass

        user = getpass.getuser()
    except Exception:
        user = "unknown"

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO audit_log 
        (path, score, zone, action, message, user, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
        (path, score, zone, action, message, user, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def get_audit_log(path=None, limit=20):
    _init_audit_table()
    conn = sqlite3.connect(DB_PATH)

    if path:
        rows = conn.execute(
            """
            SELECT path, score, zone, action, message, user, timestamp
            FROM audit_log
            WHERE path=?
            ORDER BY timestamp DESC
            LIMIT ?
        """,
            (path, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT path, score, zone, action, message, user, timestamp
            FROM audit_log
            ORDER BY timestamp DESC
            LIMIT ?
        """,
            (limit,),
        ).fetchall()

    conn.close()
    return rows


def get_audit_summary(path=None):
    _init_audit_table()
    conn = sqlite3.connect(DB_PATH)

    if path:
        rows = conn.execute(
            """
            SELECT action, COUNT(*) as count
            FROM audit_log
            WHERE path=?
            GROUP BY action
        """,
            (path,),
        ).fetchall()
    else:
        rows = conn.execute("""
            SELECT action, COUNT(*) as count
            FROM audit_log
            GROUP BY action
        """).fetchall()

    conn.close()
    return {row[0]: row[1] for row in rows}
