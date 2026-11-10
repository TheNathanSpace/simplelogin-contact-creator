import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.errors import StartupError

IDLE = timedelta(days=14)
WINDOW = timedelta(minutes=15)
FAILURE_LIMIT = 5


def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _stamp(moment):
    return moment.isoformat()


def db_path(data_dir: Path) -> Path:
    return data_dir / "app.db"


def connect(data_dir: Path):
    conn = sqlite3.connect(db_path(data_dir), timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db(data_dir: Path):
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(data_dir, 0o700)
        conn = connect(data_dir)
    except OSError as exc:
        raise StartupError(f"Could not create DATA_DIR {data_dir}: {exc.strerror}") from exc
    except sqlite3.Error as exc:
        raise StartupError(f"Could not open the database in DATA_DIR {data_dir}: {exc}") from exc
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                api_nonce BLOB NOT NULL,
                api_ciphertext BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS setup_code (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                code_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS session (
                id_hash TEXT PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                user_id INTEGER,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_failure (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.commit()
    except sqlite3.Error as exc:
        raise StartupError(f"Could not open the database in DATA_DIR {data_dir}: {exc}") from exc
    finally:
        conn.close()
    try:
        os.chmod(db_path(data_dir), 0o600)
    except OSError as exc:
        raise StartupError(f"Could not set permissions on the database in {data_dir}: {exc.strerror}") from exc


def _hash_token(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def has_user(data_dir):
    conn = connect(data_dir)
    try:
        row = conn.execute("SELECT id FROM user").fetchone()
        return row is not None
    finally:
        conn.close()


def get_user(data_dir):
    conn = connect(data_dir)
    try:
        return conn.execute("SELECT * FROM user").fetchone()
    finally:
        conn.close()


def issue_setup_code(data_dir):
    """Return a new setup code when no account exists, else None."""
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT id FROM user").fetchone():
            conn.execute("DELETE FROM setup_code")
            conn.commit()
            return None
        code = secrets.token_urlsafe(16)
        code_hash = _hash_token(code)
        conn.execute(
            """
            INSERT INTO setup_code (id, code_hash) VALUES (1, ?)
            ON CONFLICT(id) DO UPDATE SET code_hash = excluded.code_hash
            """,
            (code_hash,),
        )
        conn.commit()
        return code
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def setup_code_matches(data_dir, submitted):
    if not submitted:
        return False
    conn = connect(data_dir)
    try:
        row = conn.execute("SELECT code_hash FROM setup_code WHERE id = 1").fetchone()
    finally:
        conn.close()
    if row is None:
        return False
    actual = _hash_token(submitted)
    return hmac.compare_digest(row["code_hash"], actual)


def insert_user(data_dir, username, password_hash, nonce, ciphertext):
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT id FROM user").fetchone():
            conn.rollback()
            return False
        conn.execute(
            """
            INSERT INTO user (id, username, password_hash, api_nonce, api_ciphertext)
            VALUES (1, ?, ?, ?, ?)
            """,
            (username, password_hash, nonce, ciphertext),
        )
        conn.execute("DELETE FROM setup_code")
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
        os.chmod(db_path(data_dir), 0o600)


def create_session(data_dir, user_id):
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = _stamp(utcnow())
    conn = connect(data_dir)
    try:
        conn.execute(
            """
            INSERT INTO session (id_hash, csrf_token, user_id, created_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (_hash_token(raw), csrf, user_id, now, now),
        )
        conn.commit()
    finally:
        conn.close()
    return raw, csrf


def get_session(data_dir, raw_token):
    cutoff = _stamp(utcnow() - IDLE)
    conn = connect(data_dir)
    try:
        conn.execute("DELETE FROM session WHERE last_seen_at < ?", (cutoff,))
        if not raw_token:
            conn.commit()
            return None
        row = conn.execute(
            "SELECT * FROM session WHERE id_hash = ?",
            (_hash_token(raw_token),),
        ).fetchone()
        if row is None:
            conn.commit()
            return None
        now = _stamp(utcnow())
        conn.execute(
            "UPDATE session SET last_seen_at = ? WHERE id_hash = ?",
            (now, row["id_hash"]),
        )
        conn.commit()
        return row
    finally:
        conn.close()


def delete_session(data_dir, raw_token):
    if not raw_token:
        return
    conn = connect(data_dir)
    try:
        conn.execute("DELETE FROM session WHERE id_hash = ?", (_hash_token(raw_token),))
        conn.commit()
    finally:
        conn.close()


def csrf_matches(session_row, submitted):
    if session_row is None or not submitted:
        return False
    expected = session_row["csrf_token"]
    if len(expected) != len(submitted):
        return False
    return hmac.compare_digest(expected, submitted)


def throttled(data_dir, ip):
    cutoff = _stamp(utcnow() - WINDOW)
    conn = connect(data_dir)
    try:
        conn.execute("DELETE FROM auth_failure WHERE created_at < ?", (cutoff,))
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM auth_failure WHERE ip = ? AND created_at >= ?",
            (ip, cutoff),
        ).fetchone()
        conn.commit()
        return row["n"] >= FAILURE_LIMIT
    finally:
        conn.close()


def record_failure(data_dir, ip):
    conn = connect(data_dir)
    try:
        conn.execute(
            "INSERT INTO auth_failure (ip, created_at) VALUES (?, ?)",
            (ip, _stamp(utcnow())),
        )
        conn.commit()
    finally:
        conn.close()


def clear_failures(data_dir, ip):
    conn = connect(data_dir)
    try:
        conn.execute("DELETE FROM auth_failure WHERE ip = ?", (ip,))
        conn.commit()
    finally:
        conn.close()
