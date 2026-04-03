"""Database operations for ContrastScan"""

import hashlib
import hmac
import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from config import DB_PATH, HASH_SECRET, PRO_HOURLY_LIMIT

logger = logging.getLogger("contrastscan")

# Derive separate HMAC keys for different purposes (key separation best practice)
_raw_key = HASH_SECRET.encode()
_ip_hmac_key = hmac.new(_raw_key, b"ip-hash", hashlib.sha256).digest()
_apikey_hmac_key = hmac.new(_raw_key, b"api-key-hash", hashlib.sha256).digest()

# Thread-local connection pool — reuses connections per thread instead of
# opening/closing on every request. SQLite in WAL mode supports concurrent reads.
_local = threading.local()


def _get_thread_conn() -> sqlite3.Connection:
    """Return a reusable per-thread connection."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-8000")  # 8MB page cache
        conn.execute("PRAGMA mmap_size=67108864")  # 64MB memory-mapped I/O
        _local.conn = conn
    return conn


@contextmanager
def get_db():
    """Thread-safe DB connection — reuses per-thread connection"""
    con = _get_thread_conn()
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise


def close_thread_db():
    """Close this thread's connection (for cleanup/testing)."""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        conn.close()
        _local.conn = None


def init_db():
    """Create tables, set WAL mode"""
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")
    con.commit()
    con.close()

    with get_db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                client_hash TEXT NOT NULL DEFAULT '',
                result TEXT NOT NULL,
                grade TEXT NOT NULL,
                total_score INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                total_score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                result TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_history_domain ON scan_history(domain)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS recon_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                result TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_recon_scan ON recon_results(scan_id)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS ip_limits (
                ip TEXT PRIMARY KEY,
                usage INTEGER NOT NULL DEFAULT 0,
                window_start TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                tier TEXT NOT NULL DEFAULT 'pro',
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked INTEGER NOT NULL DEFAULT 0
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS api_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id INTEGER NOT NULL,
                endpoint TEXT NOT NULL,
                domain TEXT,
                created_at TEXT NOT NULL
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_usage_key ON api_usage(key_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_usage_time ON api_usage(created_at)")


def hash_client_ip(ip: str) -> str:
    """Hash a client IP with HMAC for privacy-safe analytics. Returns 32-char hex digest."""
    return hmac.new(_ip_hmac_key, ip.encode(), hashlib.sha256).hexdigest()[:32]


def save_scan(
    scan_id: str, domain: str, result_json: dict, grade: str, total_score: int, client_hash: str = ""
) -> None:
    """Insert scan result, write history only if score changed"""
    now = datetime.now(UTC).isoformat()
    result_str = json.dumps(result_json)

    with get_db() as con:
        con.execute(
            "INSERT INTO scans (id, domain, client_hash, result, grade, total_score, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, domain, client_hash, result_str, grade, total_score, now),
        )
        row = con.execute(
            "SELECT total_score FROM scan_history WHERE domain = ? ORDER BY id DESC LIMIT 1", (domain,)
        ).fetchone()
        last_score = row[0] if row else None

        if last_score is None or last_score != total_score:
            con.execute(
                "INSERT INTO scan_history (domain, total_score, grade, result, created_at) VALUES (?, ?, ?, ?, ?)",
                (domain, total_score, grade, result_str, now),
            )


def get_scan(scan_id: str) -> dict | None:
    with get_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def get_stats() -> tuple[int, list[dict]]:
    with get_db() as con:
        total = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        recent = con.execute("SELECT domain, grade, total_score FROM scans ORDER BY created_at DESC LIMIT 5").fetchall()
        return total, [{"domain": r[0], "grade": r[1], "score": r[2]} for r in recent]


def get_stats_detailed() -> dict:
    """Stats page data: total, unique, avg, grade distribution"""
    with get_db() as con:
        total = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        unique = con.execute("SELECT COUNT(DISTINCT domain) FROM scans").fetchone()[0]
        avg_row = con.execute(
            "SELECT AVG(total_score) FROM ("
            "  SELECT total_score FROM ("
            "    SELECT total_score, ROW_NUMBER() OVER (PARTITION BY domain ORDER BY created_at DESC) AS rn"
            "    FROM scans"
            "  ) WHERE rn = 1"
            ")"
        ).fetchone()
        avg_score = round(avg_row[0]) if avg_row[0] else 0

        grade_counts = {}
        for row in con.execute(
            "SELECT grade, COUNT(*) FROM ("
            "  SELECT grade FROM ("
            "    SELECT grade, ROW_NUMBER() OVER (PARTITION BY domain ORDER BY created_at DESC) AS rn"
            "    FROM scans"
            "  ) WHERE rn = 1"
            ") GROUP BY grade"
        ).fetchall():
            grade_counts[row[0]] = row[1]

    return {
        "total": total,
        "unique": unique,
        "avg_score": avg_score,
        "grade_counts": grade_counts,
    }


def check_and_increment_ip(ip: str, limit: int) -> tuple[bool, int]:
    """Check IP rate limit and increment atomically. Returns (allowed, current_usage).
    Resets usage if window (1 hour) has expired."""
    now = datetime.now(UTC)
    window_start_str = now.replace(minute=0, second=0, microsecond=0).isoformat()

    with get_db() as con:
        # Atomic upsert: insert or reset window, then increment only if under limit
        con.execute(
            """INSERT INTO ip_limits (ip, usage, window_start) VALUES (?, 0, ?)
               ON CONFLICT(ip) DO UPDATE SET
                 usage = CASE WHEN window_start != excluded.window_start THEN 0 ELSE usage END,
                 window_start = excluded.window_start""",
            (ip, window_start_str),
        )
        # Atomic increment with limit check
        cur = con.execute(
            """UPDATE ip_limits SET usage = usage + 1
               WHERE ip = ? AND usage < ?""",
            (ip, limit),
        )
        if cur.rowcount == 0:
            # Over limit — return current usage
            row = con.execute("SELECT usage FROM ip_limits WHERE ip = ?", (ip,)).fetchone()
            return False, row[0] if row else limit

        row = con.execute("SELECT usage FROM ip_limits WHERE ip = ?", (ip,)).fetchone()
        return True, row[0]


def get_ip_usage(ip: str) -> int:
    """Get current usage for an IP. Returns usage count."""
    now = datetime.now(UTC)
    window_start_str = now.replace(minute=0, second=0, microsecond=0).isoformat()

    with get_db() as con:
        row = con.execute("SELECT usage, window_start FROM ip_limits WHERE ip = ?", (ip,)).fetchone()

        if row is None or row[1] != window_start_str:
            return 0
        return row[0]


def cleanup_ip_limits() -> int:
    """Delete expired IP limit rows. Returns number of rows deleted."""
    now = datetime.now(UTC)
    window_start_str = now.replace(minute=0, second=0, microsecond=0).isoformat()
    with get_db() as con:
        cur = con.execute("DELETE FROM ip_limits WHERE window_start != ?", (window_start_str,))
        return cur.rowcount


def cleanup_api_usage() -> int:
    """Delete api_usage rows older than current hour. Returns number of rows deleted."""
    now = datetime.now(UTC)
    window_start_str = now.replace(minute=0, second=0, microsecond=0).isoformat()
    with get_db() as con:
        cur = con.execute("DELETE FROM api_usage WHERE created_at < ?", (window_start_str,))
        return cur.rowcount


def create_recon(scan_id: str, domain: str) -> None:
    now = datetime.now(UTC).isoformat()
    with get_db() as con:
        con.execute(
            "INSERT INTO recon_results (scan_id, domain, status, created_at) VALUES (?, ?, 'running', ?)",
            (scan_id, domain, now),
        )


def save_recon_partial(scan_id: str, recon_dict: dict) -> None:
    result_str = json.dumps(recon_dict)
    with get_db() as con:
        cur = con.execute(
            "UPDATE recon_results SET status = 'partial', result = ? WHERE scan_id = ?", (result_str, scan_id)
        )
        if cur.rowcount == 0:
            logger.warning("Recon partial save failed — scan_id %s not found", scan_id)


def save_recon(scan_id: str, recon_dict: dict) -> None:
    now = datetime.now(UTC).isoformat()
    result_str = json.dumps(recon_dict)
    with get_db() as con:
        con.execute(
            "UPDATE recon_results SET status = 'done', result = ?, completed_at = ? WHERE scan_id = ?",
            (result_str, now, scan_id),
        )


def save_recon_error(scan_id: str, error: str) -> None:
    now = datetime.now(UTC).isoformat()
    with get_db() as con:
        con.execute(
            "UPDATE recon_results SET status = 'error', result = ?, completed_at = ? WHERE scan_id = ?",
            (json.dumps({"error": error}), now, scan_id),
        )


def get_recon(scan_id: str) -> dict | None:
    with get_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute("SELECT * FROM recon_results WHERE scan_id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def get_domain_grade(domain: str) -> str | None:
    """Get latest grade for a domain (badge endpoint)"""
    with get_db() as con:
        row = con.execute(
            "SELECT grade FROM scans WHERE domain = ? ORDER BY created_at DESC LIMIT 1", (domain,)
        ).fetchone()
        return row[0] if row else None


def purge_old_client_hashes(days: int = 90) -> int:
    """Anonymize client_hash in scans older than N days. Returns number of rows updated."""
    cutoff_str = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    with get_db() as con:
        cur = con.execute("UPDATE scans SET client_hash = '' WHERE client_hash != '' AND created_at < ?", (cutoff_str,))
        return cur.rowcount


# === API Keys ===


def _hash_api_key(raw_key: str) -> str:
    """HMAC-SHA256 hash for API key storage."""
    return hmac.new(_apikey_hmac_key, raw_key.encode(), hashlib.sha256).hexdigest()


def create_api_key(email: str, tier: str = "pro") -> str:
    """Create a new API key. Returns the raw key (only shown once)."""
    import secrets

    raw_key = "cs_" + secrets.token_hex(24)  # cs_ + 48 hex chars
    key_hash = _hash_api_key(raw_key)
    key_prefix = raw_key[:10]  # cs_XXXXXXX for identification
    now = datetime.now(UTC).isoformat()

    with get_db() as con:
        con.execute(
            "INSERT INTO api_keys (key_prefix, key_hash, email, tier, created_at) VALUES (?, ?, ?, ?, ?)",
            (key_prefix, key_hash, email, tier, now),
        )
    return raw_key


def validate_api_key(raw_key: str) -> dict | None:
    """Validate an API key. Returns key info dict or None if invalid/revoked."""
    key_hash = _hash_api_key(raw_key)
    now = datetime.now(UTC).isoformat()

    with get_db() as con:
        cur = con.cursor()
        cur.row_factory = sqlite3.Row
        row = cur.execute("SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0", (key_hash,)).fetchone()
        if not row:
            return None
        con.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now, row["id"]))
        return dict(row)


def log_api_usage(key_id: int, endpoint: str, domain: str | None = None) -> None:
    """Log an API key usage event."""
    now = datetime.now(UTC).isoformat()
    with get_db() as con:
        con.execute(
            "INSERT INTO api_usage (key_id, endpoint, domain, created_at) VALUES (?, ?, ?, ?)",
            (key_id, endpoint, domain, now),
        )


def check_pro_rate_limit(key_id: int, count: int = 1) -> tuple[bool, int]:
    """Check Pro API key hourly rate limit and reserve quota atomically.
    Uses BEGIN IMMEDIATE to acquire write lock before SELECT, preventing
    TOCTOU race where two threads read the same usage count.
    count: number of scans to reserve (e.g. len(unique_domains) for bulk).
    Returns (allowed, current_usage). If allowed, `count` usage rows are inserted."""
    now = datetime.now(UTC)
    window_start = now.replace(minute=0, second=0, microsecond=0).isoformat()
    now_str = now.isoformat()

    con = _get_thread_conn()
    try:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute(
            "SELECT COUNT(*) FROM api_usage WHERE key_id = ? AND created_at >= ?",
            (key_id, window_start),
        ).fetchone()
        usage = row[0]
        if usage + count > PRO_HOURLY_LIMIT:
            con.execute("ROLLBACK")
            return False, usage
        con.executemany(
            "INSERT INTO api_usage (key_id, endpoint, domain, created_at) VALUES (?, ?, ?, ?)",
            [(key_id, "_reserve", None, now_str)] * count,
        )
        con.execute("COMMIT")
        return True, usage
    except Exception:
        try:
            con.execute("ROLLBACK")
        except Exception:
            # Connection is broken — discard it so next request gets a fresh one
            try:
                con.close()
            except Exception:
                pass
            _local.conn = None
        raise


def revoke_api_key(key_id: int) -> bool:
    """Revoke an API key. Returns True if found and revoked."""
    with get_db() as con:
        cur = con.execute("UPDATE api_keys SET revoked = 1 WHERE id = ? AND revoked = 0", (key_id,))
        return cur.rowcount > 0
