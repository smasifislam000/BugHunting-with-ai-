"""
core/db_retry.py
----------------
SQLite retry wrapper for 'database is locked' errors.
Used by database.py to avoid crashes on concurrent access.
"""

import time
import sqlite3
from contextlib import contextmanager
from typing import Callable, Any, Optional

from core.logger import get_logger, warn

log = get_logger("db_retry")


DEFAULT_MAX_RETRIES = 5
DEFAULT_BASE_DELAY = 0.2  # seconds
LOCKED_MESSAGES = ("database is locked", "database table is locked",
                   "database is busy")


def is_locked_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(m in msg for m in LOCKED_MESSAGES)


def retry_on_locked(fn: Callable, *args,
                    max_retries: int = DEFAULT_MAX_RETRIES,
                    base_delay: float = DEFAULT_BASE_DELAY,
                    **kwargs) -> Any:
    """
    Call fn(*args, **kwargs), retrying on SQLite locked errors.
    Exponential backoff.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            return fn(*args, **kwargs)
        except sqlite3.OperationalError as e:
            if not is_locked_error(e):
                raise
            last_exc = e
            delay = base_delay * (2 ** attempt)
            log.debug(f"DB locked (attempt {attempt+1}/{max_retries}), sleeping {delay:.2f}s")
            time.sleep(delay)
        except sqlite3.DatabaseError as e:
            if not is_locked_error(e):
                raise
            last_exc = e
            delay = base_delay * (2 ** attempt)
            time.sleep(delay)
    warn(f"DB retry exhausted after {max_retries} attempts")
    if last_exc:
        raise last_exc
    return None


@contextmanager
def safe_connection(db_path: str,
                    timeout: float = 30.0,
                    max_retries: int = DEFAULT_MAX_RETRIES):
    """
    Context manager yielding a sqlite3 connection with:
    - WAL mode
    - busy_timeout
    - foreign keys ON
    - automatic retry on lock
    """
    conn = None
    for attempt in range(max_retries):
        try:
            conn = sqlite3.connect(db_path, timeout=timeout)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA busy_timeout=30000;")
            conn.execute("PRAGMA foreign_keys=ON;")
            break
        except sqlite3.OperationalError as e:
            if not is_locked_error(e) or attempt == max_retries - 1:
                raise
            time.sleep(0.2 * (2 ** attempt))

    if conn is None:
        raise sqlite3.OperationalError("Could not open database")

    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def execute_with_retry(conn: sqlite3.Connection, sql: str,
                       params: tuple = (),
                       max_retries: int = DEFAULT_MAX_RETRIES):
    """Execute a single SQL statement with retry."""
    def _do():
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur
    return retry_on_locked(_do, max_retries=max_retries)


def executemany_with_retry(conn: sqlite3.Connection, sql: str,
                            seq_of_params,
                            max_retries: int = DEFAULT_MAX_RETRIES):
    def _do():
        cur = conn.cursor()
        cur.executemany(sql, seq_of_params)
        return cur
    return retry_on_locked(_do, max_retries=max_retries)


def commit_with_retry(conn: sqlite3.Connection,
                      max_retries: int = DEFAULT_MAX_RETRIES) -> None:
    retry_on_locked(conn.commit, max_retries=max_retries)


def vacuum(db_path: str) -> bool:
    """Compact the database."""
    try:
        with safe_connection(db_path) as conn:
            conn.execute("VACUUM;")
        return True
    except Exception as e:
        warn(f"VACUUM failed: {e}")
        return False


def integrity_check(db_path: str) -> bool:
    """Check DB integrity."""
    try:
        with safe_connection(db_path) as conn:
            row = conn.execute("PRAGMA integrity_check;").fetchone()
            return bool(row and row[0] == "ok")
    except Exception as e:
        warn(f"Integrity check failed: {e}")
        return False


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="DB retry utilities")
    p.add_argument("--db", default="bug_bounty.db")
    p.add_argument("--vacuum", action="store_true")
    p.add_argument("--integrity", action="store_true")
    args = p.parse_args()

    if args.vacuum:
        print("Vacuum:", vacuum(args.db))
    elif args.integrity:
        print("Integrity:", integrity_check(args.db))
    else:
        print("Use --vacuum or --integrity")