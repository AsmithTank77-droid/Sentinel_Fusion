"""
storage/database.py — SQLite connection manager with WAL mode and migrations.

Provides:
    Database — manages a single SQLite connection with thread-safe writes,
               WAL journal mode, and versioned schema migrations.

Usage:
    db = Database("sentinel.db")
    db.connect()
    with db.write() as conn:
        conn.execute("INSERT INTO ...")
    rows = db.query("SELECT * FROM events WHERE src_ip = ?", ("1.2.3.4",))
    db.close()
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator

from storage.schema import CURRENT_VERSION, MIGRATIONS


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DatabaseError(Exception):
    """Raised when a storage operation fails."""


class Database:
    """
    SQLite connection manager.

    - WAL journal mode for concurrent reads during writes.
    - threading.Lock on all writes — safe for multi-threaded use.
    - Versioned migrations applied once at connect() time.
    - Foreign keys enforced per connection.
    """

    def __init__(self, path: str = "sentinel.db") -> None:
        self.path   = path
        self._conn:  sqlite3.Connection | None = None
        self._lock:  threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Open the database and apply pending migrations."""
        self._conn = sqlite3.connect(
            self.path,
            check_same_thread=False,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        self._conn.row_factory = sqlite3.Row
        self._configure()
        self._migrate()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "Database":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Query interface
    # ------------------------------------------------------------------

    def query(
        self,
        sql: str,
        params: tuple = (),
    ) -> list[sqlite3.Row]:
        """Execute a SELECT and return all rows."""
        conn = self._require_connection()
        try:
            return conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Query failed: {exc}\nSQL: {sql}") from exc

    def query_one(
        self,
        sql: str,
        params: tuple = (),
    ) -> sqlite3.Row | None:
        """Execute a SELECT and return the first row or None."""
        conn = self._require_connection()
        try:
            return conn.execute(sql, params).fetchone()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Query failed: {exc}\nSQL: {sql}") from exc

    @contextmanager
    def write(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Context manager for write operations.
        Acquires the write lock, wraps in a transaction, commits on exit,
        rolls back on exception.

        Usage:
            with db.write() as conn:
                conn.execute("INSERT INTO ...")
        """
        conn = self._require_connection()
        with self._lock:
            try:
                yield conn
                conn.commit()
            except sqlite3.IntegrityError:
                conn.rollback()
                raise
            except Exception as exc:
                conn.rollback()
                raise DatabaseError(f"Write failed: {exc}") from exc

    def execute(self, sql: str, params: tuple = ()) -> int:
        """
        Execute a single write statement. Returns lastrowid.
        Use write() context manager for multi-statement transactions.
        """
        conn = self._require_connection()
        with self._lock:
            try:
                cursor = conn.execute(sql, params)
                conn.commit()
                return cursor.lastrowid or 0
            except sqlite3.IntegrityError:
                conn.rollback()
                raise
            except sqlite3.Error as exc:
                conn.rollback()
                raise DatabaseError(f"Execute failed: {exc}\nSQL: {sql}") from exc

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _require_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            raise DatabaseError(
                "Database is not connected. Call connect() or use as context manager."
            )
        return self._conn

    def _configure(self) -> None:
        conn = self._require_connection()
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA cache_size = -8000")  # 8 MB page cache

    def _migrate(self) -> None:
        """Apply all pending versioned migrations in order."""
        conn = self._require_connection()

        # Ensure schema_version table exists before querying it
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version    INTEGER PRIMARY KEY,
                applied_at TEXT    NOT NULL
            )
        """)
        conn.commit()

        row = conn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()
        current = row[0] if row[0] is not None else 0

        for version in sorted(MIGRATIONS):
            if version <= current:
                continue
            with self._lock:
                for statement in MIGRATIONS[version]:
                    stmt = statement.strip()
                    if stmt:
                        conn.execute(stmt)
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (version, _now()),
                )
                conn.commit()

    @property
    def schema_version(self) -> int:
        row = self.query_one("SELECT MAX(version) FROM schema_version")
        return row[0] if row and row[0] is not None else 0
