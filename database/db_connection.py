"""Database connection management for ThreatGuard."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional, Union

from config.settings import DATABASE_PATH


@contextmanager
def get_db_connection(
    db_path: Optional[Union[str, Path]] = None
) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite database connection.
    
    Enforces foreign keys, enables WAL mode where appropriate, and sets sqlite3.Row factory.
    """
    target_path = Path(db_path) if db_path else DATABASE_PATH
    
    # Ensure parent directory exists for file-based DBs
    if str(target_path) != ":memory:":
        target_path.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(target_path), timeout=20.0)
    conn.row_factory = sqlite3.Row
    
    try:
        # Enable foreign key constraint support in SQLite
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
