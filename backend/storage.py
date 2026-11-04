"""SQLite JSON records with reproducible schema and transactional updates."""
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path


def database_path() -> Path:
    return Path(os.environ.get("PHISHLENS_DB", "backend/data/phishlens.sqlite3"))


@contextmanager
def connection():
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=10) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version not in {0, 1}:
            raise RuntimeError("Unsupported database schema version; open this database with a compatible PhishLens release.")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(kind,id))")
        if version == 0:
            conn.execute("PRAGMA user_version=1")
        yield conn


def save(kind, record):
    with connection() as conn:
        conn.execute("INSERT INTO records(kind,id,data) VALUES (?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data", (kind, record["id"], json.dumps(record)))
    return record


def get(kind, identifier):
    with connection() as conn:
        row = conn.execute("SELECT data FROM records WHERE kind=? AND id=?", (kind, identifier)).fetchone()
    return json.loads(row[0]) if row else None


def all_records(kind):
    with connection() as conn:
        rows = conn.execute("SELECT data FROM records WHERE kind=? ORDER BY rowid DESC", (kind,)).fetchall()
    return [json.loads(row[0]) for row in rows]


def delete(kind, identifier):
    with connection() as conn:
        cursor = conn.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, identifier))
    return cursor.rowcount > 0


def purge():
    with connection() as conn:
        conn.execute("DELETE FROM records")
    # Remove deleted email content from free SQLite pages and the WAL too.
    with connection() as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
