"""Commit/rollback AND close SQLite handles, including on Windows."""
import sqlite3
from contextlib import contextmanager


@contextmanager
def connection(*args, **kwargs):
    db = sqlite3.connect(*args, **kwargs)
    try:
        with db:
            yield db
    finally:
        db.close()
