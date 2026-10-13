#!/bin/bash
set -e
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt
fi
configured=$(.venv/bin/python -c 'from app import create_app; import sqlite3; a=create_app(); print(bool(sqlite3.connect(a.db_path).execute("SELECT 1 FROM admin").fetchone()))')
if [ "$configured" != True ]; then
  .venv/bin/python app.py --init-admin
fi
exec .venv/bin/python app.py
