"""Local Security log reader. Events and cursor commit together; no collector HTTP API."""
import json
import socket
import sqlite3
from storage import connection
import threading
import time
import uuid
from pathlib import Path
from telemetry import INSERT, normalize, hostname
from windows_native import powershell

BASE = Path(__file__).parent


def commit_batch(database, server, data, now=None):
    now = now or time.time()
    epoch = str(uuid.UUID(data['epoch']))
    if type(data['last_record']) is not int or data['last_record'] < 0:
        raise ValueError('Cursor local inválido.')
    if data.get('gap', '') not in ('', 'log_cleared', 'checkpoint_evicted'):
        raise ValueError('Cobertura local inválida.')
    events = data['events']
    if not isinstance(events, list) or len(events) > 500:
        raise ValueError('Lote local inválido.')
    rows = [normalize(event, server, epoch, now) for event in events]
    if any(row[2] > data['last_record'] for row in rows):
        raise ValueError('Los eventos exceden el cursor confirmado.')
    state = dict(epoch=epoch, last_record=data['last_record'], last_clear=data['last_clear'])
    with connection(database, timeout=15) as db:
        db.execute('BEGIN IMMEDIATE')
        accepted = sum(db.execute(INSERT, ('windows',) + row).rowcount for row in rows)
        db.execute('INSERT OR REPLACE INTO local_collector_state VALUES(1,?)', (json.dumps(state),))
        db.execute('UPDATE collectors SET last_seen=?,last_count=? WHERE id=?', (now, accepted, 'local-desktop'))
        if data.get('gap'):
            db.execute('UPDATE collectors SET last_gap=?,gap_reason=? WHERE id=?', (now, data['gap'], 'local-desktop'))
        db.execute("DELETE FROM windows_events WHERE source='windows' AND occurred<?", (now - 90*86400,))
    return accepted


class LocalCollector:
    def __init__(self, database, folder):
        self.database = database
        self.server = hostname(socket.getfqdn())
        self.cancel = threading.Event()
        with connection(database) as db:
            db.execute('CREATE TABLE IF NOT EXISTS local_collector_state(id INTEGER PRIMARY KEY CHECK(id=1),state TEXT NOT NULL)')
            db.execute('INSERT OR IGNORE INTO collectors(id,name,server,token_hash) VALUES(?,?,?,?)',
                       ('local-desktop', 'Eventos de este servidor', self.server, 'no-network-token'))
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        if self.thread.is_alive():return
        self.cancel.clear()
        self.thread=threading.Thread(target=self.run,daemon=True)
        self.thread.start()

    def stop(self):
        self.cancel.set()
        self.thread.join(timeout=2)

    def run(self):
        while not self.cancel.is_set():
            delay = 60
            try:
                with connection(self.database) as db:
                    row = db.execute('SELECT state FROM local_collector_state WHERE id=1').fetchone()
                state = json.loads(row[0]) if row else dict(epoch=str(uuid.uuid4()), last_record=0, last_clear=None)
                data = powershell(BASE / 'windows' / 'Read-LocalLogons.ps1', state, timeout=45)
                commit_batch(self.database, self.server, data)
                if data['backlog']:
                    delay = 1
            except Exception:
                # The dashboard reports unavailable/stale coverage. Never invent logons.
                pass
            self.cancel.wait(delay)
