"""Native account expiry plus confirmed disablement and persistent Telegram outbox."""
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from flask import jsonify, request
from authentication import current_actor, reauthenticate
from storage import connection

_LOCKS={}
_LOCKS_GUARD=threading.Lock()


def instant(value, now):
    if value is None or value=='':return None
    if not isinstance(value,str) or len(value)>40:raise ValueError('Indica fecha y hora con zona horaria.')
    try:
        date=datetime.fromisoformat(value.replace('Z','+00:00'))
        if date.tzinfo is None:raise ValueError()
        result=int(date.timestamp())
        if result<=now or result>4102444800:raise ValueError()
        return result
    except (ValueError,OverflowError):raise ValueError('El vencimiento debe ser futuro, con zona horaria, antes del año 2100.') from None


class AccountExpiry:
    def __init__(self,database,directory,notify,demo=False,clock=time.time):
        self.path=database;self.directory=directory;self.notify=notify;self.demo=demo;self.clock=clock
        self.cancel=threading.Event();self.thread=None
        with _LOCKS_GUARD:self.lock=_LOCKS.setdefault(str(database),threading.RLock())
        with self.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS account_expiry(user_id TEXT PRIMARY KEY,username TEXT NOT NULL,expires_at INTEGER,previous_at INTEGER,state TEXT NOT NULL,generation TEXT NOT NULL,actor TEXT NOT NULL,updated REAL NOT NULL,error TEXT NOT NULL DEFAULT '',verified_at REAL);
            CREATE TABLE IF NOT EXISTS expiry_alerts(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,username TEXT NOT NULL,expires_at INTEGER NOT NULL,verified_at REAL NOT NULL,changed INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_try REAL NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS expiry_history(id INTEGER PRIMARY KEY,at REAL NOT NULL,user_id TEXT NOT NULL,username TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,result TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS account_expiry_due ON account_expiry(state,expires_at);
            ''')

    @contextmanager
    def db(self):
        with connection(self.path,timeout=15) as db:
            db.row_factory=sqlite3.Row
            yield db

    def _log(self,db,row,action,result,actor='sistema'):
        db.execute('INSERT INTO expiry_history(at,user_id,username,actor,action,result) VALUES(?,?,?,?,?,?)',
                   (self.clock(),row['user_id'],row['username'],actor,action,result))
        db.execute('INSERT INTO audit(actor,action,target,result) VALUES(?,?,?,?)',(actor,action,row['username'],result))

    def _info(self,identifier):
        if not self.demo:return self.directory('expiry-info',identifier=identifier)
        with self.db() as db:
            user=db.execute('SELECT * FROM users WHERE id=?',(identifier,)).fetchone()
            row=db.execute('SELECT * FROM account_expiry WHERE user_id=?',(identifier,)).fetchone()
        if not user:raise ValueError('Usuario no encontrado.')
        return dict(username=user['username'],enabled=bool(user['enabled']),expires_at=row['expires_at'] if row else None)

    def annotate(self,users):
        with self.db() as db:
            plans={r['user_id']:dict(r) for r in db.execute('SELECT * FROM account_expiry')}
            alerts={r['id']:dict(r) for r in db.execute('SELECT a.id,a.status,a.error FROM expiry_alerts a JOIN account_expiry e ON e.generation=a.id')}
        for user in users:
            row=plans.get(user['id'])
            user['expiration']=None
            if row:
                alert=alerts.get(row['generation'])
                user['expiration']=dict(expires_at=row['expires_at'],state=row['state'],error=row['error'],verified_at=row['verified_at'],alert_status=alert['status'] if alert else None,alert_error=alert['error'] if alert else '')
        return users

    def history(self):
        with self.db() as db:
            return dict(history=[dict(r) for r in db.execute('SELECT * FROM expiry_history ORDER BY id DESC LIMIT 100')],alerts=[dict(r) for r in db.execute('SELECT * FROM expiry_alerts ORDER BY verified_at DESC LIMIT 100')],demo=self.demo)

    def ensure_enable(self,identifier):
        with self.db() as db:
            r=db.execute("SELECT expires_at FROM account_expiry WHERE user_id=? AND state IN ('pending','armed','done')",(identifier,)).fetchone()
        if r and r[0] is not None and r[0]<=self.clock():
            raise ValueError('La cuenta tiene un vencimiento cumplido. Amplía o retira su vencimiento antes de activarla.')

    def save(self,identifier,value,actor):
        expires=instant(value,self.clock())
        with self.lock:
            info=self._info(identifier) # Scoped native lookup, never username-based mutation.
            with self.db() as db:
                db.execute('INSERT OR REPLACE INTO account_expiry(user_id,username,expires_at,previous_at,state,generation,actor,updated) VALUES(?,?,?,?,?,?,?,?)',
                           (identifier,info['username'],expires,info.get('expires_at'),'pending',uuid.uuid4().hex,actor,self.clock()))
            self._pending(identifier)
            with self.db() as db:r=db.execute('SELECT * FROM account_expiry WHERE user_id=?',(identifier,)).fetchone()
            if r['state']=='pending':raise OSError('La solicitud quedó guardada, pero Windows no confirmó el vencimiento. Se reintentará; revisa el estado.')
            if r['state']=='conflict':raise ValueError('Windows cambió el vencimiento durante la operación. Recarga y revisa la cuenta.')

    def _pending(self,identifier):
        with self.db() as db:
            r=db.execute('SELECT * FROM account_expiry WHERE user_id=?',(identifier,)).fetchone()
            if not r or r['state']!='pending':return
            try:
                info=self._info(identifier)
                actual=info.get('expires_at')
                if not self.demo and actual!=r['expires_at']:
                    if actual!=r['previous_at']:
                        db.execute("UPDATE account_expiry SET state='conflict',error='Vencimiento cambiado fuera de Metakampo; revisa la programación.' WHERE user_id=?",(identifier,))
                        self._log(db,r,'vencimiento no aplicado','cambio externo');return
                    iso=datetime.fromtimestamp(r['expires_at'],timezone.utc).isoformat() if r['expires_at'] is not None else None
                    info=self.directory('expiry-set',identifier=identifier,expires_at=iso)
                    if info.get('expires_at')!=r['expires_at']:raise OSError('Not confirmed')
                db.execute("UPDATE account_expiry SET state=?,error='',updated=? WHERE user_id=?",('armed' if r['expires_at'] is not None else 'cancelled',self.clock(),identifier))
                self._log(db,r,'programar vencimiento' if r['expires_at'] is not None else 'retirar vencimiento','simulado' if self.demo else 'confirmado en Windows',r['actor'])
            except Exception:
                db.execute("UPDATE account_expiry SET error='Windows no confirmó el vencimiento; se reintentará sin cambiar el estado de acceso.' WHERE user_id=?",(identifier,))

    def _due(self,identifier):
        with self.db() as db:
            r=db.execute("SELECT * FROM account_expiry WHERE user_id=? AND state='armed' AND expires_at<=?",(identifier,self.clock())).fetchone()
            if not r:return
            try:
                if self.demo:
                    info=self._info(identifier);changed=info['enabled']
                    db.execute('UPDATE users SET enabled=0 WHERE id=?',(identifier,))
                else:
                    result=self.directory('expiry-disable',identifier=identifier,expected_at=r['expires_at'])
                    if result.get('conflict'):
                        db.execute("UPDATE account_expiry SET state='conflict',error='El vencimiento nativo cambió. No se deshabilitó automáticamente.' WHERE user_id=?",(identifier,))
                        self._log(db,r,'vencimiento no aplicado','cambio externo');return
                    if result.get('enabled') is not False:raise OSError('Disable not confirmed')
                    changed=bool(result.get('changed'))
                    if result.get('username'):db.execute('UPDATE account_expiry SET username=? WHERE user_id=?',(result['username'],identifier))
                    info=result
                now=self.clock();username=info['username']
                # Native state confirmed first; transaction then records completion + notification.
                db.execute("UPDATE account_expiry SET state='done',error='',verified_at=? WHERE user_id=?",(now,identifier))
                db.execute('INSERT OR IGNORE INTO expiry_alerts(id,user_id,username,expires_at,verified_at,changed) VALUES(?,?,?,?,?,?)',
                           (r['generation'],identifier,username,r['expires_at'],now,int(changed)))
                self._log(db,r,'cuenta deshabilitada por vencimiento','simulado' if self.demo else 'deshabilitación confirmada' if changed else 'ya estaba deshabilitada')
            except Exception:
                db.execute("UPDATE account_expiry SET error='No se confirmó la deshabilitación. Revisa permisos y el estado real; se reintentará.' WHERE user_id=?",(identifier,))

    def _alerts(self):
        with self.db() as db:
            rows=list(db.execute("SELECT * FROM expiry_alerts WHERE status='pending' AND next_try<=? ORDER BY verified_at LIMIT 5",(self.clock(),)))
        for row in rows:
            if self.cancel.is_set():break
            try:
                if not self.demo:self.notify('user-alert',username=row['username'],expires=row['expires_at'],at=row['verified_at'],changed=bool(row['changed']),event_id=row['id'])
                with self.db() as db:db.execute("UPDATE expiry_alerts SET status=?,attempts=attempts+1,error='' WHERE id=?",('simulated' if self.demo else 'sent',row['id']))
            except Exception:
                delay=min(3600,30*2**min(row['attempts'],7))
                with self.db() as db:db.execute("UPDATE expiry_alerts SET attempts=attempts+1,next_try=?,error='Telegram no confirmó entrega; se reintentará con el monitor existente.' WHERE id=?",(self.clock()+delay,row['id']))

    def tick(self):
        with self.lock:
            with self.db() as db:
                pending=[r[0] for r in db.execute("SELECT user_id FROM account_expiry WHERE state='pending' LIMIT 100")]
            for identifier in pending:
                if self.cancel.is_set():break
                self._pending(identifier)
            with self.db() as db:
                due=[r[0] for r in db.execute("SELECT user_id FROM account_expiry WHERE state='armed' AND expires_at<=? LIMIT 100",(self.clock(),))]
            for identifier in due:
                if self.cancel.is_set():break
                self._due(identifier)
        self._alerts()

    def start(self):
        def run():
            while not self.cancel.is_set():
                try:self.tick()
                except Exception:pass
                self.cancel.wait(30)
        self.thread=threading.Thread(target=run,daemon=True,name='metakampo-account-expiry');self.thread.start()

    def stop(self):
        self.cancel.set()
        if self.thread:self.thread.join(timeout=2)


def register(app,engine,db,throttled):
    @app.get('/api/account-expiry')
    def expiry_history():return jsonify(engine.history())

    @app.post('/api/users/<identifier>/expiration')
    def set_account_expiry(identifier):
        data=request.get_json(silent=True)
        if not isinstance(data,dict):raise ValueError('Solicitud inválida.')
        if 'expires_at' not in data:raise ValueError('Indica un vencimiento o null para retirarlo.')
        if throttled('account-expiry',20) or not reauthenticate(db(),data.get('admin_password','')):
            return jsonify(error='Confirma tu contraseña de Metakampo.'),403
        if not app.config.get('DESKTOP') and app.config['MODE']!='demo':raise ValueError('El vencimiento se configura desde la aplicación instalada.')
        try:engine.save(identifier,data.get('expires_at'),current_actor())
        except OSError as exc:return jsonify(error=str(exc)),503
        return jsonify(ok=True)
