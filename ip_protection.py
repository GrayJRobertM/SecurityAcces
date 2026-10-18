"""Local failed-logon protection. Only this installation's exact-IP rules are touched."""
import ipaddress
import json
import socket
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from flask import jsonify, request
from authentication import reauthenticate, current_actor
from storage import connection
from directory import local_powershell_path

_LOCKS = {}
_LOCKS_LOCK = threading.Lock()
BASE = Path(__file__).parent


def address(value):
    if not isinstance(value, str) or len(value) > 64 or '%' in value:
        raise ValueError('Indica una dirección IPv4 o IPv6 válida, sin puerto.')
    ip = ipaddress.ip_address(value)
    return ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip


def network(value):
    if not isinstance(value, str) or len(value) > 80 or '%' in value:
        raise ValueError('Indica una IP o red CIDR válida.')
    if '/' not in value:
        ip = address(value)
        return ipaddress.ip_network(str(ip))
    n = ipaddress.ip_network(value, strict=True)
    if isinstance(n, ipaddress.IPv6Network) and n.network_address.ipv4_mapped:
        raise ValueError('Para IPv4 usa su notación IPv4, no IPv6 mapeada.')
    return n


def native(action, **values):
    try:
        result = subprocess.run([local_powershell_path(), '-NoLogo', '-NoProfile', '-NonInteractive',
                                 '-File', str(BASE / 'windows' / 'Protect-IP.ps1')],
                                input=json.dumps(dict(action=action, **values)), capture_output=True,
                                text=True, encoding='utf-8', timeout=30,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        data = json.loads(result.stdout.lstrip('\ufeff'))
        if result.returncode or not isinstance(data, dict) or not data.get('ok'):
            raise ValueError()
        return data
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise OSError('Windows no confirmó la operación de protección IP o del monitor Telegram.') from None


class IPProtection:
    def __init__(self, database, event_database, key, demo=False, backend=None, clock=time.time):
        self.path = Path(database)
        self.events = Path(event_database)
        self.demo = demo
        self.key = key
        self.backend = backend or native
        self.clock = clock
        self.server = socket.getfqdn().lower()
        self.cancel = threading.Event()
        with _LOCKS_LOCK:
            self.lock = _LOCKS.setdefault(str(self.path.resolve()), threading.RLock())
        self.thread = None
        with self.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY CHECK(id=1),instance TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,threshold INTEGER NOT NULL DEFAULT 5,window_minutes INTEGER NOT NULL DEFAULT 10,duration_minutes INTEGER NOT NULL DEFAULT 60,network_failures INTEGER NOT NULL DEFAULT 1,alerts INTEGER NOT NULL DEFAULT 0,since REAL NOT NULL DEFAULT 0,last_tick REAL,error TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS whitelist(id TEXT PRIMARY KEY,cidr TEXT UNIQUE NOT NULL,note TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS blocks(id TEXT PRIMARY KEY,ip TEXT NOT NULL,rule TEXT UNIQUE NOT NULL,status TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,failures INTEGER NOT NULL,username TEXT NOT NULL,reason TEXT NOT NULL,actor TEXT NOT NULL,error TEXT NOT NULL DEFAULT '',released REAL);
            CREATE UNIQUE INDEX IF NOT EXISTS live_block ON blocks(ip) WHERE status IN ('pending','blocked','error');
            CREATE TABLE IF NOT EXISTS resets(ip TEXT PRIMARY KEY,after REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS notifications(id TEXT PRIMARY KEY,ip TEXT NOT NULL,failures INTEGER NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_try REAL NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY,at REAL NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,result TEXT NOT NULL);
            ''')
            db.execute('INSERT OR IGNORE INTO config(id,instance) VALUES(1,?)', (uuid.uuid4().hex,))

    @contextmanager
    def db(self):
        with connection(self.path, timeout=15) as db:
            db.row_factory = sqlite3.Row
            yield db

    def log(self, db, action, target='', result='correcto', actor='sistema'):
        db.execute('INSERT INTO history(at,actor,action,target,result) VALUES(?,?,?,?,?)',
                   (self.clock(), actor, action, target, result))

    def allowed(self, ip, white):
        # Loopback, unspecified and multicast cannot identify an external attacker.
        return ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or any(ip in n for n in white if n.version == ip.version)

    def state(self):
        with self.db() as db:
            config = dict(db.execute('SELECT * FROM config').fetchone())
            config.pop('instance')
            try:
                with connection(self.events,timeout=15) as source:
                    row=source.execute("SELECT last_seen FROM collectors WHERE id='local-desktop'").fetchone()
                    last_collection=row[0] if row else None
            except sqlite3.Error:last_collection=None
            totals=dict(active=db.execute("SELECT COUNT(*) FROM blocks WHERE status IN ('pending','blocked','error')").fetchone()[0],pending_alerts=db.execute("SELECT COUNT(*) FROM notifications WHERE status='pending'").fetchone()[0])
            return dict(config=config, demo=self.demo, totals=totals, last_collection=last_collection,
                        blocks=[dict(x) for x in db.execute('SELECT * FROM blocks ORDER BY created DESC LIMIT 200')],
                        whitelist=[dict(x) for x in db.execute('SELECT * FROM whitelist ORDER BY created DESC')],
                        alerts=[dict(x) for x in db.execute('SELECT * FROM notifications ORDER BY created DESC LIMIT 50')],
                        history=[dict(x) for x in db.execute('SELECT * FROM history ORDER BY id DESC LIMIT 100')])

    def settings(self, data, actor):
        for flag in ('enabled','network_failures','alerts'):
            if type(data.get(flag)) is not bool:
                raise ValueError('Revisa los interruptores de protección.')
        for field, maximum in [('threshold',1000),('window_minutes',1440),('duration_minutes',43200)]:
            if type(data.get(field)) is not int or not 1 <= data[field] <= maximum:
                raise ValueError('Valor fuera de rango: '+field)
        with self.lock, self.db() as db:
            # Do not arm against historical failures when changing a policy.
            db.execute('UPDATE config SET enabled=?,threshold=?,window_minutes=?,duration_minutes=?,network_failures=?,alerts=?,since=? WHERE id=1',
                       tuple(data[f] for f in ('enabled','threshold','window_minutes','duration_minutes','network_failures','alerts'))+(self.clock(),))
            self.log(db,'guardar política',actor=actor)
        self.tick()

    def white_add(self, value, note, actor):
        cidr = str(network(value))
        if not isinstance(note,str) or len(note)>160 or any(ord(c)<32 for c in note):
            raise ValueError('La referencia admite hasta 160 caracteres.')
        with self.lock:
            with self.db() as db:
                if db.execute('SELECT COUNT(*) FROM whitelist').fetchone()[0] >= 1000:
                    raise ValueError('La lista blanca admite hasta 1000 entradas.')
                db.execute('INSERT INTO whitelist VALUES(?,?,?,?,?)',(uuid.uuid4().hex,cidr,note,actor,self.clock()))
                self.log(db,'agregar lista blanca',cidr,actor=actor)
            # Persist exemption BEFORE touching the OS: no later automatic block can race it.
            self.tick()
            with self.db() as db:
                unresolved=[r for r in db.execute("SELECT ip FROM blocks WHERE status IN ('pending','blocked','error')") if address(r['ip']) in network(cidr)]
            if unresolved:
                raise OSError('Excepción guardada, pero Windows no confirmó retirar un bloqueo propio. Revisa el estado; se reintentará automáticamente.')

    def white_remove(self, identifier, actor):
        with self.lock,self.db() as db:
            row=db.execute('SELECT * FROM whitelist WHERE id=?',(identifier,)).fetchone()
            if not row:raise ValueError('Excepción no encontrada.')
            db.execute('DELETE FROM whitelist WHERE id=?',(identifier,))
            db.execute('UPDATE config SET since=?',(self.clock(),))
            self.log(db,'retirar lista blanca',row['cidr'],actor=actor)

    def release(self, identifier, actor):
        with self.lock,self.db() as db:
            row=db.execute("SELECT * FROM blocks WHERE id=? AND status IN ('pending','blocked','error')",(identifier,)).fetchone()
            if not row:raise ValueError('Bloqueo activo no encontrado.')
            done=self._release(db,row,'desbloqueo manual',actor)
        if not done:raise OSError('Windows no confirmó el desbloqueo. Se guardó la retirada y se reintentará automáticamente.')

    def _release(self, db, row, reason, actor='sistema'):
        try:
            if not self.demo:self.backend('remove',rule=row['rule'],ip=row['ip'])
        except Exception:
            db.execute("UPDATE blocks SET status='error',error='Windows no confirmó la retirada; se reintentará.' WHERE id=?",(row['id'],))
            self.log(db,'retirar bloqueo',row['ip'],'pendiente de comprobar',actor)
            # Manual release must persist a desired state across retries.
            db.execute('UPDATE blocks SET reason=? WHERE id=?',('retirar: '+reason,row['id']))
            return False
        db.execute("UPDATE blocks SET status='released',released=?,error='',reason=? WHERE id=?",(self.clock(),reason,row['id']))
        db.execute('INSERT OR REPLACE INTO resets VALUES(?,?)',(row['ip'],self.clock()))
        self.log(db,reason,row['ip'],actor=actor)
        return True

    def _apply(self, db, row, config):
        try:
            if not self.demo:self.backend('add',rule=row['rule'],ip=row['ip'])
        except Exception:
            db.execute("UPDATE blocks SET status='error',error='Windows no confirmó el bloqueo; se reintentará.' WHERE id=?",(row['id'],))
            return
        db.execute("UPDATE blocks SET status='blocked',error='' WHERE id=?",(row['id'],))
        self.log(db,'bloquear IP',row['ip'],'simulado' if self.demo else 'regla confirmada',row['actor'])
        if config['alerts']:
            db.execute('INSERT OR IGNORE INTO notifications(id,ip,failures,created,expires) VALUES(?,?,?,?,?)',
                       (row['id'],row['ip'],row['failures'],row['created'],row['expires']))

    def manual(self, value, actor):
        ip=address(value)
        with self.lock,self.db() as db:
            white=[network(r[0]) for r in db.execute('SELECT cidr FROM whitelist')]
            if self.allowed(ip,white):raise ValueError('Esta dirección está exenta. La lista blanca tiene prioridad incluso sobre el bloqueo manual.')
            config=db.execute('SELECT * FROM config').fetchone()
            row=self._pending(db,str(ip),0,'','manual',actor,config)
            # Commit intent before OS call, so a crash can be reconciled.
            db.commit()
            self._apply(db,row,config)

    def _pending(self, db, ip, count, username, reason, actor, config):
        if db.execute("SELECT 1 FROM blocks WHERE ip=? AND status IN ('pending','blocked','error')",(ip,)).fetchone():
            raise ValueError('La IP ya tiene un bloqueo activo o pendiente.')
        if db.execute("SELECT COUNT(*) FROM blocks WHERE status IN ('pending','blocked','error')").fetchone()[0]>=1000:
            raise ValueError('Se alcanzó el límite de 1000 bloqueos activos. Revisa el historial.')
        identifier=uuid.uuid4().hex
        rule='Metakampo-IP-'+config['instance']+'-'+identifier
        now=self.clock()
        db.execute('INSERT INTO blocks(id,ip,rule,status,created,expires,failures,username,reason,actor) VALUES(?,?,?,?,?,?,?,?,?,?)',
                   (identifier,ip,rule,'pending',now,now+config['duration_minutes']*60,count,username,reason,actor))
        return db.execute('SELECT * FROM blocks WHERE id=?',(identifier,)).fetchone()

    def tick(self):
        with self.lock:
            try:
                self._tick()
            except Exception:
                with self.db() as db:
                    db.execute("UPDATE config SET error='No se completó la revisión. Comprueba Windows y la lectura de Security.'")
            self._notify()

    def _tick(self):
        now=self.clock()
        with self.db() as db:
            c=db.execute('SELECT * FROM config').fetchone()
            white=[network(r[0]) for r in db.execute('SELECT cidr FROM whitelist')]
            live=list(db.execute("SELECT * FROM blocks WHERE status IN ('pending','blocked','error')"))
            verified = None
            if live and not self.demo:
                rules=self.backend('list',instance=c['instance'])['rules']
                verified={r['rule']:r for r in rules}
            for row in live:
                if self.cancel.is_set():return
                reason=('lista blanca' if self.allowed(address(row['ip']),white) else
                        'retirada solicitada' if row['reason'].startswith('retirar: ') else
                        'vencimiento' if row['expires']<=now else
                        'protección desactivada' if not c['enabled'] and row['reason']=='automático' else '')
                if reason:self._release(db,row,reason)
                elif row['status']!='blocked' or (verified is not None and (row['rule'] not in verified or verified[row['rule']].get('ip')!=row['ip'] or not all(verified[row['rule']].get(k) for k in ('enabled','block','inbound')))):self._apply(db,row,c)
            db.commit()
            if c['enabled'] and not self.demo:
                with connection(self.events,timeout=15) as events:
                    # Local host only. Never firewall the receiver for a remote collector's events.
                    candidates=events.execute('SELECT ip,COUNT(*),MAX(occurred),MAX(username) FROM windows_events WHERE source=\'windows\' AND server=? AND event_id=4625 AND logon_type IN (10'+(',3' if c['network_failures'] else '')+') AND occurred>=? AND occurred<=? GROUP BY ip LIMIT 10001',
                        (self.server,max(c['since'],now-c['window_minutes']*60),now)).fetchall()
                    if len(candidates)>10000:raise ValueError('Demasiadas IP; revisión pendiente.')
                    # Count again after a manual release/expiry, respecting individual reset cutoffs.
                    grouped={}
                    for raw,count,last,user in candidates:
                        try:ip=address(raw)
                        except ValueError:continue
                        if self.allowed(ip,white):continue
                        canonical=str(ip)
                        reset=db.execute('SELECT after FROM resets WHERE ip=?',(canonical,)).fetchone()
                        if reset:
                            count=events.execute('SELECT COUNT(*) FROM windows_events WHERE source=\'windows\' AND server=? AND event_id=4625 AND logon_type IN (10'+(',3' if c['network_failures'] else '')+') AND ip=? AND occurred>? AND occurred>=? AND occurred<=?',
                                (self.server,raw,reset[0],max(c['since'],now-c['window_minutes']*60),now)).fetchone()[0]
                        previous=grouped.get(canonical,(0,''))
                        grouped[canonical]=(previous[0]+count,user)
                    for ip,(count,user) in grouped.items():
                        if self.cancel.is_set():return
                        if count<c['threshold'] or db.execute("SELECT 1 FROM blocks WHERE ip=? AND status IN ('pending','blocked','error')",(ip,)).fetchone():continue
                        row=self._pending(db,ip,count,user,'automático','sistema',c)
                        db.commit()
                        self._apply(db,row,c)
                        db.commit()
            db.execute("UPDATE config SET last_tick=?,error=''",(now,))

    def _notify(self):
        with self.db() as db:
            c=db.execute('SELECT * FROM config').fetchone()
            if not c['alerts']:return
            for row in list(db.execute("SELECT * FROM notifications WHERE status='pending' AND next_try<=? ORDER BY created LIMIT 5",(self.clock(),))):
                if self.cancel.is_set():break
                try:
                    if not self.demo:self.backend('alert',ip=row['ip'],failures=row['failures'],at=row['created'],expires=row['expires'],event_id=row['id'])
                    db.execute("UPDATE notifications SET status=?,attempts=attempts+1,error='' WHERE id=?",('simulated' if self.demo else 'sent',row['id']))
                except Exception:
                    delay=min(3600,30*(2**min(row['attempts'],7)))
                    db.execute("UPDATE notifications SET attempts=attempts+1,next_try=?,error='Alerta no confirmada; se reintentará con el monitor existente.' WHERE id=?",(self.clock()+delay,row['id']))

    def monitor_status(self):
        if self.demo:return dict(available=False,demo=True,message='Simulación: no se consulta ni envía a Telegram.')
        try:return self.backend('monitor')
        except Exception:return dict(available=False,message='Monitor no disponible. Revisa config.json, token.dpapi y permisos del propietario.')

    def start(self):
        if self.thread and self.thread.is_alive():return
        self.cancel.clear()
        def run():
            while not self.cancel.is_set():
                try:self.tick()
                except Exception:pass # A transient DB failure must not kill the worker.
                self.cancel.wait(10)
        self.thread=threading.Thread(target=run,daemon=True,name='metakampo-ip-protection');self.thread.start()

    def stop(self):
        self.cancel.set()
        if self.thread:self.thread.join(timeout=2)


def register(app, guard, db, audit, throttled):
    def confirmation(data):
        if not isinstance(data,dict):raise ValueError('Solicitud inválida.')
        if throttled('ip-protection',20) or not reauthenticate(db(),data.get('admin_password','')):
            raise ValueError('Confirma tu contraseña de Metakampo.')
        if not app.config.get('DESKTOP') and app.config['MODE']!='demo':
            raise ValueError('La protección IP requiere la aplicación instalada en el servidor.')

    @app.get('/api/ip-protection')
    def ip_protection_status():return jsonify(guard.state())

    @app.get('/api/ip-protection/monitor')
    def monitor():return jsonify(guard.monitor_status())

    @app.post('/api/ip-protection/<action>')
    def change(action):
        data=request.get_json(silent=True);confirmation(data)
        actor=current_actor()
        try:
            if action=='settings':guard.settings(data,actor)
            elif action=='whitelist':guard.white_add(data.get('cidr'),data.get('note',''),actor)
            elif action=='remove-whitelist':guard.white_remove(data.get('id'),actor)
            elif action=='release':guard.release(data.get('id'),actor)
            elif action=='block':guard.manual(data.get('ip'),actor)
            else:return jsonify(error='Acción no admitida.'),404
        except OSError as exc:return jsonify(error=str(exc)),503
        audit('protección IP: '+action,data.get('cidr') or data.get('ip') or data.get('id') or '')
        return jsonify(ok=True,**guard.state())
