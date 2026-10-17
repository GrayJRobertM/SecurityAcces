"""Scoped Windows event ingestion and metrics, separate from administrative audit."""
import hashlib
import json
import random
import re
import secrets
import sqlite3
from storage import connection
import time
import uuid
from datetime import datetime, timezone, timedelta
from flask import jsonify, request
from authentication import reauthenticate

IDS={4624,4625,4634,4778,4779}
EVENT_FIELDS={'record_id','event_id','at','username','domain','ip','logon_type','logon_id','session_name','status','substatus'}

def hostname(value):
    if not isinstance(value,str) or len(value)>253 or not value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in value.lower().split('.')):
        raise ValueError('Indica el nombre DNS del servidor, sin espacios ni rutas.')
    return value.lower()

def classify(event_id,logon_type,session_name):
    if event_id in (4624,4625,4634):
        outcome={4624:'success',4625:'failure',4634:'logoff'}[event_id]
        if logon_type==10:return 'rdp_'+outcome
        if logon_type in (2,7,11):return 'interactive_'+outcome
        if event_id==4625 and logon_type==3:return 'network_failure'
        return 'other_'+outcome
    return ('rdp_' if session_name.lower().startswith('rdp-tcp') else 'other_')+('reconnect' if event_id==4778 else 'disconnect')

def normalize(item,server,epoch,now=None):
    now=now or time.time()
    if not isinstance(item,dict) or set(item)-EVENT_FIELDS:raise ValueError('Solo se admiten campos normalizados; no mensajes, XML ni secretos.')
    if type(item.get('record_id')) is not int or not 1<=item['record_id']<=2**63-1:raise ValueError('Record ID inválido.')
    if type(item.get('event_id')) is not int or item['event_id'] not in IDS:raise ValueError('Evento Windows no admitido.')
    try:
        stamp=datetime.fromisoformat(item['at'].replace('Z','+00:00'))
        if stamp.tzinfo is None:raise ValueError()
        occurred=stamp.timestamp()
        if occurred<946684800 or occurred>now+300:raise ValueError()
    except (KeyError,ValueError,TypeError,AttributeError):raise ValueError('Fecha inválida: usa ISO 8601 con zona horaria y reloj sincronizado.')
    values={}
    for field,limit in [('username',256),('domain',253),('ip',64),('logon_id',32),('session_name',128),('status',64),('substatus',64)]:
        value=item.get(field,'')
        if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 for c in value):raise ValueError('Campo de evento inválido: '+field)
        values[field]=value
    typ=item.get('logon_type',0)
    if type(typ) is not int or not 0<=typ<=20:raise ValueError('Tipo de inicio de sesión inválido.')
    identity=((values['domain']+'\\') if values['domain'] else '')+(values['username'] or '(sin usuario)')
    return (server,epoch,item['record_id'],item['event_id'],occurred,identity,identity.casefold(),values['ip'],typ,
            values['logon_id'],values['session_name'],values['status'],values['substatus'],classify(item['event_id'],typ,values['session_name']))

INSERT='INSERT OR IGNORE INTO windows_events(source,server,epoch,record_id,event_id,occurred,username,identity,ip,logon_type,logon_id,session_name,status,substatus,kind) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'

def install(database,mode):
    with connection(database) as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS collectors(id TEXT PRIMARY KEY,name TEXT NOT NULL,server TEXT NOT NULL,token_hash TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,demo INTEGER NOT NULL DEFAULT 0,last_seen REAL,last_gap REAL,gap_reason TEXT NOT NULL DEFAULT '',last_count INTEGER NOT NULL DEFAULT 0,created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE UNIQUE INDEX IF NOT EXISTS collectors_active_server ON collectors(server) WHERE demo=0 AND enabled=1;
        CREATE TABLE IF NOT EXISTS windows_events(id INTEGER PRIMARY KEY,source TEXT NOT NULL,server TEXT NOT NULL,epoch TEXT NOT NULL,record_id INTEGER NOT NULL,event_id INTEGER NOT NULL,occurred REAL NOT NULL,username TEXT NOT NULL,identity TEXT NOT NULL,ip TEXT NOT NULL,logon_type INTEGER NOT NULL,logon_id TEXT NOT NULL,session_name TEXT NOT NULL,status TEXT NOT NULL,substatus TEXT NOT NULL,kind TEXT NOT NULL,UNIQUE(source,server,epoch,record_id));
        CREATE INDEX IF NOT EXISTS windows_events_time ON windows_events(source,occurred,kind);
        CREATE INDEX IF NOT EXISTS windows_events_server_time ON windows_events(source,server,occurred);
        ''')
        if mode=='demo' and not db.execute("SELECT 1 FROM windows_events WHERE source='demo' LIMIT 1").fetchone():
            seed_demo(db)

def seed_demo(db):
    rng=random.Random(74) # Deterministic synthetic fixtures, not a security primitive.
    hosts=['demo-rdp01.example.test','demo-rdp02.example.test','demo-rdp03.example.test']
    names=['ana.garcia','daniel.torres','mariana.lopez','sofia.ramirez','carlos.vega','luis.mendoza']
    now=time.time()
    epoch=str(uuid.uuid4())
    for i in range(420):
        stamp=now-rng.randint(0,20*86400)
        host=rng.choice(hosts)
        event=4625 if rng.random()<.13 else 4624
        typ=3 if event==4625 and rng.random()<.35 else 10
        item=dict(record_id=i+1,event_id=event,at=datetime.fromtimestamp(stamp,timezone.utc).isoformat(),username=rng.choice(names),domain='DEMO',ip='192.0.2.'+str(rng.randint(10,40)),logon_type=typ,logon_id=hex(i+1),status='0xC000006D' if event==4625 else '')
        db.execute(INSERT,('demo',)+normalize(item,host,epoch,now))
    for i,host in enumerate(hosts):
        db.execute('INSERT INTO collectors(id,name,server,token_hash,demo,last_seen) VALUES(?,?,?,?,1,?)',(str(uuid.uuid4()),'Fuente de ejemplo '+str(i+1),host,'demo-disabled-'+str(i),now-(i+1)*25))

def metrics(db,args,mode,now=None):
    now=now or time.time()
    try:
        days=int(args.get('days','7')); offset=int(args.get('offset','-360'))
    except (ValueError,TypeError):raise ValueError('Rango de fechas inválido.')
    if days not in (7,30,90) or not -840<=offset<=840:raise ValueError('Selecciona 7, 30 o 90 días y una zona horaria válida.')
    scope=args.get('scope','rdp')
    if scope not in ('rdp','interactive'):raise ValueError('Ámbito inválido.')
    server=args.get('server','')
    if server:server=hostname(server)
    local=datetime.fromtimestamp(now,timezone.utc)+timedelta(minutes=offset)
    first=(local-timedelta(days=days-1)).replace(hour=0,minute=0,second=0,microsecond=0)
    cutoff=(first-timedelta(minutes=offset)).timestamp()
    source='demo' if mode=='demo' else 'windows'
    success=['rdp_success']+(['interactive_success'] if scope=='interactive' else [])
    failure=['rdp_failure']+(['interactive_failure'] if scope=='interactive' else [])
    where='source=? AND occurred>=? AND occurred<=?'
    params=[source,cutoff,now]
    if server:where+=' AND server=?';params.append(server)
    successful="kind IN ("+','.join("'"+x+"'" for x in success)+")"
    failed="kind IN ("+','.join("'"+x+"'" for x in failure)+")"
    total=dict(db.execute(f"SELECT COALESCE(SUM({successful}),0) AS success,COALESCE(SUM({failed}),0) AS failure,COUNT(DISTINCT CASE WHEN {successful} THEN identity END) AS users,COUNT(DISTINCT CASE WHEN {successful} THEN server END) AS servers,COALESCE(SUM(kind='network_failure'),0) AS network_failures FROM windows_events WHERE "+where,params).fetchone())
    daily={(first+timedelta(days=i)).strftime('%Y-%m-%d'):dict(success=0,failure=0) for i in range(days)}
    for r in db.execute(f"SELECT date(occurred+?,'unixepoch') AS day,SUM({successful}) AS success,SUM({failed}) AS failure FROM windows_events WHERE "+where+" GROUP BY day",[offset*60]+params):
        if r['day'] in daily:daily[r['day']]=dict(success=r['success'],failure=r['failure'])
    def ranked(column,label):
        query=f"SELECT MAX({label}) AS name,SUM({successful}) AS success,SUM({failed}) AS failure FROM windows_events WHERE "+where+f" AND ({successful} OR {failed}) GROUP BY {column} ORDER BY success DESC,failure DESC,name LIMIT 10"
        return [dict(r) for r in db.execute(query,params)]
    demo=mode=='demo'
    collectors=[dict(r) for r in db.execute('SELECT id,name,server,enabled,last_seen,last_gap,gap_reason,last_count,demo FROM collectors WHERE demo=0 OR ?=1 ORDER BY server',(int(demo),))]
    for c in collectors:c['health']='revocado' if not c['enabled'] else 'sin datos' if c['last_seen'] is None else 'reportando' if now-c['last_seen']<=300 else 'sin señal reciente'
    visible="kind LIKE 'rdp_%'"+(" OR kind LIKE 'interactive_%'" if scope=='interactive' else '')
    event_where=where+' AND ('+visible+')'
    event_count=db.execute('SELECT COUNT(*) FROM windows_events WHERE '+event_where,params).fetchone()[0]
    events=[dict(r) for r in db.execute('SELECT server,occurred,username,identity,ip,event_id,logon_type,kind FROM windows_events WHERE '+event_where+' ORDER BY occurred DESC,id DESC LIMIT 50',params)]
    return dict(demo=demo,days=days,scope=scope,generated_at=now,offset=offset,totals=total,
                daily=[dict(day=day,**value) for day,value in daily.items()],users=ranked('identity','username'),servers=ranked('server','server'),
                events=events,event_count=event_count,collectors=collectors,
                available_servers=[r[0] for r in db.execute('SELECT DISTINCT server FROM windows_events WHERE source=? ORDER BY server',(source,))])

def register(app,db,audit,throttled):
    def reauth(data):
        if throttled('collector-admin',10):return False
        password=data.get('admin_password','')
        return reauthenticate(db(),password)

    @app.get('/api/dashboard')
    def dashboard():return jsonify(metrics(db(),request.args,app.config['MODE']))

    @app.post('/api/collectors')
    def create_collector():
        if app.config['MODE']=='ad' and not request.is_secure:return jsonify(error='Registra recolectores desde el portal HTTPS.'),403
        data=request.get_json(silent=True)
        if not isinstance(data,dict):raise ValueError('Solicitud inválida.')
        if not reauth(data):return jsonify(error='Confirma tu contraseña de administrador.'),403
        server=hostname(data.get('server'))
        name=data.get('name','')
        if not isinstance(name,str) or not name.strip() or len(name)>100 or any(ord(c)<32 for c in name):raise ValueError('Indica un nombre válido para el recolector.')
        if db().execute('SELECT 1 FROM collectors WHERE server=? AND enabled=1 AND demo=0',(server,)).fetchone():return jsonify(error='Este servidor ya tiene un recolector activo. Revócalo antes de emitir otro.'),409
        identifier=str(uuid.uuid4());token=secrets.token_urlsafe(32)
        db().execute('INSERT INTO collectors(id,name,server,token_hash) VALUES(?,?,?,?)',(identifier,name.strip(),server,hashlib.sha256(token.encode()).hexdigest()))
        audit('registrar recolector',server)
        return jsonify(id=identifier,token=token,server=server),201

    @app.post('/api/collectors/<identifier>/revoke')
    def revoke_collector(identifier):
        if app.config['MODE']=='ad' and not request.is_secure:return jsonify(error='Administra recolectores desde el portal HTTPS.'),403
        data=request.get_json(silent=True) or {}
        if not isinstance(data,dict) or not reauth(data):return jsonify(error='Confirma tu contraseña de administrador.'),403
        changed=db().execute('UPDATE collectors SET enabled=0 WHERE id=? AND demo=0',(identifier,)).rowcount
        if not changed:db().rollback();return jsonify(error='Recolector no encontrado.'),404
        audit('revocar recolector',identifier)
        return jsonify(ok=True)

    @app.post('/api/telemetry/events')
    def receive():
        if app.config['MODE']!='ad' or not request.is_secure:return jsonify(error='La recepción requiere modo AD y HTTPS.'),403
        if request.headers.get('Origin'):return jsonify(error='Solo se admiten recolectores registrados.'),403
        raw=request.headers.get('Authorization','')
        if not re.fullmatch(r'Bearer [A-Za-z0-9_-]{43}',raw):return jsonify(error='Recolector no autorizado.'),401
        collector=db().execute('SELECT * FROM collectors WHERE token_hash=? AND enabled=1 AND demo=0',(hashlib.sha256(raw[7:].encode()).hexdigest(),)).fetchone()
        if not collector:return jsonify(error='Recolector no autorizado.'),401
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or set(data)-{'epoch','events','gap_reason'}:raise ValueError('Formato de lote inválido.')
        try:epoch=str(uuid.UUID(data.get('epoch','')))
        except (ValueError,TypeError,AttributeError):raise ValueError('Generación del registro inválida.')
        items=data.get('events')
        if not isinstance(items,list) or len(items)>500:raise ValueError('El lote debe contener como máximo 500 eventos.')
        gap=data.get('gap_reason','')
        if gap not in ('','log_cleared','checkpoint_evicted'):raise ValueError('Señal de cobertura inválida.')
        now=time.time()
        rows=[normalize(item,collector['server'],epoch,now) for item in items]
        conn=db()
        accepted=0
        try:
            conn.execute('BEGIN IMMEDIATE')
            for row in rows:accepted+=conn.execute(INSERT,('windows',)+row).rowcount
            conn.execute('UPDATE collectors SET last_seen=?,last_count=? WHERE id=?',(now,accepted,collector['id']))
            if gap:conn.execute('UPDATE collectors SET last_gap=?,gap_reason=? WHERE id=?',(now,gap,collector['id']))
            conn.execute("DELETE FROM windows_events WHERE source='windows' AND occurred<?",(now-90*86400,))
            conn.commit()
        except Exception:conn.rollback();raise
        return jsonify(accepted=accepted,duplicates=len(rows)-accepted,received=len(rows),server=collector['server'])
