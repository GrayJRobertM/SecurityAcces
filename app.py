"""Metakampo Access: local demo and Windows AD adapter."""
import argparse
import base64
import getpass
import io
import hashlib
import json
import os
import re
import secrets
import sqlite3
from storage import connection
import time
import uuid
from datetime import timedelta
from pathlib import Path
from threading import Lock

from flask import Flask, g, jsonify, request, session, send_file
from werkzeug.security import check_password_hash, generate_password_hash
from directory import call_ad, call_local, DirectoryError
from security import generate_password, fingerprint, seal, unseal, CATEGORIES
from rdp import RDPError, make_package, validate_connection, portal_url, configured as rdp_configured

from telemetry import install as install_telemetry, register as register_telemetry
from access_map import register as register_access_map
from user_sync import install as install_user_sync, register as register_user_sync, remember as remember_user_password

BASE = Path(__file__).parent


def create_app(overrides=None):
    app = Flask(__name__, static_folder='static', static_url_path='/static')
    app.config.update(MODE=os.environ.get('FK_MODE', 'demo'), DATA_DIR=os.environ.get('FK_DATA_DIR', str(BASE / 'data')),
                      MAX_CONTENT_LENGTH=16384, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                      SESSION_COOKIE_SECURE=os.environ.get('FK_MODE') == 'ad', PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
                      TRUSTED_HOSTS=os.environ.get('FK_TRUSTED_HOSTS', 'localhost,127.0.0.1').split(','))
    app.config.update(overrides or {})
    if app.config['MODE'] not in ('demo', 'ad', 'local'):
        raise ValueError('FK_MODE debe ser demo, ad o local.')
    if app.config['MODE']=='local' and not app.config.get('DESKTOP'):
        raise ValueError('El modo local solo se utiliza desde la aplicación instalada.')
    folder = Path(app.config['DATA_DIR'])
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw_key = os.environ.get('FK_MASTER_KEY')
    if raw_key:
        key = base64.b64decode(raw_key, validate=True)
    elif app.config['MODE'] in ('ad','local'):
        raise ValueError('En modo real se requiere FK_MASTER_KEY (32 bytes en base64).')
    else:
        keypath = folder / 'demo.key'
        if not keypath.exists():
            fd = os.open(keypath, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(secrets.token_bytes(32))
        key = keypath.read_bytes()
    if len(key) != 32:
        raise ValueError('La clave maestra debe tener 32 bytes.')
    app.secret_key = hashlib.sha256(b'fk-session\x00' + key).digest()
    app.config['VAULT_KEY'] = key
    database = folder / 'access.sqlite3'
    with connection(database) as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1), hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, username TEXT UNIQUE NOT NULL, department TEXT, enabled INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS vault (id TEXT PRIMARY KEY, title TEXT NOT NULL, username TEXT NOT NULL, secret BLOB NOT NULL, created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS issued (fingerprint TEXT PRIMARY KEY, created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, result TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), length INTEGER NOT NULL CHECK(length BETWEEN 15 AND 64));
        INSERT OR IGNORE INTO settings VALUES (1, 15);
        CREATE TABLE IF NOT EXISTS rdp_clients (id TEXT PRIMARY KEY, host TEXT NOT NULL, username TEXT NOT NULL, code_hash TEXT NOT NULL, secret BLOB, expires REAL NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        
        ''')
        if app.config['MODE'] == 'demo' and not db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            db.executemany('INSERT INTO users VALUES (?,?,?,?,?)', [(str(uuid.uuid4()), n, u, d, e) for n,u,d,e in [
                ('Mariana López','mariana.lopez','Finanzas',1), ('Daniel Torres','daniel.torres','TI',1),
                ('Ana García','ana.garcia','Operaciones',1), ('Luis Mendoza','luis.mendoza','Comercial',0),
                ('Sofía Ramírez','sofia.ramirez','Recursos Humanos',1), ('Carlos Vega','carlos.vega','Logística',1)]])
    install_telemetry(database,app.config['MODE'])
    install_user_sync(database)
    if os.name != 'nt':
        database.chmod(0o600)
    attempts = {}
    attempts_lock = Lock()

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(database, timeout=15)
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_):
        if 'db' in g:
            g.db.close()

    def audit(action, target='', result='correcto'):
        db().execute('INSERT INTO audit(actor,action,target,result) VALUES (?,?,?,?)', ('admin', action, target, result))
        db().commit()

    def fresh_password():
        length = db().execute('SELECT length FROM settings WHERE id=1').fetchone()[0]
        for _ in range(100):
            value = generate_password(length)
            try:
                db().execute('INSERT INTO issued(fingerprint) VALUES (?)', (fingerprint(key, value),))
                db().commit()
                return value
            except sqlite3.IntegrityError:
                db().rollback()
        raise ValueError('No se pudo generar una clave única.')

    def text_field(data, field, maximum=120):
        value = data.get(field, '')
        if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c)<32 for c in value):
            raise ValueError('Completa correctamente el campo '+field+'.')
        return value.strip()

    def throttled(scope, limit=5):
        address = (scope, request.remote_addr)
        with attempts_lock:
            history = [t for t in attempts.get(address, []) if t > time.time()-900]
            if len(history) >= limit:
                return True
            attempts[address] = history + [time.time()]
        return False

    @app.before_request
    def protect():
        if request.path=='/api/user-sync/preview':
            request.max_content_length=2*1048576
        if app.config.get('DESKTOP') and request.path.startswith(('/api/telemetry/events','/api/collectors','/api/rdp/redeem')):
            return jsonify(error='Esta instalación solo admite operación local.'),403
        if request.path == '/api/telemetry/events' and request.method == 'POST':
            request.max_content_length=1048576
            return None  # Dedicated per-server collector credentials, validated in endpoint.
        if request.path == '/api/rdp/redeem' and request.method == 'POST':
            return None  # One-use capability + code + HTTPS; never uses browser sessions.
        if request.path.startswith('/api/'):
            if 'csrf' not in session:
                session['csrf'] = secrets.token_urlsafe(32)
            if request.method != 'GET':
                supplied = request.headers.get('X-CSRF-Token', '')
                if not secrets.compare_digest(supplied, session['csrf']):
                    return jsonify(error='Sesión inválida. Recarga la página.'), 403
            if request.path not in ('/api/session', '/api/login'):
                token = session.get('auth', '')
                row = db().execute('SELECT expires FROM sessions WHERE token=?', (token,)).fetchone()
                if not row or row[0] < time.time():
                    return jsonify(error='Inicia sesión para continuar.'), 401

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        if app.config['MODE'] == 'ad':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.errorhandler(ValueError)
    def invalid(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(DirectoryError)
    def ad_error(exc):
        audit('operación de directorio', '', 'error o resultado por verificar')
        return jsonify(error=str(exc)), 502

    @app.errorhandler(RDPError)
    def rdp_error(exc):
        return jsonify(error=str(exc)), 503

    @app.errorhandler(sqlite3.IntegrityError)
    def conflict(_):
        db().rollback()
        return jsonify(error='El registro ya existe.'), 409

    @app.get('/')
    def index():
        return app.send_static_file('index.html')

    @app.get('/api/session')
    def status():
        row = db().execute('SELECT expires FROM sessions WHERE token=?', (session.get('auth',''),)).fetchone()
        return jsonify(csrf=session['csrf'], authenticated=bool(row and row[0]>time.time()), mode=app.config['MODE'], desktop=bool(app.config.get('DESKTOP')),
                       setup=bool(db().execute('SELECT 1 FROM admin').fetchone()))

    @app.post('/api/login')
    def login():
        data = request.get_json(silent=True) or {}
        if throttled('login'):
            return jsonify(error='Demasiados intentos. Espera 15 minutos.'), 429
        row = db().execute('SELECT hash FROM admin WHERE id=1').fetchone()
        password = data.get('password')
        if not isinstance(password,str) or len(password)>256 or data.get('username')!='admin' or not row or not check_password_hash(row[0], password):
            audit('inicio de sesión', '', 'rechazado')
            return jsonify(error='Credenciales inválidas.'), 401
        with attempts_lock:
            attempts.pop(('login',request.remote_addr),None)
        old = session.get('auth','')
        session.clear()
        session.update(auth=secrets.token_hex(32), csrf=secrets.token_urlsafe(32))
        session.permanent = True
        db().execute('DELETE FROM sessions WHERE token=? OR expires<?', (old,time.time()))
        db().execute('INSERT INTO sessions VALUES (?,?)',(session['auth'],time.time()+900))
        audit('inicio de sesión')
        return jsonify(csrf=session['csrf'])

    @app.post('/api/logout')
    def logout():
        db().execute('DELETE FROM sessions WHERE token=?',(session.get('auth',''),))
        audit('cierre de sesión')
        session.clear()
        return jsonify(ok=True)

    def native_directory(action,**values):
        return (call_local if app.config['MODE']=='local' else call_ad)(action,**values)

    @app.get('/api/users')
    def users():
        values = native_directory('list') if app.config['MODE']!='demo' else [dict(r) for r in db().execute('SELECT * FROM users ORDER BY name')]
        return jsonify(users=values or [])

    @app.post('/api/users')
    def add_user():
        data = request.get_json() or {}
        name, username, department = text_field(data,'name'),text_field(data,'username',20),text_field(data,'department')
        if not re.fullmatch(r'[a-zA-Z0-9._-]{1,20}',username):
            raise ValueError('El usuario admite letras, números, punto, guion y guion bajo; máximo 20 caracteres.')
        password = fresh_password()
        if app.config['MODE']!='demo':
            result=native_directory('create', name=name, username=username, department=department, password=password)
            if result and result.get('id'):
                remember_user_password(db(),key,result['id'],username,password,result.get('domain_guid',''),result.get('stamp',''))
        else:
            identifier=str(uuid.uuid4())
            db().execute('INSERT INTO users VALUES (?,?,?,?,1)',(identifier,name,username,department))
            remember_user_password(db(),key,identifier,username,password,db().execute('SELECT identifier FROM sync_instance').fetchone()[0],str(uuid.uuid4()))
        audit('crear usuario',username)
        return jsonify(password=password, message='Usuario local creado. La contraseña respeta la política de Windows.' if app.config['MODE']=='local' else 'Usuario creado. Debe cambiar la contraseña al iniciar sesión.'),201

    @app.post('/api/users/<identifier>/<action>')
    def user_action(identifier,action):
        if action not in ('reset','enable','disable','unlock'):
            raise ValueError('Operación no permitida.')
        if app.config['MODE']=='local':
            if not re.fullmatch(r'S-1-5-21-\d+-\d+-\d+-\d+',identifier):
                raise ValueError('Identificador local inválido.')
        else:
            try:
                uuid.UUID(identifier)
            except ValueError:
                raise ValueError('Identificador inválido.')
        password = fresh_password() if action=='reset' else None
        if app.config['MODE']!='demo':
            result=native_directory(action, identifier=identifier, **({'password':password} if password else {}))
            if password and result and result.get('username'):
                remember_user_password(db(),key,identifier,result['username'],password,result.get('domain_guid',''),result.get('stamp',''))
        else:
            if not db().execute('SELECT 1 FROM users WHERE id=?',(identifier,)).fetchone():
                return jsonify(error='Usuario no encontrado.'),404
            if password:
                username=db().execute('SELECT username FROM users WHERE id=?',(identifier,)).fetchone()[0]
                remember_user_password(db(),key,identifier,username,password,db().execute('SELECT identifier FROM sync_instance').fetchone()[0],str(uuid.uuid4()))
            if action in ('enable','disable'):
                db().execute('UPDATE users SET enabled=? WHERE id=?',(action=='enable',identifier))
        audit(action,identifier)
        return jsonify(ok=True,password=password)

    @app.get('/api/policy')
    def policy():
        return jsonify(length=db().execute('SELECT length FROM settings WHERE id=1').fetchone()[0],
                       mixedCase=True,numbers=True,symbols=True,uniqueWithinRegistry=True)

    @app.post('/api/policy')
    def update_policy():
        length = (request.get_json() or {}).get('length')
        if type(length) is not int or not 15<=length<=64:
            raise ValueError('La longitud debe estar entre 15 y 64 caracteres.')
        db().execute('UPDATE settings SET length=? WHERE id=1',(length,))
        audit('actualizar política',str(length))
        return jsonify(ok=True)

    @app.post('/api/generate')
    def generate():
        value = fresh_password()
        audit('generar contraseña')
        return jsonify(password=value)

    @app.get('/api/vault')
    def vault():
        return jsonify(entries=[dict(r) for r in db().execute('SELECT id,title,username,created FROM vault ORDER BY created DESC')])

    @app.post('/api/vault')
    def vault_add():
        data=request.get_json() or {}
        title,username=text_field(data,'title'),text_field(data,'username')
        value=fresh_password()
        identifier=str(uuid.uuid4())
        db().execute('INSERT INTO vault(id,title,username,secret) VALUES (?,?,?,?)',(identifier,title,username,seal(key,identifier,value)))
        audit('crear credencial',identifier)
        return jsonify(id=identifier,password=value),201

    @app.post('/api/vault/<identifier>/reveal')
    def reveal(identifier):
        if throttled('reveal', 10):
            return jsonify(error='Demasiados intentos. Espera 15 minutos.'), 429
        data=request.get_json() or {}
        row=db().execute('SELECT hash FROM admin WHERE id=1').fetchone()
        supplied=data.get('password','')
        if not isinstance(supplied,str) or len(supplied)>256 or not check_password_hash(row[0],supplied):
            audit('revelar credencial',identifier,'rechazado')
            return jsonify(error='Confirma tu contraseña de administrador.'),403
        entry=db().execute('SELECT secret FROM vault WHERE id=?',(identifier,)).fetchone()
        if not entry:
            return jsonify(error='Credencial no encontrada.'),404
        with attempts_lock:
            attempts.pop(('reveal',request.remote_addr),None)
        audit('revelar credencial',identifier)
        return jsonify(password=unseal(key,identifier,entry[0]))

    @app.get('/api/rdp/status')
    def rdp_status():
        if app.config.get('DESKTOP'):
            return jsonify(demo=app.config['MODE']=='demo', desktop=True,
                           configured=os.name=='nt' and bool(os.environ.get('FK_RDP_CERT_HASH')),
                           message='Firma con los certificados configurados. Credenciales protegidas para este equipo y cuenta Windows.')
        return jsonify(demo=app.config['MODE']=='demo', configured=rdp_configured(), activationMinutes=30,
                       message='La firma requiere Windows, certificado RDP, certificado de firma de código y portal HTTPS.')

    @app.get('/api/rdp/clients')
    def rdp_clients():
        # Retain metadata for audit but erase expired delivery payloads on access.
        db().execute('UPDATE rdp_clients SET secret=NULL WHERE expires<?',(time.time(),))
        db().commit()
        rows=[dict(r) for r in db().execute('SELECT id,host,username,expires,consumed,created FROM rdp_clients ORDER BY created DESC LIMIT 100')]
        for item in rows:
            item['status']='revocado' if item['consumed']==2 else 'activado' if item['consumed']==1 else 'caducado' if item['expires']<time.time() else 'pendiente'
        return jsonify(clients=rows)

    @app.post('/api/rdp/package')
    def rdp_package():
        data=request.get_json(silent=True)
        if not isinstance(data,dict):raise ValueError('Solicitud inválida.')
        host,username,port=validate_connection(data.get('host'),data.get('username'),data.get('port',3389))
        if app.config['MODE']=='demo':
            package=make_package(host,username,port,demo=True)
            audit('vista previa RDP',host)
            signed=False
        else:
            if not request.is_secure and not app.config.get('DESKTOP'):
                return jsonify(error='Genera paquetes con credenciales desde el portal HTTPS.'),403
            if throttled('rdp-export', 10):return jsonify(error='Demasiados intentos. Espera 15 minutos.'),429
            supplied=data.get('admin_password','')
            admin=db().execute('SELECT hash FROM admin WHERE id=1').fetchone()
            if not admin or not isinstance(supplied,str) or len(supplied)>256 or not check_password_hash(admin[0],supplied):
                audit('generar cliente RDP',host,'reautenticación rechazada')
                return jsonify(error='Confirma tu contraseña de administrador.'),403
            password=data.get('account_password')
            code=data.get('activation_code')
            if not isinstance(password,str) or not 1<=len(password)<=256 or '\x00' in password:
                raise ValueError('Indica la contraseña vigente de la cuenta para RDP.')
            if app.config.get('DESKTOP'):
                from windows_native import dpapi, machine_identity
                identity=machine_identity()
                identifier=str(uuid.uuid4())
                credentials=dpapi(json.dumps(dict(host=host,username=username,password=password)).encode())
                configuration=dict(id=identifier,host=host,username=username,local=True,
                                   identity=identity,credential=base64.b64encode(credentials).decode())
                package=make_package(host,username,port,configuration=configuration)
                db().execute('INSERT INTO rdp_clients(id,host,username,code_hash,secret,expires,consumed) VALUES (?,?,?,?,NULL,?,1)',
                             (identifier,host,username,'local-dpapi',time.time()))
                audit('generar cliente RDP local firmado',host)
                response=send_file(io.BytesIO(package),mimetype='application/zip',as_attachment=True,
                                   download_name='Metakampo-RDP-local-firmado.zip')
                response.headers['X-RDP-Signed']='true'
                return response
            if not isinstance(code,str) or not 15<=len(code)<=128 or code.strip()!=code or code==password or not all(any(c in group for c in code) for group in CATEGORIES):
                raise ValueError('El código de activación debe tener 15 a 128 caracteres con mayúsculas, minúsculas, números y símbolos, sin espacios externos, y ser diferente de la contraseña RDP.')
            identifier=str(uuid.uuid4())
            configuration=dict(id=identifier,host=host,username=username,portal=portal_url())
            # No broker credential is saved until both native signatures succeed.
            package=make_package(host,username,port,configuration=configuration)
            encrypted=seal(key,identifier,json.dumps(dict(host=host,username=username,password=password)))
            db().execute('UPDATE rdp_clients SET secret=NULL WHERE expires<?',(time.time(),))
            db().execute('INSERT INTO rdp_clients(id,host,username,code_hash,secret,expires) VALUES (?,?,?,?,?,?)',
                         (identifier,host,username,generate_password_hash(code,method='pbkdf2:sha256:1000000'),encrypted,time.time()+1800))
            audit('generar cliente RDP firmado',host)
            signed=True
        response=send_file(io.BytesIO(package),mimetype='application/zip',as_attachment=True,
                           download_name='Metakampo-RDP-firmado.zip' if signed else 'Metakampo-RDP-DEMO-sin-firma.zip')
        response.headers['X-RDP-Signed']='true' if signed else 'false'
        return response

    @app.post('/api/rdp/clients/<identifier>/revoke')
    def revoke_rdp(identifier):
        count=db().execute('UPDATE rdp_clients SET secret=NULL,consumed=2 WHERE id=? AND consumed=0',(identifier,)).rowcount
        if not count:
            db().rollback()
            return jsonify(error='El paquete ya fue activado, revocado o no existe.'),409
        audit('revocar activación RDP',identifier)
        return jsonify(ok=True)

    @app.post('/api/rdp/redeem')
    def redeem_rdp():
        # The Windows launcher supplies a one-time code without any administrator session.
        if app.config['MODE']!='ad' or not request.is_secure:
            return jsonify(error='La activación de credenciales requiere HTTPS y modo AD.'),403
        if request.headers.get('Origin'):
            return jsonify(error='La activación se realiza desde el lanzador Windows.'),403
        data=request.get_json(silent=True)
        if not isinstance(data,dict):return jsonify(error='Activación inválida.'),400
        identifier,code=data.get('id'),data.get('code')
        if not isinstance(identifier,str) or len(identifier)!=36 or not isinstance(code,str) or not 15<=len(code)<=128:
            return jsonify(error='Activación inválida.'),400
        if throttled('rdp-redeem',25) or throttled('rdp-code:'+identifier,5):
            return jsonify(error='Demasiados intentos. Espera 15 minutos.'),429
        conn=db()
        conn.execute('BEGIN IMMEDIATE')
        try:
            entry=conn.execute('SELECT * FROM rdp_clients WHERE id=?',(identifier,)).fetchone()
            if not entry or entry['consumed'] or entry['expires']<time.time() or not entry['secret'] or not check_password_hash(entry['code_hash'],code):
                if entry and entry['expires']<time.time():
                    conn.execute('UPDATE rdp_clients SET secret=NULL WHERE id=?',(identifier,))
                    conn.commit()
                else:conn.rollback()
                return jsonify(error='Código inválido, usado, revocado o caducado.'),403
            credentials=json.loads(unseal(key,identifier,entry['secret']))
            conn.execute('UPDATE rdp_clients SET consumed=1,secret=NULL WHERE id=?',(identifier,))
            conn.execute('INSERT INTO audit(actor,action,target,result) VALUES (?,?,?,?)',('cliente Windows','activar cliente RDP',identifier,'correcto'))
            conn.commit()
        except Exception:
            conn.rollback()
            return jsonify(error='No se pudo activar el paquete.'),503
        return jsonify(credentials)

    @app.get('/api/audit')
    def audit_list():
        return jsonify(events=[dict(r) for r in db().execute('SELECT * FROM audit ORDER BY id DESC LIMIT 200')])

    register_telemetry(app,db,audit,throttled)
    register_access_map(app,db)
    register_user_sync(app,db,audit,throttled,fresh_password,native_directory)
    app.db_path = database
    return app


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--init-admin',action='store_true')
    parser.add_argument('--port',type=int,default=8765)
    args=parser.parse_args()
    app=create_app()
    if args.init_admin:
        first=getpass.getpass('Nueva contraseña del administrador (mínimo 15 caracteres): ')
        if len(first)<15 or first!=getpass.getpass('Confirma la contraseña: '):
            raise SystemExit('La contraseña no cumple o la confirmación no coincide.')
        with connection(app.db_path) as db:
            db.execute('INSERT OR REPLACE INTO admin VALUES (1,?)',(generate_password_hash(first, method="pbkdf2:sha256:1000000"),))
            db.execute('DELETE FROM sessions')
        print('Administrador configurado. Usuario: admin')
    else:
        from waitress import serve
        print(f'Metakampo Access · {app.config["MODE"]} · http://127.0.0.1:{args.port}',flush=True)
        serve(app,host='127.0.0.1',port=args.port,threads=4,trusted_proxy='127.0.0.1',trusted_proxy_headers={'x-forwarded-proto','x-forwarded-for'})
