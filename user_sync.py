"""Portable encrypted account sync; administrator authorization is separate from the transfer key."""
import base64
import csv
import hashlib
import io
import json
import re
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime,timezone
from flask import jsonify,request,session,send_file
from werkzeug.security import check_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from security import seal,unseal,CATEGORIES,fingerprint
from storage import connection
from directory import call_ad,DirectoryError

MAX_USERS=500
MAX_FILE=1048576
AAD=b'Freshkampo.Access.UserSync.v1'
COLUMNS=['username','name','department','enabled']


def install(database):
    with connection(database) as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS sync_instance(id INTEGER PRIMARY KEY CHECK(id=1),identifier TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS managed_passwords(user_id TEXT PRIMARY KEY,username TEXT NOT NULL,domain_guid TEXT NOT NULL,stamp TEXT NOT NULL,secret BLOB NOT NULL,updated REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS sync_plans(id TEXT PRIMARY KEY,owner TEXT NOT NULL,expires REAL NOT NULL,secret BLOB,consumed INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS sync_jobs(id TEXT PRIMARY KEY,owner TEXT NOT NULL,status TEXT NOT NULL,total INTEGER NOT NULL,completed INTEGER NOT NULL DEFAULT 0,results TEXT NOT NULL DEFAULT '[]',created REAL NOT NULL);
        ''')
        db.execute('INSERT OR IGNORE INTO sync_instance VALUES(1,?)',(str(uuid.uuid4()),))
        db.execute("UPDATE sync_jobs SET status='interrumpido: verificar AD antes de reintentar' WHERE status='aplicando'")


def remember(db,key,identifier,username,password,domain_guid,stamp):
    db.execute('INSERT OR REPLACE INTO managed_passwords VALUES(?,?,?,?,?,?)',
               (identifier,username,domain_guid,stamp or '',seal(key,'user-sync:'+identifier,password),time.time()))
    db.commit()


def strong_transfer(value):
    if not isinstance(value,str) or not 15<=len(value)<=256 or any(ord(c)<32 for c in value) or not all(any(c in group for c in value) for group in CATEGORIES):
        raise ValueError('La clave de transferencia debe tener al menos 15 caracteres con mayúsculas, minúsculas, números y símbolos.')


def encrypt_package(payload,password):
    strong_transfer(password)
    salt=secrets.token_bytes(16);nonce=secrets.token_bytes(12)
    key=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,600000,32)
    cipher=AESGCM(key).encrypt(nonce,json.dumps(payload,ensure_ascii=False).encode(),AAD)
    return json.dumps(dict(format='Freshkampo-UserSync',version=1,kdf='PBKDF2-SHA256-600000',salt=base64.b64encode(salt).decode(),nonce=base64.b64encode(nonce).decode(),ciphertext=base64.b64encode(cipher).decode())).encode()


def decrypt_package(raw,password):
    strong_transfer(password)
    if len(raw)>MAX_FILE:raise ValueError('El archivo excede 1 MiB.')
    try:
        package=json.loads(raw)
        if set(package)!={'format','version','kdf','salt','nonce','ciphertext'} or package['format']!='Freshkampo-UserSync' or package['version']!=1 or package['kdf']!='PBKDF2-SHA256-600000':raise ValueError()
        salt=base64.b64decode(package['salt'],validate=True);nonce=base64.b64decode(package['nonce'],validate=True);cipher=base64.b64decode(package['ciphertext'],validate=True)
        if len(salt)!=16 or len(nonce)!=12 or len(cipher)<16:raise ValueError()
        key=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,600000,32)
        return json.loads(AESGCM(key).decrypt(nonce,cipher,AAD))
    except (ValueError,TypeError,KeyError,InvalidTag,UnicodeError):
        raise ValueError('Archivo alterado, formato no compatible o clave de transferencia incorrecta.') from None


def clean_user(item):
    if not isinstance(item,dict) or set(item)-set(COLUMNS+['password','source_id','stamp','domain_guid']):raise ValueError('Columnas de usuario no admitidas.')
    result={}
    for field,maximum in [('username',20),('name',120),('department',120)]:
        value=item.get(field,'')
        if not isinstance(value,str) or len(value)>maximum or any(ord(c)<32 for c in value):raise ValueError('Campo de usuario inválido: '+field)
        result[field]=value.strip()
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,20}',result['username']) or not result['name']:raise ValueError('Completa el nombre y un usuario válido de hasta 20 caracteres.')
    enabled=item.get('enabled')
    if enabled in ('true','1'):enabled=True
    elif enabled in ('false','0'):enabled=False
    if type(enabled) is not bool:raise ValueError('enabled debe ser true o false.')
    result['enabled']=enabled
    for field in ('password','source_id','stamp','domain_guid'):
        value=item.get(field)
        if value is not None and (not isinstance(value,str) or len(value)>256 or any(ord(c)<32 for c in value)):raise ValueError('Dato de sincronización inválido.')
        result[field]=value
    return result


def read_csv(raw):
    if len(raw)>MAX_FILE:raise ValueError('El archivo excede 1 MiB.')
    try:
        text=raw.decode('utf-8-sig')
        delimiter=';' if text.splitlines()[0].count(';')>text.splitlines()[0].count(',') else ','
        reader=csv.DictReader(io.StringIO(text),delimiter=delimiter,strict=True)
        if len(reader.fieldnames or [])!=len(COLUMNS) or set(reader.fieldnames or [])!=set(COLUMNS):raise ValueError('El CSV debe contener username,name,department,enabled. Las contraseñas requieren .fksync cifrado.')
        users=[]
        for row in reader:
            for field in ('username','name','department'):
                if row.get(field,'').startswith("'"):row[field]=row[field][1:]
            users.append(clean_user(row))
            if len(users)>MAX_USERS:raise ValueError('Máximo 500 usuarios por archivo.')
        return users
    except (UnicodeError,csv.Error,IndexError,AttributeError):raise ValueError('Usa CSV UTF-8 con columnas y valores completos.') from None


def csv_bytes(users):
    buffer=io.StringIO(newline='');writer=csv.DictWriter(buffer,fieldnames=COLUMNS);writer.writeheader()
    def safe(value):
        value=str(value or '')
        return "'"+value if value.startswith("'") or value.lstrip().startswith(('=','+','-','@')) else value
    for user in users:writer.writerow({field:('true' if user['enabled'] else 'false') if field=='enabled' else safe(user.get(field)) for field in COLUMNS})
    return buffer.getvalue().encode('utf-8-sig')


def snapshot(users):
    values=[{field:user.get(field) for field in ['id']+COLUMNS} for user in users]
    return hashlib.sha256(json.dumps(sorted(values,key=lambda row:row['username'].casefold()),sort_keys=True).encode()).hexdigest()


def register(app,db,audit,throttled,fresh_password):
    key=app.config['VAULT_KEY']
    app.sync_threads=[]
    def users():
        return (call_ad('list') or []) if app.config['MODE']=='ad' else [dict(row) for row in db().execute('SELECT * FROM users')]
    def reauth(data):
        if throttled('user-sync',15):return False
        supplied=data.get('admin_password','')
        admin=db().execute('SELECT hash FROM admin WHERE id=1').fetchone()
        return isinstance(supplied,str) and len(supplied)<=256 and admin and check_password_hash(admin[0],supplied)
    def stamps(identifiers):
        if app.config['MODE']=='ad':
            value=call_ad('stamps',identifiers=identifiers)
            return value['domain_guid'],{row['id']:row['stamp'] for row in value['users']}
        domain=db().execute('SELECT identifier FROM sync_instance').fetchone()[0]
        return domain,{row['user_id']:row['stamp'] for row in db().execute('SELECT user_id,stamp FROM managed_passwords')}
    def available(current,extra_ids=()):
        records={row['user_id']:dict(row) for row in db().execute('SELECT * FROM managed_passwords')}
        domain,versions=stamps(list({user['id'] for user in current if user['id'] in records}|set(extra_ids)))
        result={}
        for user in current:
            stored=records.get(user['id'])
            if stored and stored['domain_guid']==domain and stored['stamp'] and versions.get(user['id'])==stored['stamp']:
                result[user['id']]=dict(password=unseal(key,'user-sync:'+user['id'],stored['secret']),stamp=stored['stamp'],domain_guid=domain)
        return result,domain,versions

    @app.post('/api/user-sync/export')
    def export():
        data=request.get_json(silent=True) or {}
        if not isinstance(data,dict) or not reauth(data):return jsonify(error='Confirma la contraseña del administrador de esta instalación.'),403
        current=users()
        if len(current)>MAX_USERS:raise ValueError('Máximo 500 usuarios por archivo; configura una OU de alcance menor.')
        include=data.get('include_passwords',True)
        if type(include) is not bool:raise ValueError('Selección de exportación inválida.')
        omitted=0
        if include:
            transfer=data.get('transfer_password','');strong_transfer(transfer)
            if transfer==data.get('admin_password'):raise ValueError('Usa una clave de transferencia diferente de la contraseña administrativa.')
            known,domain,_=available(current);exported=[]
            for user in current:
                if user['id'] not in known:omitted+=1;continue
                exported.append(dict({field:user.get(field,'') for field in COLUMNS},enabled=bool(user['enabled']),source_id=user['id'],**known[user['id']]))
            if not exported:return jsonify(error='No hay contraseñas administradas verificables. Restablece primero las cuentas que deseas sincronizar desde el Directorio; las claves actuales de AD no se pueden leer.'),409
            raw=encrypt_package(dict(version=1,users=exported,includes_passwords=True,created=datetime.now(timezone.utc).isoformat()),transfer)
            filename='Freshkampo-usuarios-con-claves.fksync'
        else:
            raw=csv_bytes(current);filename='Freshkampo-usuarios-sin-claves.csv';exported=current
        audit('exportar usuarios con claves' if include else 'exportar usuarios CSV',str(len(exported)))
        response=send_file(io.BytesIO(raw),mimetype='application/octet-stream',as_attachment=True,download_name=filename)
        response.headers['X-Sync-Included']=str(len(exported));response.headers['X-Sync-Omitted']=str(omitted)
        return response

    @app.post('/api/user-sync/preview')
    def preview():
        data=request.form
        if not reauth(data):return jsonify(error='Confirma la contraseña del administrador de esta instalación.'),403
        upload=request.files.get('file')
        if not upload:raise ValueError('Selecciona un archivo .fksync o CSV UTF-8.')
        raw=upload.read(MAX_FILE+1)
        if len(raw)>MAX_FILE:raise ValueError('El archivo excede 1 MiB.')
        if upload.filename.lower().endswith('.csv'):
            items=read_csv(raw)
        elif upload.filename.lower().endswith('.fksync'):
            payload=decrypt_package(raw,data.get('transfer_password',''))
            if not isinstance(payload,dict) or payload.get('version')!=1 or payload.get('includes_passwords') is not True or not isinstance(payload.get('users'),list):raise ValueError('Archivo de sincronización inválido.')
            items=[clean_user(item) for item in payload['users']]
            if any(not item['password'] for item in items):raise ValueError('El archivo cifrado debe contener las contraseñas de todas sus cuentas.')
        else:raise ValueError('Formato no admitido. Usa .fksync o .csv.')
        if not 1<=len(items)<=MAX_USERS:raise ValueError('El archivo debe incluir entre 1 y 500 usuarios.')
        if len({item['username'].casefold() for item in items})!=len(items):raise ValueError('El archivo contiene usuarios duplicados.')
        length=db().execute('SELECT length FROM settings').fetchone()[0]
        current=users();by_name={user['username'].casefold():user for user in current}
        known,domain,versions=available(current,[by_name[item['username'].casefold()]['id'] for item in items if item['password'] and item['username'].casefold() in by_name]);planned=[]
        supplied_passwords={}
        for item in items:
            password=item['password']
            if password is not None and (len(password)<length or not all(any(char in category for char in password) for category in CATEGORIES)):
                raise ValueError('Una contraseña no cumple la política vigente. No se importó ningún usuario.')
            existing=by_name.get(item['username'].casefold())
            if password and existing and item['domain_guid']==domain and item['source_id']==existing['id'] and (not item['stamp'] or item['stamp']!=versions.get(existing['id'])):
                raise ValueError('Una contraseña del archivo no coincide con la versión actual del mismo dominio, o no puede verificarse. Actualiza el archivo y comprueba la replicación; no se restauran contraseñas antiguas automáticamente.')
            if password:
                digest=fingerprint(key,password)
                if digest in supplied_passwords and supplied_passwords[digest]!=item['username'].casefold():raise ValueError('El archivo asigna la misma contraseña a cuentas diferentes.')
                supplied_passwords[digest]=item['username'].casefold()
                if any(user_id!=(existing or {}).get('id') and value['password']==password for user_id,value in known.items()):raise ValueError('Una contraseña coincide con otra cuenta administrada en esta instalación.')
            reset=bool(password and existing)
            if reset and (existing['id'] in known and secrets.compare_digest(known[existing['id']]['password'].encode(),password.encode())):reset=False
            if reset and item['domain_guid']==domain and item['source_id']==existing['id'] and item['stamp'] and item['stamp']==versions.get(existing['id']):reset=False
            metadata=bool(existing and any((bool(existing[field]) if field=='enabled' else existing.get(field) or '')!=item[field] for field in ('name','department','enabled')))
            planned.append(dict(item,target_id=existing['id'] if existing else None,target_stamp=versions.get(existing['id'],'') if existing else '',reset=reset,metadata=metadata,
                                action='crear' if not existing else 'restablecer contraseña'+(' y actualizar' if metadata else '') if reset else 'actualizar atributos' if metadata else 'conservar / sincronizar clave local'))
        identifier=str(uuid.uuid4())
        contents=dict(snapshot=snapshot(current),items=planned,domain=domain)
        db().execute('DELETE FROM sync_plans WHERE expires<?',(time.time(),))
        db().execute('INSERT INTO sync_plans(id,owner,expires,secret) VALUES(?,?,?,?)',(identifier,session['auth'],time.time()+900,seal(key,identifier,json.dumps(contents))))
        db().commit()
        audit('previsualizar importación',str(len(planned)))
        return jsonify(plan=identifier,users=[{field:item[field] for field in COLUMNS+['action']} for item in planned],
                       creates=sum(not item['target_id'] for item in planned),resets=sum(item['reset'] for item in planned),updates=sum(item['metadata'] for item in planned),expires_minutes=15)

    @app.post('/api/user-sync/apply')
    def apply():
        data=request.get_json(silent=True) or {}
        if not isinstance(data,dict) or not reauth(data):return jsonify(error='Confirma nuevamente la contraseña administrativa para aplicar la importación.'),403
        identifier=data.get('plan','')
        plan=db().execute('SELECT * FROM sync_plans WHERE id=? AND owner=? AND consumed=0 AND expires>?',(identifier,session['auth'],time.time())).fetchone()
        if not plan:return jsonify(error='Vista previa caducada, usada o de otra sesión.'),409
        contents=json.loads(unseal(key,identifier,plan['secret']))
        current=users()
        if snapshot(current)!=contents['snapshot']:return jsonify(error='El directorio cambió después de la vista previa. Vuelve a previsualizar el archivo.'),409
        domain,current_stamps=stamps([item['target_id'] for item in contents['items'] if item['target_id'] and item['password']])
        if domain!=contents['domain'] or any(current_stamps.get(item['target_id'],'')!=item['target_stamp'] for item in contents['items'] if item['target_id'] and item['password']):
            return jsonify(error='Cambió la versión de una contraseña después de previsualizar. Revisa de nuevo el archivo.'),409
        db().execute('BEGIN IMMEDIATE')
        if db().execute("SELECT 1 FROM sync_jobs WHERE status='aplicando' LIMIT 1").fetchone():db().rollback();return jsonify(error='Espera a que termine la importación en curso.'),409
        changed=db().execute('UPDATE sync_plans SET consumed=1,secret=NULL WHERE id=? AND owner=? AND consumed=0 AND expires>?',(identifier,session['auth'],time.time())).rowcount
        if not changed:db().rollback();return jsonify(error='La importación ya fue utilizada.'),409
        job=str(uuid.uuid4());owner=session['auth']
        db().execute('INSERT INTO sync_jobs(id,owner,status,total,created) VALUES(?,?,?,?,?)',(job,owner,'aplicando',len(contents['items']),time.time()))
        db().commit();audit('iniciar sincronización',job)
        def run():
            results=[]
            with app.app_context():
                for item in contents['items']:
                    try:
                        identifier=item['target_id'];password=item['password'];native=None
                        if not identifier:
                            password=password or fresh_password()
                            if app.config['MODE']=='ad':
                                native=call_ad('create',name=item['name'],username=item['username'],department=item['department'],password=password,enabled=item['enabled']);identifier=native['id']
                            else:
                                identifier=str(uuid.uuid4());db().execute('INSERT INTO users VALUES(?,?,?,?,?)',(identifier,item['name'],item['username'],item['department'],int(item['enabled'])));db().commit()
                        else:
                            if item['metadata']:
                                if app.config['MODE']=='ad':call_ad('update',identifier=identifier,name=item['name'],department=item['department'],enabled=item['enabled'])
                                else:db().execute('UPDATE users SET name=?,department=?,enabled=? WHERE id=?',(item['name'],item['department'],int(item['enabled']),identifier));db().commit()
                            if item['reset'] and app.config['MODE']=='ad':native=call_ad('reset',identifier=identifier,password=password)
                        if password:
                            if app.config['MODE']=='ad':
                                if native:domain,stamp=native.get('domain_guid',''),native.get('stamp','')
                                else:
                                    domain,versions=stamps([identifier]);stamp=versions.get(identifier,'')
                                    if stamp!=item['target_stamp']:raise DirectoryError('La contraseña cambió durante la importación.')
                            else:domain=contents['domain'];stamp=str(uuid.uuid4())
                            remember(db(),key,identifier,item['username'],password,domain,stamp)
                            db().execute('INSERT OR IGNORE INTO issued(fingerprint) VALUES(?)',(fingerprint(key,password),));db().commit()
                        result=dict(username=item['username'],result='aplicado',action=item['action'])
                        audit('sincronizar usuario',item['username'])
                    except Exception:
                        db().rollback();result=dict(username=item['username'],result='error: verificar estado real antes de reintentar',action=item['action'])
                        audit('sincronizar usuario',item['username'],'error o resultado por verificar')
                    results.append(result)
                    failed=result['result']!='aplicado'
                    db().execute('UPDATE sync_jobs SET completed=?,results=?,status=? WHERE id=?',
                                 (len(results),json.dumps(results),'detenido: verificar estado real' if failed else 'completado' if len(results)==len(contents['items']) else 'aplicando',job));db().commit()
                    if failed:break
        worker=threading.Thread(target=run,daemon=True)
        app.sync_threads[:]=[thread for thread in app.sync_threads if thread.is_alive()]
        app.sync_threads.append(worker)
        worker.start()
        return jsonify(job=job),202

    @app.get('/api/user-sync/jobs/<identifier>')
    def job(identifier):
        row=db().execute('SELECT id,status,total,completed,results FROM sync_jobs WHERE id=?',(identifier,)).fetchone()
        if not row:return jsonify(error='Importación no encontrada para esta sesión.'),404
        result=dict(row);result['results']=json.loads(result['results']);return jsonify(result)

    @app.get('/api/user-sync/jobs')
    def jobs():
        return jsonify(jobs=[dict(row) for row in db().execute('SELECT id,status,total,completed,created FROM sync_jobs ORDER BY created DESC LIMIT 20')])

    @app.post('/api/user-sync/password/<identifier>')
    def sync_reveal(identifier):
        data=request.get_json(silent=True) or {}
        if not isinstance(data,dict) or not reauth(data):return jsonify(error='Confirma la contraseña de administrador.'),403
        current=users();known,_,_=available([user for user in current if user['id']==identifier])
        if identifier not in known:return jsonify(error='La contraseña no está disponible o cambió fuera del gestor.'),409
        audit('consultar contraseña administrada',identifier)
        return jsonify(password=known[identifier]['password'])
