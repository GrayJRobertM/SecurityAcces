"""Individual full-administration accounts; Windows directory accounts are separate."""
import re
import sqlite3
from flask import session, request, jsonify, g, has_request_context
from werkzeug.security import check_password_hash, generate_password_hash


def current_actor():
    return getattr(g,'actor','admin') if has_request_context() else 'sistema'


def account_hash(db, username):
    if username=='admin':
        row=db.execute('SELECT hash FROM admin WHERE id=1').fetchone()
    else:
        row=db.execute('SELECT hash FROM app_operators WHERE username=? AND enabled=1',(username,)).fetchone()
    return row[0] if row else None


def reauthenticate(db, password):
    if not isinstance(password,str) or len(password)>256:return False
    value=account_hash(db,current_actor())
    return bool(value and check_password_hash(value,password))


def install(db):
    db.execute('CREATE TABLE IF NOT EXISTS app_operators(username TEXT PRIMARY KEY,name TEXT NOT NULL,hash TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1)')
    if 'actor' not in {row[1] for row in db.execute('PRAGMA table_info(sessions)')}:
        db.execute("ALTER TABLE sessions ADD COLUMN actor TEXT NOT NULL DEFAULT 'admin'")


def register(app,db,audit,throttled,fresh_password):
    @app.get('/api/operators')
    def operators():
        rows=[dict(row) for row in db().execute('SELECT username,name,enabled FROM app_operators ORDER BY name')]
        return jsonify(users=[dict(username='admin',name='Administrador propietario',enabled=True,protected=True)]+rows,current=current_actor())

    def chosen_password(data):
        value=data.get('password','')
        if not isinstance(value,str) or len(value)>256:raise ValueError('Contraseña inválida.')
        return value if value else fresh_password()

    def confirm(data):
        return not throttled('operators:'+current_actor(),15) and reauthenticate(db(),data.get('admin_password'))

    @app.post('/api/operators')
    def create_operator():
        data=request.get_json() or {}
        if not confirm(data):return jsonify(error='Confirma tu contraseña de Metakampo.'),403
        username=data.get('username');name=data.get('name')
        if not isinstance(username,str) or not re.fullmatch('[A-Za-z0-9._-]{1,40}',username) or username.lower()=='admin':raise ValueError('Elige un usuario distinto de admin, con letras, números, punto, guion o guion bajo.')
        if not isinstance(name,str) or not name.strip() or len(name)>120 or any(ord(c)<32 for c in name):raise ValueError('Indica el nombre del administrador.')
        username=username.lower();password=chosen_password(data)
        try:db().execute('INSERT INTO app_operators VALUES(?,?,?,1)',(username,name.strip(),generate_password_hash(password,method='pbkdf2:sha256:1000000')))
        except sqlite3.IntegrityError:return jsonify(error='Ese administrador ya existe.'),409
        audit('crear administrador del gestor',username)
        return jsonify(username=username,password=password),201

    @app.post('/api/operators/<username>/<action>')
    def change_operator(username,action):
        data=request.get_json() or {}
        if not confirm(data):return jsonify(error='Confirma tu contraseña de Metakampo.'),403
        if action not in ('reset','status'):raise ValueError('Operación no permitida para esta cuenta.')
        if username=='admin':
            if action!='reset' or current_actor()!='admin':raise ValueError('Solo el propietario puede cambiar su contraseña.')
            password=chosen_password(data)
            db().execute('UPDATE admin SET hash=? WHERE id=1',(generate_password_hash(password,method='pbkdf2:sha256:1000000'),))
            db().execute("DELETE FROM sessions WHERE actor='admin'")
            audit('cambiar contraseña del propietario','admin')
            return jsonify(ok=True,password=password)
        if not db().execute('SELECT 1 FROM app_operators WHERE username=?',(username,)).fetchone():return jsonify(error='Administrador no encontrado.'),404
        password=None
        if action=='reset':
            password=chosen_password(data);db().execute('UPDATE app_operators SET hash=? WHERE username=?',(generate_password_hash(password,method='pbkdf2:sha256:1000000'),username))
        else:
            enabled=data.get('enabled')
            if type(enabled) is not bool:raise ValueError('Estado inválido.')
            if username==current_actor() and not enabled:raise ValueError('No puedes desactivar tu propia cuenta.')
            db().execute('UPDATE app_operators SET enabled=? WHERE username=?',(enabled,username))
        db().execute('DELETE FROM sessions WHERE actor=?',(username,))
        audit('actualizar administrador del gestor',username)
        return jsonify(ok=True,password=password)
