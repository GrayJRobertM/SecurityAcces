"""Standalone Windows desktop entry point; the HTTP transport is private to its window."""
import argparse
import base64
import ctypes
import hashlib
import json
import os
import re
import secrets
import sqlite3
from storage import connection
import sys
import tempfile
import threading
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash
from app import create_app
from windows_native import dpapi, machine_identity, restrict_folder

BASE = Path(__file__).parent
VERSION = '1.4.0'


def validate_settings(data):
    if not isinstance(data, dict):
        raise ValueError('Configuración inválida.')
    mode = data.get('mode', 'ad')
    if mode not in ('ad', 'demo','local'):
        raise ValueError('Selecciona usuarios locales, Active Directory o demostración.')
    result = dict(mode=mode)
    for name in ('server', 'ou', 'suffix', 'rdp_cert', 'script_cert', 'store'):
        value = data.get(name, '')
        if not isinstance(value, str) or len(value) > 1024 or any(ord(c) < 32 for c in value):
            raise ValueError('Revisa los campos de configuración.')
        result[name] = value.strip()
    if mode == 'ad':
        from telemetry import hostname
        result['server'] = hostname(result['server'])
        result['suffix'] = hostname(result['suffix'])
        if not re.match(r'(?i)^OU=.+,DC=.+', result['ou']) or ';' in result['ou']:
            raise ValueError('Indica el DN completo de la OU, por ejemplo OU=Pruebas,DC=empresa,DC=local.')
    if mode!='ad':
        result.update(server='',ou='',suffix='')
    for name in ('rdp_cert', 'script_cert'):
        result[name] = result[name].replace(' ', '').upper()
        if result[name] and not re.fullmatch(r'(?:[A-F0-9]{40}|[A-F0-9]{64})', result[name]):
            raise ValueError('Las huellas de certificados deben tener 40 o 64 caracteres hexadecimales.')
    if result['store'] not in ('CurrentUser', 'LocalMachine'):
        raise ValueError('Selecciona un almacén de certificados válido.')
    return result


class Store:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.identity = machine_identity()
        self.folder.mkdir(parents=True, exist_ok=True)
        restrict_folder(self.folder, self.identity['sid'])
        self.file = self.folder / 'installation.dpapi'
        self.values = None
        if self.file.exists():
            self.values = json.loads(dpapi(self.file.read_bytes(), decrypt=True))
            if self.values['identity'] != self.identity:
                raise OSError('Esta instalación pertenece a otro equipo o cuenta Windows.')

    def save(self, settings):
        values = dict(identity=self.identity, settings=settings,
                      key=self.values['key'] if self.values else base64.b64encode(secrets.token_bytes(32)).decode())
        protected = dpapi(json.dumps(values).encode())
        temporary = self.file.with_suffix('.tmp')
        temporary.write_bytes(protected)
        temporary.replace(self.file)
        self.values = values

    def application(self):
        settings = self.values['settings']
        os.environ['FK_MASTER_KEY'] = self.values['key']
        for name, variable in [('server', 'FK_AD_SERVER'), ('ou', 'FK_AD_OU'), ('suffix', 'FK_AD_UPN_SUFFIX'),
                               ('rdp_cert', 'FK_RDP_CERT_HASH'), ('script_cert', 'FK_RDP_SCRIPT_CERT_HASH'),
                               ('store', 'FK_RDP_CERT_STORE')]:
            os.environ[variable] = settings[name]
        os.environ['FK_DESKTOP'] = '1'
        try:
            return create_app(dict(MODE=settings['mode'], DATA_DIR=str(self.folder / settings['mode']),
                                   DESKTOP=True, SESSION_COOKIE_SECURE=False, TRUSTED_HOSTS=['127.0.0.1']))
        finally:
            os.environ.pop('FK_MASTER_KEY', None)


class DesktopGate:
    """One-use window bootstrap, independent of the administrator login session."""
    def __init__(self, application):
        self.application = application
        self.bootstrap = secrets.token_urlsafe(32)
        self.capability = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.host = None

    def __call__(self, env, start_response):
        def deny():
            start_response('403 Forbidden', [('Content-Type', 'text/plain; charset=utf-8'), ('Cache-Control', 'no-store')])
            return ['Acceso disponible únicamente en la ventana instalada.'.encode()]
        if env.get('REMOTE_ADDR') != '127.0.0.1' or env.get('HTTP_HOST') != self.host:
            return deny()
        if env.get('PATH_INFO') == '/desktop-open' and env.get('REQUEST_METHOD') == 'GET':
            token = parse_qs(env.get('QUERY_STRING', '')).get('token', [''])[0]
            with self.lock:
                if not self.bootstrap or not secrets.compare_digest(token, self.bootstrap):
                    return deny()
                self.bootstrap = None
            start_response('303 See Other', [('Location', '/'), ('Cache-Control', 'no-store'),
                                            ('Referrer-Policy', 'no-referrer'),
                                            ('Set-Cookie', 'fk_desktop=' + self.capability + '; HttpOnly; SameSite=Strict; Path=/')])
            return [b'']
        cookie = SimpleCookie()
        try:
            cookie.load(env.get('HTTP_COOKIE', ''))
            value = cookie['fk_desktop'].value if 'fk_desktop' in cookie else ''
        except Exception:
            return deny()
        if not secrets.compare_digest(value, self.capability):
            return deny()
        origin = env.get('HTTP_ORIGIN')
        if origin and origin != 'http://' + self.host:
            return deny()
        # The desktop never accepts remote collectors or an RDP credential broker.
        if env.get('PATH_INFO', '').startswith(('/api/telemetry/events', '/api/collectors', '/api/rdp/redeem')):
            return deny()
        return self.application(env, start_response)


def setup_application(store, gate, on_ready):
    app = Flask('desktop_setup', static_folder=str(BASE / 'static'))
    app.secret_key = secrets.token_bytes(32)
    app.config.update(MAX_CONTENT_LENGTH=16384, TRUSTED_HOSTS=['127.0.0.1'])
    csrf = secrets.token_urlsafe(32)
    failures = []
    save_lock = threading.Lock()

    @app.after_request
    def headers(response):
        response.headers.update({'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        return response

    @app.get('/')
    def page():
        return app.send_static_file('desktop-setup.html')

    @app.get('/desktop/settings')
    def settings():
        return jsonify(csrf=csrf, configured=bool(store.values),
                       settings=store.values['settings'] if store.values else dict(mode='ad', store='CurrentUser'))

    @app.post('/desktop/settings')
    def save():
        if not secrets.compare_digest(request.headers.get('X-CSRF-Token', ''), csrf):
            return jsonify(error='Sesión de configuración inválida.'), 403
        data = request.get_json(silent=True) or {}
        import time
        with save_lock:
            failures[:] = [stamp for stamp in failures if stamp > time.time()-900]
            if len(failures) >= 5:
                return jsonify(error='Demasiados intentos. Espera 15 minutos o cierra y vuelve a abrir la aplicación.'),429
        try:
            settings = validate_settings(data)
            password = data.get('password', '')
            if not isinstance(password, str) or len(password) > 256:
                raise ValueError('Contraseña inválida.')
            if store.values:
                database = store.folder / store.values['settings']['mode'] / 'access.sqlite3'
                with connection(database) as db:
                    admin = db.execute('SELECT hash FROM admin WHERE id=1').fetchone()
                if not admin or not check_password_hash(admin[0], password):
                    with save_lock:
                        failures.append(time.time())
                    return jsonify(error='Confirma la contraseña administrativa de esta aplicación.'), 403
            else:
                from security import CATEGORIES
                if len(password) < 15 or not all(any(c in group for c in password) for group in CATEGORIES):
                    raise ValueError('Elige una contraseña de al menos 15 caracteres con mayúsculas, minúsculas, números y símbolos.')
                if password != data.get('confirmation'):
                    raise ValueError('La confirmación no coincide.')
            if settings['mode'] == 'ad':
                from windows_native import powershell
                result = powershell(BASE / 'windows' / 'Check-Desktop.ps1', settings)
                if not result['ad']:
                    raise ValueError('Instala RSAT Active Directory y verifica el controlador de dominio, la OU y los permisos de lectura.')
            if settings['mode']=='local':
                from directory import call_local
                try:
                    call_local('check')
                except Exception:
                    raise ValueError('Para usuarios locales, abre Metakampo como administrador en un Windows Server miembro o independiente. No admite controladores de dominio.') from None
            initial = not store.values
            previous = store.values
            store.values = dict(identity=store.identity,settings=settings,
                                key=previous['key'] if previous else base64.b64encode(secrets.token_bytes(32)).decode())
            try:
                real = store.application()
                with connection(real.db_path) as db:
                    existing_admin=db.execute('SELECT hash FROM admin WHERE id=1').fetchone()
                    if existing_admin and not check_password_hash(existing_admin[0],password):
                        raise ValueError('El entorno de destino tiene otra contraseña administrativa. Confirma esa misma contraseña en ambos entornos antes de cambiar.')
                    if not existing_admin:
                        db.execute('INSERT INTO admin VALUES(1,?)',(generate_password_hash(password,method='pbkdf2:sha256:1000000'),))
                store.save(settings)
            except Exception:
                store.values = previous
                raise
            gate.application = real
            on_ready(real)
            return jsonify(ok=True)
        except (ValueError, OSError) as exc:
            return jsonify(error=str(exc)), 400
    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--configure', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--gui-smoke-test', action='store_true')
    parser.add_argument('--gui-smoke-report', default='gui-smoke-report.txt')
    args = parser.parse_args()
    if args.self_test:
        # A real frozen-executable smoke test uses ephemeral DPAPI data, never production.
        with tempfile.TemporaryDirectory(prefix='fk-selftest-') as folder:
            store = Store(folder)
            store.save(validate_settings(dict(mode='demo', store='CurrentUser')))
            reopened = Store(folder)
            assert reopened.values == store.values
            app = reopened.application()
            assert app.config['DESKTOP'] and app.db_path.exists()
            for filename in ('desktop-setup.html', 'app.js', 'icons.svg', 'fonts/InterVariable.woff2',
                             'access-map.js','access-map.css','maps/world.svg'):
                assert (BASE / 'static' / filename).exists(), filename
            assert (BASE / 'windows' / 'Read-LocalLogons.ps1').exists()
            assert (BASE / 'windows' / 'department-groups.ps1').exists()
            from access_map import Locator
            locator=Locator(BASE / 'geodata' / 'city.mmdb')
            try:
                assert locator.lookup('8.8.8.8')['located'], 'Offline geolocation not bundled'
            finally:locator.close()
            password=secrets.token_urlsafe(24)
            with connection(app.db_path) as db:
                db.execute('INSERT INTO admin VALUES(1,?)',(generate_password_hash(password,method='pbkdf2:sha256:1000000'),))
            with app.test_client() as client:
                base='http://127.0.0.1'
                csrf=client.get('/api/session',base_url=base).json['csrf']
                login=client.post('/api/login',base_url=base,json=dict(username='admin',password=password),headers={'X-CSRF-Token':csrf})
                assert login.status_code==200
                mapped=client.get('/api/map',base_url=base)
                assert mapped.status_code==200 and mapped.json['points']
                point=mapped.json['points'][0]['id']
                assert client.get('/api/map/events',base_url=base,query_string=dict(point=point)).json['events']
            print('Metakampo Access desktop self-test OK')
        return
    if os.name != 'nt':
        raise SystemExit('La aplicación instalable está diseñada para Windows Server x64.')
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion') as key:
        installation_type=winreg.QueryValueEx(key,'InstallationType')[0]
    if installation_type != 'Server':
        raise OSError('Se requiere Windows Server con experiencia de escritorio.')
    import webview
    from waitress import create_server
    from local_telemetry import LocalCollector
    temporary = tempfile.TemporaryDirectory(prefix='fk-gui-smoke-') if args.gui_smoke_test else None
    folder = Path(temporary.name) if temporary else Path(os.environ['LOCALAPPDATA']) / 'Freshkampo' / 'Access'
    store = Store(folder)
    lockfile = open(folder / 'desktop.lock', 'a+b')
    if not lockfile.tell():
        lockfile.write(b'0')
        lockfile.flush()
    import msvcrt
    lockfile.seek(0)
    try:
        msvcrt.locking(lockfile.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        raise OSError('Metakampo Access ya está abierto en esta cuenta Windows.')
    collectors = []
    def ready(app):
        for old in collectors:
            old.stop()
        collectors.clear()
        if app.config['MODE'] in ('ad','local'):
            collector = LocalCollector(app.db_path, folder)
            collectors.append(collector)
            collector.start()
    gate = DesktopGate(None)
    if store.values and not args.configure:
        gate.application = store.application()
        ready(gate.application)
    else:
        gate.application = setup_application(store, gate, ready)
    server = create_server(gate, host='127.0.0.1', port=0, threads=4,
                           clear_untrusted_proxy_headers=True)
    gate.host = '127.0.0.1:' + str(server.effective_port)
    url = 'http://' + gate.host + '/desktop-open?token=' + gate.bootstrap
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    webview.settings.update(ALLOW_DOWNLOADS=True, ALLOW_FILE_URLS=False,
                            OPEN_EXTERNAL_LINKS_IN_BROWSER=False, REMOTE_DEBUGGING_PORT=None)
    window = webview.create_window('Metakampo Access · Este servidor', url=url,
                                  width=1360, height=900, min_size=(900, 650), text_select=True)
    smoke_errors = []
    if args.gui_smoke_test:
        def check_window():
            try:
                loaded = window.evaluate_js("document.title === 'Configurar Metakampo Access' && !!document.getElementById('setup-form') && document.getElementById('save').disabled === false")
                if not loaded:
                    raise RuntimeError('El asistente de escritorio no se cargó correctamente en WebView2.')
                Path(args.gui_smoke_report).write_text('Native WebView2 window + authenticated local setup loaded successfully.\n', encoding='utf-8')
            except Exception as exc:
                smoke_errors.append(str(exc))
            finally:
                window.destroy()
        window.events.loaded += check_window
    try:
        webview.start(gui='edgechromium', private_mode=True, debug=False,
                      storage_path=str(folder / 'webview'))
    finally:
        for collector in collectors:
            collector.stop()
        server.close()
        lockfile.close()
        if temporary:
            temporary.cleanup()
    if smoke_errors:
        raise RuntimeError(smoke_errors[0])


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        if '--self-test' in sys.argv or '--gui-smoke-test' in sys.argv:
            raise
        if os.name == 'nt':
            ctypes.windll.user32.MessageBoxW(None, str(exc), 'Metakampo Access · No se pudo iniciar', 16)
        else:
            raise
