"""Owner-only, pinned signed updates. No remote code runs before verification."""
import base64
import ctypes
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from flask import g, jsonify, request
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from authentication import current_actor, reauthenticate
from directory import local_powershell_path
from update_trust import VERSION, REPOSITORY, PUBLIC_KEY, PUBLIC_XML

BASE=Path(__file__).parent
ASSET='Metakampo-Access-Setup-x64.exe'
ENVELOPE='metakampo-update.json'
API='https://api.github.com/repos/'+REPOSITORY+'/releases/latest'
MUTEX=r'Global\Metakampo.Access.Update.v1'
MAX_PACKAGE=1024*1024*1024


class UpdateError(ValueError):pass


def version(value):
    if not isinstance(value,str) or not re.fullmatch(r'(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})',value):
        raise UpdateError('Versión de actualización inválida.')
    return tuple(int(p) for p in value.split('.'))


def asset_url(tag,name):
    if not re.fullmatch(r'metakampo-v[0-9]+\.[0-9]+\.[0-9]+',tag) or name not in (ASSET,ENVELOPE):raise UpdateError('Origen de actualización inválido.')
    return 'https://github.com/'+REPOSITORY+'/releases/download/'+tag+'/'+name


def verified_manifest(raw,public_key=PUBLIC_KEY):
    try:
        if len(raw)>32768:raise ValueError()
        envelope=json.loads(raw)
        if not isinstance(envelope,dict) or set(envelope)!={'payload','signature'}:raise ValueError()
        payload=base64.b64decode(envelope['payload'],validate=True);signature=base64.b64decode(envelope['signature'],validate=True)
        if len(payload)>8192 or len(signature)!=384:raise ValueError()
        key=serialization.load_pem_public_key(public_key.encode())
        if key.key_size!=3072:raise ValueError()
        key.verify(signature,payload,padding.PKCS1v15(),hashes.SHA256())
        data=json.loads(payload)
        if set(data)!={'schema','version','tag','platform','asset','size','sha256','published_at'}:raise ValueError()
        if type(data['schema']) is not int or data['schema']!=1 or data['platform']!='windows-x64' or data['asset']!=ASSET:raise ValueError()
        version(data['version'])
        if data['tag']!='metakampo-v'+data['version']:raise ValueError()
        if type(data['size']) is not int or not 0<data['size']<=MAX_PACKAGE:raise ValueError()
        if not isinstance(data['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',data['sha256']):raise ValueError()
        if type(data['published_at']) is not int or not 1700000000<=data['published_at']<=time.time()+86400:raise ValueError()
        return data
    except (ValueError,TypeError,KeyError,AttributeError,InvalidSignature):
        raise UpdateError('No se confirmó la firma o el formato del paquete. No se ejecutará.') from None


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        check_url(newurl)
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def check_url(url):
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!='https' or parsed.hostname not in ('api.github.com','github.com','release-assets.githubusercontent.com','objects.githubusercontent.com') or parsed.username or parsed.password or parsed.port not in (None,443):
        raise UpdateError('El servidor de actualizaciones redirigió a un origen no permitido.')


def open_url(url):
    check_url(url)
    request=urllib.request.Request(url,headers={'User-Agent':'Metakampo-Access-Updater/'+VERSION,'Accept':'application/vnd.github+json' if url==API else 'application/octet-stream'})
    return urllib.request.build_opener(SafeRedirect()).open(request,timeout=30)


def read_url(url,limit):
    with open_url(url) as response:
        raw=response.read(limit+1)
    if len(raw)>limit:raise UpdateError('Respuesta de actualización demasiado grande.')
    return raw


def verify_package(path,manifest):
    with open(path,'rb') as stream:
        digest=hashlib.sha256();count=0;first=stream.read(65536)
        if first[:2]!=b'MZ':raise UpdateError('El paquete no es un instalador Windows válido.')
        chunk=first
        while chunk:
            count+=len(chunk)
            if count>manifest['size']:raise UpdateError('El tamaño del paquete no coincide.')
            digest.update(chunk);chunk=stream.read(1024*1024)
    if count!=manifest['size'] or digest.hexdigest()!=manifest['sha256']:raise UpdateError('La integridad del paquete no coincide. No se ejecutará.')


def maintenance_requested():
    if os.name!='nt':return False
    from ctypes import wintypes as W
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.OpenMutexW.argtypes=[W.DWORD,W.BOOL,W.LPCWSTR];k.OpenMutexW.restype=W.HANDLE;k.CloseHandle.argtypes=[W.HANDLE]
    handle=k.OpenMutexW(0x100000,False,MUTEX)
    if handle:k.CloseHandle(handle);return True
    return ctypes.get_last_error()!=2 # Access denied is not permission to start during maintenance.


def no_reparse(path):
    path=Path(path)
    for entry in [path]+list(path.parents):
        if entry.exists():
            info=entry.lstat()
            if entry.is_symlink() or getattr(info,'st_file_attributes',0)&0x400:raise UpdateError('La ruta de actualización no puede contener enlaces ni puntos de reanálisis.')


def secure_stage(root):
    root=Path(root).resolve();no_reparse(root)
    cache=root/'.metakampo-updates';no_reparse(cache);cache.mkdir(exist_ok=True)
    if os.name!='nt':raise UpdateError('La instalación de actualizaciones requiere Windows.')
    # Staging is under the installation, not in the owner's writable data/TEMP folder.
    subprocess.run(['icacls.exe',str(cache),'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F'],check=True,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
    subprocess.run(['icacls.exe',str(cache),'/setowner','*S-1-5-32-544'],check=True,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
    stage=cache/uuid.uuid4().hex;stage.mkdir();no_reparse(stage)
    return stage


def backup_store(folder):
    folder=Path(folder);target=folder/'update-backups'/(time.strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8])
    target.mkdir(parents=True,exist_ok=False)
    items=[folder/'installation.dpapi',folder/'ip-protection.sqlite3',folder/'ip-protection-demo.sqlite3']
    items += [folder/mode/'access.sqlite3' for mode in ('local','ad','demo')]
    if os.name=='nt':
        from background_protection import folder as protection_folder
        central=protection_folder()/'protection.sqlite3'
        if central.exists():
            no_reparse(central)
            with closing(sqlite3.connect(central,timeout=15)) as source,closing(sqlite3.connect(target/'shared-protection.sqlite3')) as dest:source.backup(dest)
    for path in items:
        if not path.exists():continue
        no_reparse(path)
        output=target/path.relative_to(folder);output.parent.mkdir(parents=True,exist_ok=True)
        if path.suffix=='.sqlite3':
            with closing(sqlite3.connect(path,timeout=15)) as source,closing(sqlite3.connect(output)) as dest:source.backup(dest)
        else:shutil.copy2(path,output)
    return target


class UpdateManager:
    def __init__(self,folder,root=None,current=VERSION,reader=read_url,opener=open_url):
        self.folder=Path(folder);self.root=Path(root).resolve() if root else None;self.current=current
        self.reader=reader;self.opener=opener;self.condition=threading.Condition();self.active=0;self.draining=False
        self.phase='idle';self.message='Busca una versión publicada y firmada.';self.latest=None;self.envelope=None;self.stage=None;self.received=0;self.checked_at=None;self.thread=None;self.auto_cancel=threading.Event();self.auto_thread=None
        self.prepare=None;self.resume=None;self.close=None

    def state(self):
        with self.condition:
            result=None
            if self.root:
                path=self.root/'.metakampo-updates'/'result.json'
                try:
                    if path.stat().st_size<=8192:result=json.loads(path.read_text(encoding='utf-8-sig'))
                except (OSError,ValueError):pass
            return dict(installed=self.current,phase=self.phase,message=self.message,latest=self.latest,received=self.received,checked_at=self.checked_at,can_install=bool(self.root and self.prepare and self.close),draining=self.draining,last_result=result,source='https://github.com/'+REPOSITORY+'/releases')

    def enter(self):
        with self.condition:
            if self.draining:return False
            self.active+=1;return True

    def leave(self):
        with self.condition:self.active-=1;self.condition.notify_all()

    def _job(self,phase,work):
        with self.condition:
            if self.thread and self.thread.is_alive():raise UpdateError('Ya hay una comprobación o actualización en curso.')
            if self.draining:raise UpdateError('La aplicación está preparando la actualización.')
            self.phase=phase;self.message='Comprobando versiones…' if phase=='checking' else 'Descargando paquete firmado…' if phase=='downloading' else 'Preparando cierre y copia de seguridad…'
            def run():
                try:work()
                except Exception as exc:
                    with self.condition:
                        self.phase='error';self.message=str(exc) if isinstance(exc,UpdateError) else 'No se pudo completar la actualización. Comprueba conexión, permisos y políticas Windows.'
            self.thread=threading.Thread(target=run,daemon=True,name='metakampo-update');self.thread.start()

    def check(self):
        with self.condition:
            if self.phase=='ready':raise UpdateError('Aplica primero el paquete que ya está descargado.')
        self._job('checking',self._check)

    def _check(self):
        try:release=json.loads(self.reader(API,1024*1024))
        except urllib.error.HTTPError as exc:
            if exc.code==404:
                with self.condition:self.phase='current';self.message='Todavía no hay una versión publicada en este canal.';self.checked_at=time.time()
                return
            raise UpdateError('GitHub no confirmó la consulta. Comprueba conexión o límite de solicitudes.') from None
        except (OSError,ValueError):raise UpdateError('No se pudo consultar GitHub Releases. Comprueba salida HTTPS.') from None
        if not isinstance(release,dict) or release.get('draft') is not False or release.get('prerelease') is not False:raise UpdateError('La publicación no es una versión estable.')
        tag=release.get('tag_name','')
        raw=self.reader(asset_url(tag,ENVELOPE),32768)
        manifest=verified_manifest(raw)
        if tag!=manifest['tag']:raise UpdateError('La versión publicada no coincide con su firma.')
        with self.condition:
            if version(manifest['version'])<=version(self.current):
                self.phase='current';self.message='Tienes la versión actual de este canal.';self.latest=None;self.envelope=None
            else:
                # A ready package is not silently swapped out by a later check.
                self.latest=manifest;self.envelope=raw;self.stage=None;self.received=0;self.phase='available';self.message='Hay una versión nueva con firma verificada.'
            self.checked_at=time.time()

    def download(self):
        with self.condition:
            if not self.latest or not self.envelope:raise UpdateError('Primero busca una actualización disponible.')
            if not self.root:raise UpdateError('Descarga disponible únicamente desde la aplicación instalada.')
        self._job('downloading',self._download)

    def _download(self):
        manifest=verified_manifest(self.envelope)
        if version(manifest['version'])<=version(self.current):raise UpdateError('No se permite instalar la misma versión ni una anterior.')
        stage=secure_stage(self.root);partial=stage/'package.part';final=stage/ASSET
        try:
            with self.opener(asset_url(manifest['tag'],ASSET)) as response,partial.open('xb') as stream:
                count=0
                while True:
                    chunk=response.read(1024*1024)
                    if not chunk:break
                    count+=len(chunk)
                    if count>manifest['size']:raise UpdateError('El paquete excede el tamaño firmado.')
                    stream.write(chunk)
                    with self.condition:self.received=count
            verify_package(partial,manifest);partial.replace(final)
            (stage/ENVELOPE).write_bytes(self.envelope)
            helper=(BASE/'windows'/'Apply-Update.ps1').read_text(encoding='utf-8-sig').replace('@@PUBLIC_XML@@',PUBLIC_XML)
            (stage/'Apply-Update.ps1').write_text(helper,encoding='utf-8-sig')
            with self.condition:self.stage=stage;self.phase='ready';self.message='Paquete verificado. El propietario puede aplicar la actualización.'
        except Exception:
            if partial.exists():partial.unlink()
            raise

    def apply(self,requested):
        with self.condition:
            if self.phase!='ready' or not self.stage or not self.latest or requested!=self.latest['version']:raise UpdateError('Descarga y verifica primero la versión seleccionada.')
            if not self.prepare or not self.close:raise UpdateError('Instala desde la ventana del propietario.')
        self._job('preparing',self._apply)

    def _apply(self):
        process=None;stopped=False
        try:
            manifest=verified_manifest((self.stage/ENVELOPE).read_bytes())
            if manifest!=self.latest or version(manifest['version'])<=version(self.current):raise UpdateError('El paquete preparado ya no coincide con la actualización seleccionada.')
            verify_package(self.stage/ASSET,manifest)
            with self.condition:
                self.draining=True
                until=time.monotonic()+60
                while self.active:
                    remaining=until-time.monotonic()
                    if remaining<=0:raise UpdateError('Hay operaciones activas. Termina esas tareas y vuelve a actualizar.')
                    self.condition.wait(min(remaining,1))
            stopped=True;self.prepare()
            saved=backup_store(self.folder)
            plan=dict(schema=1,version=manifest['version'],owner_pid=os.getpid(),restart_shared=True,interactive=not getattr(self,'service_host',False),service_host=bool(getattr(self,'service_host',False)))
            (self.stage/'plan.json').write_text(json.dumps(plan),encoding='utf-8')
            process=subprocess.Popen([local_powershell_path(),'-NoLogo','-NoProfile','-NonInteractive','-File',str(self.stage/'Apply-Update.ps1'),'-Plan',str(self.stage/'plan.json')],creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            until=time.monotonic()+20
            while time.monotonic()<until:
                if process.poll() is not None:raise UpdateError('Windows no inició el instalador seguro. Revisa la política de PowerShell y el resultado de actualización.')
                if (self.stage/'ready.json').exists():break
                time.sleep(.2)
            else:raise UpdateError('Windows no confirmó el actualizador. La aplicación permanecerá abierta.')
            with self.condition:self.message='Cerrando Metakampo para instalar '+manifest['version']+'. Copia de seguridad: '+str(saved);self.phase='installing'
            self.close()
        except Exception:
            if process and process.poll() is None:process.terminate();process.wait(timeout=10)
            if stopped and self.resume:self.resume()
            with self.condition:self.draining=False
            raise

    def start_auto(self):
        if self.auto_thread:return
        def run():
            if self.auto_cancel.wait(20):return
            while not self.auto_cancel.is_set():
                try:
                    if self.phase not in ('ready','preparing','installing','downloading','checking'):self.check()
                except UpdateError:pass
                self.auto_cancel.wait(6*3600)
        self.auto_thread=threading.Thread(target=run,daemon=True,name='metakampo-update-check');self.auto_thread.start()

    def stop_auto(self):self.auto_cancel.set()


def register(app,db,audit,throttled):
    manager=app.config.get('UPDATE_MANAGER')
    @app.before_request
    def update_maintenance():
        if not manager or not request.path.startswith('/api/') or request.path.startswith('/api/updates/') or request.path=='/api/session':return
        if not manager.enter():return jsonify(error='Metakampo está preparando una actualización. Espera a que termine.'),503
        g.update_counted=True
    @app.teardown_request
    def release_update_count(_):
        if manager and g.pop('update_counted',False):manager.leave()
    def owner_allowed():
        if not manager or not app.config.get('DESKTOP') or current_actor()!='admin':return False
        if not request.environ.get('metakampo.shared_client'):return True
        if not getattr(manager,'service_host',False):return False
        scope=request.environ.get('metakampo.impersonate')
        if not scope:return False
        from windows_native import current_sid
        with scope():return current_sid()==manager.owner_sid
    @app.get('/api/updates/status')
    def update_status():
        result=manager.state() if manager else dict(installed=VERSION,phase='unavailable',message='El actualizador funciona desde la ventana instalada del propietario.',latest=None,received=0,can_install=False,draining=False,checked_at=None,last_result=None,source='https://github.com/'+REPOSITORY+'/releases')
        result['owner']=owner_allowed()
        return jsonify(result)
    @app.post('/api/updates/<action>')
    def update_action(action):
        if not owner_allowed():return jsonify(error='Inicia sesión como admin desde la sesión Windows propietaria original para actualizar.'),403
        if throttled('updates',20):return jsonify(error='Demasiadas solicitudes de actualización. Espera unos minutos.'),429
        data=request.get_json(silent=True) or {}
        if not isinstance(data,dict):raise ValueError('Solicitud inválida.')
        if action=='check':manager.check()
        elif action=='download':manager.download()
        elif action=='apply':
            if not reauthenticate(db(),data.get('admin_password','')):return jsonify(error='Confirma la contraseña del propietario.'),403
            manager.apply(data.get('version'));audit('preparar actualización',data.get('version',''))
        else:return jsonify(error='Acción no admitida.'),404
        return jsonify(manager.state()),202
